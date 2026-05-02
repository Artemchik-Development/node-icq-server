const iconv = require('iconv-lite');
const { OscarBuilder, parseTLVs } = require('./oscar');
const db = require('./database');

// ═══════════════════════════════════════════
//  User Info & Helpers
// ═══════════════════════════════════════════

function packUserInfoOnline(session) {
    const uinBuf = Buffer.from(session.uin, 'utf8');
    const b = new OscarBuilder();
    b.u8(uinBuf.length).raw(uinBuf);
    b.u16(0);
    const tlvMap = session.userTLVs;
    b.u16(tlvMap.size);
    for (const [type, value] of tlvMap) b.tlv(type, value);
    return b.build();
}

function packUserInfoOffline(uin) {
    const uinBuf = Buffer.from(uin, 'utf8');
    return new OscarBuilder().u8(uinBuf.length).raw(uinBuf).u16(0).u16(0).build();
}

function parseSSIItems(data) {
    const items =[];
    let pos = 0;
    while (pos + 10 <= data.length) {
        const nameLen = data.readUInt16BE(pos); pos += 2;
        if (pos + nameLen + 8 > data.length) break;
        const name = data.subarray(pos, pos + nameLen).toString('utf8'); pos += nameLen;
        const gid = data.readUInt16BE(pos); pos += 2;
        const iid = data.readUInt16BE(pos); pos += 2;
        const type = data.readUInt16BE(pos); pos += 2;
        const tlvLen = data.readUInt16BE(pos); pos += 2;
        let tlvData = null;
        if (tlvLen > 0) {
            if (pos + tlvLen > data.length) break;
            tlvData = Buffer.from(data.subarray(pos, pos + tlvLen));
            pos += tlvLen;
        }
        items.push({ name, gid, iid, type, tlvData });
    }
    return items;
}

function writeLNTS(str) {
    const data = Buffer.from((str || '') + '\0', 'utf8');
    const len = Buffer.alloc(2);
    len.writeUInt16LE(data.length);
    return Buffer.concat([len, data]);
}

function writeLTLV(type, buf) {
    const head = Buffer.alloc(4);
    head.writeUInt16LE(type, 0);
    head.writeUInt16LE(buf.length, 2);
    return Buffer.concat([head, buf]);
}

// ИСПРАВЛЕНИЕ: Формирование строки внутри "Матрешки" LTLV
function writeLTLVString(type, str) {
    const sBuf = Buffer.from((str || '') + '\0', 'utf8');
    const valBuf = Buffer.alloc(2 + sBuf.length);
    valBuf.writeUInt16LE(sBuf.length, 0); // Внутренняя длина строки
    sBuf.copy(valBuf, 2);
    return writeLTLV(type, valBuf);
}

function buildICBMParams() {
    return new OscarBuilder().u16(0x0000).u32(0x0000000B).u16(8000).u16(999).u16(999).u32(0).u16(0).build();
}

function mergeTLVs(session, rawTlvs) {
    for (const key of Object.keys(rawTlvs)) session.userTLVs.set(Number(key), rawTlvs[Number(key)]);
}

// ═══════════════════════════════════════════
//  Главный обработчик BOS
// ═══════════════════════════════════════════

const BOS = {
    async handlePacket(session, snac, context) {
        const { family, subtype } = snac;
        try {
            if (family === 0x0001) return await this.handleGeneric(session, snac, context);
            if (family === 0x0002) return await this.handleLocate(session, snac, context);
            if (family === 0x0003) return await this.handleBuddy(session, snac, context);
            if (family === 0x0004) return await this.handleICBM(session, snac, context);
            if (family === 0x0009) return this.handlePrivacy(session, snac);
            if (family === 0x0013) return await this.handleSSI(session, snac, context);
            if (family === 0x0015) return await this.handleICQ(session, snac, context);
        } catch (e) {
            console.error(`\x1b[31m[BOS ERR]\x1b[0m`, e);
        }
    },

    async handleGeneric(session, snac, ctx) {
        const { subtype, reqId } = snac;
        if (subtype === 0x0002) {
            console.log(`\x1b[32m[READY]\x1b[0m ${session.uin}`);
            
            if (!session.dbChecked) {
                session.dbChecked = true;
                const cols =['profile','awayMsg','firstname','lastname','city','phone','homepage','about','gender','age','nickname','email'];
                for(const c of cols) { try { await db.run(`ALTER TABLE users ADD COLUMN ${c} TEXT`); } catch(e){} }
            }

            try {
                const me = await db.searchByUIN(session.uin);
                if (me) { session.profile = me.about || ''; session.awayMsg = me.awayMsg || ''; }
            } catch(e) {}

            session.sendSNAC(0x0001, 0x000F, 0, 0, packUserInfoOnline(session));
            const offline = await db.getOffline(session.uin);
            for (const msg of offline) session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
        }
        if (subtype === 0x0006) session.sendSNAC(0x0001, 0x0007, 0, reqId, this.buildRateResponse());
        if (subtype === 0x0008) session.sendSNAC(0x0001, 0x0013, 0, 0, new OscarBuilder().u16(0x0004).tlv(0x000B, 'Welcome!').build());
        if (subtype === 0x000E) {
            const rawTlvs = parseTLVs(snac.data); mergeTLVs(session, rawTlvs);
            if (rawTlvs[0x0006] && rawTlvs[0x0006].length >= 4) session.status = rawTlvs[0x0006].readUInt16BE(2);
            await this.notifyWatchers(session, ctx.sessions, true);
        }
        if (subtype === 0x0011) {
            if (snac.data.length >= 4) {
                const idle = snac.data.readUInt32BE(0);
                if (idle > 0) { const buf = Buffer.alloc(4); buf.writeUInt32BE(idle); session.userTLVs.set(0x0004, buf); } 
                else session.userTLVs.delete(0x0004);
            }
        }
        if (subtype === 0x0017) {
            const b = new OscarBuilder();
            [[0x0001, 0x0004],[0x0002, 0x0001],[0x0003, 0x0001],[0x0004, 0x0001],[0x0009, 0x0001],[0x0013, 0x0005],[0x0015, 0x0001]].forEach(([f, v]) => b.u16(f).u16(v));
            session.sendSNAC(0x0001, 0x0018, 0, reqId, b.build());
        }
        if (subtype === 0x001E) { mergeTLVs(session, parseTLVs(snac.data)); await this.notifyWatchers(session, ctx.sessions, true); }
        if (subtype === 0x0004) session.sendSNAC(0x0001, 0x0001, 0, reqId, new OscarBuilder().u16(0x0005).build());
    },

    buildRateResponse() {
        const b = new OscarBuilder();
        b.u16(1).u16(0x0001).u32(80).u32(2500).u32(2000).u32(1500).u32(1000).u32(2500).u32(6000).u32(0).u8(0);
        const pairs =[];
        const families = {
            0x0001:[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x0E,0x0F,0x11,0x13,0x17,0x18,0x1E],
            0x0002:[0x01,0x02,0x03,0x04,0x05,0x06], 0x0003:[0x01,0x02,0x03,0x04,0x05,0x0B,0x0C],
            0x0004:[0x01,0x02,0x04,0x05,0x06,0x07,0x0C], 0x0009:[0x01,0x02,0x03],
            0x0013:[0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0E,0x0F,0x11,0x12],
            0x0015:[0x01,0x02,0x03],
        };
        for (const [fam, subs] of Object.entries(families)) for (const sub of subs) pairs.push([parseInt(fam), sub]);
        b.u16(0x0001).u16(pairs.length); pairs.forEach(([f, s]) => b.u16(f).u16(s));
        return b.build();
    },

    async notifyWatchers(session, sessions, online) {
        const targetUin = session.uin;
        for (const[uin, ws] of sessions) {
            if (uin === targetUin || !ws.watching.has(targetUin)) continue;
            ws.sendSNAC(0x0003, online ? 0x000B : 0x000C, 0, 0, online ? packUserInfoOnline(session) : packUserInfoOffline(targetUin));
        }
        const ssiWatchers = await db.all("SELECT DISTINCT uin FROM ssi WHERE name = ? AND type = 0",[targetUin]);
        for (const row of ssiWatchers) {
            const ws = sessions.get(row.uin);
            if (ws && !ws.watching.has(targetUin)) {
                ws.watching.add(targetUin);
                ws.sendSNAC(0x0003, online ? 0x000B : 0x000C, 0, 0, online ? packUserInfoOnline(session) : packUserInfoOffline(targetUin));
            }
        }
    },

    async sendBuddyStatuses(session, sessions) {
        for (const buddyUin of session.watching) {
            const bs = sessions.get(buddyUin);
            if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
        }
    },

    async handleLocate(session, snac, ctx) {
        const { subtype, reqId } = snac;
        if (subtype === 0x0002) session.sendSNAC(0x0002, 0x0003, 0, reqId, new OscarBuilder().tlv(0x0001, 0x0400).tlv(0x0002, 0x0010).tlv(0x0005, 0x000A).build());
        
        if (subtype === 0x0004) {
            const tlvs = parseTLVs(snac.data);
            if (tlvs[0x0002]) { 
                session.profile = tlvs[0x0002].toString('utf8'); 
                try { await db.run("UPDATE users SET about = ? WHERE uin = ?",[session.profile, session.uin]); } catch(e){}
            }
            if (tlvs[0x0004]) { 
                session.awayMsg = tlvs[0x0004].toString('utf8'); 
                try { await db.run("UPDATE users SET awayMsg = ? WHERE uin = ?", [session.awayMsg, session.uin]); } catch(e){}
            }
            if (tlvs[0x0005]) { session.userTLVs.set(0x000D, tlvs[0x0005]); await this.notifyWatchers(session, ctx.sessions, true); }
        }
        
        if (subtype === 0x0005 && snac.data.length >= 3) {
            const flags = snac.data.readUInt16BE(0); const targetUin = snac.data.subarray(3, 3 + snac.data[2]).toString();
            const ts = ctx.sessions.get(targetUin);
            const userDb = await db.searchByUIN(targetUin); 

            const b = new OscarBuilder(); const tb = Buffer.from(targetUin); b.u8(tb.length).raw(tb).u16(0);
            
            const infoPairs =[]; 
            if (ts) {
                for (const[type, value] of ts.userTLVs) infoPairs.push([type, value]);
                infoPairs.push([0x0002, Buffer.from(ts.profile || (userDb ? userDb.about : '') || `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from(ts.awayMsg || '')]);
            } else {
                infoPairs.push([0x0001, Buffer.from([0x00, 0x40])]);
                infoPairs.push([0x0002, Buffer.from(userDb ? (userDb.about || '') : `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from('')]);
            }
            b.u16(infoPairs.length); infoPairs.forEach(([t, v]) => b.tlv(t, v));
            session.sendSNAC(0x0002, 0x0006, 0, reqId, b.build());
        }
    },

    async handleBuddy(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0003, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 1000).tlv(0x0002, 200).tlv(0x0003, 200).build());
        if (snac.subtype === 0x0004 || snac.subtype === 0x0005) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1; if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                if (snac.subtype === 0x0004) { session.watching.add(buddyUin); const bs = ctx.sessions.get(buddyUin); if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs)); }
                else session.watching.delete(buddyUin);
            }
        }
    },

    async handleICBM(session, snac, ctx) {
        if (snac.subtype === 0x0004 || snac.subtype === 0x0002) return session.sendSNAC(0x0004, 0x0005, 0, snac.reqId, buildICBMParams());
        if (snac.subtype === 0x0006) {
            const d = snac.data; if (d.length < 11) return;
            const cookie = d.subarray(0, 8); const channel = d.readUInt16BE(8); const uinLen = d[10];
            const recipient = d.subarray(11, 11 + uinLen).toString('utf8'); const tlvs = parseTLVs(d.subarray(11 + uinLen));
            const target = ctx.sessions.get(recipient);

            // ИСПРАВЛЕНИЕ INFIUM: Проброс всех TLV параметров (XML плагины, Typing Status)
            if (channel === 2) {
                if (target) {
                    const b = new OscarBuilder().raw(cookie).u16(channel).u8(session.uin.length).string(session.uin)
                             .u16(0).u16(3).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, session.userTLVs.get(0x0006) || Buffer.from([0,0,0,0])).tlv(0x03, session.userTLVs.get(0x0003) || Buffer.alloc(4));
                    
                    // Пересылаем все TLV, которые клиент вложил (кроме самого сообщения), чтобы плагины работали
                    for (const [t, v] of Object.entries(tlvs)) {
                        if (t !== '5' && t !== '2') b.tlv(parseInt(t), v); 
                    }
                    if (tlvs[0x05]) b.tlv(0x05, tlvs[0x05]);
                    
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
                return;
            }

            let msgText = '';
            if (channel === 1 && tlvs[0x0002]) {
                const frag = tlvs[0x0002]; let pos = 0;
                while (pos + 4 <= frag.length) {
                    const fId = frag[pos]; const fLen = frag.readUInt16BE(pos + 2); const fData = frag.subarray(pos + 4, pos + 4 + fLen); pos += 4 + fLen;
                    if (fId === 0x01 && fData.length >= 4) { const cs = fData.readUInt16BE(0); const raw = fData.subarray(4); msgText = (cs === 0x0003) ? iconv.decode(raw, 'win1251') : raw.toString('utf8'); }
                }
            } else if (channel === 4 && tlvs[0x0005] && tlvs[0x0005].length >= 8) {
                msgText = tlvs[0x0005].subarray(8, 8 + tlvs[0x0005].readUInt16LE(6)).toString('utf8').replace(/\0/g, '');
            }

            console.log(`\x1b[32m[MSG]\x1b[0m ${session.uin} → ${recipient} : ${msgText}`);

            if (target) {
                let tlv02 = tlvs[0x0002];
                if (channel === 1 && msgText) {
                    const textBuf = Buffer.from(msgText, 'utf8');
                    const msgBody = Buffer.concat([Buffer.alloc(4), textBuf]);
                    const msgHeader = Buffer.alloc(4); msgHeader[0] = 0x01; msgHeader[1] = 0x01; msgHeader.writeUInt16BE(msgBody.length, 2);
                    tlv02 = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]), msgHeader, msgBody]);
                }
                const b = new OscarBuilder().raw(cookie).u16(channel).u8(Buffer.from(session.uin).length).string(session.uin)
                         .u16(0).u16(3).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, session.userTLVs.get(0x0006) || Buffer.from([0,0,0,0])).tlv(0x03, session.userTLVs.get(0x0003) || Buffer.alloc(4));
                if (tlv02) b.tlv(0x02, tlv02); if (tlvs[0x0005]) b.tlv(0x0005, tlvs[0x0005]);
                target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                if (tlvs[0x0003]) session.sendSNAC(0x0004, 0x000C, 0, snac.reqId, new OscarBuilder().raw(cookie).u16(channel).u8(recipient.length).string(recipient).build());
            } else if (msgText) await db.storeOffline(session.uin, recipient, msgText);
        }
    },

    buildIncomingMsg(senderUin, text, ts) {
        const cookie = Buffer.alloc(8); cookie.writeUInt32BE(Math.floor(Math.random() * 0xFFFFFFFF), 0); cookie.writeUInt32BE(Math.floor(ts || Date.now() / 1000), 4);
        const msgBody = Buffer.concat([Buffer.alloc(4), Buffer.from(text, 'utf8')]);
        const msgHeader = Buffer.alloc(4); msgHeader[0] = 0x01; msgHeader[1] = 0x01; msgHeader.writeUInt16BE(msgBody.length, 2);
        const signonTime = Buffer.alloc(4); signonTime.writeUInt32BE(Math.floor(Date.now() / 1000));
        return new OscarBuilder().raw(cookie).u16(1).u8(senderUin.length).string(senderUin).u16(0).u16(3).tlv(0x0001, Buffer.from([0x00, 0x40])).tlv(0x0006, Buffer.from([0, 0, 0, 0])).tlv(0x0003, signonTime).tlv(0x0002, Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]), msgHeader, msgBody])).build();
    },

    handlePrivacy(session, snac) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0009, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 200).tlv(0x0002, 200).build());
    },

    async handleSSI(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0013, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0004, 1000).tlv(0x0005, 100).tlv(0x0006, 200).tlv(0x0007, 200).tlv(0x0008, 200).build());
        
        if (snac.subtype === 0x0004 || snac.subtype === 0x0005) {
            const items = await db.getSSI(session.uin);
            if (snac.subtype === 0x0005 && snac.data.length >= 6) {
                const cliTs = snac.data.readUInt32BE(0); const cliCnt = snac.data.readUInt16BE(4);
                if (cliCnt === items.length && cliTs > 0) {
                    session.sendSNAC(0x0013, 0x000F, 0, snac.reqId, new OscarBuilder().u32(Math.floor(Date.now() / 1000)).u16(items.length).build());
                    for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
                    return;
                }
            }
            for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
            const b = new OscarBuilder().u8(0).u16(items.length);
            for (const i of items) { 
                const nb = Buffer.from(i.name || '', 'utf8'); 
                const tlvBuf = i.tlv ? Buffer.from(i.tlv) : Buffer.alloc(0);
                b.u16(nb.length).raw(nb).u16(i.gid).u16(i.iid).u16(i.type).u16(tlvBuf.length); 
                if(tlvBuf.length > 0) b.raw(tlvBuf); 
            }
            b.u32(Math.floor(Date.now() / 1000));
            session.sendSNAC(0x0013, 0x0006, 0, snac.reqId, b.build());
        }
        
        if (snac.subtype === 0x0007) { await this.sendBuddyStatuses(session, ctx.sessions); await this.notifyWatchers(session, ctx.sessions, true); }
        
        if (snac.subtype === 0x0008 || snac.subtype === 0x0009 || snac.subtype === 0x000A) {
            const items = parseSSIItems(snac.data); const results =[];
            try { await db.run("ALTER TABLE ssi ADD COLUMN tlv BLOB"); } catch(e) {}
            for (const item of items) {
                const tlvBlob = item.tlvData ? Buffer.from(item.tlvData) : null;
                try {
                    if (snac.subtype === 0x0008) { 
                        await db.run("DELETE FROM ssi WHERE uin = ? AND name = ?",[session.uin, item.name]); 
                        await db.run("INSERT INTO ssi (uin, name, gid, iid, type, tlv) VALUES (?, ?, ?, ?, ?, ?)",[session.uin, item.name, item.gid, item.iid, item.type, tlvBlob]); 
                        if (item.type === 0 && item.name) { session.watching.add(item.name); const bs = ctx.sessions.get(item.name); if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs)); } 
                    }
                    if (snac.subtype === 0x0009) await db.run("UPDATE ssi SET gid = ?, type = ?, tlv = ? WHERE uin = ? AND name = ? AND iid = ?",[item.gid, item.type, tlvBlob, session.uin, item.name, item.iid]);
                    if (snac.subtype === 0x000A) { await db.run("DELETE FROM ssi WHERE uin = ? AND name = ? AND iid = ?",[session.uin, item.name, item.iid]); if (item.type === 0 && item.name) session.watching.delete(item.name); }
                    results.push(0x0000);
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2); results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, snac.reqId, ack);
        }
        if (snac.subtype === 0x0012) { const buddies = await db.getSSIBuddies(session.uin); for (const b of buddies) session.watching.add(b.name); }
    },

    // ═══════════════════════════════════════════════
    //  ICQ ADVANCED DATA & FULL INFO
    // ═══════════════════════════════════════════════

    async handleICQ(session, snac, ctx) {
        if (snac.subtype !== 0x0002) return;
        const tlvs = parseTLVs(snac.data);
        const extData = tlvs[0x0001];
        if (!extData || extData.length < 10) return;

        const ownerUin = extData.readUInt32LE(2);
        const cmdType  = extData.readUInt16LE(6);
        const seq      = extData.readUInt16LE(8);
        const subData  = extData.subarray(10);

        if (cmdType === 0x003C) {
            const offline = await db.getOffline(session.uin);
            for (const msg of offline) session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
            this.sendICQDirect(session, snac.reqId, ownerUin, 0x0042, seq, Buffer.alloc(0));
            return;
        }

        if (cmdType === 0x003E) return;

        if (cmdType === 0x07D0 && subData.length >= 2) {
            const subCmd = subData.readUInt16LE(0);
            const metaData = subData.subarray(2);

            // 1. ПОЛУЧЕНИЕ ИНФОРМАЦИИ (Get Info)
            if (subCmd === 0x04BA || subCmd === 0x04B2 || subCmd === 0x051F) {
                let targetUin = session.uin;
                if (metaData.length >= 4) { const v = metaData.readUInt32LE(0); if (v > 0) targetUin = v.toString(); }
                const user = await db.searchByUIN(targetUin);
                
                if (subCmd === 0x04B2) {
                    // КРАТКАЯ ИНФОРМАЦИЯ
                    const bufs =[Buffer.from([0x0A])]; 
                    if (user) {
                        bufs.push(writeLNTS(user.nickname));
                        bufs.push(writeLNTS(user.firstname));
                        bufs.push(writeLNTS(user.lastname));
                        bufs.push(writeLNTS(user.email));
                        bufs.push(Buffer.from([0x00])); 
                        bufs.push(Buffer.from([0x00, 0x00])); 
                        bufs.push(Buffer.from([user.gender ? parseInt(user.gender) : 0])); 
                        bufs.push(Buffer.from([0x00, 0x00])); 
                    } else {
                        bufs.push(writeLNTS('Unknown')); bufs.push(writeLNTS('')); bufs.push(writeLNTS('')); bufs.push(writeLNTS(''));
                        bufs.push(Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));
                    }
                    this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x00BA, Buffer.concat(bufs));
                } else {
                    // ПОЛНАЯ АНКЕТА (ИСПРАВЛЕНИЕ: LTLV со встроенной длиной строки)
                    const bufs =[Buffer.from([0x0A])];
                    if (user) {
                        // UIN отправляется как DWORD
                        const uinBuf = Buffer.alloc(4); uinBuf.writeUInt32LE(parseInt(user.uin) || 0);
                        bufs.push(writeLTLV(310, uinBuf));
                        
                        if (user.nickname) bufs.push(writeLTLVString(340, user.nickname));
                        if (user.firstname) bufs.push(writeLTLVString(350, user.firstname));
                        if (user.lastname) bufs.push(writeLTLVString(360, user.lastname));
                        if (user.email) bufs.push(writeLTLVString(370, user.email));
                        if (user.city) bufs.push(writeLTLVString(380, user.city));
                        if (user.phone) bufs.push(writeLTLVString(400, user.phone));
                        if (user.homepage) bufs.push(writeLTLVString(580, user.homepage));
                        if (user.about) bufs.push(writeLTLVString(700, user.about));
                        
                        if (user.gender) { const gb = Buffer.alloc(1); gb.writeUInt8(parseInt(user.gender)); bufs.push(writeLTLV(560, gb)); }
                        if (user.age) { const ab = Buffer.alloc(2); ab.writeUInt16LE(parseInt(user.age)); bufs.push(writeLTLV(550, ab)); }
                    }
                    this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x0118, Buffer.concat(bufs));
                }
                return;
            }
            
            // 2. СОХРАНЕНИЕ АНКЕТЫ (Set Info)
            if (subCmd === 0x0C3A || subCmd === 0x0D0E) {
                let pos = 0; const updates = {};
                while(pos + 4 <= metaData.length) {
                    const tType = metaData.readUInt16LE(pos); const tLen = metaData.readUInt16LE(pos+2); pos += 4;
                    if (tLen > 0 && pos + tLen <= metaData.length) {
                        const valBuf = metaData.subarray(pos, pos+tLen);
                        let strVal = '';
                        // ИСПРАВЛЕНИЕ: строка идет после 2 байт своей собственной длины
                        if (tLen > 2) strVal = valBuf.subarray(2).toString('utf8').replace(/\0/g, '').trim();

                        if (tType === 340) updates.nickname = strVal;
                        if (tType === 350) updates.firstname = strVal;
                        if (tType === 360) updates.lastname = strVal;
                        if (tType === 370) updates.email = strVal;
                        if (tType === 380) updates.city = strVal;
                        if (tType === 400) updates.phone = strVal;
                        if (tType === 550 && tLen >= 2) updates.age = valBuf.readUInt16LE(0);
                        if (tType === 560 && tLen >= 1) updates.gender = valBuf.readUInt8(0);
                        if (tType === 580) updates.homepage = strVal;
                        if (tType === 700) updates.about = strVal;
                    }
                    pos += tLen;
                }

                const keys = Object.keys(updates);
                if (keys.length > 0) {
                    const setStr = keys.map(k => `${k} = ?`).join(', ');
                    const values = keys.map(k => updates[k]); values.push(session.uin);
                    try { await db.run(`UPDATE users SET ${setStr} WHERE uin = ?`, values); } catch(e) {}
                }
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x0C3F, Buffer.from([0x0A])); 
                console.log(`\x1b[35m[ПРОФИЛЬ]\x1b[0m ${session.uin} обновил анкету:`, Object.keys(updates));
                return;
            }

            // 3. ПОИСК (QIP 2005 / INFIUM)
            let sqlQuery = "", sqlParam = "";
            if (subCmd === 0x0569 && metaData.length >= 8) { 
                sqlParam = metaData.readUInt32LE(4).toString(); sqlQuery = "SELECT * FROM users WHERE uin = ?";
            } 
            else if (subCmd === 0x055F || subCmd === 0x0FA0) { 
                const clean = metaData.toString('utf8').replace(/[^\x20-\x7E\u0400-\u04FF]/g, ' ').trim();
                const parts = clean.split(/\s+/); sqlParam = parts[parts.length - 1] || '';
                if (sqlParam) {
                    if (/^\d+$/.test(sqlParam)) sqlQuery = "SELECT * FROM users WHERE uin = ?";
                    else if (sqlParam.includes('@')) sqlQuery = "SELECT * FROM users WHERE email = ?";
                    else sqlQuery = "SELECT * FROM users WHERE nickname = ?";
                }
            } 
            else {
                // ВОССТАНОВЛЕНО: Отвечаем на неизвестные команды плагинов (чтобы Infium не зависал при логине)
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, subCmd + 1, Buffer.from([0x00]));
                return; 
            }

            if (sqlQuery && sqlParam) {
                console.log(`\x1b[35m[QIP SEARCH]\x1b[0m ${session.uin} ищет: "${sqlParam}"`);
                let results = [];
                try {
                    if(sqlQuery.includes("email = ?")) results = await db.searchByDetails({ email: sqlParam });
                    else if(sqlQuery.includes("nickname = ?")) results = await db.searchByDetails({ nickname: sqlParam });
                    else { const u = await db.searchByUIN(sqlParam); if(u) results.push(u); }
                } catch(e) {}
                
                if (subCmd === 0x0FA0) this.sendInfiumSearchResult(session, snac.reqId, ownerUin, seq, results);
                else this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq, results);
            } else {
                if (subCmd === 0x0FA0) this.sendInfiumSearchResult(session, snac.reqId, ownerUin, seq,[]);
                else this.sendQip2005SearchResult(session, snac.reqId, ownerUin, seq,[]);
            }
        }
    },

    sendQip2005SearchResult(session, reqId, ownerUin, seq, users) {
        if (!users || users.length === 0) return this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.from([0x0A, 0x00, 0x00])); 
        const bufs =[]; bufs.push(Buffer.from([0x0A])); 
        const countBuf = Buffer.alloc(2); countBuf.writeUInt16LE(users.length); bufs.push(countBuf); 
        for (const user of users) {
            const uinBuf = Buffer.alloc(4); uinBuf.writeUInt32LE(parseInt(user.uin) || 0); bufs.push(uinBuf);
            bufs.push(writeLNTS(user.nickname)); bufs.push(writeLNTS(user.firstname)); bufs.push(writeLNTS(user.lastname)); bufs.push(writeLNTS(user.email));
            bufs.push(Buffer.from([0x00])); bufs.push(Buffer.alloc(2)); bufs.push(Buffer.from([user.gender || 0])); bufs.push(Buffer.alloc(2));
        }
        this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.concat(bufs));
    },

    sendInfiumSearchResult(session, reqId, ownerUin, seq, users) {
        if (!users || users.length === 0) return this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x0FA1, Buffer.alloc(0)); 
        for (const user of users) {
            const bufs =[]; const uinBuf = Buffer.alloc(4); uinBuf.writeUInt32LE(parseInt(user.uin) || 0);
            bufs.push(writeLTLV(0x0136, uinBuf)); 
            
            // ИСПРАВЛЕНИЕ: Использование правильного конвертера строк с префиксом длины
            if (user.nickname) bufs.push(writeLTLVString(0x0154, user.nickname)); 
            if (user.firstname) bufs.push(writeLTLVString(0x015E, user.firstname)); 
            if (user.lastname) bufs.push(writeLTLVString(0x0168, user.lastname)); 
            if (user.email) bufs.push(writeLTLVString(0x0172, user.email)); 
            bufs.push(writeLTLV(0x0212, Buffer.from([0x00]))); 
            
            this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x0FA1, Buffer.concat(bufs));
        }
        this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x0FA1, Buffer.alloc(0));
    },

    sendICQDirect(session, snacReqId, ownerUin, cmdType, seq, payload) {
        const inner = Buffer.alloc(8); inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(cmdType, 4); inner.writeUInt16LE(seq, 6);
        const innerFull = payload.length > 0 ? Buffer.concat([inner, payload]) : inner;
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    },

    sendICQMetaReply(session, snacReqId, ownerUin, seq, subType, payload) {
        const inner = Buffer.alloc(10); inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(0x07DA, 4); inner.writeUInt16LE(seq, 6); inner.writeUInt16LE(subType, 8);
        const innerFull = Buffer.concat([inner, payload]);
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    }
};

module.exports = BOS;
