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
        if (pos + tlvLen > data.length) break;
        const tlvData = Buffer.from(data.subarray(pos, pos + tlvLen)); pos += tlvLen;
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

function readLNTS(buf, offset) {
    if (offset + 2 > buf.length) return { str: '', next: offset };
    const len = buf.readUInt16LE(offset);
    if (len <= 1) return { str: '', next: offset + 2 + len };
    const str = buf.subarray(offset + 2, offset + 2 + len - 1).toString('utf8');
    return { str, next: offset + 2 + len };
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
        const { sessions } = ctx;

        if (subtype === 0x0002) {
            console.log(`\x1b[32m[READY]\x1b[0m ${session.uin} (watching ${session.watching.size})`);
            session.sendSNAC(0x0001, 0x000F, 0, 0, packUserInfoOnline(session));

            const offline = await db.getOffline(session.uin);
            for (const msg of offline) {
                session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
            }
        }
        if (subtype === 0x0006) session.sendSNAC(0x0001, 0x0007, 0, reqId, this.buildRateResponse());
        if (subtype === 0x0008) session.sendSNAC(0x0001, 0x0013, 0, 0, new OscarBuilder().u16(0x0004).tlv(0x000B, 'Welcome!').build());
        if (subtype === 0x000E) {
            const rawTlvs = parseTLVs(snac.data);
            mergeTLVs(session, rawTlvs);
            if (rawTlvs[0x0006] && rawTlvs[0x0006].length >= 4) session.status = rawTlvs[0x0006].readUInt16BE(2);
            await this.notifyWatchers(session, sessions, true);
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
            [[0x0001, 0x0004],[0x0002, 0x0001],[0x0003, 0x0001],[0x0004, 0x0001],[0x0009, 0x0001],[0x0013, 0x0005],[0x0015, 0x0001]]
                .forEach(([f, v]) => b.u16(f).u16(v));
            session.sendSNAC(0x0001, 0x0018, 0, reqId, b.build());
        }
        if (subtype === 0x001E) {
            mergeTLVs(session, parseTLVs(snac.data));
            await this.notifyWatchers(session, sessions, true);
        }
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
        b.u16(0x0001).u16(pairs.length);
        pairs.forEach(([f, s]) => b.u16(f).u16(s));
        return b.build();
    },

    async notifyWatchers(session, sessions, online) {
        const targetUin = session.uin;
        for (const [uin, ws] of sessions) {
            if (uin === targetUin) continue;
            if (!ws.watching.has(targetUin)) continue;
            if (online) ws.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(session));
            else ws.sendSNAC(0x0003, 0x000C, 0, 0, packUserInfoOffline(targetUin));
        }
        const ssiWatchers = await db.all("SELECT DISTINCT uin FROM ssi WHERE name = ? AND type = 0", [targetUin]);
        for (const row of ssiWatchers) {
            const ws = sessions.get(row.uin);
            if (ws && !ws.watching.has(targetUin)) {
                ws.watching.add(targetUin);
                if (online) ws.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(session));
                else ws.sendSNAC(0x0003, 0x000C, 0, 0, packUserInfoOffline(targetUin));
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
            if (tlvs[0x0002]) session.profile = tlvs[0x0002].toString();
            if (tlvs[0x0004]) session.awayMsg = tlvs[0x0004].toString();
            if (tlvs[0x0005]) { session.userTLVs.set(0x000D, tlvs[0x0005]); await this.notifyWatchers(session, ctx.sessions, true); }
        }
        if (subtype === 0x0005 && snac.data.length >= 3) {
            const flags = snac.data.readUInt16BE(0);
            const uinLen = snac.data[2];
            const targetUin = snac.data.subarray(3, 3 + uinLen).toString();
            const ts = ctx.sessions.get(targetUin);

            const b = new OscarBuilder();
            const tb = Buffer.from(targetUin);
            b.u8(tb.length).raw(tb).u16(0);

            if (ts) {
                const infoPairs =[];
                for (const[type, value] of ts.userTLVs) infoPairs.push([type, value]);
                infoPairs.push([0x0002, Buffer.from(ts.profile || `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from(ts.awayMsg || '')]);
                b.u16(infoPairs.length);
                infoPairs.forEach(([t, v]) => b.tlv(t, v));
            } else {
                b.u16(2).tlv(0x0001, Buffer.from([0x00, 0x40])).tlv(0x0002, `UIN: ${targetUin}`);
            }
            session.sendSNAC(0x0002, 0x0006, 0, reqId, b.build());
        }
    },

    async handleBuddy(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0003, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 1000).tlv(0x0002, 200).tlv(0x0003, 200).build());
        if (snac.subtype === 0x0004) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1;
                if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                session.watching.add(buddyUin);
                const bs = ctx.sessions.get(buddyUin);
                if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
            }
        }
        if (snac.subtype === 0x0005) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1;
                if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                session.watching.delete(buddyUin);
            }
        }
    },

    async handleICBM(session, snac, ctx) {
        if (snac.subtype === 0x0004 || snac.subtype === 0x0002) { session.sendSNAC(0x0004, 0x0005, 0, snac.reqId, buildICBMParams()); return; }
        if (snac.subtype === 0x0006) {
            const d = snac.data;
            if (d.length < 11) return;
            const cookie = d.subarray(0, 8);
            const channel = d.readUInt16BE(8);
            const uinLen = d[10];
            const recipient = d.subarray(11, 11 + uinLen).toString('utf8');
            const tlvs = parseTLVs(d.subarray(11 + uinLen));
            const target = ctx.sessions.get(recipient);

            // Бесшумный проброс QIP-уведомлений о печати
            if (channel === 2) {
                if (target) {
                    const b = new OscarBuilder().raw(cookie).u16(channel).u8(session.uin.length).string(session.uin).u16(0).u16(2).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, Buffer.from([0,0,0,0]));
                    if (tlvs[0x02]) b.tlv(0x02, tlvs[0x02]);
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
                return;
            }

            let msgText = '';
            if (channel === 1 && tlvs[0x0002]) {
                const frag = tlvs[0x0002];
                let pos = 0;
                while (pos + 4 <= frag.length) {
                    const fId = frag[pos]; const fLen = frag.readUInt16BE(pos + 2); const fData = frag.subarray(pos + 4, pos + 4 + fLen); pos += 4 + fLen;
                    if (fId === 0x01 && fData.length >= 4) {
                        const cs = fData.readUInt16BE(0); const raw = fData.subarray(4);
                        if (cs === 0x0003) msgText = iconv.decode(raw, 'win1251');
                        else msgText = raw.toString('utf8');
                    }
                }
            } else if (channel === 4 && tlvs[0x0005] && tlvs[0x0005].length >= 8) {
                msgText = tlvs[0x0005].subarray(8, 8 + tlvs[0x0005].readUInt16LE(6)).toString('utf8').replace(/\0/g, '');
            }

            console.log(`\x1b[32m[MSG]\x1b[0m ${session.uin} → ${recipient} : ${msgText}`);

            if (target) {
                const b = new OscarBuilder().raw(cookie).u16(channel).u8(Buffer.from(session.uin).length).string(session.uin).u16(0);
                const infoTlvs = [];
                for (const t of[0x0001, 0x0003, 0x0006, 0x000C, 0x000D]) if (session.userTLVs.has(t)) infoTlvs.push([t, session.userTLVs.get(t)]);
                b.u16(infoTlvs.length);
                infoTlvs.forEach(([t, v]) => b.tlv(t, v));
                if (tlvs[0x0002]) b.tlv(0x0002, tlvs[0x0002]);
                if (tlvs[0x0005]) b.tlv(0x0005, tlvs[0x0005]);
                target.sendSNAC(0x0004, 0x0007, 0, 0, b.build());
                if (tlvs[0x0003]) session.sendSNAC(0x0004, 0x000C, 0, snac.reqId, new OscarBuilder().raw(cookie).u16(channel).u8(recipient.length).string(recipient).build());
            } else if (msgText) {
                await db.storeOffline(session.uin, recipient, msgText);
            }
        }
    },

    buildIncomingMsg(senderUin, text, ts) {
        const cookie = Buffer.alloc(8);
        cookie.writeUInt32BE(Math.floor(Math.random() * 0xFFFFFFFF), 0);
        cookie.writeUInt32BE(Math.floor(ts || Date.now() / 1000), 4);
        const textBuf = Buffer.from(text, 'utf8');
        const msgBody = Buffer.concat([Buffer.alloc(4), textBuf]);
        const msgHeader = Buffer.alloc(4);
        msgHeader[0] = 0x01; msgHeader[1] = 0x01; msgHeader.writeUInt16BE(msgBody.length, 2);
        const b = new OscarBuilder().raw(cookie).u16(1).u8(senderUin.length).string(senderUin).u16(0).u16(2).tlv(0x0001, Buffer.from([0x00, 0x40])).tlv(0x0006, Buffer.from([0, 0, 0, 0])).tlv(0x0002, Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]), msgHeader, msgBody]));
        return b.build();
    },

    handlePrivacy(session, snac) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0009, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0001, 200).tlv(0x0002, 200).build());
    },

    async handleSSI(session, snac, ctx) {
        if (snac.subtype === 0x0002) session.sendSNAC(0x0013, 0x0003, 0, snac.reqId, new OscarBuilder().tlv(0x0004, 1000).tlv(0x0005, 100).tlv(0x0006, 200).tlv(0x0007, 200).tlv(0x0008, 200).build());
        if (snac.subtype === 0x0004) {
            const items = await db.getSSI(session.uin);
            for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
            const b = new OscarBuilder().u8(0).u16(items.length);
            for (const i of items) { const nb = Buffer.from(i.name || '', 'utf8'); b.u16(nb.length).raw(nb).u16(i.gid).u16(i.iid).u16(i.type).u16(i.tlvData ? i.tlvData.length : 0); if(i.tlvData) b.raw(i.tlvData); }
            b.u32(Math.floor(Date.now() / 1000));
            session.sendSNAC(0x0013, 0x0006, 0, snac.reqId, b.build());
        }
        // ВОССТАНОВЛЕНО: Без этого Infium зависает на логине
        if (snac.subtype === 0x0005) {
            const items = await db.getSSI(session.uin);
            if (snac.data.length >= 6) {
                const cliTs = snac.data.readUInt32BE(0);
                const cliCnt = snac.data.readUInt16BE(4);
                if (cliCnt === items.length && cliTs > 0) {
                    const nb = new OscarBuilder().u32(Math.floor(Date.now() / 1000)).u16(items.length);
                    session.sendSNAC(0x0013, 0x000F, 0, snac.reqId, nb.build());
                    for (const i of items) { if (i.type === 0 && i.name) session.watching.add(i.name); }
                    return;
                }
            }
            for (const i of items) if (i.type === 0 && i.name) session.watching.add(i.name);
            const b = new OscarBuilder().u8(0).u16(items.length);
            for (const i of items) { const nb = Buffer.from(i.name || '', 'utf8'); b.u16(nb.length).raw(nb).u16(i.gid).u16(i.iid).u16(i.type).u16(i.tlvData ? i.tlvData.length : 0); if(i.tlvData) b.raw(i.tlvData); }
            b.u32(Math.floor(Date.now() / 1000));
            session.sendSNAC(0x0013, 0x0006, 0, snac.reqId, b.build());
        }
        if (snac.subtype === 0x0007) { await this.sendBuddyStatuses(session, ctx.sessions); await this.notifyWatchers(session, ctx.sessions, true); }
        if (snac.subtype === 0x0008 || snac.subtype === 0x0009 || snac.subtype === 0x000A) {
            const items = parseSSIItems(snac.data);
            const results =[];
            for (const item of items) {
                try {
                    if (snac.subtype === 0x0008) { await db.run("DELETE FROM ssi WHERE uin = ? AND name = ?",[session.uin, item.name]); await db.run("INSERT INTO ssi (uin, name, gid, iid, type) VALUES (?, ?, ?, ?, ?)",[session.uin, item.name, item.gid, item.iid, item.type]); if (item.type === 0 && item.name) { session.watching.add(item.name); const bs = ctx.sessions.get(item.name); if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs)); } }
                    if (snac.subtype === 0x0009) await db.run("UPDATE ssi SET gid = ?, type = ? WHERE uin = ? AND name = ? AND iid = ?",[item.gid, item.type, session.uin, item.name, item.iid]);
                    if (snac.subtype === 0x000A) { await db.run("DELETE FROM ssi WHERE uin = ? AND name = ? AND iid = ?",[session.uin, item.name, item.iid]); if (item.type === 0 && item.name) session.watching.delete(item.name); }
                    results.push(0x0000);
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2);
            results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, snac.reqId, ack);
        }
        if (snac.subtype === 0x0012) { const buddies = await db.getSSIBuddies(session.uin); for (const b of buddies) session.watching.add(b.name); }
    },

    // ═══════════════════════════════════════════════
    //  ICQ ADVANCED DATA (Поиск QIP 2005 / INFIUM)
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

            let sqlQuery = "", sqlParam = "";

            if (subCmd === 0x0569 && metaData.length >= 8) { 
                sqlParam = metaData.readUInt32LE(4).toString();
                sqlQuery = "SELECT * FROM users WHERE uin = ?";
            } 
            else if (subCmd === 0x055F || subCmd === 0x0FA0) { 
                const clean = metaData.toString('utf8').replace(/[^\x20-\x7E\u0400-\u04FF]/g, ' ').trim();
                const parts = clean.split(/\s+/);
                sqlParam = parts[parts.length - 1] || '';
                
                if (sqlParam) {
                    if (/^\d+$/.test(sqlParam)) sqlQuery = "SELECT * FROM users WHERE uin = ?";
                    else if (sqlParam.includes('@')) sqlQuery = "SELECT * FROM users WHERE email = ?";
                    else sqlQuery = "SELECT * FROM users WHERE nickname = ?";
                }
            } 
            else if (subCmd === 0x04BA || subCmd === 0x04B2 || subCmd === 0x051F) {
                let targetUin = session.uin;
                if (metaData.length >= 4) { const v = metaData.readUInt32LE(0); if (v > 0) targetUin = v.toString(); }
                const user = await db.searchByUIN(targetUin);
                const bufs =[Buffer.from([0x0A])];
                if (user) { bufs.push(writeLNTS(user.nickname)); bufs.push(writeLNTS(user.firstname)); bufs.push(writeLNTS(user.lastname)); bufs.push(writeLNTS(user.email)); bufs.push(Buffer.from([0,0,0])); }
                else { bufs.push(writeLNTS('Unknown')); bufs.push(writeLNTS('')); bufs.push(writeLNTS('')); bufs.push(writeLNTS('')); bufs.push(Buffer.from([0,0,0])); }
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, subCmd === 0x04BA ? 0x0104 : 0x00FB, Buffer.concat(bufs));
                return;
            }
            else if (subCmd === 0x0C3A || subCmd === 0x0D0E) {
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x0C3F, Buffer.from([0x0A]));
                return;
            }
            else {
                // ИГНОРИРУЕМ неизвестные команды Infium, чтобы не было крашей при логине
                console.log(`\x1b[90m[META]\x1b[0m Unhandled subCmd=0x${subCmd.toString(16).padStart(4,'0')}`);
                return; 
            }

            if (sqlQuery && sqlParam) {
                console.log(`\x1b[35m[QIP SEARCH]\x1b[0m ${session.uin} ищет: "${sqlParam}"`);
                let results = [];
                try {
                    if(sqlQuery.includes("email = ?")) results = await db.searchByDetails({ email: sqlParam });
                    else if(sqlQuery.includes("nickname = ?")) results = await db.searchByDetails({ nickname: sqlParam });
                    else {
                        const u = await db.searchByUIN(sqlParam);
                        if(u) results.push(u);
                    }
                } catch(e) {}
                this.sendSearchResult(session, snac.reqId, ownerUin, seq, results);
            } else {
                this.sendSearchResult(session, snac.reqId, ownerUin, seq,[]);
            }
        }
    },

    sendSearchResult(session, reqId, ownerUin, seq, users) {
        if (!users || users.length === 0) {
            this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.from([0x00, 0x00])); // Пустой список
            return;
        }

        const bufs = [];
        bufs.push(Buffer.from([0x0A])); // 0x0A = Success
        
        // ВАЖНОЕ ИСПРАВЛЕНИЕ: Счетчик результатов (2 байта). Спасает от обрезки ника и UIN 458753
        const countBuf = Buffer.alloc(2);
        countBuf.writeUInt16LE(users.length);
        bufs.push(countBuf);

        for (const user of users) {
            const uinBuf = Buffer.alloc(4);
            uinBuf.writeUInt32LE(parseInt(user.uin) || 0);
            bufs.push(uinBuf);

            bufs.push(writeLNTS(user.nickname));
            bufs.push(writeLNTS(user.firstname));
            bufs.push(writeLNTS(user.lastname));
            bufs.push(writeLNTS(user.email));

            bufs.push(Buffer.from([0x00])); // AuthFlag
            bufs.push(Buffer.alloc(2));     // Status
            bufs.push(Buffer.from([user.gender || 0])); // Gender
            bufs.push(Buffer.alloc(2));     // Age
        }

        // 0x01AE (Конец Списка) - Infium моментально уберет загрузку поиска.
        this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.concat(bufs));
    },

    sendICQDirect(session, snacReqId, ownerUin, cmdType, seq, payload) {
        const inner = Buffer.alloc(8);
        inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(cmdType, 4);
        inner.writeUInt16LE(seq, 6);
        const innerFull = payload.length > 0 ? Buffer.concat([inner, payload]) : inner;
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    },

    sendICQMetaReply(session, snacReqId, ownerUin, seq, subType, payload) {
        const inner = Buffer.alloc(10);
        inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(0x07DA, 4);
        inner.writeUInt16LE(seq, 6);
        inner.writeUInt16LE(subType, 8);
        const innerFull = Buffer.concat([inner, payload]);
        const lenBuf = Buffer.alloc(2); lenBuf.writeUInt16LE(innerFull.length);
        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    }
};

module.exports = BOS;
