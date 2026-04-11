const iconv = require('iconv-lite');
const { OscarBuilder, parseTLVs } = require('./oscar');
const db = require('./database');

// ═══════════════════════════════════════════
//  User Info
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
    const b = new OscarBuilder();
    b.u8(uinBuf.length).raw(uinBuf);
    b.u16(0).u16(0);
    return b.build();
}

// ═══════════════════════════════════════════
//  Вспомогательные
// ═══════════════════════════════════════════

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
    return new OscarBuilder()
        .u16(0x0000).u32(0x0000000B)
        .u16(8000).u16(999).u16(999).u32(0).u16(0)
        .build();
}

function mergeTLVs(session, rawTlvs) {
    for (const key of Object.keys(rawTlvs)) {
        session.userTLVs.set(Number(key), rawTlvs[Number(key)]);
    }
}

const STATUS_NAMES = {
    0x0000: 'Online', 0x0001: 'Away', 0x0002: 'DND',
    0x0004: 'NA', 0x0010: 'Occupied', 0x0020: 'Free4Chat', 0x0100: 'Invisible',
};

// ═══════════════════════════════════════════
//  Главный обработчик
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
            console.log(`\x1b[90m[SKIP]\x1b[0m family=0x${family.toString(16)} sub=0x${subtype.toString(16)}`);
        } catch (e) {
            console.error(`\x1b[31m[BOS ERR]\x1b[0m`, e);
        }
    },

    // ═══════════════════════════════════════
    //  Generic 0x0001
    // ═══════════════════════════════════════

    async handleGeneric(session, snac, ctx) {
        const { subtype, reqId } = snac;
        const { sessions } = ctx;

        // 0x02 — CLI_READY
        if (subtype === 0x0002) {
            console.log(`\x1b[32m[READY]\x1b[0m ${session.uin} (watching ${session.watching.size})`);
            session.sendSNAC(0x0001, 0x000F, 0, 0, packUserInfoOnline(session));

            const offline = await db.getOffline(session.uin);
            for (const msg of offline) {
                session.sendSNAC(0x0004, 0x0007, 0, 0,
                    this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
                console.log(`[OFFLINE] ${msg.sender} → ${session.uin}: ${msg.message}`);
            }
        }

        // 0x06 — CLI_RATE_REQUEST
        if (subtype === 0x0006) {
            session.sendSNAC(0x0001, 0x0007, 0, reqId, this.buildRateResponse());
        }

        // 0x08 — CLI_RATE_ACK
        if (subtype === 0x0008) {
            console.log(`\x1b[90m[RATE ACK]\x1b[0m ${session.uin}`);
            session.sendSNAC(0x0001, 0x0013, 0, 0,
                new OscarBuilder().u16(0x0004).tlv(0x000B, 'Welcome!').build());
        }

        // 0x0E — CLI_SET_STATUS
        if (subtype === 0x000E) {
            const rawTlvs = parseTLVs(snac.data);
            mergeTLVs(session, rawTlvs);
            if (rawTlvs[0x0006] && rawTlvs[0x0006].length >= 4) {
                session.status = rawTlvs[0x0006].readUInt16BE(2);
            }
            const name = STATUS_NAMES[session.status] || `0x${session.status.toString(16)}`;
            console.log(`\x1b[33m[STATUS]\x1b[0m ${session.uin}: ${name}`);
            await this.notifyWatchers(session, sessions, true);
        }

        // 0x11 — CLI_SET_IDLE
        if (subtype === 0x0011) {
            if (snac.data.length >= 4) {
                const idle = snac.data.readUInt32BE(0);
                if (idle > 0) {
                    const buf = Buffer.alloc(4); buf.writeUInt32BE(idle);
                    session.userTLVs.set(0x0004, buf);
                } else {
                    session.userTLVs.delete(0x0004);
                }
            }
        }

        // 0x17 — CLI_FAMILIES_VERSIONS
        if (subtype === 0x0017) {
            const b = new OscarBuilder();
            [[0x0001, 0x0004], [0x0002, 0x0001],[0x0003, 0x0001],[0x0004, 0x0001],[0x0009, 0x0001], [0x0013, 0x0005],[0x0015, 0x0001],
            ].forEach(([f, v]) => b.u16(f).u16(v));
            session.sendSNAC(0x0001, 0x0018, 0, reqId, b.build());
        }

        // 0x1E — CLI_SET_EXTENDED_STATUS
        if (subtype === 0x001E) {
            const rawTlvs = parseTLVs(snac.data);
            mergeTLVs(session, rawTlvs);
            console.log(`\x1b[35m[X-STATUS]\x1b[0m ${session.uin}`);
            await this.notifyWatchers(session, sessions, true);
        }

        // 0x04 — CLI_REQUEST_SERVICE
        if (subtype === 0x0004) {
            session.sendSNAC(0x0001, 0x0001, 0, reqId,
                new OscarBuilder().u16(0x0005).build());
        }
    },

    // ═══════════════════════════════════════
    //  Rate Response
    // ═══════════════════════════════════════

    buildRateResponse() {
        const b = new OscarBuilder();
        b.u16(1);
        b.u16(0x0001); b.u32(80);
        b.u32(2500); b.u32(2000); b.u32(1500); b.u32(1000);
        b.u32(2500); b.u32(6000);
        b.u32(0); b.u8(0);

        const pairs = [];
        const families = {
            0x0001:[0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,0x0008,
                     0x000E,0x000F,0x0011,0x0013,0x0017,0x0018,0x001E],
            0x0002:[0x0001,0x0002,0x0003,0x0004,0x0005,0x0006],
            0x0003:[0x0001,0x0002,0x0003,0x0004,0x0005,0x000B,0x000C],
            0x0004:[0x0001,0x0002,0x0004,0x0005,0x0006,0x0007,0x000C],
            0x0009:[0x0001,0x0002,0x0003],
            0x0013:[0x0001,0x0002,0x0003,0x0004,0x0005,0x0006,0x0007,
                     0x0008,0x0009,0x000A,0x000E,0x000F,0x0011,0x0012],
            0x0015:[0x0001,0x0002,0x0003],
        };
        for (const [fam, subs] of Object.entries(families)) {
            for (const sub of subs) pairs.push([parseInt(fam), sub]);
        }

        b.u16(0x0001); b.u16(pairs.length);
        pairs.forEach(([f, s]) => b.u16(f).u16(s));
        return b.build();
    },

    // ═══════════════════════════════════════
    //  Уведомление наблюдателей
    // ═══════════════════════════════════════

    async notifyWatchers(session, sessions, online) {
        const targetUin = session.uin;
        let notified = 0;

        for (const [uin, ws] of sessions) {
            if (uin === targetUin) continue;
            if (!ws.watching.has(targetUin)) continue;
            if (online) ws.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(session));
            else ws.sendSNAC(0x0003, 0x000C, 0, 0, packUserInfoOffline(targetUin));
            notified++;
        }

        const ssiWatchers = await db.all(
            "SELECT DISTINCT uin FROM ssi WHERE name = ? AND type = 0",[targetUin]
        );
        for (const row of ssiWatchers) {
            const ws = sessions.get(row.uin);
            if (ws && !ws.watching.has(targetUin)) {
                ws.watching.add(targetUin);
                if (online) ws.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(session));
                else ws.sendSNAC(0x0003, 0x000C, 0, 0, packUserInfoOffline(targetUin));
                notified++;
            }
        }

        if (notified > 0) {
            const a = online ? '\x1b[32mARRIVED\x1b[0m' : '\x1b[31mDEPARTED\x1b[0m';
            console.log(`  ${a} ${targetUin} → ${notified} watcher(s)`);
        }
    },

    async sendBuddyStatuses(session, sessions) {
        let sent = 0;
        for (const buddyUin of session.watching) {
            const bs = sessions.get(buddyUin);
            if (bs) {
                session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
                sent++;
            }
        }
        if (sent > 0) console.log(`\x1b[36m[BUDDIES]\x1b[0m Sent ${sent} online status(es) to ${session.uin}`);
    },

    // ═══════════════════════════════════════
    //  Locate 0x0002
    // ═══════════════════════════════════════

    async handleLocate(session, snac, ctx) {
        const { subtype, reqId } = snac;
        const { sessions } = ctx;

        if (subtype === 0x0002) {
            session.sendSNAC(0x0002, 0x0003, 0, reqId,
                new OscarBuilder().tlv(0x0001, 0x0400).tlv(0x0002, 0x0010).tlv(0x0005, 0x000A).build());
        }

        if (subtype === 0x0004) {
            const tlvs = parseTLVs(snac.data);
            if (tlvs[0x0002]) session.profile = tlvs[0x0002].toString();
            if (tlvs[0x0004]) session.awayMsg = tlvs[0x0004].toString();
            if (tlvs[0x0005]) {
                session.userTLVs.set(0x000D, tlvs[0x0005]);
                await this.notifyWatchers(session, sessions, true);
            }
        }

        if (subtype === 0x0005 && snac.data.length >= 3) {
            const flags = snac.data.readUInt16BE(0);
            const uinLen = snac.data[2];
            const targetUin = snac.data.subarray(3, 3 + uinLen).toString();
            const ts = sessions.get(targetUin);

            const b = new OscarBuilder();
            const tb = Buffer.from(targetUin);
            b.u8(tb.length).raw(tb);
            b.u16(0);

            if (ts) {
                const infoPairs = [];
                for (const [type, value] of ts.userTLVs) infoPairs.push([type, value]);
                infoPairs.push([0x0002, Buffer.from(ts.profile || `UIN: ${targetUin}`)]);
                if (flags & 0x0002) infoPairs.push([0x0004, Buffer.from(ts.awayMsg || '')]);
                b.u16(infoPairs.length);
                infoPairs.forEach(([t, v]) => b.tlv(t, v));
            } else {
                b.u16(2);
                b.tlv(0x0001, Buffer.from([0x00, 0x40]));
                b.tlv(0x0002, `UIN: ${targetUin}`);
            }
            session.sendSNAC(0x0002, 0x0006, 0, reqId, b.build());
        }
    },

    // ═══════════════════════════════════════
    //  Buddy 0x0003
    // ═══════════════════════════════════════

    async handleBuddy(session, snac, ctx) {
        const { subtype, reqId } = snac;
        const { sessions } = ctx;

        if (subtype === 0x0002) {
            session.sendSNAC(0x0003, 0x0003, 0, reqId,
                new OscarBuilder().tlv(0x0001, 1000).tlv(0x0002, 200).tlv(0x0003, 200).build());
        }

        if (subtype === 0x0004) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1;
                if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                session.watching.add(buddyUin);
                const bs = sessions.get(buddyUin);
                if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
            }
        }

        if (subtype === 0x0005) {
            let pos = 0; const d = snac.data;
            while (pos < d.length) {
                const bl = d[pos]; pos += 1;
                if (pos + bl > d.length) break;
                const buddyUin = d.subarray(pos, pos + bl).toString('utf8'); pos += bl;
                session.watching.delete(buddyUin);
            }
        }
    },

    // ═══════════════════════════════════════
    //  ICBM 0x0004
    // ═══════════════════════════════════════

    async handleICBM(session, snac, ctx) {
        const { subtype, reqId } = snac;
        if (subtype === 0x0004 || subtype === 0x0002) { 
            session.sendSNAC(0x0004, 0x0005, 0, reqId, buildICBMParams()); return; 
        }
        if (subtype === 0x0006) { await this.handleSendMsg(session, snac, ctx); return; }
    },

    async handleSendMsg(session, snac, ctx) {
        const { sessions } = ctx;
        const d = snac.data;
        if (d.length < 11) return;

        const cookie = d.subarray(0, 8);
        const channel = d.readUInt16BE(8);
        const uinLen = d[10];
        const recipient = d.subarray(11, 11 + uinLen).toString('utf8');
        const tlvData = d.subarray(11 + uinLen);
        const tlvs = parseTLVs(tlvData);

        const target = sessions.get(recipient);

        // QIP Typing Notification (Канал 2) - бесшумный проброс, не парсим как текст
        if (channel === 2) {
            if (target) {
                const b = new OscarBuilder();
                b.raw(cookie).u16(channel).u8(session.uin.length).string(session.uin)
                 .u16(0).u16(2).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, Buffer.from([0,0,0,0]));
                if (tlvs[0x02]) b.tlv(0x02, tlvs[0x02]);
                target.sendSNAC(0x04, 0x07, 0, 0, b.build());
            }
            return; 
        }

        let msgText = '';
        if (channel === 1 && tlvs[0x0002]) msgText = this.parseCh1(tlvs[0x0002]);
        else if (channel === 4 && tlvs[0x0005]) msgText = this.parseCh4(tlvs[0x0005]);
        else msgText = `(ch${channel})`;

        console.log(`\x1b[32m[MSG]\x1b[0m ${session.uin} → ${recipient} : ${msgText}`);

        if (target) {
            this.forwardMessage(session, target, cookie, channel, tlvs);
            if (tlvs[0x0003]) {
                session.sendSNAC(0x0004, 0x000C, 0, snac.reqId,
                    new OscarBuilder().raw(cookie).u16(channel).u8(recipient.length).string(recipient).build());
            }
        } else {
            if (msgText) {
                await db.storeOffline(session.uin, recipient, msgText);
                console.log(`  Stored offline for ${recipient}`);
            }
        }
    },

    forwardMessage(sender, target, cookie, channel, originalTlvs) {
        const senderBuf = Buffer.from(sender.uin, 'utf8');
        const b = new OscarBuilder();
        b.raw(cookie).u16(channel).u8(senderBuf.length).raw(senderBuf);
        b.u16(0);

        const infoTlvs =[];
        for (const t of[0x0001, 0x0003, 0x0006, 0x000C, 0x000D]) {
            if (sender.userTLVs.has(t)) infoTlvs.push([t, sender.userTLVs.get(t)]);
        }
        b.u16(infoTlvs.length);
        infoTlvs.forEach(([t, v]) => b.tlv(t, v));

        if (originalTlvs[0x0002]) b.tlv(0x0002, originalTlvs[0x0002]);
        if (originalTlvs[0x0005]) b.tlv(0x0005, originalTlvs[0x0005]);
        if (originalTlvs[0x0003]) b.tlv(0x0003, Buffer.alloc(0));

        target.sendSNAC(0x0004, 0x0007, 0, 0, b.build());
    },

    buildIncomingMsg(senderUin, text, ts) {
        const cookie = Buffer.alloc(8);
        cookie.writeUInt32BE(Math.floor(Math.random() * 0xFFFFFFFF), 0);
        cookie.writeUInt32BE(Math.floor(ts || Date.now() / 1000), 4);

        const textBuf = Buffer.from(text, 'utf8');
        const features = Buffer.from([0x05, 0x01, 0x00, 0x04, 0x01, 0x01, 0x01, 0x02]);
        const charset = Buffer.alloc(4);
        const msgBody = Buffer.concat([charset, textBuf]);
        const msgHeader = Buffer.alloc(4);
        msgHeader[0] = 0x01; msgHeader[1] = 0x01;
        msgHeader.writeUInt16BE(msgBody.length, 2);

        const senderBuf = Buffer.from(senderUin, 'utf8');
        const b = new OscarBuilder();
        b.raw(cookie).u16(1).u8(senderBuf.length).raw(senderBuf);
        b.u16(0).u16(2);
        b.tlv(0x0001, Buffer.from([0x00, 0x40]));
        b.tlv(0x0006, Buffer.from([0, 0, 0, 0]));
        b.tlv(0x0002, Buffer.concat([features, msgHeader, msgBody]));
        return b.build();
    },

    parseCh1(data) {
        try {
            let pos = 0;
            while (pos + 4 <= data.length) {
                const fragId = data[pos];
                const fragLen = data.readUInt16BE(pos + 2);
                const fragData = data.subarray(pos + 4, pos + 4 + fragLen);
                pos += 4 + fragLen;
                if (fragId === 0x01 && fragData.length >= 4) {
                    const cs = fragData.readUInt16BE(0);
                    const raw = fragData.subarray(4);
                    if (raw.length === 0) return '';
                    if (cs === 0x0000) return raw.toString('utf8');
                    if (cs === 0x0002) return raw.toString('utf16le');
                    if (cs === 0x0003) return iconv.decode(raw, 'win1251');
                    return raw.toString('utf8');
                }
            }
        } catch (e) {}
        return '(parse error)';
    },

    parseCh4(data) {
        try {
            if (data.length >= 8) {
                const msgLen = data.readUInt16LE(6);
                return data.subarray(8, 8 + msgLen).toString('utf8').replace(/\0/g, '');
            }
        } catch (e) {}
        return '(ch4)';
    },

    // ═══════════════════════════════════════
    //  Privacy 0x0009
    // ═══════════════════════════════════════

    handlePrivacy(session, snac) {
        if (snac.subtype === 0x0002) {
            session.sendSNAC(0x0009, 0x0003, 0, snac.reqId,
                new OscarBuilder().tlv(0x0001, 200).tlv(0x0002, 200).build());
        }
    },

    // ═══════════════════════════════════════
    //  SSI 0x0013
    // ═══════════════════════════════════════

    async handleSSI(session, snac, ctx) {
        const { subtype, reqId } = snac;
        const { sessions } = ctx;

        if (subtype === 0x0002) {
            session.sendSNAC(0x0013, 0x0003, 0, reqId,
                new OscarBuilder().tlv(0x0004, 1000).tlv(0x0005, 100).tlv(0x0006, 200).tlv(0x0007, 200).tlv(0x0008, 200).build());
        }

        if (subtype === 0x0004) {
            await this.sendSSIList(session, reqId);
        }

        if (subtype === 0x0005) {
            if (snac.data.length >= 6) {
                const cliTs = snac.data.readUInt32BE(0);
                const cliCnt = snac.data.readUInt16BE(4);
                const items = await db.getSSI(session.uin);

                if (cliCnt === items.length && cliTs > 0) {
                    const nb = new OscarBuilder().u32(Math.floor(Date.now() / 1000)).u16(items.length);
                    session.sendSNAC(0x0013, 0x000F, 0, reqId, nb.build());
                    for (const item of items) {
                        if (item.type === 0 && item.name) session.watching.add(item.name);
                    }
                    return;
                }
            }
            await this.sendSSIList(session, reqId);
        }

        if (subtype === 0x0007) {
            console.log(`\x1b[36m[SSI ACTIVATE]\x1b[0m ${session.uin}`);
            await this.sendBuddyStatuses(session, sessions);
            await this.notifyWatchers(session, sessions, true);
        }

        if (subtype === 0x0008) {
            const items = parseSSIItems(snac.data);
            const results = [];
            for (const item of items) {
                try {
                    await db.addSSI(session.uin, item.name, item.gid, item.iid, item.type, item.tlvData);
                    results.push(0x0000);
                    if (item.type === 0 && item.name) {
                        session.watching.add(item.name);
                        const bs = sessions.get(item.name);
                        if (bs) session.sendSNAC(0x0003, 0x000B, 0, 0, packUserInfoOnline(bs));
                    }
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2);
            results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, reqId, ack);
        }

        if (subtype === 0x0009) {
            const items = parseSSIItems(snac.data);
            const results =[];
            for (const item of items) {
                try {
                    await db.addSSI(session.uin, item.name, item.gid, item.iid, item.type, item.tlvData);
                    results.push(0x0000);
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2);
            results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, reqId, ack);
        }

        if (subtype === 0x000A) {
            const items = parseSSIItems(snac.data);
            const results =[];
            for (const item of items) {
                try {
                    await db.deleteSSI(session.uin, item.gid, item.iid);
                    results.push(0x0000);
                    if (item.type === 0 && item.name) session.watching.delete(item.name);
                } catch (e) { results.push(0x000A); }
            }
            const ack = Buffer.alloc(results.length * 2);
            results.forEach((r, i) => ack.writeUInt16BE(r, i * 2));
            session.sendSNAC(0x0013, 0x000E, 0, reqId, ack);
        }

        if (subtype === 0x0011 || subtype === 0x0012) {
            if (subtype === 0x0012) {
                const buddies = await db.getSSIBuddies(session.uin);
                for (const b of buddies) session.watching.add(b.name);
            }
        }
    },

    async sendSSIList(session, reqId) {
        const items = await db.getSSI(session.uin);
        for (const item of items) {
            if (item.type === 0 && item.name) session.watching.add(item.name);
        }

        const b = new OscarBuilder();
        b.u8(0).u16(items.length);
        for (const item of items) {
            const nameBuf = Buffer.from(item.name || '', 'utf8');
            b.u16(nameBuf.length).raw(nameBuf);
            b.u16(item.gid).u16(item.iid).u16(item.type);
            const tlv = item.tlv || Buffer.alloc(0);
            b.u16(tlv.length);
            if (tlv.length > 0) b.raw(tlv);
        }
        b.u32(Math.floor(Date.now() / 1000));
        session.sendSNAC(0x0013, 0x0006, 0, reqId, b.build());
    },

    // ═══════════════════════════════════════════════
    //  ICQ Extensions 0x0015 (QIP SEARCH / INFO)
    // ═══════════════════════════════════════════════

    async handleICQ(session, snac, ctx) {
        if (snac.subtype !== 0x0002) return;
        const tlvs = parseTLVs(snac.data);
        const extData = tlvs[0x0001];
        if (!extData || extData.length < 10) return;

        const dataLen  = extData.readUInt16LE(0);
        const ownerUin = extData.readUInt32LE(2);
        const cmdType  = extData.readUInt16LE(6);
        const seq      = extData.readUInt16LE(8);
        const subData  = extData.subarray(10);

        if (cmdType === 0x003C) {
            const offline = await db.getOffline(session.uin);
            for (const msg of offline) {
                session.sendSNAC(0x0004, 0x0007, 0, 0, this.buildIncomingMsg(msg.sender, msg.message, msg.ts));
            }
            this.sendICQDirect(session, snac.reqId, ownerUin, 0x0042, seq, Buffer.alloc(0));
            return;
        }

        if (cmdType === 0x003E) return;

        if (cmdType === 0x07D0 && subData.length >= 2) {
            const subCmd = subData.readUInt16LE(0);
            const metaData = subData.subarray(2);

            // ИСПРАВЛЕНО: 0x0569 (QIP 2005 Поиск по UIN - Little Endian)
            if (subCmd === 0x0569) {
                await this.searchByUIN(session, snac.reqId, ownerUin, seq, metaData);
                return;
            }

            // ИСПРАВЛЕНО: 0x055F (QIP 2005 Поиск по деталям - LTLV)
            if (subCmd === 0x055F) {
                await this.searchByDetails(session, snac.reqId, ownerUin, seq, metaData);
                return;
            }

            // ИСПРАВЛЕНО: 0x0FA0 (QIP Infium Advanced Web Search)
            if (subCmd === 0x0FA0) {
                await this.searchByInfium(session, snac.reqId, ownerUin, seq, metaData);
                return;
            }

            if (subCmd === 0x0573) {
                await this.searchByEmail(session, snac.reqId, ownerUin, seq, metaData);
                return;
            }

            if (subCmd === 0x04BA || subCmd === 0x04B2 || subCmd === 0x051F) {
                await this.sendUserInfo(session, snac.reqId, ownerUin, seq, subCmd, metaData);
                return;
            }

            if (subCmd === 0x0C3A || subCmd === 0x0D0E) {
                this.sendICQMetaReply(session, snac.reqId, ownerUin, seq, 0x0C3F, Buffer.from([0x0A]));
                return;
            }
        }
    },

    // ═══════════════════════════════════════════════
    //  Блоки поиска QIP
    // ═══════════════════════════════════════════════

    async searchByInfium(session, reqId, ownerUin, seq, data) {
        let searchStr = "";
        
        // QIP Infium прячет текст в Big-Endian LTLV с типом 0x0032 (50) внутри пакета 0x0FA0
        for (let i = 0; i < data.length - 4; i++) {
            if (data.readUInt16BE(i) === 0x0032) { 
                const len = data.readUInt16BE(i + 2);
                if (i + 4 + len <= data.length) {
                    searchStr = data.subarray(i + 4, i + 4 + len).toString('utf8').replace(/\0/g, '').trim();
                    break;
                }
            }
        }
        
        // Фолбэк-экстрактор на всякий случай
        if (!searchStr) {
            const clean = data.toString('utf8').replace(/[^\x20-\x7E\u0400-\u04FF]/g, ' ').trim();
            const parts = clean.split(/\s+/);
            searchStr = parts[parts.length - 1] || '';
        }

        console.log(`\x1b[35m[INFIUM SEARCH]\x1b[0m ${session.uin} ищет: "${searchStr}"`);

        let results = [];
        if (searchStr) {
            if (/^\d+$/.test(searchStr)) {
                const u = await db.searchByUIN(searchStr);
                if (u) results.push(u);
            } else if (searchStr.includes('@')) {
                results = await db.searchByDetails({ email: searchStr });
            } else {
                results = await db.searchByDetails({ nickname: searchStr });
            }
        }
        
        // Магия: QIP Infium отлично "кушает" стандартный ответ (0x01A4/0x01AE), 
        // который автоматом прерывает бесконечный цикл загрузки!
        this.sendSearchResult(session, reqId, ownerUin, seq, results);
    },

    async searchByUIN(session, reqId, ownerUin, seq, data) {
        let targetUin = '';

        // Метод 0: QIP 2005 (LTLV с типом 0x0136 / 310)
        if (data.length >= 8 && data.readUInt16LE(0) === 0x0136) {
            targetUin = data.readUInt32LE(4).toString();
        }
        // Метод 1: LNTS (стандартный формат)
        else if (data.length >= 3) {
            const r = readLNTS(data, 0);
            if (r.str && /^\d+$/.test(r.str)) targetUin = r.str;
        }
        // Метод 2: DWORD LE (старые клиенты)
        if (!targetUin && data.length >= 4) {
            const v = data.readUInt32LE(0);
            if (v > 0 && v < 1000000000) targetUin = v.toString();
        }

        console.log(`\x1b[35m[SEARCH UIN]\x1b[0m ${session.uin} → "${targetUin}"`);

        if (!targetUin) {
            this.sendSearchResult(session, reqId, ownerUin, seq, []);
            return;
        }

        const user = await db.searchByUIN(targetUin);
        this.sendSearchResult(session, reqId, ownerUin, seq, user ? [user] :[]);
    },

    async searchByDetails(session, reqId, ownerUin, seq, data) {
        let query = {};
        
        // Метод 0: QIP 2005 (LTLV формат)
        if (data.length > 4 && data.readUInt16LE(0) > 0x00FF) {
            let pos = 0;
            while(pos + 4 <= data.length) {
                const tType = data.readUInt16LE(pos);
                const tLen = data.readUInt16LE(pos+2);
                pos += 4;
                if (tType === 340 && pos + tLen <= data.length && tLen > 2) {
                    query.nickname = data.subarray(pos+2, pos+tLen).toString('utf8').replace(/\0/g, '').trim();
                }
                pos += tLen;
            }
        } else {
            let pos = 0;
            const r1 = readLNTS(data, pos); pos = r1.next;
            const r2 = readLNTS(data, pos); pos = r2.next;
            const r3 = readLNTS(data, pos); pos = r3.next;
            const r4 = readLNTS(data, pos); pos = r4.next;
            query = { firstname: r1.str, lastname: r2.str, nickname: r3.str, email: r4.str };
        }

        console.log(`\x1b[35m[SEARCH DETAILS]\x1b[0m ${session.uin}:`, JSON.stringify(query));
        const results = await db.searchByDetails(query);
        this.sendSearchResult(session, reqId, ownerUin, seq, results);
    },

    async searchByEmail(session, reqId, ownerUin, seq, data) {
        const r = readLNTS(data, 0);
        const results = await db.searchByDetails({ email: r.str });
        this.sendSearchResult(session, reqId, ownerUin, seq, results);
    },

    // ═══════════════════════════════════════════════
    //  Формирование результата поиска
    // ═══════════════════════════════════════════════

    sendSearchResult(session, reqId, ownerUin, seq, users) {
        if (users.length === 0) {
            // МАРКЕР КОНЦА СПИСКА! Без него QIP зависает.
            this.sendICQMetaReply(session, reqId, ownerUin, seq, 0x01AE, Buffer.from([0x32, 0x00, 0x00]));
            return;
        }

        for (let i = 0; i < users.length; i++) {
            const user = users[i];
            const isLast = (i === users.length - 1);
            const subType = isLast ? 0x01AE : 0x01A4;

            const bufs = [];
            bufs.push(Buffer.from([0x0A])); 

            const uinBuf = Buffer.alloc(4);
            uinBuf.writeUInt32LE(parseInt(user.uin) || 0);
            bufs.push(uinBuf);

            bufs.push(writeLNTS(user.nickname || ''));
            bufs.push(writeLNTS(user.firstname || ''));
            bufs.push(writeLNTS(user.lastname || ''));
            bufs.push(writeLNTS(user.email || ''));

            bufs.push(Buffer.from([0x00])); 
            bufs.push(Buffer.alloc(2));     
            bufs.push(Buffer.from([user.gender || 0])); 

            const ageBuf = Buffer.alloc(2);
            ageBuf.writeUInt16LE(user.age || 0);
            bufs.push(ageBuf);

            this.sendICQMetaReply(session, reqId, ownerUin, seq, subType, Buffer.concat(bufs));
        }
    },

    // ═══════════════════════════════════════════════
    //  User info request
    // ═══════════════════════════════════════════════

    async sendUserInfo(session, reqId, ownerUin, seq, subCmd, data) {
        let targetUin = session.uin;
        if (data.length >= 4) {
            const v = data.readUInt32LE(0);
            if (v > 0) targetUin = v.toString();
        }

        const user = await db.searchByUIN(targetUin);
        const replyType = (subCmd === 0x04BA) ? 0x0104 : 0x00FB;

        const bufs = [];
        bufs.push(Buffer.from([0x0A]));

        if (user) {
            bufs.push(writeLNTS(user.nickname || ''));
            bufs.push(writeLNTS(user.firstname || ''));
            bufs.push(writeLNTS(user.lastname || ''));
            bufs.push(writeLNTS(user.email || ''));
            bufs.push(Buffer.from([0x00, 0x00, 0x00]));
        } else {
            bufs.push(writeLNTS('Unknown'));
            bufs.push(writeLNTS(''));
            bufs.push(writeLNTS(''));
            bufs.push(writeLNTS(''));
            bufs.push(Buffer.from([0x00, 0x00, 0x00]));
        }

        this.sendICQMetaReply(session, reqId, ownerUin, seq, replyType, Buffer.concat(bufs));
    },

    sendICQDirect(session, snacReqId, ownerUin, cmdType, seq, payload) {
        const inner = Buffer.alloc(8);
        inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(cmdType, 4);
        inner.writeUInt16LE(seq, 6);

        const innerFull = payload.length > 0 ? Buffer.concat([inner, payload]) : inner;
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16LE(innerFull.length);

        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    },

    sendICQMetaReply(session, snacReqId, ownerUin, seq, subType, payload) {
        const inner = Buffer.alloc(10);
        inner.writeUInt32LE(parseInt(ownerUin) || parseInt(session.uin) || 0, 0);
        inner.writeUInt16LE(0x07DA, 4);
        inner.writeUInt16LE(seq, 6);
        inner.writeUInt16LE(subType, 8);

        const innerFull = Buffer.concat([inner, payload]);
        const lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16LE(innerFull.length);

        session.sendSNAC(0x0015, 0x0003, 0, snacReqId, new OscarBuilder().tlv(0x0001, Buffer.concat([lenBuf, innerFull])).build());
    },
};

module.exports = BOS;
