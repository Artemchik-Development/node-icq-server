const crypto = require('crypto');
const { OscarBuilder, makeSNAC, parseTLVs } = require('./oscar');
const db = require('./database');
const config = require('./config');

const PENDING_COOKIES = new Map();

// --- Хелперы ---
function md5(data) {
    return crypto.createHash('md5').update(data).digest();
}

function packUserInfo(uin, status = 0) {
    const b = new OscarBuilder();
    const uinBuf = Buffer.from(uin);
    b.u8(uinBuf.length).raw(uinBuf);
    b.u16(0).u16(2);
    b.tlv(0x0001, Buffer.from([0x00, 0x40])); 
    const statusBuf = Buffer.alloc(4);
    statusBuf.writeUInt16BE(0, 0); 
    statusBuf.writeUInt16BE(status, 2); 
    b.tlv(0x0006, statusBuf);
    return b.build();
}

// --- Обработчики ---
const Auth = {
    keys: new Map(),
    async handlePacket(session, snac) {
        if (snac.subtype === 0x0002) {
            const tlvs = parseTLVs(snac.data);
            const uin = tlvs[0x0001]?.toString();
            const passHash = tlvs[0x0025]; 
            const passRaw = tlvs[0x0002];  

            const user = await db.get("SELECT * FROM users WHERE uin = ?", [uin]);
            if (!user) return session.sendSNAC(0x17, 0x03, 0, 0, new OscarBuilder().tlv(0x08, Buffer.from([0, 0x04])).build()); 

            let success = false;
            if (passHash) {
                const key = this.keys.get(uin) || '';
                const hashMaterial = Buffer.concat([
                    Buffer.from(key, 'hex'), md5(user.password), Buffer.from("AOL Instant Messenger (SM)")
                ]);
                success = md5(hashMaterial).equals(passHash);
            } else if (passRaw) {
                success = true; 
            }

            if (success) {
                const cookie = crypto.randomBytes(32);
                PENDING_COOKIES.set(cookie.toString('hex'), uin);
                const b = new OscarBuilder();
                b.tlv(0x01, uin).tlv(0x05, `${config.BOS_ADDRESS}:${config.BOS_PORT}`).tlv(0x06, cookie);
                session.sendSNAC(0x17, 0x03, 0, snac.reqId, b.build());
                session.close();
            } else {
                session.sendSNAC(0x17, 0x03, 0, 0, new OscarBuilder().tlv(0x08, Buffer.from([0, 0x05])).build());
            }
        }
        
        if (snac.subtype === 0x0006) {
            const tlvs = parseTLVs(snac.data);
            let uin = tlvs[0x0001]?.toString() || snac.data.subarray(2, 2 + snac.data.readUInt16BE(0)).toString();
            const key = crypto.randomBytes(16).toString('hex');
            this.keys.set(uin, key);
            session.sendSNAC(0x17, 0x07, 0, snac.reqId, new OscarBuilder().u16(key.length).string(key).build());
        }
    }
};

const BOS = {
    async handlePacket(session, snac, server) {
        const { family, subtype, reqId } = snac;

        // --- Generic (0x01) ---
        if (family === 0x01) {
            if (subtype === 0x02) { 
                session.sendSNAC(0x01, 0x0F, 0, 0, packUserInfo(session.uin));
                const watchList = await db.all("SELECT uin FROM ssi WHERE name = ? AND type = 0", [session.uin]);
                watchList.forEach(w => {
                    const s = server.sessions.get(w.uin);
                    if (s) s.sendSNAC(0x03, 0x0B, 0, 0, packUserInfo(session.uin, session.status));
                });
            } else if (subtype === 0x06) { 
                const b = new OscarBuilder().u16(1).raw(Buffer.alloc(30)).u16(1).u16(config.FAMILIES.length); 
                config.FAMILIES.forEach(f => b.u16(f.fam).u16(0));
                session.sendSNAC(0x01, 0x07, 0, reqId, b.build());
            } else if (subtype === 0x0E) { 
                const tlvs = parseTLVs(snac.data);
                if (tlvs[0x06]) session.status = tlvs[0x06].readUInt16BE(2);
            }
        }

        // --- ICBM / Messaging (0x04) ---
        if (family === 0x04) {
            if (subtype === 0x02) { 
                session.sendSNAC(0x04, 0x05, 0, reqId, new OscarBuilder().u16(0).u32(0x0B).u16(8000).u16(999).u16(999).u32(0).build());
            } else if (subtype === 0x06) { 
                const cookie = snac.data.subarray(0, 8);
                const channel = snac.data.readUInt16BE(8);
                const uinLen = snac.data[10];
                const recipient = snac.data.subarray(11, 11 + uinLen).toString();
                const tlvs = parseTLVs(snac.data.subarray(11 + uinLen));

                const target = server.sessions.get(recipient);
                
                // Если Канал 2 (Индикатор набора текста / статусы QIP)
                if (channel === 2) {
                    if (target) {
                        const b = new OscarBuilder().raw(cookie).u16(2).u8(session.uin.length).string(session.uin)
                                .u16(0).u16(2).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, Buffer.from([0,0,0,0])); 
                        if (tlvs[0x02]) b.tlv(0x02, tlvs[0x02]);
                        target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                    }
                    return; // Текст не читаем, выходим!
                }

                // Канал 1 (Текст сообщения)
                let msgText = "(binary)";
                if (tlvs[0x02]) {
                    const idx = tlvs[0x02].indexOf(Buffer.from([0x01, 0x01]));
                    if (idx !== -1) msgText = tlvs[0x02].subarray(idx + 8).toString('utf8');
                }
                console.log(`[ЧАТ] ${session.uin} -> ${recipient}: ${msgText}`);
                
                if (target) {
                    const b = new OscarBuilder().raw(cookie).u16(1).u8(session.uin.length).string(session.uin)
                            .u16(0).u16(2).tlv(0x01, Buffer.from([0x00, 0x40])).tlv(0x06, Buffer.from([0,0,0,0])).tlv(0x02, tlvs[0x02]); 
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
            }
        }

        // --- SSI / Roster (0x13) ---
        if (family === 0x13) {
            if (subtype === 0x04) { 
                const items = await db.all("SELECT * FROM ssi WHERE uin = ?", [session.uin]);
                const b = new OscarBuilder().u8(0).u16(items.length); 
                items.forEach(i => b.u16(i.name.length).string(i.name).u16(i.gid).u16(i.iid).u16(i.type).u16(0));
                b.u32(Math.floor(Date.now()/1000));
                session.sendSNAC(0x13, 0x06, 0, reqId, b.build());
            } else if (subtype === 0x08 || subtype === 0x09 || subtype === 0x0A) { 
                let pos = 0; const acks =[];
                while (pos < snac.data.length) {
                    if (pos + 2 > snac.data.length) break;
                    const nameLen = snac.data.readUInt16BE(pos); pos += 2;
                    const name = snac.data.subarray(pos, pos + nameLen).toString('utf8'); pos += nameLen;
                    const gid = snac.data.readUInt16BE(pos); pos += 2;
                    const iid = snac.data.readUInt16BE(pos); pos += 2;
                    const type = snac.data.readUInt16BE(pos); pos += 2;
                    const tlvLen = snac.data.readUInt16BE(pos); pos += 2 + tlvLen; 

                    try {
                        if (subtype === 0x08) {
                            await db.run("DELETE FROM ssi WHERE uin = ? AND name = ?",[session.uin, name]);
                            await db.run("INSERT INTO ssi (uin, name, gid, iid, type) VALUES (?, ?, ?, ?, ?)",[session.uin, name, gid, iid, type]);
                        } else if (subtype === 0x09) {
                            await db.run("UPDATE ssi SET gid = ?, type = ? WHERE uin = ? AND name = ? AND iid = ?",[gid, type, session.uin, name, iid]);
                        } else if (subtype === 0x0A) {
                            await db.run("DELETE FROM ssi WHERE uin = ? AND name = ? AND iid = ?",[session.uin, name, iid]);
                        }
                    } catch (e) {}
                    acks.push(0x0000); 
                }
                const ackBuf = Buffer.alloc(acks.length * 2);
                acks.forEach((ack, idx) => ackBuf.writeUInt16BE(ack, idx * 2));
                session.sendSNAC(0x13, 0x0E, 0, reqId, ackBuf);
            }
        }

        // --- QIP ADVANCED META DATA / СЛОЖНЫЙ ПОИСК (Family 0x15) ---
        if (family === 0x15 && subtype === 0x02) {
            const tlvs = parseTLVs(snac.data);
            const metaTlv = tlvs[0x0001];
            
            if (metaTlv && metaTlv.length >= 10) {
                // Разбор Little-Endian формата QIP
                const reqUin = metaTlv.readUInt32LE(2); // UIN ищущего (100000)
                const cmd = metaTlv.readUInt16LE(6);    // Команда (0x07D0)
                const seq = metaTlv.readUInt16LE(8);    // Идентификатор транзакции QIP
                
                if (cmd === 0x07D0 && metaTlv.length >= 12) {
                    const subCmd = metaTlv.readUInt16LE(10);
                    const metaData = metaTlv.subarray(12);

                    // Функция для правильного ответа на 0x15 запросы (решает проблему зависания)
                    const sendMetaReply = (replySubCmd, payloadBuf) => {
                        const buf = Buffer.alloc(12 + payloadBuf.length);
                        buf.writeUInt16LE(10 + payloadBuf.length, 0); // Длина TLV 1 (без самой длины)
                        buf.writeUInt32LE(reqUin, 2);
                        buf.writeUInt16LE(0x07D0, 6);
                        buf.writeUInt16LE(seq, 8); // Эхо номера транзакции!
                        buf.writeUInt16LE(replySubCmd, 10);
                        payloadBuf.copy(buf, 12);

                        const b = new OscarBuilder();
                        b.tlv(0x0001, buf);
                        session.sendSNAC(0x15, 0x03, 0, reqId, b.build());
                    };

                    let sqlQuery = "", sqlParam = "";
                    let isUinSearch = false;

                    // QIP 2005 / Infium: Поиск по UIN
                    if (subCmd === 0x0569 && metaData.length >= 8) {
                        sqlParam = metaData.readUInt32LE(4).toString();
                        sqlQuery = "SELECT * FROM users WHERE uin = ?";
                        isUinSearch = true;
                        console.log(`[QIP ПОИСК] Ищем UIN: ${sqlParam}`);
                    } 
                    // QIP 2005: Поиск по Нику / Почте (WhitePages)
                    else if (subCmd === 0x055F) {
                        let pos = 0;
                        while(pos + 4 <= metaData.length) {
                            const tType = metaData.readUInt16LE(pos);
                            const tLen = metaData.readUInt16LE(pos+2);
                            pos += 4;
                            if (tType === 340 && pos + tLen <= metaData.length && tLen > 2) {
                                sqlParam = metaData.subarray(pos+2, pos+tLen).toString('utf8').replace(/\0/g, '').trim();
                                if (sqlParam.includes('@')) sqlQuery = "SELECT * FROM users WHERE email = ?";
                                else sqlQuery = "SELECT * FROM users WHERE nickname = ? OR uin = ?";
                                console.log(`[QIP ПОИСК] Ищем детали: "${sqlParam}"`);
                            }
                            pos += tLen;
                        }
                    }
                    // QIP Infium: Расширенный XML-поиск (Web Search)
                    else if (subCmd === 0x0FA0) {
                        console.log(`[QIP ПОИСК] Блокируем XML-запрос, отдаем Конец Списка.`);
                        sendMetaReply(0x0FA1, Buffer.from([0x00])); // Возвращаем пустой ответ
                        return;
                    } 
                    // Служебные запросы (Например, запрос профиля 0x04B2 или офлайн сообщений 0x04D0)
                    else {
                        sendMetaReply(subCmd + 1, Buffer.from([0x00])); // Глушим зависания!
                        return;
                    }

                    // Если смогли распарсить поисковой запрос:
                    if (sqlQuery && sqlParam) {
                        try {
                            const user = await db.get(sqlQuery,[sqlParam, sqlParam]);
                            if (user && isUinSearch) {
                                // Пакуем найденного пользователя (Формат 0x056A)
                                const strToBuf = (s) => Buffer.from((s || '') + '\0', 'utf8');
                                const nickBuf = strToBuf(user.nickname);
                                const emailBuf = strToBuf(user.email);
                                
                                const payload = Buffer.alloc(1 + 4 + nickBuf.length + 2 + emailBuf.length + 4);
                                let p = 0;
                                payload.writeUInt8(1, p++); // 1 = Найден
                                payload.writeUInt32LE(parseInt(user.uin), p); p += 4;
                                nickBuf.copy(payload, p); p += nickBuf.length;
                                payload.writeUInt16LE(0, p); p += 2; // Пустые FirstName/LastName
                                emailBuf.copy(payload, p); p += emailBuf.length;
                                payload.writeUInt32LE(0, p); p += 4; // Пустые флаги Auth/Status
                                
                                sendMetaReply(0x056A, payload); 
                                sendMetaReply(0x056A, Buffer.from([0x00])); // МАРКЕР КОНЦА (Решает проблему зависания!)
                            } 
                            else {
                                // Ничего не найдено (или был WhitePages запрос)
                                sendMetaReply(subCmd + 1, Buffer.from([0x00])); // 00 = Конец поиска
                            }
                        } catch (e) {
                            sendMetaReply(subCmd + 1, Buffer.from([0x00]));
                        }
                    } else {
                        // Пустой запрос
                        sendMetaReply(subCmd + 1, Buffer.from([0x00]));
                    }
                }
            }
        }
    }
};

module.exports = { Auth, BOS, PENDING_COOKIES };
