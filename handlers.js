const crypto = require('crypto');
const { OscarBuilder, makeSNAC, parseTLVs } = require('./oscar');
const db = require('./database');
const config = require('./config');

const PENDING_COOKIES = new Map(); // cookie hex -> uin

// --- Хелперы ---

function md5(data) {
    return crypto.createHash('md5').update(data).digest();
}

function packUserInfo(uin, status = 0) {
    const b = new OscarBuilder();
    const uinBuf = Buffer.from(uin);
    
    b.u8(uinBuf.length).raw(uinBuf);
    b.u16(0).u16(2); // warning, tlv count
    b.tlv(0x0001, Buffer.from([0x00, 0x40])); // User class: ICQ
    
    const statusBuf = Buffer.alloc(4);
    statusBuf.writeUInt16BE(0, 0); // web status
    statusBuf.writeUInt16BE(status, 2); // status
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
                    Buffer.from(key, 'hex'),
                    md5(user.password),
                    Buffer.from("AOL Instant Messenger (SM)")
                ]);
                success = md5(hashMaterial).equals(passHash);
            } else if (passRaw) {
                success = true; 
            }

            if (success) {
                const cookie = crypto.randomBytes(32);
                PENDING_COOKIES.set(cookie.toString('hex'), uin);
                
                const b = new OscarBuilder();
                b.tlv(0x01, uin);
                b.tlv(0x05, `${config.BOS_ADDRESS}:${config.BOS_PORT}`);
                b.tlv(0x06, cookie);
                session.sendSNAC(0x17, 0x03, 0, snac.reqId, b.build());
                session.close();
            } else {
                session.sendSNAC(0x17, 0x03, 0, 0, new OscarBuilder().tlv(0x08, Buffer.from([0, 0x05])).build());
            }
        }
        
        if (snac.subtype === 0x0006) {
            const tlvs = parseTLVs(snac.data);
            let uin = tlvs[0x0001]?.toString();
            if (!uin) {
                const len = snac.data.readUInt16BE(0);
                uin = snac.data.subarray(2, 2 + len).toString();
            }
            
            const key = crypto.randomBytes(16).toString('hex');
            this.keys.set(uin, key);
            
            const b = new OscarBuilder();
            b.u16(key.length).string(key);
            session.sendSNAC(0x17, 0x07, 0, snac.reqId, b.build());
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
                const b = new OscarBuilder();
                b.u16(1).raw(Buffer.alloc(30)).u16(1).u16(config.FAMILIES.length); 
                config.FAMILIES.forEach(f => b.u16(f.fam).u16(0));
                session.sendSNAC(0x01, 0x07, 0, reqId, b.build());
            } else if (subtype === 0x0E) { 
                const tlvs = parseTLVs(snac.data);
                if (tlvs[0x06]) session.status = tlvs[0x06].readUInt16BE(2);
            }
        }

        // --- Location / User Info (0x02) ---
        if (family === 0x02) {
            if (subtype === 0x05) { 
                const infoType = snac.data.readUInt16BE(0);
                const nameLen = snac.data.readUInt8(2);
                const targetUin = snac.data.subarray(3, 3 + nameLen).toString('utf8');

                const b = new OscarBuilder();
                b.u16(infoType).u8(targetUin.length).string(targetUin).u16(0).u16(1);
                b.tlv(0x01, Buffer.from([0x00, 0x40])); 
                session.sendSNAC(0x02, 0x06, 0, reqId, b.build());
            }
        }

        // --- ICBM / Messaging (0x04) ---
        if (family === 0x04) {
            if (subtype === 0x02) { 
                const b = new OscarBuilder().u16(0).u32(0x0B).u16(8000).u16(999).u16(999).u32(0);
                session.sendSNAC(0x04, 0x05, 0, reqId, b.build());
            } else if (subtype === 0x06) { 
                const cookie = snac.data.subarray(0, 8);
                const channel = snac.data.readUInt16BE(8);
                const uinLen = snac.data[10];
                const recipient = snac.data.subarray(11, 11 + uinLen).toString();
                const tlvData = snac.data.subarray(11 + uinLen);
                const tlvs = parseTLVs(tlvData);

                // ИСПРАВЛЕНИЕ: Канал 2 (Уведомления о наборе текста и расширенные статусы QIP)
                if (channel === 2) {
                    console.log(`[TYPING/XTSTATUS] ${session.uin} -> ${recipient}`);
                    const target = server.sessions.get(recipient);
                    if (target) {
                        const b = new OscarBuilder();
                        b.raw(cookie).u16(2).u8(session.uin.length).string(session.uin);
                        b.u16(0).u16(2); // warn, tlv count
                        b.tlv(0x01, Buffer.from([0x00, 0x40])); 
                        b.tlv(0x06, Buffer.from([0,0,0,0])); 
                        if (tlvs[0x02]) b.tlv(0x02, tlvs[0x02]); // Пробрасываем данные как есть
                        target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                    }
                    return; // Дальше текст не парсим!
                }

                // Канал 1: Обычные текстовые сообщения
                let msgText = "(binary)";
                if (tlvs[0x02]) {
                    const frag = tlvs[0x02];
                    const txtIdx = frag.indexOf(Buffer.from([0x01, 0x01]));
                    if (txtIdx !== -1) {
                        msgText = frag.subarray(txtIdx + 8).toString('utf8');
                    }
                }

                console.log(`[MSG] ${session.uin} -> ${recipient}: ${msgText}`);
                const target = server.sessions.get(recipient);
                if (target) {
                    const b = new OscarBuilder();
                    b.raw(cookie).u16(1).u8(session.uin.length).string(session.uin);
                    b.u16(0).u16(2); 
                    b.tlv(0x01, Buffer.from([0x00, 0x40])); 
                    b.tlv(0x06, Buffer.from([0,0,0,0])); 
                    b.tlv(0x02, tlvs[0x02]); 
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
            }
        }

        // --- Standard Directory Search (0x0A) ---
        if (family === 0x0A && subtype === 0x02) {
            const tlvs = parseTLVs(snac.data);
            const cleanStr = (buf) => buf.toString('utf8').replace(/\0/g, '').trim();

            let sqlQuery = "", sqlParam = "";
            for (const[key, buf] of Object.entries(tlvs)) {
                const val = cleanStr(buf);
                if (val.length === 0 || val === "393526") continue; // Игнор мусора QIP

                if (/^\d+$/.test(val)) { sqlQuery = "SELECT * FROM users WHERE uin = ?"; sqlParam = val; } 
                else if (val.includes('@')) { sqlQuery = "SELECT * FROM users WHERE email = ?"; sqlParam = val; } 
                else { sqlQuery = "SELECT * FROM users WHERE nickname = ?"; sqlParam = val; }
            }

            const b = new OscarBuilder();
            if (sqlQuery && sqlParam) {
                const user = await db.get(sqlQuery, [sqlParam]);
                if (user) {
                    b.u16(1).u8(user.uin.length).string(user.uin).u16(0).u16(1).tlv(0x01, Buffer.from([0x00, 0x40])); 
                } else b.u16(0); 
            } else b.u16(0); 
            session.sendSNAC(0x0A, 0x03, 0, reqId, b.build());
        }

        // --- SSI / Roster (0x13) ---
        if (family === 0x13) {
            if (subtype === 0x04) { 
                const items = await db.all("SELECT * FROM ssi WHERE uin = ?", [session.uin]);
                const b = new OscarBuilder();
                b.u8(0).u16(items.length); 
                items.forEach(i => {
                    b.u16(i.name.length).string(i.name);
                    b.u16(i.gid).u16(i.iid).u16(i.type).u16(0); 
                });
                b.u32(Math.floor(Date.now()/1000));
                session.sendSNAC(0x13, 0x06, 0, reqId, b.build());
                
            } else if (subtype === 0x08 || subtype === 0x09 || subtype === 0x0A) { 
                let pos = 0;
                const acks =[];
                while (pos < snac.data.length) {
                    if (pos + 2 > snac.data.length) break;
                    const nameLen = snac.data.readUInt16BE(pos); pos += 2;
                    if (pos + nameLen > snac.data.length) break;
                    const name = snac.data.subarray(pos, pos + nameLen).toString('utf8'); pos += nameLen;
                    if (pos + 6 > snac.data.length) break;
                    const gid = snac.data.readUInt16BE(pos); pos += 2;
                    const iid = snac.data.readUInt16BE(pos); pos += 2;
                    const type = snac.data.readUInt16BE(pos); pos += 2;
                    if (pos + 2 > snac.data.length) break;
                    const tlvLen = snac.data.readUInt16BE(pos); pos += 2;
                    pos += tlvLen; 

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

        // --- QIP INFIUM ADVANCED SEARCH (Family 0x15) ---
        // ИСПРАВЛЕНИЕ: Это блок для правильного парсинга Little-Endian параметров (LTLV)
        if (family === 0x15 && subtype === 0x02) {
            const tlvs = parseTLVs(snac.data);
            const metaTlv = tlvs[0x0001];
            
            if (metaTlv && metaTlv.length >= 10) {
                // Разбираем заголовки (младший байт вперед)
                const cmd = metaTlv.readUInt16LE(6);
                const seq = metaTlv.readUInt16LE(8);
                
                if (cmd === 0x07D0 && metaTlv.length >= 12) {
                    const subCmd = metaTlv.readUInt16LE(10);
                    const metaData = metaTlv.subarray(12);
                    
                    let sqlQuery = "", sqlParam = "";

                    // QIP: Поиск по UIN
                    if (subCmd === 0x0569 && metaData.length >= 8) {
                        // Вот так правильно извлекается UIN, а не кривое 393526!
                        sqlParam = metaData.readUInt32LE(4).toString();
                        sqlQuery = "SELECT * FROM users WHERE uin = ?";
                        console.log(`[QIP SEARCH] Ищем UIN: ${sqlParam}`);
                    } 
                    // QIP: Поиск по Нику / Email
                    else if (subCmd === 0x055F) {
                        let pos = 0;
                        while(pos + 4 <= metaData.length) {
                            const tType = metaData.readUInt16LE(pos);
                            const tLen = metaData.readUInt16LE(pos+2);
                            pos += 4;
                            // Тег 340 (0x0154) - это поле ввода White Pages
                            if (tType === 340 && pos + tLen <= metaData.length && tLen > 2) {
                                sqlParam = metaData.subarray(pos+2, pos+tLen).toString('utf8').replace(/\0/g, '').trim();
                                if (sqlParam.includes('@')) sqlQuery = "SELECT * FROM users WHERE email = ?";
                                else sqlQuery = "SELECT * FROM users WHERE nickname = ? OR uin = ?";
                                console.log(`[QIP SEARCH] Ищем WhitePages: "${sqlParam}"`);
                            }
                            pos += tLen;
                        }
                    }

                    if (sqlQuery && sqlParam) {
                        try {
                            const user = await db.get(sqlQuery,[sqlParam, sqlParam]);
                            const b = new OscarBuilder();
                            if (user) {
                                b.u16(1).u8(user.uin.length).string(user.uin).u16(0).u16(1).tlv(0x01, Buffer.from([0x00, 0x40])); 
                            } else {
                                b.u16(0);
                            }
                            
                            // ГЕНИАЛЬНЫЙ ТРЮК: вместо сборки чудовищно сложного ответа 0x15,
                            // мы скармливаем клиенту QIP стандартый пакет ответа 0x0A (классический поиск).
                            // Менеджер транзакций QIP свяжет их по ReqId и успешно откроет окно добавления!
                            session.sendSNAC(0x0A, 0x03, 0, reqId, b.build());
                        } catch (e) { console.error(e); }
                    }
                }
            }
        }
    }
};

module.exports = { Auth, BOS, PENDING_COOKIES };
