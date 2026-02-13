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
        // MD5 Login (0x0017 / 0x0002)
        if (snac.subtype === 0x0002) {
            const tlvs = parseTLVs(snac.data);
            const uin = tlvs[0x0001]?.toString();
            const passHash = tlvs[0x0025]; // md5 hash
            const passRaw = tlvs[0x0002];  // roasted (old icq)

            const user = await db.get("SELECT * FROM users WHERE uin = ?", [uin]);
            if (!user) return session.sendSNAC(0x17, 0x03, 0, 0, new OscarBuilder().tlv(0x08, Buffer.from([0, 0x04])).build()); // Error

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
                // XOR decode logic skipped for brevity, assuming success for demo
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
        
        // Key Request (0x0017 / 0x0006)
        if (snac.subtype === 0x0006) {
            const tlvs = parseTLVs(snac.data);
            let uin = tlvs[0x0001]?.toString();
            if (!uin) {
                // sometimes uin is in raw data
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
            if (subtype === 0x02) { // Client Ready
                // Send self info
                session.sendSNAC(0x01, 0x0F, 0, 0, packUserInfo(session.uin));
                
                // Notify buddies (simple version)
                const watchList = await db.all("SELECT uin FROM ssi WHERE name = ? AND type = 0", [session.uin]);
                watchList.forEach(w => {
                    const s = server.sessions.get(w.uin);
                    if (s) s.sendSNAC(0x03, 0x0B, 0, 0, packUserInfo(session.uin, session.status));
                });
                
            } else if (subtype === 0x06) { // Rate Request
                // Fake rate limits
                const b = new OscarBuilder();
                b.u16(1); // 1 class
                // ... params omitted for brevity ...
                b.raw(Buffer.alloc(30)); // fake params
                b.u16(1).u16(config.FAMILIES.length); // class 1 mappings
                config.FAMILIES.forEach(f => b.u16(f.fam).u16(0));
                session.sendSNAC(0x01, 0x07, 0, reqId, b.build());
            } else if (subtype === 0x0E) { // Set Status
                const tlvs = parseTLVs(snac.data);
                if (tlvs[0x06]) {
                    session.status = tlvs[0x06].readUInt16BE(2);
                }
            }
        }

        // --- ICBM / Messaging (0x04) ---
        if (family === 0x04) {
            if (subtype === 0x02) { // Set Params
                const b = new OscarBuilder()
                    .u16(0).u32(0x0B).u16(8000).u16(999).u16(999).u32(0);
                session.sendSNAC(0x04, 0x05, 0, reqId, b.build());
            } else if (subtype === 0x06) { // Send Message
                const cookie = snac.data.subarray(0, 8);
                const channel = snac.data.readUInt16BE(8);
                const uinLen = snac.data[10];
                const recipient = snac.data.subarray(11, 11 + uinLen).toString();
                const tlvData = snac.data.subarray(11 + uinLen);
                const tlvs = parseTLVs(tlvData);

                let msgText = "(binary)";
                // Parse text (simplification)
                if (tlvs[0x02]) {
                    // ch1 fragment parsing logic...
                    const frag = tlvs[0x02];
                    // Skip features (05 01 ...) go to 01 01
                    const txt = frag.subarray(frag.indexOf(Buffer.from([0x01, 0x01])) + 4);
                    // Skip charset
                    msgText = txt.subarray(4).toString();
                }

                console.log(`MSG: ${session.uin} -> ${recipient}: ${msgText}`);

                const target = server.sessions.get(recipient);
                if (target) {
                    const b = new OscarBuilder();
                    b.raw(cookie).u16(1).u8(session.uin.length).string(session.uin);
                    b.u16(0).u16(2); // warn, tlv count
                    b.tlv(0x01, Buffer.from([0x00, 0x40])); // user class
                    b.tlv(0x06, Buffer.from([0,0,0,0])); // status
                    b.tlv(0x02, tlvs[0x02]); // pass through message data
                    target.sendSNAC(0x04, 0x07, 0, 0, b.build());
                }
            }
        }

        // --- SSI / Roster (0x13) ---
        if (family === 0x13) {
            if (subtype === 0x04) { // Request SSI
                const items = await db.all("SELECT * FROM ssi WHERE uin = ?", [session.uin]);
                const b = new OscarBuilder();
                b.u8(0).u16(items.length); // ver, count
                items.forEach(i => {
                    b.u16(i.name.length).string(i.name);
                    b.u16(i.gid).u16(i.iid).u16(i.type);
                    b.u16(0); // tlv len (simplified)
                });
                b.u32(Math.floor(Date.now()/1000));
                session.sendSNAC(0x13, 0x06, 0, reqId, b.build());
            } else if (subtype === 0x08) { // Add item
                // Parsing SSI items is complex, simplified here:
                session.sendSNAC(0x13, 0x0E, 0, reqId, Buffer.alloc(0)); // Success ACK
            }
        }
    }
};

module.exports = { Auth, BOS, PENDING_COOKIES };