const crypto = require('crypto');
const db = require('./database');
const { OscarBuilder, parseTLVs } = require('./oscar');
const config = require('./config');

// ═══════════════════════════════════════════
//  XOR Roasting таблица (QIP 2005, ICQ 2000)
// ═══════════════════════════════════════════

const ROAST = Buffer.from([
    0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
    0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
]);

function xorDecode(buf) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
        out[i] = buf[i] ^ ROAST[i % ROAST.length];
    }
    let end = out.length;
    while (end > 0 && out[end - 1] === 0) end--;
    return out.subarray(0, end).toString('utf8');
}

function md5(data) {
    return crypto.createHash('md5').update(data).digest();
}

// ═══════════════════════════════════════════
//  Auth
// ═══════════════════════════════════════════

const Auth = {
    keys: new Map(),
    pendingCookies: new Map(),

    // ── Проверка пароля (XOR и MD5) ──
    async checkCredentials(uin, tlvs) {
        const user = await db.get("SELECT * FROM users WHERE uin = ?", [uin]);
        if (!user) {
            console.log(`\x1b[31m[AUTH]\x1b[0m UIN ${uin} not found`);
            return false;
        }

        const md5Hash = tlvs[0x0025]; // QIP Infium, Miranda, Pidgin
        const roasted = tlvs[0x0002]; // QIP 2005, ICQ 2000, R&Q

        if (md5Hash) {
            // ══════════════════════════════════════════
            //  MD5 авторизация
            //
            //  Формула клиента:
            //    MD5( auth_key_BYTES + MD5(password) + "AOL Instant Messenger (SM)" )
            //
            //  ВАЖНО: auth_key_BYTES — это именно те байты,
            //  которые клиент получил по сети.
            //  Мы отправляем hex-строку как ASCII,
            //  значит клиент использует ASCII-байты этой строки.
            //
            //  Поэтому: Buffer.from(authKey) — НЕ 'hex'!
            // ══════════════════════════════════════════
            const authKey = this.keys.get(uin) || '';
            
            const material = Buffer.concat([
                Buffer.from(authKey),  // ASCII байты hex-строки (как клиент получил)
                md5(user.password),
                Buffer.from('AOL Instant Messenger (SM)')
            ]);
            
            const expected = md5(material);
            const ok = expected.equals(md5Hash);
            
            console.log(`\x1b[33m[AUTH]\x1b[0m MD5 for ${uin}: ${ok ? '\x1b[32mPASS' : '\x1b[31mFAIL'}\x1b[0m`);
            if (!ok) {
                console.log(`  Expected: ${expected.toString('hex')}`);
                console.log(`  Got:      ${md5Hash.toString('hex')}`);
                console.log(`  Key used: "${authKey}" (${authKey.length} bytes)`);
            }
            
            // Очищаем использованный ключ
            this.keys.delete(uin);
            return ok;
        }

        if (roasted) {
            // ══════════════════════════════════════════
            //  XOR авторизация (QIP 2005)
            // ══════════════════════════════════════════
            const decoded = xorDecode(roasted);
            const ok = (decoded === user.password);
            console.log(`\x1b[33m[AUTH]\x1b[0m XOR for ${uin}: ${ok ? '\x1b[32mPASS' : '\x1b[31mFAIL'}\x1b[0m`);
            return ok;
        }

        console.log(`\x1b[31m[AUTH]\x1b[0m No password TLV for ${uin}`);
        return false;
    },

    // ── BUCP: обработка SNAC на AUTH сервере ──
    async handlePacket(session, snac) {

        // ── Запрос ключа (SNAC 0x17/0x06) ──
        if (snac.subtype === 0x0006) {
            let uin = '';

            // Парсим UIN из TLV или raw data
            const tlvs = parseTLVs(snac.data);
            if (tlvs[0x0001]) {
                uin = tlvs[0x0001].toString();
            } else if (snac.data.length >= 4) {
                const len = snac.data.readUInt16BE(0);
                if (len > 0 && len < snac.data.length - 2) {
                    uin = snac.data.subarray(2, 2 + len).toString();
                }
            }

            console.log(`\x1b[33m[AUTH]\x1b[0m Key request for UIN: ${uin}`);

            // Генерируем ключ и сохраняем
            const key = crypto.randomBytes(32).toString('hex');
            if (uin) this.keys.set(uin, key);

            // Ответ: SNAC(0x17, 0x07)
            const keyBuf = Buffer.from(key);
            const resp = new OscarBuilder()
                .u16(keyBuf.length)
                .raw(keyBuf);

            session.sendSNAC(0x0017, 0x0007, 0, snac.reqId, resp.build());
        }

        // ── MD5 логин (SNAC 0x17/0x02) ──
        if (snac.subtype === 0x0002) {
            const tlvs = parseTLVs(snac.data);
            const uinTlv = tlvs[0x0001];

            if (!uinTlv) {
                console.log(`\x1b[31m[AUTH]\x1b[0m No UIN in login packet`);
                return;
            }

            const uin = uinTlv.toString();
            console.log(`\x1b[33m[AUTH]\x1b[0m BUCP login: ${uin}`);

            const valid = await this.checkCredentials(uin, tlvs);

            if (valid) {
                console.log(`\x1b[32m[AUTH OK]\x1b[0m ${uin} → BOS`);

                const cookie = crypto.randomBytes(256);
                this.pendingCookies.set(cookie.toString('hex'), uin);

                const resp = new OscarBuilder()
                    .tlv(0x0001, uin)
                    .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                    .tlv(0x0006, cookie);

                session.sendSNAC(0x0017, 0x0003, 0, snac.reqId, resp.build());
                session.disconnect();
            } else {
                console.log(`\x1b[31m[AUTH FAIL]\x1b[0m ${uin}`);

                // Код ошибки 0x0005 = неверный пароль
                const errBuf = Buffer.alloc(2);
                errBuf.writeUInt16BE(0x0005);

                const resp = new OscarBuilder()
                    .tlv(0x0001, uin)
                    .tlv(0x0004, 'http://icq.com/')
                    .tlv(0x0008, errBuf);

                session.sendSNAC(0x0017, 0x0003, 0, snac.reqId, resp.build());
            }
        }
    }
};

module.exports = Auth;