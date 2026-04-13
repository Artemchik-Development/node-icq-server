const crypto = require('crypto');
const db = require('./database');
const { OscarBuilder, parseTLVs } = require('./oscar');
const config = require('./config');

// ═══════════════════════════════════════════
//  XOR Roasting (QIP 2005, ICQ 2000)
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

        const md5Hash = tlvs[0x0025];
        const roasted = tlvs[0x0002];

        if (md5Hash) {
            const authKey = this.keys.get(uin) || '';
            const material = Buffer.concat([
                Buffer.from(authKey),
                md5(user.password),
                Buffer.from('AOL Instant Messenger (SM)')
            ]);
            const expected = md5(material);
            const ok = expected.equals(md5Hash);
            console.log(`\x1b[33m[AUTH]\x1b[0m MD5 for ${uin}: ${ok ? '\x1b[32mPASS' : '\x1b[31mFAIL'}\x1b[0m`);
            this.keys.delete(uin);
            return ok;
        }

        if (roasted) {
            const decoded = xorDecode(roasted);
            const ok = (decoded === user.password);
            console.log(`\x1b[33m[AUTH]\x1b[0m XOR for ${uin}: ${ok ? '\x1b[32mPASS' : '\x1b[31mFAIL'}\x1b[0m`);
            return ok;
        }

        return false;
    },

    // ── BUCP SNAC обработка ──
    async handlePacket(session, snac) {

        
        if (snac.subtype === 0x0004) {
            await this.handleRegistration(session, snac);
            return;
        }

        // SNAC(0x17, 0x06) — Запрос ключа
        if (snac.subtype === 0x0006) {
            let uin = '';
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

            const key = crypto.randomBytes(32).toString('hex');
            if (uin) this.keys.set(uin, key);

            const keyBuf = Buffer.from(key);
            session.sendSNAC(0x0017, 0x0007, 0, snac.reqId,
                new OscarBuilder().u16(keyBuf.length).raw(keyBuf).build());
        }

        // SNAC(0x17, 0x02) — MD5 логин
        if (snac.subtype === 0x0002) {
            const tlvs = parseTLVs(snac.data);
            const uinTlv = tlvs[0x0001];
            if (!uinTlv) return;

            const uin = uinTlv.toString();
            console.log(`\x1b[33m[AUTH]\x1b[0m BUCP login: ${uin}`);

            const valid = await this.checkCredentials(uin, tlvs);

            if (valid) {
                console.log(`\x1b[32m[AUTH OK]\x1b[0m ${uin} → BOS`);

                const cookie = crypto.randomBytes(256);
                this.pendingCookies.set(cookie.toString('hex'), uin);

                session.sendSNAC(0x0017, 0x0003, 0, snac.reqId,
                    new OscarBuilder()
                        .tlv(0x0001, uin)
                        .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                        .tlv(0x0006, cookie)
                        .build());

                session.disconnect();
            } else {
                console.log(`\x1b[31m[AUTH FAIL]\x1b[0m ${uin}`);

                const errBuf = Buffer.alloc(2);
                errBuf.writeUInt16BE(0x0005);

                session.sendSNAC(0x0017, 0x0003, 0, snac.reqId,
                    new OscarBuilder()
                        .tlv(0x0001, uin)
                        .tlv(0x0004, 'http://icq.com/')
                        .tlv(0x0008, errBuf)
                        .build());
            }
        }
    },

    // ═══════════════════════════════════════════════
    //  Обработка регистрации
    //
    //  SNAC(0x17, 0x04) — CLI_REGISTRATION_REQUEST
    //
    //  Потоки клиентов:
    //
    //  ICQ 2000/2001:
    //    1. FLAP Ch1 (версия)
    //    2. SNAC(17,04) с TLV 0x01(пустой) + TLV 0x02(пароль)
    //    3. Ждёт SNAC(17,05) с новым UIN
    //
    //  ICQ 2002/2003/Lite:
    //    1. FLAP Ch1 (версия)
    //    2. SNAC(17,04) с TLV 0x01(желаемый UIN) + TLV 0x02(пароль)
    //    3. Ждёт SNAC(17,05) с назначенным UIN
    //
    //  Miranda / Pidgin:
    //    1. FLAP Ch1 (версия)
    //    2. SNAC(17,04) с TLV 0x01("") + TLV 0x02(пароль) + другие TLV
    //    3. Ждёт SNAC(17,05) с новым UIN
    //
    //  Ответ на успех:
    //    SNAC(0x17, 0x05):
    //      TLV 0x0001 — Назначенный UIN
    //      TLV 0x0006 — Auth cookie (для авто-входа)
    //
    //  Ответ на ошибку:
    //    SNAC(0x17, 0x01):
    //      TLV 0x0008 — Error code
    //      TLV 0x0004 — Error URL
    //
    //  Коды ошибок:
    //    0x0001 — Invalid SNAC
    //    0x0006 — Internal error
    //    0x0014 — No free UINs
    // ═══════════════════════════════════════════════

    async handleRegistration(session, snac) {
        console.log(`\x1b[35m[REGISTER]\x1b[0m Registration request received`);

        // ── Проверка: включена ли регистрация ──
        if (!config.REGISTRATION_ENABLED) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Registration is disabled`);
            this.sendRegError(session, snac.reqId, 0x0006, 'Registration is disabled');
            return;
        }

        // ── Парсинг TLV ──
        const tlvs = parseTLVs(snac.data);

        // Пароль (TLV 0x02) — XOR roasted
        let password = '';
        if (tlvs[0x0002]) {
            password = xorDecode(tlvs[0x0002]);
        } else if (tlvs[0x0025]) {
            // Некоторые клиенты отправляют MD5 хеш — не подходит для регистрации
            // Нужен plain-text пароль
            console.log(`\x1b[31m[REGISTER]\x1b[0m Client sent MD5 hash instead of password`);
            this.sendRegError(session, snac.reqId, 0x0006, 'Cannot register with MD5 auth');
            return;
        }

        if (!password || password.length < 1) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m No password provided`);
            this.sendRegError(session, snac.reqId, 0x0006, 'Password required');
            return;
        }

        // Желаемый UIN (TLV 0x01) — может быть пустым
        let desiredUin = '';
        if (tlvs[0x0001]) {
            desiredUin = tlvs[0x0001].toString().trim();
        }

        // Дополнительные данные
        let email = '';
        if (tlvs[0x000E]) email = tlvs[0x000E].toString(); // Country/Email (иногда)

        // Клиентская информация (для логов)
        let clientInfo = '';
        if (tlvs[0x0003]) clientInfo = tlvs[0x0003].toString(); // Client ID string

        console.log(`\x1b[35m[REGISTER]\x1b[0m Desired UIN: "${desiredUin || 'auto'}", Password: "${password}", Client: "${clientInfo}"`);

        // ── Регистрация ──
        const opts = {
            nickname: desiredUin || undefined,
            email: email,
        };

        // Если клиент указал конкретный UIN — попробовать его
        if (desiredUin && /^\d+$/.test(desiredUin)) {
            opts.uin = desiredUin;
        }

        const result = await db.registerUser(password, opts);

        if (result.error) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Failed: ${result.error}`);

            if (result.error.includes('already taken')) {
                this.sendRegError(session, snac.reqId, 0x0014, result.error);
            } else if (result.error.includes('No free UINs')) {
                this.sendRegError(session, snac.reqId, 0x0014, result.error);
            } else {
                this.sendRegError(session, snac.reqId, 0x0006, result.error);
            }
            return;
        }

        const newUin = result.uin;
        console.log(`\x1b[32m[REGISTER]\x1b[0m ★ New user registered: UIN ${newUin}`);

        // ── Успешный ответ ──
        // SNAC(0x17, 0x05) — SRV_REGISTRATION_REPLY
        const cookie = crypto.randomBytes(256);
        this.pendingCookies.set(cookie.toString('hex'), newUin);

        const resp = new OscarBuilder()
            .tlv(0x0001, newUin)
            .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
            .tlv(0x0006, cookie);

        session.sendSNAC(0x0017, 0x0005, 0, snac.reqId, resp.build());

        console.log(`\x1b[32m[REGISTER]\x1b[0m Sent new UIN ${newUin} to client, cookie ready for BOS`);

        // Некоторые клиенты ждут закрытия соединения
        // Другие сами переподключаются
        // Не закрываем принудительно — пусть клиент решает
    },

    // ═══════════════════════════════════════════════
    //  Обработка регистрации через Channel 1
    //
    //  Некоторые старые клиенты (ICQ 99b, 2000a)
    //  отправляют регистрацию прямо в первом пакете:
    //
    //  FLAP Ch1: version(4) + TLV 0x01("") + TLV 0x02(password)
    //
    //  Если TLV 0x01 пустой и есть TLV 0x02 —
    //  это запрос регистрации, а не логин.
    // ═══════════════════════════════════════════════

    async handleChannel1Registration(session, tlvs) {
        if (!config.REGISTRATION_ENABLED) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Registration disabled (channel 1)`);
            return false;
        }

        const uinTlv = tlvs[0x0001];
        const passTlv = tlvs[0x0002];

        if (!passTlv) return false;

        // Если UIN пустой — это регистрация
        const uin = uinTlv ? uinTlv.toString().trim() : '';

        if (uin && uin.length > 0) {
            // Не пустой UIN — это логин, не регистрация
            return false;
        }

        console.log(`\x1b[35m[REGISTER]\x1b[0m Channel 1 registration detected`);

        const password = xorDecode(passTlv);
        if (!password) return false;

        const result = await db.registerUser(password, {});

        if (result.error) {
            console.log(`\x1b[31m[REGISTER]\x1b[0m Failed: ${result.error}`);

            const errBuf = Buffer.alloc(2);
            errBuf.writeUInt16BE(0x0006);

            session.sendFLAP(0x04, new OscarBuilder()
                .tlv(0x0004, 'http://icq.com/')
                .tlv(0x0008, errBuf)
                .build());
            session.socket.end();
            return true;
        }

        const newUin = result.uin;
        console.log(`\x1b[32m[REGISTER]\x1b[0m ★ New user (ch1): UIN ${newUin}`);

        const cookie = crypto.randomBytes(256);
        this.pendingCookies.set(cookie.toString('hex'), newUin);

        // Ответ через FLAP Ch4 (как для старого логина)
        session.sendFLAP(0x04, new OscarBuilder()
            .tlv(0x0001, newUin)
            .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
            .tlv(0x0006, cookie)
            .build());

        session.socket.end();
        return true;
    },

    // ── Ошибка регистрации ──
    sendRegError(session, reqId, errorCode, errorText) {
        const errBuf = Buffer.alloc(2);
        errBuf.writeUInt16BE(errorCode);

        session.sendSNAC(0x0017, 0x0001, 0, reqId,
            new OscarBuilder()
                .tlv(0x0008, errBuf)
                .tlv(0x0004, errorText || 'http://icq.com/')
                .build());
    },
};

module.exports = Auth;