const sqlite3 = require('sqlite3').verbose();
const config = require('./config');

const db = new sqlite3.Database(config.DB_PATH);

function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function (err) {
            if (err) reject(err); else resolve(this);
        });
    });
}

function get(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) reject(err); else resolve(row);
        });
    });
}

function all(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) reject(err); else resolve(rows);
        });
    });
}

// ═══════════════════════════════════════════
//  Инициализация таблиц
// ═══════════════════════════════════════════

async function init() {
    await run(`CREATE TABLE IF NOT EXISTS users (
        uin       TEXT PRIMARY KEY,
        password  TEXT,
        nickname  TEXT DEFAULT '',
        firstname TEXT DEFAULT '',
        lastname  TEXT DEFAULT '',
        email     TEXT DEFAULT '',
        gender    INTEGER DEFAULT 0,
        age       INTEGER DEFAULT 0
    )`);

    await run(`CREATE TABLE IF NOT EXISTS ssi (
        uin  TEXT,
        name TEXT,
        gid  INTEGER,
        iid  INTEGER,
        type INTEGER,
        tlv  BLOB,
        PRIMARY KEY (uin, gid, iid)
    )`);

    await run(`CREATE TABLE IF NOT EXISTS offline (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        sender    TEXT,
        recipient TEXT,
        message   TEXT,
        ts        REAL
    )`);
}

// ═══════════════════════════════════════════
//  SSI
// ═══════════════════════════════════════════

async function getSSI(uin) {
    return await all("SELECT * FROM ssi WHERE uin = ?", [uin]);
}

async function addSSI(uin, name, gid, iid, type, tlvBuf) {
    await run(
        "INSERT OR REPLACE INTO ssi (uin, name, gid, iid, type, tlv) VALUES (?,?,?,?,?,?)",
        [uin, name, gid, iid, type, tlvBuf]
    );
}

async function deleteSSI(uin, gid, iid) {
    await run("DELETE FROM ssi WHERE uin = ? AND gid = ? AND iid = ?", [uin, gid, iid]);
}

async function getSSIBuddies(uin) {
    return await all("SELECT name FROM ssi WHERE uin = ? AND type = 0", [uin]);
}

// ═══════════════════════════════════════════
//  Поиск
// ═══════════════════════════════════════════

async function searchByUIN(targetUin) {
    return await get("SELECT * FROM users WHERE uin = ?", [targetUin]);
}

async function searchByDetails({ nickname, firstname, lastname, email }) {
    let conditions = [];
    let params = [];

    if (nickname) { conditions.push("LOWER(nickname) LIKE LOWER(?)"); params.push(`%${nickname}%`); }
    if (firstname) { conditions.push("LOWER(firstname) LIKE LOWER(?)"); params.push(`%${firstname}%`); }
    if (lastname) { conditions.push("LOWER(lastname) LIKE LOWER(?)"); params.push(`%${lastname}%`); }
    if (email) { conditions.push("LOWER(email) LIKE LOWER(?)"); params.push(`%${email}%`); }

    if (conditions.length === 0) return [];
    return await all(`SELECT * FROM users WHERE ${conditions.join(' AND ')} LIMIT 20`, params);
}

// ═══════════════════════════════════════════
//  Оффлайн
// ═══════════════════════════════════════════

async function storeOffline(sender, recipient, message) {
    await run(
        "INSERT INTO offline (sender, recipient, message, ts) VALUES (?,?,?,?)",
        [sender, recipient, message, Date.now() / 1000]
    );
}

async function getOffline(recipient) {
    const rows = await all("SELECT * FROM offline WHERE recipient = ? ORDER BY ts", [recipient]);
    if (rows.length > 0) {
        const ids = rows.map(r => r.id).join(',');
        await run(`DELETE FROM offline WHERE id IN (${ids})`);
    }
    return rows;
}

// ═══════════════════════════════════════════
//  Регистрация — автоназначение UIN
// ═══════════════════════════════════════════

async function getNextUIN() {
    // Находим максимальный существующий UIN в диапазоне
    const row = await get(
        "SELECT MAX(CAST(uin AS INTEGER)) as maxuin FROM users WHERE CAST(uin AS INTEGER) BETWEEN ? AND ?",
        [config.UIN_MIN, config.UIN_MAX]
    );

    if (row && row.maxuin) {
        const next = row.maxuin + 1;
        if (next <= config.UIN_MAX) return next.toString();
    }

    // Если нет пользователей или переполнение — ищем первый свободный
    for (let uin = config.UIN_MIN; uin <= config.UIN_MAX; uin++) {
        const exists = await get("SELECT 1 FROM users WHERE uin = ?", [uin.toString()]);
        if (!exists) return uin.toString();
    }

    return null; // Нет свободных UIN
}

async function registerUser(password, opts = {}) {
    let uin = opts.uin;

    // Если UIN не указан — назначить автоматически
    if (!uin) {
        uin = await getNextUIN();
        if (!uin) return { error: 'No free UINs available' };
    }

    // Проверить что UIN свободен
    const exists = await get("SELECT 1 FROM users WHERE uin = ?", [uin]);
    if (exists) return { error: 'UIN already taken' };

    // Создать пользователя
    try {
        await run(
            `INSERT INTO users (uin, password, nickname, firstname, lastname, email)
             VALUES (?,?,?,?,?,?)`,
            [
                uin,
                password,
                opts.nickname || uin,
                opts.firstname || '',
                opts.lastname || '',
                opts.email || '',
            ]
        );

        return { uin, success: true };
    } catch (e) {
        return { error: e.message };
    }
}

// ═══════════════════════════════════════════
//  CLI
// ═══════════════════════════════════════════

if (require.main === module) {
    (async () => {
        await init();
        const args = process.argv.slice(2);
        const cmd = args[0];

        if (cmd === 'add') {
            const [, uin, pass, nick, first, last, email] = args;
            if (!uin || !pass) {
                console.log("Usage: node database.js add <UIN> <PASS> [NICK] [FIRST] [LAST] [EMAIL]");
                process.exit(1);
            }
            const result = await registerUser(pass, {
                uin, nickname: nick, firstname: first, lastname: last, email
            });
            if (result.success) console.log(`\x1b[32m[OK]\x1b[0m User ${result.uin} registered.`);
            else console.error(`\x1b[31m[ERR]\x1b[0m ${result.error}`);

        } else if (cmd === 'list') {
            const users = await all("SELECT uin, nickname, firstname, lastname, email FROM users ORDER BY CAST(uin AS INTEGER)");
            console.log("\n  UIN         Nick        Name              Email");
            console.log("  " + "-".repeat(60));
            if (users.length === 0) console.log("  (empty)");
            users.forEach(u => {
                const name = [u.firstname, u.lastname].filter(Boolean).join(' ') || '-';
                console.log(`  ${u.uin.padEnd(12)}${(u.nickname || '-').padEnd(12)}${name.padEnd(18)}${u.email || '-'}`);
            });
            console.log(`\n  Total: ${users.length} users\n`);

        } else if (cmd === 'del') {
            if (!args[1]) { console.log("Usage: node database.js del <UIN>"); process.exit(1); }
            await run("DELETE FROM users WHERE uin = ?", [args[1]]);
            await run("DELETE FROM ssi WHERE uin = ?", [args[1]]);
            console.log(`User ${args[1]} deleted.`);

        } else if (cmd === 'search') {
            const q = args[1];
            if (!q) { console.log("Usage: node database.js search <query>"); process.exit(1); }
            const rows = await all(
                "SELECT * FROM users WHERE uin LIKE ? OR nickname LIKE ? OR firstname LIKE ? OR lastname LIKE ?",
                [`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`]
            );
            rows.forEach(r => console.log(`  UIN: ${r.uin}  Nick: ${r.nickname}  Name: ${r.firstname} ${r.lastname}`));
            if (!rows.length) console.log("  No results.");

        } else if (cmd === 'nextuin') {
            const uin = await getNextUIN();
            console.log(`Next available UIN: ${uin || 'NONE'}`);

        } else {
            console.log("\nICQ Database Manager");
            console.log("  node database.js add  <UIN> <PASS> [NICK] [FIRST] [LAST] [EMAIL]");
            console.log("  node database.js del  <UIN>");
            console.log("  node database.js list");
            console.log("  node database.js search <query>");
            console.log("  node database.js nextuin\n");
        }
        process.exit(0);
    })();
}

module.exports = {
    init, run, get, all,
    getSSI, addSSI, deleteSSI, getSSIBuddies,
    searchByUIN, searchByDetails,
    storeOffline, getOffline,
    getNextUIN, registerUser,
};