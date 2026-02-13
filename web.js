const http = require('http');
const url = require('url');
const db = require('./database');

const WEB_PORT = 8080;

// ═══════════════════════════════════════════
//  HTML шаблоны
// ═══════════════════════════════════════════

function pageLayout(title, content) {
    return `<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a1628 0%, #1a2a4a 50%, #0d1f3c 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            color: #e0e0e0;
        }

        .container {
            background: rgba(20, 30, 50, 0.9);
            border: 1px solid rgba(100, 150, 255, 0.2);
            border-radius: 16px;
            padding: 40px;
            width: 420px;
            box-shadow: 
                0 0 40px rgba(50, 100, 255, 0.1),
                0 20px 60px rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(10px);
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo .flower {
            font-size: 48px;
            display: block;
            margin-bottom: 8px;
        }

        .logo h1 {
            font-size: 24px;
            color: #7eb8ff;
            font-weight: 600;
            letter-spacing: 1px;
        }

        .logo p {
            color: #6a7a9a;
            font-size: 13px;
            margin-top: 4px;
        }

        .form-group {
            margin-bottom: 16px;
        }

        .form-group label {
            display: block;
            font-size: 13px;
            color: #8a9aba;
            margin-bottom: 6px;
            font-weight: 500;
        }

        .form-group label .required {
            color: #ff6b6b;
        }

        .form-group input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(10, 20, 40, 0.8);
            border: 1px solid rgba(100, 150, 255, 0.15);
            border-radius: 8px;
            color: #e0e0e0;
            font-size: 14px;
            transition: all 0.3s;
            outline: none;
        }

        .form-group input:focus {
            border-color: rgba(100, 150, 255, 0.5);
            box-shadow: 0 0 15px rgba(50, 100, 255, 0.15);
            background: rgba(15, 25, 50, 0.9);
        }

        .form-group input::placeholder {
            color: #4a5a7a;
        }

        .form-row {
            display: flex;
            gap: 12px;
        }

        .form-row .form-group {
            flex: 1;
        }

        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #2a5aaa, #3a7aee);
            border: none;
            border-radius: 8px;
            color: white;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            margin-top: 8px;
            letter-spacing: 0.5px;
        }

        .btn:hover {
            background: linear-gradient(135deg, #3a6abb, #4a8aff);
            box-shadow: 0 4px 20px rgba(50, 100, 255, 0.3);
            transform: translateY(-1px);
        }

        .btn:active {
            transform: translateY(0);
        }

        .alert {
            padding: 14px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            line-height: 1.4;
        }

        .alert-success {
            background: rgba(40, 167, 69, 0.15);
            border: 1px solid rgba(40, 167, 69, 0.3);
            color: #6ddf8a;
        }

        .alert-error {
            background: rgba(220, 53, 69, 0.15);
            border: 1px solid rgba(220, 53, 69, 0.3);
            color: #ff7a8a;
        }

        .alert-info {
            background: rgba(50, 100, 200, 0.15);
            border: 1px solid rgba(50, 100, 200, 0.3);
            color: #7eb8ff;
        }

        .info-box {
            margin-top: 24px;
            padding: 16px;
            background: rgba(10, 20, 40, 0.6);
            border: 1px solid rgba(100, 150, 255, 0.1);
            border-radius: 8px;
        }

        .info-box h3 {
            font-size: 13px;
            color: #7eb8ff;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .info-box .param {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            font-size: 13px;
            border-bottom: 1px solid rgba(100, 150, 255, 0.05);
        }

        .info-box .param:last-child {
            border-bottom: none;
        }

        .info-box .param .label {
            color: #6a7a9a;
        }

        .info-box .param .value {
            color: #aaccff;
            font-family: 'Consolas', monospace;
            font-weight: 600;
        }

        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #4a5a7a;
        }

        .footer a {
            color: #5a8acc;
            text-decoration: none;
        }

        .uin-display {
            text-align: center;
            padding: 20px;
            background: rgba(40, 167, 69, 0.1);
            border: 1px solid rgba(40, 167, 69, 0.2);
            border-radius: 12px;
            margin: 16px 0;
        }

        .uin-display .uin-number {
            font-size: 36px;
            font-weight: 700;
            color: #6ddf8a;
            font-family: 'Consolas', monospace;
            letter-spacing: 3px;
        }

        .uin-display .uin-label {
            font-size: 12px;
            color: #6a7a9a;
            margin-top: 4px;
        }

        .online-counter {
            text-align: center;
            font-size: 12px;
            color: #4a6a8a;
            margin-top: 8px;
        }

        .online-counter span {
            color: #6ddf8a;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        ${content}
    </div>
</body>
</html>`;
}

function registerPage(message = '', messageType = '') {
    let alertHtml = '';
    if (message) {
        alertHtml = `<div class="alert alert-${messageType}">${message}</div>`;
    }

    const content = `
        <div class="logo">
            <span class="flower">❄</span>
            <h1>ICQ Server</h1>
            <p>Регистрация нового аккаунта</p>
        </div>

        ${alertHtml}

        <form method="POST" action="/register">
            <div class="form-group">
                <label>UIN (номер) <span class="required">*</span></label>
                <input type="text" name="uin" placeholder="Например: 123456" 
                       pattern="[0-9]+" title="Только цифры" required
                       autocomplete="off">
            </div>

            <div class="form-group">
                <label>Пароль <span class="required">*</span></label>
                <input type="password" name="password" placeholder="Минимум 3 символа" 
                       minlength="3" required>
            </div>

            <div class="form-group">
                <label>Никнейм</label>
                <input type="text" name="nickname" placeholder="Отображаемое имя">
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>Имя</label>
                    <input type="text" name="firstname" placeholder="Имя">
                </div>
                <div class="form-group">
                    <label>Фамилия</label>
                    <input type="text" name="lastname" placeholder="Фамилия">
                </div>
            </div>

            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" placeholder="user@example.com">
            </div>

            <button type="submit" class="btn">Зарегистрироваться</button>
        </form>

        <div class="info-box">
            <h3>Настройки подключения</h3>
            <div class="param">
                <span class="label">Сервер</span>
                <span class="value">${require('./config').BOS_ADDRESS}</span>
            </div>
            <div class="param">
                <span class="label">Порт</span>
                <span class="value">${require('./config').AUTH_PORT}</span>
            </div>
            <div class="param">
                <span class="label">Протокол</span>
                <span class="value">OSCAR (ICQ)</span>
            </div>
        </div>

        <div class="footer">
            Совместимые клиенты: QIP, Miranda, Pidgin, ICQ, R&Q
        </div>
    `;

    return pageLayout('ICQ — Регистрация', content);
}

function successPage(uin) {
    const content = `
        <div class="logo">
            <span class="flower">✓</span>
            <h1>Регистрация успешна!</h1>
        </div>

        <div class="uin-display">
            <div class="uin-number">${uin}</div>
            <div class="uin-label">Ваш UIN</div>
        </div>

        <div class="alert alert-success">
            Аккаунт создан. Используйте этот UIN и ваш пароль для входа
            через любой ICQ-совместимый клиент.
        </div>

        <div class="info-box">
            <h3>Как подключиться</h3>
            <div class="param">
                <span class="label">1. Откройте клиент</span>
                <span class="value">QIP / Miranda / Pidgin</span>
            </div>
            <div class="param">
                <span class="label">2. Сервер</span>
                <span class="value">${require('./config').BOS_ADDRESS}</span>
            </div>
            <div class="param">
                <span class="label">3. Порт</span>
                <span class="value">${require('./config').AUTH_PORT}</span>
            </div>
            <div class="param">
                <span class="label">4. UIN</span>
                <span class="value">${uin}</span>
            </div>
            <div class="param">
                <span class="label">5. Пароль</span>
                <span class="value">••••••</span>
            </div>
        </div>

        <form action="/" method="GET" style="margin-top: 16px;">
            <button type="submit" class="btn">← Зарегистрировать ещё</button>
        </form>

        <div class="footer">
            Запомните ваш UIN: <strong>${uin}</strong>
        </div>
    `;

    return pageLayout('ICQ — Готово!', content);
}

function usersPage(users) {
    let rows = '';
    if (users.length === 0) {
        rows = '<tr><td colspan="4" style="text-align:center;color:#6a7a9a;padding:20px;">Нет зарегистрированных пользователей</td></tr>';
    } else {
        users.forEach(u => {
            const name = [u.firstname, u.lastname].filter(Boolean).join(' ') || '—';
            rows += `<tr>
                <td style="font-weight:600;color:#7eb8ff;">${u.uin}</td>
                <td>${u.nickname || '—'}</td>
                <td>${name}</td>
                <td>${u.email || '—'}</td>
            </tr>`;
        });
    }

    const content = `
        <div class="logo">
            <span class="flower">👥</span>
            <h1>Пользователи</h1>
            <p>Всего: ${users.length}</p>
        </div>

        <div style="overflow-x:auto;">
            <table style="width:100%;border-collapse:collapse;font-size:13px;">
                <thead>
                    <tr style="border-bottom:1px solid rgba(100,150,255,0.15);">
                        <th style="padding:10px 8px;text-align:left;color:#6a7a9a;font-weight:600;">UIN</th>
                        <th style="padding:10px 8px;text-align:left;color:#6a7a9a;font-weight:600;">Ник</th>
                        <th style="padding:10px 8px;text-align:left;color:#6a7a9a;font-weight:600;">Имя</th>
                        <th style="padding:10px 8px;text-align:left;color:#6a7a9a;font-weight:600;">Email</th>
                    </tr>
                </thead>
                <tbody>
                    ${rows}
                </tbody>
            </table>
        </div>

        <form action="/" method="GET" style="margin-top: 20px;">
            <button type="submit" class="btn">← Регистрация</button>
        </form>
    `;

    return pageLayout('ICQ — Пользователи', content);
}

// ═══════════════════════════════════════════
//  Парсинг POST данных
// ═══════════════════════════════════════════

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk;
            if (body.length > 1e6) { req.destroy(); reject(new Error('Too large')); }
        });
        req.on('end', () => {
            const params = {};
            body.split('&').forEach(pair => {
                const [key, val] = pair.split('=').map(s => decodeURIComponent(s.replace(/\+/g, ' ')));
                if (key) params[key] = val || '';
            });
            resolve(params);
        });
    });
}

// ═══════════════════════════════════════════
//  HTTP сервер
// ═══════════════════════════════════════════

async function startWeb() {
    await db.init();

    const server = http.createServer(async (req, res) => {
        const parsed = url.parse(req.url, true);
        const path = parsed.pathname;

        try {
            // ── Главная (форма регистрации) ──
            if (path === '/' && req.method === 'GET') {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(registerPage());
                return;
            }

            // ── Обработка регистрации ──
            if (path === '/register' && req.method === 'POST') {
                const data = await parseBody(req);

                const uin = (data.uin || '').trim();
                const password = (data.password || '').trim();
                const nickname = (data.nickname || '').trim() || uin;
                const firstname = (data.firstname || '').trim();
                const lastname = (data.lastname || '').trim();
                const email = (data.email || '').trim();

                // Валидация
                if (!uin || !password) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(registerPage('UIN и пароль обязательны.', 'error'));
                    return;
                }

                if (!/^\d+$/.test(uin)) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(registerPage('UIN должен содержать только цифры.', 'error'));
                    return;
                }

                if (password.length < 3) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(registerPage('Пароль должен быть минимум 3 символа.', 'error'));
                    return;
                }

                // Проверка существования
                const existing = await db.get("SELECT uin FROM users WHERE uin = ?", [uin]);
                if (existing) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(registerPage(`UIN ${uin} уже зарегистрирован. Выберите другой.`, 'error'));
                    return;
                }

                // Регистрация
                try {
                    await db.run(
                        `INSERT INTO users (uin, password, nickname, firstname, lastname, email)
                         VALUES (?,?,?,?,?,?)`,
                        [uin, password, nickname, firstname, lastname, email]
                    );

                    console.log(`\x1b[32m[WEB]\x1b[0m Registered UIN ${uin} (${nickname})`);

                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(successPage(uin));
                } catch (e) {
                    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                    res.end(registerPage(`Ошибка: ${e.message}`, 'error'));
                }
                return;
            }

            // ── Список пользователей ──
            if (path === '/users' && req.method === 'GET') {
                const users = await db.all(
                    "SELECT uin, nickname, firstname, lastname, email FROM users ORDER BY uin"
                );
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(usersPage(users));
                return;
            }

            // ── API: список пользователей (JSON) ──
            if (path === '/api/users' && req.method === 'GET') {
                const users = await db.all(
                    "SELECT uin, nickname, firstname, lastname, email FROM users ORDER BY uin"
                );
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ users, count: users.length }));
                return;
            }

            // ── API: регистрация (JSON) ──
            if (path === '/api/register' && req.method === 'POST') {
                const data = await parseBody(req);
                const uin = (data.uin || '').trim();
                const password = (data.password || '').trim();

                if (!uin || !password) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'UIN and password required' }));
                    return;
                }

                try {
                    await db.run(
                        `INSERT INTO users (uin, password, nickname, firstname, lastname, email)
                         VALUES (?,?,?,?,?,?)`,
                        [uin, password, data.nickname || uin, data.firstname || '', data.lastname || '', data.email || '']
                    );
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, uin }));
                } catch (e) {
                    res.writeHead(409, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'UIN already exists' }));
                }
                return;
            }

            // ── 404 ──
            res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(pageLayout('404', '<div class="logo"><span class="flower">🔍</span><h1>404</h1><p>Страница не найдена</p></div>'));

        } catch (e) {
            console.error(`\x1b[31m[WEB ERROR]\x1b[0m`, e);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Server Error');
        }
    });

    server.listen(WEB_PORT, () => {
        console.log(`\x1b[1mWEB\x1b[0m server on http://localhost:${WEB_PORT}`);
        console.log(`  Registration: http://localhost:${WEB_PORT}/`);
        console.log(`  Users list:   http://localhost:${WEB_PORT}/users`);
        console.log(`  API:          http://localhost:${WEB_PORT}/api/users`);
    });
}

// Запуск
if (require.main === module) {
    startWeb();
} else {
    module.exports = { startWeb };
}