const http = require('http');
const url = require('url');
const db = require('./database');
const config = require('./config');

const WEB_PORT = 8080;
let serverRef = null; // Ссылка на запущенный сервер (сессии и функции)

// ═══════════════════════════════════════════
//  CSS & Основной шаблон (Layout)
// ═══════════════════════════════════════════

const CSS = `
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.5; }
    .container { max-width: 800px; margin: 40px auto; padding: 20px; }
    
    h1 { color: #38bdf8; font-weight: 300; margin-bottom: 20px; }
    h2 { color: #7dd3fc; font-weight: 400; margin-bottom: 15px; font-size: 20px; }
    
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 24px; margin-bottom: 24px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
    
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 13px; color: #94a3b8; margin-bottom: 6px; }
    .form-group input, .form-group textarea { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: #e2e8f0; border-radius: 6px; outline: none; }
    .form-group input:focus { border-color: #38bdf8; }
    
    .btn { padding: 10px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 600; text-decoration: none; display: inline-block; transition: 0.2s; }
    .btn-primary { background: #0284c7; color: white; }
    .btn-primary:hover { background: #0369a1; }
    .btn-danger { background: #dc2626; color: white; padding: 6px 12px; font-size: 12px;}
    .btn-danger:hover { background: #b91c1c; }
    
    table { width: 100%; border-collapse: collapse; }
    th { text-align: left; color: #94a3b8; font-size: 12px; text-transform: uppercase; padding: 12px; border-bottom: 1px solid #334155; }
    td { padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }
    tr:last-child td { border-bottom: none; }
    
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
    .online { background: #064e3b; color: #34d399; }
    
    .nav { display: flex; gap: 15px; margin-bottom: 30px; border-bottom: 1px solid #334155; padding-bottom: 10px; }
    .nav a { color: #94a3b8; text-decoration: none; padding: 8px 16px; border-radius: 6px; font-weight: 500; }
    .nav a:hover, .nav a.active { background: #334155; color: #fff; }
    
    .alert { padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
    .alert-success { background: #064e3b; color: #34d399; border: 1px solid #059669; }
    .alert-error { background: #450a0a; color: #f87171; border: 1px solid #dc2626; }
`;

function layout(title, content) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>${title} - ICQ Server</title>
    <style>${CSS}</style>
</head>
<body>
    <div class="container">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:30px;">
            <h1>🧊 NodeICQ Server</h1>
            <div>
                <a href="/" class="btn" style="color:#94a3b8">Register</a>
                <a href="/admin" class="btn btn-primary" style="margin-left:10px">Admin Panel</a>
            </div>
        </div>
        ${content}
    </div>
</body>
</html>`;
}

// ═══════════════════════════════════════════
//  1. Страница Регистрации (Открытая)
// ═══════════════════════════════════════════

function viewRegistration(msg = '', type = '') {
    let alert = msg ? `<div class="alert alert-${type}">${msg}</div>` : '';

    const content = `
        <div style="max-width: 400px; margin: 0 auto;">
            ${alert}
            <div class="card">
                <h2>Create Account</h2>
                <form method="POST" action="/register">
                    <div class="form-group">
                        <label>Password *</label>
                        <input type="password" name="password" required placeholder="Minimum 3 chars">
                    </div>
                    <div class="form-group">
                        <label>Nickname</label>
                        <input type="text" name="nickname" placeholder="e.g. CoolHacker">
                    </div>
                    <div class="form-group">
                        <label>Email (optional)</label>
                        <input type="email" name="email" placeholder="user@example.com">
                    </div>
                    <button type="submit" class="btn btn-primary" style="width:100%;margin-top:10px;padding:12px;">
                        Register (Auto-assign UIN)
                    </button>
                </form>
            </div>
            
            <div class="card" style="font-size:13px;color:#94a3b8;">
                <strong>Connection settings:</strong><br><br>
                Host: <span style="color:#fff">${config.BOS_ADDRESS}</span><br>
                Port: <span style="color:#fff">${config.AUTH_PORT}</span><br>
                Protocol: <span style="color:#fff">ICQ (OSCAR)</span>
            </div>
        </div>
    `;
    return layout('Registration', content);
}

function viewRegSuccess(uin) {
    return layout('Success', `
        <div style="max-width: 400px; margin: 0 auto; text-align: center;">
            <div class="card">
                <h2 style="color:#34d399;font-size:24px;">Success!</h2>
                <p style="margin:20px 0;color:#94a3b8;">Your assigned ICQ Number (UIN) is:</p>
                <div style="font-size:48px;font-weight:bold;color:#38bdf8;letter-spacing:4px;margin-bottom:30px;">
                    ${uin}
                </div>
                <a href="/" class="btn btn-primary">Create Another</a>
            </div>
        </div>
    `);
}

// ═══════════════════════════════════════════
//  2. Админ-панель (Закрытая)
// ═══════════════════════════════════════════

async function viewAdminDashboard() {
    const onlineCount = serverRef ? serverRef.sessions.size : 0;
    const users = await db.all("SELECT count(*) as c FROM users");
    const totalUsers = users[0].c;

    let sessionRows = '';
    if (serverRef) {
        for (const [uin, session] of serverRef.sessions) {
            sessionRows += `<tr>
                <td><strong>${uin}</strong></td>
                <td>${session.socket.remoteAddress}</td>
                <td><span class="badge online">ONLINE</span></td>
                <td style="text-align:right">
                    <form method="POST" action="/admin/kick" style="display:inline">
                        <input type="hidden" name="uin" value="${uin}">
                        <button class="btn btn-danger">Kick</button>
                    </form>
                </td>
            </tr>`;
        }
    }
    if (!sessionRows) sessionRows = '<tr><td colspan="4" style="text-align:center;color:#64748b;">No active connections</td></tr>';

    return `
        <div class="nav">
            <a href="/admin" class="active">Dashboard (Online)</a>
            <a href="/admin/users">User Database</a>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:24px;">
            <div class="card" style="text-align:center;">
                <h2 style="font-size:40px;color:#34d399;margin:0;">${onlineCount}</h2>
                <span style="color:#94a3b8;">Online Users</span>
            </div>
            <div class="card" style="text-align:center;">
                <h2 style="font-size:40px;color:#38bdf8;margin:0;">${totalUsers}</h2>
                <span style="color:#94a3b8;">Total Registered Accounts</span>
            </div>
        </div>

        <div class="card">
            <h2>📢 System Broadcast</h2>
            <p style="font-size:12px;color:#94a3b8;margin-bottom:10px;">Send a message to all online users from "System"</p>
            <form method="POST" action="/admin/broadcast">
                <div class="form-group">
                    <textarea name="message" rows="3" required placeholder="Type your message here..."></textarea>
                </div>
                <button class="btn btn-primary">Broadcast Message</button>
            </form>
        </div>

        <div class="card">
            <h2>🟢 Active Sessions</h2>
            <table>
                <thead><tr><th>UIN</th><th>IP Address</th><th>Status</th><th style="text-align:right">Action</th></tr></thead>
                <tbody>${sessionRows}</tbody>
            </table>
        </div>
    `;
}

async function viewAdminUsers() {
    const users = await db.all("SELECT * FROM users ORDER BY CAST(uin AS INTEGER)");
    
    let rows = users.map(u => `
        <tr>
            <td><strong>${u.uin}</strong></td>
            <td>${u.nickname || '-'}</td>
            <td>${u.email || '-'}</td>
            <td>${u.password}</td>
            <td style="text-align:right">
                <form method="POST" action="/admin/delete" style="display:inline" onsubmit="return confirm('Delete user ${u.uin}? This cannot be undone.');">
                    <input type="hidden" name="uin" value="${u.uin}">
                    <button class="btn btn-danger">Delete</button>
                </form>
            </td>
        </tr>
    `).join('');

    if (!rows) rows = '<tr><td colspan="5" style="text-align:center;">No users registered</td></tr>';

    return `
        <div class="nav">
            <a href="/admin">Dashboard (Online)</a>
            <a href="/admin/users" class="active">User Database</a>
        </div>
        <div class="card">
            <h2>👥 Registered Users</h2>
            <table>
                <thead><tr><th>UIN</th><th>Nickname</th><th>Email</th><th>Password</th><th style="text-align:right">Action</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

// ═══════════════════════════════════════════
//  Basic Auth Middleware
// ═══════════════════════════════════════════

function checkAuth(req, res) {
    const auth = req.headers['authorization'];
    if (!auth) return false;

    // Декодируем строку Basic dXNlcjpwYXNz
    const tmp = auth.split(' ');
    const plain = Buffer.from(tmp[1], 'base64').toString();
    const [user, pass] = plain.split(':');

    // Сверяем с config.js
    if (user === config.ADMIN_USER && pass === config.ADMIN_PASS) {
        return true;
    }
    return false;
}

function requestAuth(res) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="NodeICQ Admin Panel"' });
    res.end('Access denied');
}

// ═══════════════════════════════════════════
//  Хелперы HTTP
// ═══════════════════════════════════════════

function parseBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            const params = {};
            body.split('&').forEach(p => {
                const [k, v] = p.split('=');
                if (k) params[k] = decodeURIComponent((v || '').replace(/\+/g, ' '));
            });
            resolve(params);
        });
    });
}

function sendHtml(res, html) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
}

// ═══════════════════════════════════════════
//  HTTP Сервер
// ═══════════════════════════════════════════

async function startWeb(mainServerContext) {
    serverRef = mainServerContext; // Сохраняем контекст для админки

    const server = http.createServer(async (req, res) => {
        const u = url.parse(req.url, true);
        const path = u.pathname;

        try {
            // ───────────────────────────────────────
            // 1. ПУБЛИЧНАЯ ЗОНА (РЕГИСТРАЦИЯ)
            // ───────────────────────────────────────
            
            if (path === '/' && req.method === 'GET') {
                return sendHtml(res, viewRegistration());
            }

            if (path === '/register' && req.method === 'POST') {
                if (!config.REGISTRATION_ENABLED) {
                    return sendHtml(res, viewRegistration('Registration is currently disabled by administrator.', 'error'));
                }

                const data = await parseBody(req);
                const password = (data.password || '').trim();
                
                if (password.length < 3) {
                    return sendHtml(res, viewRegistration('Password must be at least 3 characters long.', 'error'));
                }

                // Используем функцию из database.js, которая автоматически назначает UIN
                const result = await db.registerUser(password, {
                    nickname: data.nickname,
                    email: data.email
                });

                if (result.error) {
                    return sendHtml(res, viewRegistration(result.error, 'error'));
                }

                console.log(`\x1b[32m[WEB]\x1b[0m New user registered: ${result.uin}`);
                return sendHtml(res, viewRegSuccess(result.uin));
            }

            // ───────────────────────────────────────
            // 2. АДМИН-ПАНЕЛЬ (ЗАКРЫТАЯ)
            // ───────────────────────────────────────
            
            if (path.startsWith('/admin')) {
                // Проверка пароля
                if (!checkAuth(req, res)) {
                    return requestAuth(res);
                }

                // GET Роуты
                if (req.method === 'GET') {
                    if (path === '/admin') {
                        return sendHtml(res, layout('Dashboard', await viewAdminDashboard()));
                    }
                    if (path === '/admin/users') {
                        return sendHtml(res, layout('Users', await viewAdminUsers()));
                    }
                }

                // POST Действия
                if (req.method === 'POST') {
                    const data = await parseBody(req);

                    if (path === '/admin/kick') {
                        const session = serverRef.sessions.get(data.uin);
                        if (session) {
                            session.disconnect();
                            console.log(`\x1b[31m[ADMIN]\x1b[0m Kicked user ${data.uin}`);
                        }
                    }

                    if (path === '/admin/broadcast') {
                        if (serverRef.broadcast && data.message) {
                            const count = serverRef.broadcast(data.message);
                            console.log(`\x1b[36m[ADMIN]\x1b[0m Broadcast sent to ${count} users`);
                        }
                    }

                    if (path === '/admin/delete') {
                        if (data.uin) {
                            await db.run("DELETE FROM users WHERE uin = ?", [data.uin]);
                            await db.run("DELETE FROM ssi WHERE uin = ?", [data.uin]);
                            const session = serverRef.sessions.get(data.uin);
                            if (session) session.disconnect();
                            console.log(`\x1b[31m[ADMIN]\x1b[0m Deleted user ${data.uin}`);
                        }
                    }

                    // Редирект обратно после действия
                    res.writeHead(302, { 'Location': req.headers.referer || '/admin' });
                    res.end();
                    return;
                }
            }

            // 404
            res.writeHead(404);
            res.end('404 Not Found');

        } catch (e) {
            console.error(`\x1b[31m[WEB ERR]\x1b[0m`, e);
            res.writeHead(500);
            res.end('Internal Server Error');
        }
    });

    server.listen(WEB_PORT, () => {
        console.log(`\x1b[1mWEB\x1b[0m server running on \x1b[36mhttp://localhost:${WEB_PORT}\x1b[0m`);
        console.log(`      Registration:  http://localhost:${WEB_PORT}/`);
        console.log(`      Admin Panel:   http://localhost:${WEB_PORT}/admin`);
    });
}

module.exports = { startWeb };
