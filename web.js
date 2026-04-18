const http = require('http');
const https = require('https');
const fs = require('fs');
const url = require('url');
const crypto = require('crypto');
const db = require('./database');
const config = require('./config');

// Подключаем официальный файл авторизации для передачи Cookie
const Auth = require('./auth'); 

const WEB_PORT = 8080;
const HTTPS_PORT = 443;
let serverRef = null;

// Хранилища для ICQ HTTP API
const HTTP_CHALLENGES = new Map(); 
const HTTP_TOKENS = new Map();     

// ═══════════════════════════════════════════
//  Styles & Templates
// ═══════════════════════════════════════════

const CSS = `
    body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    h1, h2 { color: #38bdf8; font-weight: 300; }
    .card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    th { text-align: left; color: #94a3b8; font-size: 12px; text-transform: uppercase; padding: 10px; border-bottom: 1px solid #334155; }
    td { padding: 10px; border-bottom: 1px solid #334155; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .online { background: #064e3b; color: #34d399; }
    .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; color: white; display: inline-block; text-decoration: none; font-weight: bold;}
    .btn-danger { background: #ef4444; }
    .btn-primary { background: #3b82f6; }
    .btn-primary:hover { background: #2563eb; }
    input[type=text], input[type=password], textarea { width: 100%; padding: 10px; background: #0f172a; border: 1px solid #334155; color: white; border-radius: 4px; margin-top: 5px; box-sizing: border-box; }
    .nav { display: flex; gap: 10px; margin-bottom: 20px; }
    .nav a { color: #94a3b8; text-decoration: none; padding: 5px 10px; border-radius: 4px; }
    .nav a.active { background: #334155; color: white; }
    label { color: #94a3b8; font-size: 12px; font-weight: bold; text-transform: uppercase; }
`;

function layout(title, content) {
    return `<!DOCTYPE html><html><head><title>${title}</title><style>${CSS}</style></head><body>
    <div class="container">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h1>ArtemICQ Admin</h1>
            <div>
                <a href="/" class="btn btn-primary" style="margin-right:10px;">Регистрация</a>
                <a href="/admin" class="btn btn-danger">Admin Panel</a>
            </div>
        </div>
        ${content}
    </div></body></html>`;
}

function publicRegistration() {
    return `
        <div class="card" style="max-width: 400px; margin: 40px auto;">
            <h2 style="text-align: center; margin-top: 0;">Получить UIN</h2>
            <form id="regForm">
                <div style="margin-bottom: 15px;">
                    <label>Никнейм (необязательно)</label>
                    <input type="text" id="regNick" placeholder="Например: Artem">
                </div>
                <div style="margin-bottom: 20px;">
                    <label>Пароль</label>
                    <input type="password" id="regPass" required placeholder="Придумайте пароль">
                </div>
                <button type="submit" id="regBtn" class="btn btn-primary" style="width: 100%; font-size: 16px;">Зарегистрироваться</button>
            </form>
            <div id="regResult" style="margin-top: 20px; text-align: center; display: none;"></div>
        </div>
        <script>
            document.getElementById('regForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const btn = document.getElementById('regBtn');
                const resBox = document.getElementById('regResult');
                btn.disabled = true; btn.innerText = "Секундочку...";
                try {
                    const response = await fetch('/api/register', {
                        method: 'POST', headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ nickname: document.getElementById('regNick').value, password: document.getElementById('regPass').value })
                    });
                    const data = await response.json();
                    if (data.success) {
                        resBox.style.display = 'block';
                        resBox.innerHTML = '<span style="color:#94a3b8; font-size:14px;">Ваш новый UIN:</span><br><strong style="font-size:36px; color:#34d399; letter-spacing: 2px;">' + data.uin + '</strong><br><br><span style="color:#e2e8f0; font-size:12px;">Запомните UIN и пароль. Теперь вы можете войти в ICQ клиент.</span>';
                        document.getElementById('regForm').style.display = 'none';
                    } else {
                        resBox.style.display = 'block';
                        resBox.innerHTML = '<span style="color:#ef4444;">Ошибка: ' + data.error + '</span>';
                        btn.disabled = false; btn.innerText = "Зарегистрироваться";
                    }
                } catch(err) {
                    resBox.style.display = 'block';
                    resBox.innerHTML = '<span style="color:#ef4444;">Ошибка соединения с сервером.</span>';
                    btn.disabled = false; btn.innerText = "Зарегистрироваться";
                }
            });
        </script>
    `;
}

async function adminDashboard() {
    const onlineCount = serverRef ? serverRef.sessions.size : 0;
    const users = await db.all("SELECT count(*) as c FROM users");
    const totalUsers = users[0].c;

    let sessionRows = '';
    if (serverRef) {
        for (const [uin, session] of serverRef.sessions) {
            sessionRows += `<tr><td><strong>${uin}</strong></td><td>${session.socket.remoteAddress}</td><td><span class="badge online">ONLINE</span></td>
            <td><form method="POST" action="/admin/kick" style="display:inline"><input type="hidden" name="uin" value="${uin}"><button class="btn btn-danger">KICK</button></form></td></tr>`;
        }
    }
    if (!sessionRows) sessionRows = '<tr><td colspan="4" style="text-align:center;color:#64748b;">No users online</td></tr>';

    return `
        <div class="nav"><a href="/admin" class="active">Dashboard</a><a href="/admin/users">All Users</a></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
            <div class="card" style="text-align:center;"><h2 style="font-size:36px;color:#34d399;margin:0;">${onlineCount}</h2><span style="color:#94a3b8;">Online Users</span></div>
            <div class="card" style="text-align:center;"><h2 style="font-size:36px;color:#38bdf8;margin:0;">${totalUsers}</h2><span style="color:#94a3b8;">Registered Accounts</span></div>
        </div>
        <div class="card"><h2>📢 System Broadcast</h2><form method="POST" action="/admin/broadcast"><textarea name="message" rows="3" placeholder="Введите сообщение..."></textarea><div style="margin-top:10px;text-align:right;"><button class="btn btn-primary">SEND</button></div></form></div>
        <div class="card"><h2>🟢 Active Sessions</h2><table><thead><tr><th>UIN</th><th>IP</th><th>Status</th><th>Action</th></tr></thead><tbody>${sessionRows}</tbody></table></div>
    `;
}

async function adminUsers() {
    const users = await db.all("SELECT * FROM users ORDER BY CAST(uin AS INTEGER)");
    let rows = users.map(u => `<tr><td>${u.uin}</td><td>${u.nickname || '-'}</td><td>${u.email || '-'}</td>
        <td><form method="POST" action="/admin/delete_user" style="display:inline"><input type="hidden" name="uin" value="${u.uin}"><button class="btn btn-danger">DEL</button></form></td></tr>`).join('');
    return `<div class="nav"><a href="/admin">Dashboard</a><a href="/admin/users" class="active">All Users</a></div><div class="card"><h2>👥 User Database</h2><table><thead><tr><th>UIN</th><th>Nickname</th><th>Email</th><th>Action</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function checkAuth(req, res) {
    const auth = req.headers['authorization'];
    if (!auth) return false;
    const tmp = auth.split(' ');
    const buf = Buffer.from(tmp[1], 'base64');
    const creds = buf.toString().split(':');
    return creds[0] === config.ADMIN_USER && creds[1] === config.ADMIN_PASS;
}

function requestAuth(res) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="ICQ Admin Panel"' });
    res.end('Access denied');
}

function parseBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            if (req.headers['content-type'] && req.headers['content-type'].includes('json')) {
                try { resolve(JSON.parse(body)); } catch(e) { resolve({}); }
            } else {
                const params = {};
                body.split('&').forEach(p => {
                    const kv = p.split('=');
                    if (kv[0]) params[kv[0]] = decodeURIComponent((kv[1] || '').replace(/\+/g, ' '));
                });
                resolve(params);
            }
        });
    });
}

// ═══════════════════════════════════════════
//  HTTP Server (API & Admin)
// ═══════════════════════════════════════════

async function startWeb(mainServer) {
    serverRef = mainServer;
    await db.init();

    // Единый обработчик запросов для HTTP и HTTPS
    const requestHandler = async (req, res) => {
        const u = url.parse(req.url, true);
        const path = (u.pathname || '').replace(/\/$/, ""); 

        // CORS Headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            return res.end();
        }

        // 0. ПУБЛИЧНАЯ СТРАНИЦА РЕГИСТРАЦИИ (HTML)
        if ((path === '' || path === '/' || path === '/register') && req.method === 'GET') {
            res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
            return res.end(layout('Регистрация ArtemICQ', publicRegistration()));
        }

        // 1. ПУБЛИЧНЫЙ API РЕГИСТРАЦИИ (POST)
        if (path === '/api/register' && req.method === 'POST') {
            const data = await parseBody(req);
            if (!data.password) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: false, error: 'Password is required' }));
            }
            try {
                const lastUser = await db.all("SELECT uin FROM users ORDER BY CAST(uin AS INTEGER) DESC LIMIT 1");
                let nextUin = config.UIN_MIN || 100000;
                if (lastUser && lastUser.length > 0) nextUin = Math.max(nextUin, parseInt(lastUser[0].uin) + 1);

                await db.run("INSERT INTO users (uin, password, nickname, email) VALUES (?, ?, ?, ?)",[
                    nextUin.toString(), data.password, data.nickname || '', data.email || ''
                ]);
                console.log(`\x1b[32m[WEB API]\x1b[0m Зарегистрирован новый UIN: ${nextUin}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: true, uin: nextUin.toString() }));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                return res.end(JSON.stringify({ success: false, error: 'DB Error' }));
            }
        }

        // 2. ICQ HTTP API (Для ICQ 7, 8 и мобильных)
        if (path === '/auth/getChallenge' && req.method === 'POST') {
            const tid = crypto.randomBytes(8).toString('hex');
            const challenge = crypto.randomBytes(8).toString('hex');
            HTTP_CHALLENGES.set(tid, challenge);
            const xml = `<response xmlns="https://api.login.aol.com"><statuscode>200</statuscode><statustext>OK</statustext><data><tid>${tid}</tid><normalize>false</normalize><truncate>true</truncate><realm>AOL Instant Messenger (SM)</realm><challengeword>${challenge}</challengeword></data></response>`;
            res.writeHead(200, { 'Content-Type': 'application/xml' });
            return res.end(xml);
        }

        if (path === '/auth/clientLogin' && req.method === 'POST') {
            const data = await parseBody(req);
            const uin = data.s;
            const clientPwdHash = data.pwd; 
            const user = await db.get("SELECT * FROM users WHERE uin = ?",[uin]);
            let success = false;

            if (user && clientPwdHash) {
                for (const [tid, challenge] of HTTP_CHALLENGES.entries()) {
                    const expectedHash = crypto.createHmac('sha256', user.password).update(challenge).digest('base64');
                    if (expectedHash === clientPwdHash || user.password === clientPwdHash) {
                        success = true;
                        HTTP_CHALLENGES.delete(tid);
                        break;
                    }
                }
            }

            if (success) {
                const token = crypto.randomBytes(32).toString('base64');
                const secret = crypto.randomBytes(8).toString('hex');
                HTTP_TOKENS.set(token, user.uin);
                const xml = `<response xmlns="https://api.login.aol.com"><statuscode>200</statuscode><statustext>OK</statustext><data><token><expiresin>315569260</expiresin><a>${token}</a></token><sessionsecret>${secret}</sessionsecret><hosttime>${Math.floor(Date.now() / 1000)}</hosttime><loginid>${user.uin}</loginid></data></response>`;
                console.log(`\x1b[32m[HTTP AUTH]\x1b[0m Успешный вход: ${user.uin}`);
                res.writeHead(200, { 'Content-Type': 'application/xml' });
                return res.end(xml);
            } else {
                console.log(`\x1b[31m[HTTP AUTH FAIL]\x1b[0m Ошибка входа UIN: ${uin}`);
                res.writeHead(401, { 'Content-Type': 'application/xml' });
                return res.end(`<response xmlns="https://api.login.aol.com"><statuscode>401</statuscode><statustext>Invalid login</statustext></response>`);
            }
        }

        if (path === '/aim/startOSCARSession') {
            const token = u.query.a;
            const uin = HTTP_TOKENS.get(token);
            if (uin) {
                const cookieBuf = crypto.randomBytes(32);
                const cookieHex = cookieBuf.toString('hex');
                
                if (Auth && Auth.pendingCookies) {
                    Auth.pendingCookies.set(cookieHex, uin);
                }

                const bosHost = `${config.BOS_ADDRESS || '2.26.61.185'}:${config.BOS_PORT || 5191}`;
                const xml = `<response xmlns="https://api.oscar.aol.com"><statuscode>200</statuscode><statustext>OK</statustext><data><host>${bosHost}</host><cookie>${cookieBuf.toString('base64')}</cookie></data></response>`;
                res.writeHead(200, { 'Content-Type': 'application/xml' });
                return res.end(xml);
            } else {
                res.writeHead(401, { 'Content-Type': 'application/xml' });
                return res.end(`<response xmlns="https://api.oscar.aol.com"><statuscode>401</statuscode><statustext>Unauthorized</statustext></response>`);
            }
        }

        // 3. ADMIN PANEL
        if (path.startsWith('/admin')) {
            if (!checkAuth(req, res)) return requestAuth(res);

            if (req.method === 'GET') {
                let content = path === '/admin/users' ? await adminUsers() : await adminDashboard();
                res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
                return res.end(layout('Admin Panel', content));
            }

            if (req.method === 'POST') {
                const data = await parseBody(req);
                if (path === '/admin/kick' && serverRef) {
                    const session = serverRef.sessions.get(data.uin);
                    if (session) session.disconnect();
                }
                if (path === '/admin/broadcast' && serverRef && data.message) serverRef.broadcast(data.message);
                if (path === '/admin/delete_user') {
                    await db.run("DELETE FROM users WHERE uin = ?", [data.uin]);
                    await db.run("DELETE FROM ssi WHERE uin = ?", [data.uin]);
                    if (serverRef) {
                        const session = serverRef.sessions.get(data.uin);
                        if (session) session.disconnect();
                    }
                }
                res.writeHead(302, { 'Location': req.headers.referer || '/admin' });
                return res.end();
            }
        }

        res.writeHead(404);
        res.end('Not found');
    };

    // Запускаем HTTP сервер (Порт 8080)
    const httpServer = http.createServer(requestHandler);
    httpServer.listen(WEB_PORT, () => {
        console.log(`\x1b[1mWEB\x1b[0m HTTP сервер запущен на порту ${WEB_PORT}`);
    });

    // Запускаем HTTPS сервер (Порт 443)
    try {
        if (fs.existsSync('key.pem') && fs.existsSync('cert.pem')) {
            const options = {
                key: fs.readFileSync('key.pem'),
                cert: fs.readFileSync('cert.pem')
            };
            const httpsServer = https.createServer(options, requestHandler);
            
            httpsServer.listen(443, () => {
                console.log(`\x1b[1mWEB\x1b[0m HTTPS API запущен на порту 443`);
            }).on('error', (err) => {
                if (err.code === 'EACCES') {
                    console.log(`\x1b[33m[WEB]\x1b[0m Нет прав для запуска HTTPS на порту 443 (нужен sudo)`);
                } else {
                    console.log(`\x1b[31m[WEB]\x1b[0m Ошибка HTTPS: ${err.message}`);
                }
            });
        } else {
            console.log(`\x1b[33m[WEB]\x1b[0m Сертификаты (key.pem и cert.pem) не найдены. HTTPS-сервер отключен.`);
        }
    } catch (e) {
        console.log(`\x1b[1mWEB\x1b[0m lol at http://localhost:8080/admin`);
    });
}

module.exports = { startWeb };
