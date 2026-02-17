const http = require('http');
const url = require('url');
const db = require('./database');
const config = require('./config');

const WEB_PORT = 8080;
let serverRef = null; // To access active sessions

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
    tr:last-child td { border-bottom: none; }
    .badge { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    .online { background: #064e3b; color: #34d399; }
    .offline { background: #450a0a; color: #f87171; }
    .btn { padding: 6px 12px; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; text-decoration: none; display: inline-block; }
    .btn-danger { background: #ef4444; color: white; }
    .btn-primary { background: #3b82f6; color: white; }
    input[type=text], textarea { width: 100%; padding: 8px; background: #0f172a; border: 1px solid #334155; color: white; border-radius: 4px; margin-top: 5px; }
    .nav { display: flex; gap: 10px; margin-bottom: 20px; }
    .nav a { color: #94a3b8; text-decoration: none; padding: 5px 10px; border-radius: 4px; }
    .nav a:hover, .nav a.active { background: #334155; color: white; }
`;

function layout(title, content) {
    return `<!DOCTYPE html><html><head><title>${title}</title><style>${CSS}</style></head><body>
    <div class="container">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
            <h1>ICQ Server <span style="font-size:14px;color:#64748b;">v1.0</span></h1>
            <div>
                <a href="/" class="btn btn-primary">Registration</a>
                <a href="/admin" class="btn btn-danger">Admin Panel</a>
            </div>
        </div>
        ${content}
    </div></body></html>`;
}

// ═══════════════════════════════════════════
//  Admin Views
// ═══════════════════════════════════════════

async function adminDashboard() {
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
                <td>
                    <form method="POST" action="/admin/kick" style="display:inline">
                        <input type="hidden" name="uin" value="${uin}">
                        <button class="btn btn-danger">KICK</button>
                    </form>
                </td>
            </tr>`;
        }
    }

    if (!sessionRows) sessionRows = '<tr><td colspan="4" style="text-align:center;color:#64748b;">No users online</td></tr>';

    return `
        <div class="nav">
            <a href="/admin" class="active">Dashboard</a>
            <a href="/admin/users">All Users</a>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;">
            <div class="card" style="text-align:center;">
                <h2 style="font-size:36px;color:#34d399;margin:0;">${onlineCount}</h2>
                <span style="color:#94a3b8;">Online Users</span>
            </div>
            <div class="card" style="text-align:center;">
                <h2 style="font-size:36px;color:#38bdf8;margin:0;">${totalUsers}</h2>
                <span style="color:#94a3b8;">Registered Accounts</span>
            </div>
        </div>

        <div class="card">
            <h2>📢 System Broadcast</h2>
            <form method="POST" action="/admin/broadcast">
                <textarea name="message" rows="3" placeholder="Type a message to all online users..."></textarea>
                <div style="margin-top:10px;text-align:right;">
                    <button class="btn btn-primary">SEND</button>
                </div>
            </form>
        </div>

        <div class="card">
            <h2>🟢 Active Sessions</h2>
            <table>
                <thead><tr><th>UIN</th><th>IP</th><th>Status</th><th>Action</th></tr></thead>
                <tbody>${sessionRows}</tbody>
            </table>
        </div>
    `;
}

async function adminUsers() {
    const users = await db.all("SELECT * FROM users ORDER BY CAST(uin AS INTEGER)");
    let rows = users.map(u => `
        <tr>
            <td>${u.uin}</td>
            <td>${u.nickname || '-'}</td>
            <td>${u.email || '-'}</td>
            <td>
                <form method="POST" action="/admin/delete_user" style="display:inline" onsubmit="return confirm('Delete ${u.uin}?');">
                    <input type="hidden" name="uin" value="${u.uin}">
                    <button class="btn btn-danger">DEL</button>
                </form>
            </td>
        </tr>
    `).join('');

    return `
        <div class="nav">
            <a href="/admin">Dashboard</a>
            <a href="/admin/users" class="active">All Users</a>
        </div>
        <div class="card">
            <h2>👥 User Database</h2>
            <table>
                <thead><tr><th>UIN</th><th>Nickname</th><th>Email</th><th>Action</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
    `;
}

// ═══════════════════════════════════════════
//  Auth Middleware
// ═══════════════════════════════════════════

function checkAuth(req, res) {
    const auth = req.headers['authorization'];
    if (!auth) return false;

    const tmp = auth.split(' ');
    const buf = Buffer.from(tmp[1], 'base64');
    const plain = buf.toString();
    const [credsUser, credsPass] = plain.split(':');

    if (credsUser === config.ADMIN_USER && credsPass === config.ADMIN_PASS) {
        return true;
    }
    return false;
}

function requestAuth(res) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="ICQ Admin Panel"' });
    res.end('Access denied');
}

// ═══════════════════════════════════════════
//  Helpers
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

// ═══════════════════════════════════════════
//  Server
// ═══════════════════════════════════════════

async function startWeb(mainServer) {
    serverRef = mainServer;
    await db.init();

    const server = http.createServer(async (req, res) => {
        const u = url.parse(req.url, true);
        
        // ── Public Registration ──
        if (u.pathname === '/' || u.pathname === '/register') {
            // (Keep your existing registration code here if you want)
            // For brevity, I'm showing a simple redirect to admin or a placeholder
            if (req.method === 'GET') {
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(layout('ICQ Reg', '<div class="card"><h2>Public Registration</h2><p>Use the API or client to register.</p></div>'));
            }
            return;
        }

        // ── Admin Area ──
        if (u.pathname.startsWith('/admin')) {
            if (!checkAuth(req, res)) return requestAuth(res);

            if (req.method === 'GET') {
                let content = '';
                if (u.pathname === '/admin/users') content = await adminUsers();
                else content = await adminDashboard();
                
                res.writeHead(200, {'Content-Type': 'text/html'});
                res.end(layout('Admin Panel', content));
                return;
            }

            if (req.method === 'POST') {
                const data = await parseBody(req);

                // KICK USER
                if (u.pathname === '/admin/kick') {
                    const session = serverRef.sessions.get(data.uin);
                    if (session) {
                        session.disconnect();
                        console.log(`[ADMIN] Kicked ${data.uin}`);
                    }
                }

                // BROADCAST
                if (u.pathname === '/admin/broadcast') {
                    if (serverRef && data.message) {
                        serverRef.broadcast(data.message);
                        console.log(`[ADMIN] Broadcast: ${data.message}`);
                    }
                }

                // DELETE USER
                if (u.pathname === '/admin/delete_user') {
                    await db.run("DELETE FROM users WHERE uin = ?", [data.uin]);
                    await db.run("DELETE FROM ssi WHERE uin = ?", [data.uin]);
                    // Also kick if online
                    const session = serverRef.sessions.get(data.uin);
                    if (session) session.disconnect();
                    console.log(`[ADMIN] Deleted ${data.uin}`);
                }

                // Redirect back
                res.writeHead(302, { 'Location': req.headers.referer || '/admin' });
                res.end();
                return;
            }
        }

        res.writeHead(404);
        res.end('Not found');
    });

    server.listen(8080, () => {
        console.log(`\x1b[1mWEB\x1b[0m Admin Panel at http://localhost:8080/admin`);
    });
}

module.exports = { startWeb };
