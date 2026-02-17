const net = require('net');
const crypto = require('crypto');
const config = require('./config');
const db = require('./database');
const { hexDump } = require('./utils');
const Auth = require('./auth');
const BOS = require('./bos');
const { makeFLAP, makeSNAC, parseTLVs, OscarBuilder, FLAP_MAGIC, HEADER_SIZE } = require('./oscar');

const sessions = new Map();

// ═══════════════════════════════════════════
//  Session Class
// ═══════════════════════════════════════════

class Session {
    constructor(socket, type) {
        this.socket = socket;
        this.type = type; // 'AUTH' or 'BOS'
        this.buffer = Buffer.alloc(0);
        this.seq = 0;
        this.uin = null;
        this.status = 0;
        this.signonTime = 0;
        this.profile = '';
        this.awayMsg = '';
        this.watching = new Set();
        this.userTLVs = new Map();
    }

    initDefaults() {
        // Basic user info
        this.userTLVs.set(0x0001, Buffer.from([0x00, 0x40])); // Class: ICQ
        this.userTLVs.set(0x0006, Buffer.from([0x00, 0x00, 0x00, 0x00])); // Status: Online
        
        const tBuf = Buffer.alloc(4);
        tBuf.writeUInt32BE(this.signonTime);
        this.userTLVs.set(0x0003, tBuf); // Signon time

        // Capabilities (Typing, UTF8, etc)
        this.userTLVs.set(0x000D, Buffer.concat([
            Buffer.from('094613494C7F11D18222444553540000', 'hex'), // SRV_RELAY
            Buffer.from('0946134E4C7F11D18222444553540000', 'hex'), // UTF-8
        ]));

        // DC Info (Internal IP)
        const dc = Buffer.alloc(37);
        dc.writeUInt32BE(0x7F000001, 0);  // 127.0.0.1
        dc.writeUInt8(0x04, 8);
        dc.writeUInt16BE(0x000A, 9);
        this.userTLVs.set(0x000C, dc);
    }

    sendFLAP(channel, data) {
        this.seq = (this.seq + 1) & 0xFFFF;
        const packet = makeFLAP(channel, this.seq, data || Buffer.alloc(0));
        hexDump(packet, `→ OUT [${this.type}] ${this.uin || ''}`);
        try { this.socket.write(packet); } catch (e) {}
    }

    sendSNAC(fam, sub, flags, reqId, data) {
        this.sendFLAP(0x02, makeSNAC(fam, sub, flags, reqId, data || Buffer.alloc(0)));
    }

    disconnect() {
        try {
            this.sendFLAP(0x04, Buffer.alloc(0));
            this.socket.end();
        } catch (e) {}
    }
}

// ═══════════════════════════════════════════
//  FLAP Handler
// ═══════════════════════════════════════════

async function handleFLAP(session, channel, data) {

    // ── Channel 1: Hello / Auth ──
    if (channel === 0x01) {

        if (session.type === 'AUTH') {
            if (data.length <= 4) {
                console.log(`\x1b[33m[AUTH]\x1b[0m BUCP handshake`);
                return;
            }

            const tlvs = parseTLVs(data.subarray(4));
            const uinTlv = tlvs[0x0001];
            const hasPass = tlvs[0x0002] || tlvs[0x0025];

            // Old-style Login OR Registration (Channel 1)
            if (uinTlv && hasPass) {
                const uin = uinTlv.toString().trim();

                // Empty UIN = Registration Request
                if (!uin || uin.length === 0) {
                    console.log(`\x1b[35m[AUTH]\x1b[0m Empty UIN → Registration`);
                    await Auth.handleChannel1Registration(session, tlvs);
                    return;
                }

                // Normal Login
                console.log(`\x1b[33m[AUTH]\x1b[0m Old-style login: ${uin}`);
                const valid = await Auth.checkCredentials(uin, tlvs);

                if (valid) {
                    console.log(`\x1b[32m[AUTH OK]\x1b[0m ${uin} → BOS`);
                    const cookie = crypto.randomBytes(256);
                    Auth.pendingCookies.set(cookie.toString('hex'), uin);
                    
                    const resp = new OscarBuilder()
                        .tlv(0x0001, uin)
                        .tlv(0x0005, `${config.BOS_ADDRESS}:${config.BOS_PORT}`)
                        .tlv(0x0006, cookie);
                    
                    session.sendFLAP(0x04, resp.build());
                    session.socket.end();
                } else {
                    console.log(`\x1b[31m[AUTH FAIL]\x1b[0m ${uin}`);
                    const errBuf = Buffer.alloc(2);
                    errBuf.writeUInt16BE(0x0005); // Invalid password
                    
                    const resp = new OscarBuilder()
                        .tlv(0x0001, uin)
                        .tlv(0x0004, 'http://icq.com/')
                        .tlv(0x0008, errBuf);
                    
                    session.sendFLAP(0x04, resp.build());
                    session.socket.end();
                }
                return;
            }

            if (uinTlv) {
                console.log(`\x1b[33m[AUTH]\x1b[0m BUCP client ${uinTlv.toString()}`);
            }
            return;
        }

        // BOS Connection
        if (session.type === 'BOS') {
            if (data.length <= 4) return;
            const tlvs = parseTLVs(data.subarray(4));
            const cookieTlv = tlvs[0x0006];
            
            if (!cookieTlv) { session.disconnect(); return; }

            const uin = Auth.pendingCookies.get(cookieTlv.toString('hex'));
            if (!uin) {
                console.log(`\x1b[31m[BOS]\x1b[0m Invalid cookie`);
                session.disconnect();
                return;
            }

            Auth.pendingCookies.delete(cookieTlv.toString('hex'));

            // Kick old session
            const old = sessions.get(uin);
            if (old) { try { old.disconnect(); } catch (e) {} sessions.delete(uin); }

            // Init session
            session.uin = uin;
            session.signonTime = Math.floor(Date.now() / 1000);
            session.initDefaults();
            sessions.set(uin, session);

            // Load watching from SSI
            const ssibuddies = await db.getSSIBuddies(uin);
            for (const b of ssibuddies) session.watching.add(b.name);

            console.log(`\x1b[32m[BOS]\x1b[0m ${uin} ONLINE (${sessions.size} users)`);

            // Send supported families
            const fam = new OscarBuilder();
            [0x0001, 0x0002, 0x0003, 0x0004, 0x0009, 0x0013, 0x0015].forEach(f => fam.u16(f));
            session.sendSNAC(0x0001, 0x0003, 0, 0, fam.build());

            // MOTD
            session.sendSNAC(0x0001, 0x0013, 0, 0,
                new OscarBuilder().u16(1).tlv(0x000B, 'Welcome to NodeICQ!').build());
        }
    }

    // ── Channel 2: SNAC Data ──
    else if (channel === 0x02) {
        if (data.length < 10) return;
        
        const snac = {
            family:  data.readUInt16BE(0),
            subtype: data.readUInt16BE(2),
            flags:   data.readUInt16BE(4),
            reqId:   data.readUInt32BE(6),
            data:    data.subarray(10)
        };

        if (session.type === 'AUTH') {
            await Auth.handlePacket(session, snac);
        } else if (session.type === 'BOS' && session.uin) {
            await BOS.handlePacket(session, snac, { sessions });
        }
    }
}

// ═══════════════════════════════════════════
//  TCP Server Factory
// ═══════════════════════════════════════════

function createServer(type, port) {
    net.createServer(socket => {
        const session = new Session(socket, type);
        const addr = `${socket.remoteAddress}:${socket.remotePort}`;
        console.log(`[${type}] Connection from ${addr}`);

        // IMPORTANT: Send Hello first!
        session.sendFLAP(0x01, Buffer.from([0x00, 0x00, 0x00, 0x01]));

        socket.on('data', async chunk => {
            hexDump(chunk, `← IN  [${type}] ${session.uin || addr}`);
            session.buffer = Buffer.concat([session.buffer, chunk]);

            while (session.buffer.length >= HEADER_SIZE) {
                if (session.buffer[0] !== FLAP_MAGIC) {
                    console.log(`\x1b[31mBad FLAP magic\x1b[0m`);
                    socket.destroy();
                    return;
                }

                const dataLen = session.buffer.readUInt16BE(4);
                const totalLen = HEADER_SIZE + dataLen;
                if (session.buffer.length < totalLen) break;

                const chan = session.buffer[1];
                const frameData = Buffer.from(session.buffer.subarray(HEADER_SIZE, totalLen));
                session.buffer = session.buffer.subarray(totalLen);

                try {
                    await handleFLAP(session, chan, frameData);
                } catch (e) {
                    console.error(`\x1b[31m[ERROR]\x1b[0m`, e.stack || e);
                }
            }
        });

        socket.on('error', () => {});
        socket.on('close', async () => {
            if (session.uin && sessions.get(session.uin) === session) {
                sessions.delete(session.uin);
                console.log(`\x1b[31m[OFFLINE]\x1b[0m ${session.uin} (${sessions.size} online)`);
                try { await BOS.notifyWatchers(session, sessions, false); } catch (e) {}
            }
        });

    }).listen(port, config.HOST, () => {
        console.log(`\x1b[1m${type}\x1b[0m server on port ${port}`);
    });
}

// ═══════════════════════════════════════════
//  Main Entry Point
// ═══════════════════════════════════════════

// Server Context for Web Admin Panel
const ServerContext = {
    sessions: sessions,
    
    // Broadcast message to all online BOS users
    broadcast: (text) => {
        const pkt = BOS.buildIncomingMsg("System", text, Date.now()/1000);
        let count = 0;
        for (const session of sessions.values()) {
            if (session.type === 'BOS') {
                session.sendSNAC(0x0004, 0x0007, 0, 0, pkt);
                count++;
            }
        }
        return count;
    }
};

(async () => {
    // 1. Init Database
    await db.init();

    // 2. Start TCP Servers
    createServer('AUTH', config.AUTH_PORT);
    createServer('BOS',  config.BOS_PORT);

    // 3. Start Web Server (with admin panel)
    try {
        const { startWeb } = require('./web');
        await startWeb(ServerContext);
    } catch (e) {
        console.log(`\x1b[90m[WEB]\x1b[0m Web server disabled: ${e.message}`);
    }

    // 4. Log Config
    const regStatus = config.REGISTRATION_ENABLED ? '\x1b[32mON\x1b[0m' : '\x1b[31mOFF\x1b[0m';
    console.log(`\nRegistration: ${regStatus} (Range: ${config.UIN_MIN}-${config.UIN_MAX})`);
    console.log(`Admin Panel:  http://localhost:8080/admin`);
    console.log(`\nReady to serve.\n`);
})();
