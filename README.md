# node-icq-server
A self-hostable ICQ server.

## Features

### Core Protocol
- **Dual Authentication** — MD5 (BUCP) + XOR Roasting
- **FLAP/SNAC/TLV** — Full binary protocol implementation
- **Rate Limiting** — Proper rate response for strict clients

### Messaging
- **Channel 1** — Plain text messages (ASCII, UTF-8, UTF-16, CP1251)
- **Channel 2** — Rendezvous / Extended messages
- **Channel 4** — Old-style ICQ messages
- **Message ACK** — Server acknowledgement support

### Contacts & Presence
- **SSI (Server-Side Information)** — Full contact list management
  - Add / Update / Delete contacts and groups
  - Persistent storage in SQLite
  - SSI Activate handling
  - SSI Check with "no changes" optimization
- **Buddy Statuses** — Real-time online/offline notifications
- **Standard Statuses** — Online, Away, DND, NA, Occupied, Free for Chat, Invisible
- **X-Statuses** — Angry, Depression, At Home, At Work, etc.
- **Extended Statuses** — Mood, status notes via BART (TLV 0x001D)
- **Capabilities** — Full TLV passthrough for client compatibility





## Client Compatibility

| Client | Version | Auth Method | Status |
|--------|---------|-------------|--------|
| **QIP 2005** | Build 8095+ | XOR (Roasted) | ✅ Full |
| **QIP Infium** | 9040+ | MD5 (BUCP) | ✅ Full |
| **Pidgin** | Any | MD5 | ✅ Full |
| **Jimm** | Any | MD5 | ✅ Full |
| **QIP 2012**| Any | MD5| ✅ Full |

### Installation

```bash
git clone https://github.com/Artemchik-Development/node-icq-server.git
cd node-icq-server
npm install
node server.js
```
## User registration
```
# Basic registration
node database.js add 1000 password

# Full registration with details
node database.js add 1000 mypass Alice Alice Smith alice@mail.com

# List all users
node database.js list

# Search users
node database.js search Alice

# Delete user
node database.js del 1000
```

<div align="center">

Made with ❤️ for the ICQ community

