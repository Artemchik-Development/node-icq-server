module.exports = {
    HOST: '0.0.0.0',
    AUTH_PORT: 5190,
    BOS_PORT: 5191,
    BOS_ADDRESS: '0.0.0.0',
    DB_PATH: './icq.db',
    DEBUG_PACKETS: process.env.DEBUG_PACKETS === 'true',

    REGISTRATION_ENABLED: true,
    UIN_MIN: 100000,
    UIN_MAX: 999999,

    // ═══════════════════════════════════════
    //  Admin Panel Config
    // ═══════════════════════════════════════
    ADMIN_USER: 'admin',
    ADMIN_PASS: process.env.ADMIN_PASS || 'CHANGE_ME',
};