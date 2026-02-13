const FLAP_MAGIC = 0x2A;
const HEADER_SIZE = 6;

class OscarBuilder {
    constructor() { this.buffers = []; }

    u8(val) {
        const b = Buffer.alloc(1);
        b.writeUInt8(val);
        this.buffers.push(b);
        return this;
    }

    u16(val) {
        const b = Buffer.alloc(2);
        b.writeUInt16BE(val);
        this.buffers.push(b);
        return this;
    }

    u32(val) {
        const b = Buffer.alloc(4);
        b.writeUInt32BE(val);
        this.buffers.push(b);
        return this;
    }

    string(str, encoding = 'utf8') {
        if (!str) return this;
        this.buffers.push(Buffer.isBuffer(str) ? str : Buffer.from(str, encoding));
        return this;
    }

    raw(data) {
        if (!data) return this;
        if (Buffer.isBuffer(data)) {
            this.buffers.push(data);
        } else if (data instanceof Uint8Array) {
            this.buffers.push(Buffer.from(data));
        }
        // Игнорируем невалидные типы
        return this;
    }

    // TLV: поддержка string, number, Buffer, пустой
    tlv(type, value) {
        let valBuf;

        if (value === undefined || value === null) {
            valBuf = Buffer.alloc(0);
        } else if (Buffer.isBuffer(value)) {
            valBuf = value;
        } else if (typeof value === 'string') {
            valBuf = Buffer.from(value, 'utf8');
        } else if (typeof value === 'number') {
            // Автоопределение: <= 0xFFFF → 2 байта, иначе 4
            if (value <= 0xFFFF) {
                valBuf = Buffer.alloc(2);
                valBuf.writeUInt16BE(value);
            } else {
                valBuf = Buffer.alloc(4);
                valBuf.writeUInt32BE(value);
            }
        } else if (value instanceof Uint8Array) {
            valBuf = Buffer.from(value);
        } else {
            valBuf = Buffer.alloc(0);
        }

        const header = Buffer.alloc(4);
        header.writeUInt16BE(type, 0);
        header.writeUInt16BE(valBuf.length, 2);
        this.buffers.push(header);
        if (valBuf.length > 0) this.buffers.push(valBuf);

        return this;
    }

    build() {
        // Защита: фильтруем только валидные буферы
        const valid = this.buffers.filter(b => Buffer.isBuffer(b));
        return Buffer.concat(valid);
    }
}

function parseTLVs(buffer) {
    const tlvs = {};
    let pos = 0;
    while (pos + 4 <= buffer.length) {
        const type = buffer.readUInt16BE(pos);
        const len = buffer.readUInt16BE(pos + 2);
        pos += 4;
        if (pos + len > buffer.length) break;
        tlvs[type] = buffer.subarray(pos, pos + len);
        pos += len;
    }
    return tlvs;
}

function makeSNAC(family, subtype, flags, reqId, data) {
    const header = Buffer.alloc(10);
    header.writeUInt16BE(family, 0);
    header.writeUInt16BE(subtype, 2);
    header.writeUInt16BE(flags, 4);
    header.writeUInt32BE(reqId, 6);
    if (!data || data.length === 0) return header;
    return Buffer.concat([header, data]);
}

function makeFLAP(channel, seq, data) {
    const header = Buffer.alloc(6);
    header.writeUInt8(FLAP_MAGIC, 0);
    header.writeUInt8(channel, 1);
    header.writeUInt16BE(seq, 2);
    header.writeUInt16BE(data ? data.length : 0, 4);
    if (!data || data.length === 0) return header;
    return Buffer.concat([header, data]);
}

module.exports = { OscarBuilder, parseTLVs, makeSNAC, makeFLAP, FLAP_MAGIC, HEADER_SIZE };