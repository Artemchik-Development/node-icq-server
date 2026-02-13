const config = require('./config');

function hexDump(data, prefix = '') {
    if (!config.DEBUG_PACKETS) return;

    const width = 16;
    let lines = [];
    
    for (let i = 0; i < data.length; i += width) {
        const chunk = data.slice(i, i + width);
        
        // Hex part
        const hex = [];
        for (let j = 0; j < width; j++) {
            if (j < chunk.length) {
                hex.push(chunk[j].toString(16).padStart(2, '0').toUpperCase());
            } else {
                hex.push('  ');
            }
        }
        
        // ASCII part
        let ascii = '';
        for (const byte of chunk) {
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        }

        lines.push(`${i.toString(16).padStart(4, '0')}  ${hex.join(' ')}  |${ascii}|`);
    }

    console.log(prefix);
    console.log(lines.join('\n'));
    console.log('-'.repeat(60));
}

module.exports = { hexDump };