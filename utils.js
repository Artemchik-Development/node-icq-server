const config = require('./config');

function hexDump(data, prefix = '') {
    if (!config.DEBUG_PACKETS) return;
    if (!data || data.length === 0) return;

    const width = 16;
    let lines = [];
    
    // Красивый заголовок
    console.log(`\x1b[36m${prefix}\x1b[0m (Len: ${data.length})`);

    for (let i = 0; i < data.length; i += width) {
        const chunk = data.subarray(i, i + width);
        
        // Hex часть
        const hex = [];
        for (let j = 0; j < width; j++) {
            if (j < chunk.length) {
                hex.push(chunk[j].toString(16).padStart(2, '0').toUpperCase());
            } else {
                hex.push('  ');
            }
        }
        
        // ASCII часть
        let ascii = '';
        for (const byte of chunk) {
            // Печатные символы
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        }

        lines.push(`  ${i.toString(16).padStart(4, '0')}  ${hex.join(' ')}  |${ascii}|`);
    }

    console.log(lines.join('\n'));
    console.log('\x1b[90m' + '-'.repeat(60) + '\x1b[0m');
}

module.exports = { hexDump };