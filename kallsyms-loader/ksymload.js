var fs = require('fs');
var r2 = require('r2pipe').lpipeSync();


// Check args
if (process.argv.length !== 3) {
    console.log('Usage: ksymload.js kallsym_file');
    process.exit(1);
}

// Read kallsym file
var kallsym = fs.readFileSync(process.argv[2]).toString();


// Change to symbols flagspace
r2.cmd('fs symbols');

// Traverse kallsym entries
var entry, data;
var lines = kallsym.split('\n');

for (var x = 0; x < lines.length; x++) {
    entry = lines[x];
    data  = entry.split(' ');

    // Skip modules
    if (entry[entry.length-1] === ']')
        continue;

    // Skip absolute entries
    if (data[1] === 'A')
        continue;

    // Create a new flag in radare2
    r2.cmd('f sym.' + data[2] +' @ 0x' + data[0]);
}

// Return to general flagspace
r2.cmd('fs *');
