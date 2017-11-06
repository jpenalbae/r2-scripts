/*
* This has been rewritten in a rush as the old promise api is no
* longer available. So code is a mess and a mix of sync and async,
* es5 and es6 progamming styles, etc...
*
* This code should be burned.
*/

'use strict';
var r2pipe = require ("r2pipe");

const encFunc = {
    start: 0,
    end: 0
}

const decFunc = {
    start: 0,
    end: 0
}


function decryptAddr(addr, len, start, end, callback)
{
    const bytes = info.bin.bits / 8;

    /* 32 bits */
    if ( bytes === 4) {
        r2.cmd('wv ' + addr + ' @ `aer?esp`+4');
        r2.cmd('wv ' + len  + ' @ `aer?esp`+8');
        r2.cmd('aer eip=' + start);
        r2.cmd('aecu ' + end);
        const res = r2.cmd('ps @ ' + addr);
        callback(res);

     /* 64 bits */
     } else if (bytes === 8) {
        r2.cmd('aer rdi=' + addr);
        r2.cmd('aer rsi=' + len);
        r2.cmd('aer rip=' + start);
        r2.cmd('aecu ' + end);
        const res = r2.cmd('ps @ ' + addr);
        callback(res);
     }
}


function findFlag(name) 
{
    for (var x = flags.length - 1; x >= 0; x--) {
        if (flags[x].name === name)
            return flags[x];
    };

    return null;
}


/* Shit to avoid async magic */
function printDaemonStrings(strings, pos, callback)
{
    /* Exit if there are no more elements in the array */
    if (!strings[pos]) {
        callback();
        return;
    }

    var str = strings[pos];
    decryptAddr(str.offset, str.size, encFunc.start, encFunc.end, function(res) {
        console.log('  - ' + res.replace('\n', ''));
        printDaemonStrings(strings, ++pos, callback);
    });

}


function decodeDaemon(callback)
{
    var daemonname = [];
    var dF = findFlag('obj.daemonname');

    /* Split the daemonflag symbol */
    let res = r2.cmdj('pcj ' + dF.size + '@ obj.daemonname')
    let start = dF.offset;
    let size = 0;
    let isString = true;

    for (var x = 0; x < res.length; x++) {

        if ((res[x] === 0) && isString) {
            daemonname.push( { offset: start, size: size } );
            isString = false;
        } else if ((res[x] !== 0) && (!isString)) {
            start = dF.offset + x;
            isString = true;
            size = 0;
        }

        size++;
    };

    console.log('[+] daemonname');
    printDaemonStrings(daemonname, 0, function() { callback(); })

}


/* Main code */
const r2 = r2pipe.pipeSync(process.argv[2]);

r2.cmd('aei');
r2.cmd('e io.cache=true');
r2.cmd('aer esp=0x00108000');
r2.cmd('aer rsp=0x00108000');

let info = r2.cmdj('ij');
let flags = r2.cmdj('fj');

r2.cmd('af @ sym.encrypt_code');
r2.cmd('af @ sym.decrypt_remotestr');

let tmpres =  r2.cmdj('pdfj @ sym.encrypt_code');
encFunc.start = tmpres.ops[0].offset;
encFunc.end = tmpres.ops[tmpres.ops.length-1].offset;

tmpres = r2.cmdj('pdfj @ sym.decrypt_remotestr');
//let encAddr = findFlag('sym.encrypt_code').offset.toString(16);
decFunc.start = tmpres.ops[0].offset;
for (var x = 0; x < tmpres.ops.length; x++) {
    if (tmpres.ops[x].opcode.indexOf('sym.encrypt_code') !== -1) {
        decFunc.end = tmpres.ops[x+1].offset;
        break;
    }
};

decodeDaemon(function() {
    const remotestr = findFlag('obj.remotestr');

    decryptAddr(remotestr.offset, 0, decFunc.start, decFunc.end, function(res) {
        console.log('\n[+] remotestr');
        var addresses = res.split('|');
        for (var i = 0; i < addresses.length; i++) {
            console.log('  - ' + addresses[i]);
        };
        r2.quit();
    });
});
