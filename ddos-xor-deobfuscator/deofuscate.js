
var r2pipe = require ("r2pipe");

var r2 = null;

var flags = null;
var info = null;

var encFunc = {
    start: 0,
    end: 0
}

var decFunc = {
    start: 0,
    end: 0
}


function decryptAddr(addr, len, start, end, callback)
{
    var bytes = info.bin.bits / 8;

    /* 32 bits */
    if ( bytes === 4) {
        r2.promise(r2.cmd, 'wv ' + addr + ' @ `aer?esp`+4', null)
             .then(r2.cmd, 'wv ' + len  + ' @ `aer?esp`+8', null)
             .then(r2.cmd, 'aer eip=' + start, null)
             .then(r2.cmd, 'aecu ' + end, null)
             .then(r2.cmd, 'ps @ ' + addr, function(res) { 
                callback(res);
             });

     /* 64 bits */
     } else if (bytes === 8) {
        r2.promise(r2.cmd, 'aer rdi=' + addr, null)
             .then(r2.cmd, 'aer rsi=' + len, null)
             .then(r2.cmd, 'aer rip=' + start, null)
             .then(r2.cmd, 'aecu ' + end, null)
             .then(r2.cmd, 'ps @ ' + addr, function(res) { 
                callback(res);
             });
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
    r2.cmdj('pcj ' + dF.size + '@ obj.daemonname' , function(res) {
        var start = dF.offset;
        var size = 0;
        var isString = true;

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
        

    });   
}



/* Main code */
r2pipe.pipe (process.argv[2], function (or2) {
    r2 = or2;

    /* Initialise radare */
    r2.promise(r2.cmd, 'aei', null)
        .then(r2.cmd,  'aeim', null)
        .then(r2.cmd,  'e io.cache=true', null)
        .then(r2.cmd,  'aer esp=0x00108000', null)
        .then(r2.cmd,  'aer rsp=0x00108000', null)
        .then(r2.cmdj, 'ij', function(data) { info = data; })
        .then(r2.cmdj, 'fj', function(data) {  flags = data; })
        .then(r2.cmd,  'af @ sym.encrypt_code', null)
        .then(r2.cmd,  'af @ sym.decrypt_remotestr', null)
        .then(r2.cmdj, 'pdfj @ sym.encrypt_code', function(data) {
            encFunc.start = data.ops[0].offset;
            encFunc.end = data.ops[data.ops.length-1].offset;
        })
        .then(r2.cmdj, 'pdfj @ sym.decrypt_remotestr', function(data) {

            var encAddr = findFlag('sym.encrypt_code').offset.toString(16);
            decFunc.start = data.ops[0].offset;

            for (var x = 0; x < data.ops.length; x++) {
                if (data.ops[x].opcode.indexOf(encAddr) !== -1) {
                    decFunc.end = data.ops[x+1].offset;
                    break;
                }
            };
        })

        /* Start decrypting */
        .done(function() {
            decodeDaemon(function() {
                var remotestr = findFlag('obj.remotestr');
                decryptAddr(remotestr.offset, 0, decFunc.start, decFunc.end, function(res) {
                    console.log('\n[+] remotestr');
                    var addresses = res.split('|');
                    for (var i = 0; i < addresses.length; i++) {
                        console.log('  - ' + addresses[i]);
                    };
                    r2.quit();
                });
            });
        });

});
