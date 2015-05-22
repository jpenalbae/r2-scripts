#!/usr/bin/env node

var r2pipe = require('r2pipe');
var util = require('util');

var pendingSyscalls = 0;
var syscalls = null;
var r2 = null;


function syscallName(num) {
    for (var x = 0; x < syscalls.length; x++) {
        if (syscalls[x].num == num)
            return syscalls[x].name;
    };
}

function commentSyscall(num, offset) {
    /* Resolve syscall */
    var scNum = parseInt(num, 16);
    var scName = syscallName(scNum);
    console.log(' - found Syscall: ' + scName);

    /* Set the commet */
    var cmd = 'CC LINUX - sys_' + scName + ' @' + offset;
    pendingSyscalls++;
    r2.cmd(cmd, function (res) {
        pendingSyscalls--;
        if (!pendingSyscalls)
            r2.quit();
    });
}


function analFunction(funcData) {
    //console.log(' - Analizing function: ' + funcData.name);

    r2.cmdj('pdfj @' + funcData.name, function(res) {
        for (var x = res.ops.length - 1; x >= 0; x--) {

            /* search for int 0x80*/
            if (res.ops[x].bytes === 'cd80') {

                /* Seach for syscall number */
                for (var i = x - 1; i >= 0; i--) {

                    /* Exit if we find another syscall */
                    if (res.ops[i].bytes === 'cd80')
                        break;

                    /* Ignore non mov opcodes */
                    if (res.ops[i].type !== 'mov')
                        continue;

                    if (res.ops[i].opcode.match(/ eax,| ax,| al,/) !== null) {
                        var num = res.ops[i].opcode.split(',')[1].trim();

                        /* Reject non valid hex */
                        if (num.match(/^[x0-9a-f]+$/) === null)
                            continue;

                        commentSyscall(num, res.ops[x].offset);
                    }
                };
            }
        };
    });
}



r2pipe.rlangpipe(function (or2) {
    r2 = or2;
    console.log('Analizing file');

    // Analyze binary
    r2.cmdj('aa', function (res) {
        console.log('Analysis finished');

        // Get syscalls
        r2.cmdj('asj', function(sc) {
            syscalls = sc;

            // List functions
            r2.cmdj('aflj', function (res) {
                console.log('Searching for syscalls');
                res.forEach(analFunction);
            });
        });
    });

});


