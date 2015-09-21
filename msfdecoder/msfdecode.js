#!/usr/bin/env node
"use strict";

var fs = require('fs');
var r2pipe = require('r2pipe');


const maxSteps = 50000;
const file = process.argv[2];
const dumpFile = process.argv[3];


function dumpShellcode(start) {
    r2.cmd('e asm.comments=false');
    r2.cmd('e asm.lines=false');
    r2.cmd('e asm.flags=false');

    let end = r2.cmdj('oj')[0].size;
    let dissas = r2.cmd('pD ' + (end-start) + ' @ ' + start);
    let raw = new Buffer(r2.cmdj('p8j ' + (end-start) + ' @ ' + start));
    fs.writeFileSync(dumpFile, raw);

    console.log(dissas);
}


function decode () {
    let cop, regs;
    let steps = 0;
    let lastFpu = 0;
    let lastLoop = 0;

    for (;;) {
        cop = r2.cmdj('pdj 1 @ eip')[0];
        regs = r2.cmdj('arj');

        /* Check for end of shellcode or invalid opcode */
        if (cop.type === 'invalid') {
            dumpShellcode(lastLoop);
            return;
        }

        /* Emulate fpu opcodes */
        if ((cop.opcode.indexOf('f') === 0) && (cop.bytes.indexOf('d') === 0)) {
            if (cop.opcode.indexOf('fnstenv') === 0)
                r2.cmd('wv ' + lastFpu + ' @ esp');
            else
                lastFpu = cop.offset;
        }
        
        /* Check for end of loop opcodes */
        if ((cop.opcode.indexOf('loop') === 0) && (regs.ecx <= 1)) {
            //console.log('End loop');
            //let shellcode = r2.cmd('pd 30 @ eip+2');
            //console.log(shellcode);
            lastLoop = cop.offset+2;
        }

        r2.cmd('aes');

        /* Limit the steps to avoid infinite loops */
        steps++;
        if (steps >= maxSteps) {
            console.error("Maximum steps reached. Exiting.");
            break;
        }
    }

}


if (process.argv.length != 4) {
    console.log('Usage: node msfdecode.js [encodedfile] [outputfile]');
    return;
}

var r2 = r2pipe.pipeSync(file);

/* Setup ESIL VM */
r2.cmd('e io.cache=true');
r2.cmd('e asm.bits=32');
r2.cmd('aei');
r2.cmd('aeim');
r2.cmd('aer esp=0x00108000');
r2.cmd('.ar*');

/* Start the emulation */
decode();

r2.quit();