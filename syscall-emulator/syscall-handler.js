"use strict";

var r2pipe = require('r2pipe');
var r2 = r2pipe.openSync();



function handleSyscall () {
	let regs = r2.cmdj('arj');
	switch (regs.eax)	{
		case 4: 		// sys_write
			let len = regs.edx;
			let fd = regs.ebx;
			let buf = new Buffer(r2.cmdj('p8j ' + len + ' @ ' + regs.ecx));
			console.log('[SYSCALL] write() - fd: ' + fd + ' buf: ' + buf);
			break;
		case 1:  	// sys_exit
			let code = regs.ebx;
			let r2pid = parseInt(r2.cmd('?v $p'));
			console.log('[SYSCALL] exit() - code: ' + code);
			// process.kill(r2pid, 'SIGINT');
			// For now there is no way to stop ESIL from r2pipe
			break;
	}
}


const int = parseInt(process.argv[2]);

if (int === 0x80){
	handleSyscall();
} else {
	console.error('Unhandled interrupt code: ' + int);
	process.exit(0);
}

