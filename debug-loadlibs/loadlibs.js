#!/usr/bin/env node
'use strict';

const r2pipe = require('r2pipe');
const r2 = r2pipe.lpipeSync();


function createFlags(entry) {
   let symbols;

   try {
      symbols = r2.syscmdj('rabin2 -j -s ' + entry.file);
   } catch (e) {
      console.log('Could not open file.');
      return;
   }

   symbols.symbols.forEach(function(symbol) {
      let offset = symbol.vaddr + entry.addr;
      let name = 'lib.' + symbol.flagname;

      if ((symbol.type === 'FUNC') || (symbol.type === 'OBJECT'))
         r2.cmd('f ' + name + ' ' + offset + ' ' + symbol.size);

      if ((symbol.type === 'FUNC') && (symbol.size > 0))
         r2.cmd('af+ ' + offset + ' ' + symbol.size + ' ' + name);
   });
}


/* Sanity check */
try {
   r2.cmd('?V');
} catch (e) {
   console.log('This script must be run from inside a r2 session');
   process.exit(1);
}

/* Get memory map */
const memmap = r2.cmdj('dmj');
if (memmap.length === 0) {
   console.log('Memory map is empty. Maybe you forgot to start r2 with -d');
   return;
}

/* Check every memory map entry */
let x;
for (x=1; x<memmap.length; x++) {

   if (memmap[x].perm.indexOf('x') === -1)
      continue;
   if (memmap[x].file.match(/^\/.*\.so$/) === null)
      continue;

   console.log('Loading symbols for: ' + memmap[x].file);
   createFlags(memmap[x]);
}

return 0;
