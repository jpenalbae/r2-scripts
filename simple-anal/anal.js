var r2pipe = require('r2pipe');


if (!process.argv[2]) {
    console.error('You must supply a file to analize');
    process.exit(1);
}

var file = process.argv[2];


var r2 = r2pipe.pipeSync(file)
console.log('===================================');
console.log('              IMPORTS');
console.log('===================================');
console.log(r2.syscmdj('rabin2 -j -i ' + file));

console.log('===================================');
console.log('              STRINGS');
console.log('===================================');
console.log(r2.syscmdj('rabin2 -j -zz ' + file));

console.log('===================================');
console.log('              SECTIONS');
console.log('===================================');
console.log(r2.syscmdj('rabin2 -j -S ' + file));

console.log('===================================');
console.log('              SYMBOLS');
console.log('===================================');
console.log(r2.syscmdj('rabin2 -j -s ' + file));

r2.quit();