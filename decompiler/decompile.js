#!/usr/bin/env node

var retdec = require('retdec').apiKey('YOUR_API_KEY_HERE');
var r2pipe = require('r2pipe');


function findFlag(name) 
{
    for (var x = flags.length - 1; x >= 0; x--) {
        if (flags[x].name === name)
            return flags[x];
    };

    return null;
}


function findFunction(code)
{
    var split = code.split('\n');
    var pattern = 'void function_'+ foffset +'(void) {';
    var found = false;

    console.log(code);

    for (var x = 0; x < split.length; x++) {

        /* Search for function start */
        if (split[x].indexOf(pattern) !== -1)
            found = true;


        /* Print till end of function */
        if (found) {
            console.log(split[x]);
            if (split[x] === '}')
                break;
        }

    }

    if (!found)
        console.log("Function not found. Sorry :(");
}


function decompile()
{
    retdec.decompile(filename, 'bin', {decomp_var_names: 'simple'} , function(err, res) {
        if (err) {
            console.log('Error (' + err + '): ' + res);
            r2.quit();
            return;
        }

        //findFunction(res.hll.toString());
        console.log(res.hll.toString());
        r2.quit();
    });
}



// if (process.argv.length !== 3) {
//     console.log('You must suply a function offset');
//     return 0;
// }

// var foffset;
// if (process.argv[2].indexOf('sym.') === 0)
//     foffset = process.argv[2].substr(4, process.argv[2].length);
// else
//     foffset = findFlag(process.argv[2]).offset.toString(16);


var r2 = r2pipe.lpipeSync();
var filename = r2.cmdj('oj')[0].uri;
var flags = r2.cmdj('fj');


console.log('Please wait for decompilation to finish....\n');
decompile();

