#!/usr/bin/env node

var retdec = require('retdec').apiKey('YOUR_API_KEY_KEY_HERE');
var r2pipe = require('r2pipe');
var parseArgs = require('minimist');


var decopts = {};


function printHelp()
{
    console.log('\nUsage: $decompile [-achs] [-n naming] @ addr');
    console.log('  -a: disable selective decompilation (decompile the hole file)');
    console.log('  -c: clear comments');
    console.log('  -s: silent. Do not display messages');
    console.log('  -h: displays this help menu');
    console.log('  -n naming: select variable naming');
    console.log('');
    console.log('Where valid variable namings are:');
    console.log('  readable: Tries to produce as meaningful variable names as possible');
    console.log('  address: Variables are named by their addresses in the binary file');
    console.log('  hungarian: Prefix variables with their type');
    console.log('  simple: Name variables simply by assigning fruit names');
    console.log('  unified: Globals, locals and parameters are named just gX, vX and aX');
    console.log('');
    console.log('**********************************************************************');
    console.log('     This will upload the binary being analyzed to retdec.com !!!');
    console.log('                       You have been warned...');
    console.log('**********************************************************************\n');
}


function decompile(options)
{
    retdec.decompile(filename, 'bin', options , function(err, res) {
        if (err) {
            console.log('Error (' + err + '): ' + res);
            r2.quit();
            return;
        }

        var output = res.hll.toString();

        /* Args: Remove comments */
        if (args.c)
            output = output.replace(/^\/.*$\n\n?/mig, '');

        console.log(output);
        r2.quit();
    });
}


/* Start r2pipe, get filename and current position */
var r2 = r2pipe.lpipeSync();
var filename = r2.cmdj('oj')[0].uri;
var fname = r2.cmd('s');


/* Parse arguments */
var args = parseArgs(process.argv.slice(2));

/* Args: help */
if (args.h) {
    printHelp();
    process.exit(0);    
}

/* Args: Selective decompilation */
if (!args.a) {
    var fcn = r2.cmdj('pdfj @ ' + fname);
    if (fcn === null) {
        console.error('R2 cannot find function at ' + fname);
        console.error('Try aa/aac or af before running this script');
        process.exit(1);
    }

    var startAddr = '0x' + fcn.ops[0].offset.toString(16);
    var endAddr = '0x' + fcn.ops[fcn.ops.length-1].offset.toString(16);
    if (!args.s) {
        console.log("Start: " + startAddr);
        console.log("End: " + endAddr);
    }
    decopts['sel_decomp_ranges'] = startAddr + '-' + endAddr;
}

/* Args: var naming */
if (args.n)
    decopts['decomp_var_names'] = args.n;


/* Do the decompilation */
if (!args.s) {
    console.log('Uploading binary to retdec.com');
    console.log('Please wait for decompilation to finish....\n');
}
decompile(decopts);

