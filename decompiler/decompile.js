#!/usr/bin/env node
var fs = require('fs');
var r2pipe = require('r2pipe');
var parseArgs = require('minimist');
var retdec = null;

var decopts = {};


/* Setup the api key */
try {
    var home = process.env.HOME;
    var key = fs.readFileSync(home + '/.config/radare2/retdec.key').toString();
    retdec = require('retdec').apiKey(key.split('\n')[0]);
} catch (e) {
    console.error(e.stack);
    console.error('\nCould not load retdec.com api key');
    console.error('Put your api key into ~/.config/radare2/retdec.key');
    process.exit(1);
}

/* Check for rlangpipe */
if (!process.env.R2PIPE_IN || !process.env.R2PIPE_OUT) {
    console.error('This script must be run inside radare2');
    console.error('Exiting...');
    process.exit(1);
}


function printHelp()
{
    console.log('\nUsage: $decompile [-acChps] [-n naming] @ addr');
    console.log('  -a: disable selective decompilation (decompile the hole file)');
    console.log('  -c: clear comments');
    console.log('  -C: save decompilation results in r2 as a comment');
    console.log('  -p: produce python code instead of C');
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


function removeComments(code) {
    var regexp = (args.p)? '^#.*$\n\n?' : '^\/.*$\n\n?';
    code = code.replace(new RegExp(regexp, 'mig'), '');
    return code;
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
        var noComments = removeComments(output);

        /* Args: Save output as R2 comment */
        if (args.C && !args.a) {
            var comment = new Buffer("DECOMPILER OUTPUT\n\n" + noComments);
            comment = comment.toString('base64');
            r2.cmd('CCu base64:' + comment + ' @ ' + fname);
        }

        var results = (args.c)? noComments : output;
        console.log(results);

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

/* Args: Python ouput */
if (args.p)
    decopts['target_language'] = 'py';

/* Do the decompilation */
if (!args.s) {
    console.log('Uploading binary to retdec.com');
    console.log('Please wait for decompilation to finish....\n');
}
decompile(decopts);

