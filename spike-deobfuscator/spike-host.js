var r2pipe = require('r2pipe');

const TRACE_LIMIT = 8;

var r2;
var flags;
var info;


/**
 * Returns the offset of a radare flag
 * 
 * @param  {string} name  The flag name
 * @return {int}          The offset
 */
function findFlag(name) 
{
    for (var x = flags.length - 1; x >= 0; x--) {
        if (flags[x].name === name)
            return flags[x];
    };

    return null;
}


/**
 * Finds offset on the disassembly which calls to fcn
 * 
 * @param  {object} disass  Function disassembly
 * @param  {string} fcn     Function call we are searching
 * @return {int}            Offset which calls the function
 */
function findCall(disass, fcn)
{
    var analOffset = findFlag(fcn).offset.toString(16);

    for (var x = 0; x < disass.length; x++) {
        if (disass[x].type === 'call') {
            if (disass[x].opcode.split(' ')[1] === '0x'+analOffset) {
                return x;
            }
        }
    }

    return null;
}

function findPreviousCall(disass, offset)
{
    for (var x = offset - 1; x >= 0; x--) {
        if (disass[x].type === 'call') {
            return x;
        }
    }

     return null;
}

function emulate(start, end)
{
    var bytes = info.bin.bits / 8;

    console.log("Emulating: ");
    console.log('- start: 0x' + start.toString(16));
    console.log('- end: 0x' + end.toString(16));
    console.log('');

    /* 32 bits */
    if ( bytes === 4) {
        r2.promise(r2.cmd, 'aer eip=' + start, null)
            .then(r2.cmd, 'aecu ' + end, null)
            .then(r2.cmd, '.dr*', null)
            .then(r2.cmd, 'ps @ `*esp`', function(res) { 
                console.log('Host: ' + res);
                r2.quit();
            });
    /* 64 bits */
    } else if (bytes === 8) {
        console.error('x86_64 not implemented');
        r2.quit();
    }


    r2.promise(r2.cmd, 'aei', null);
}


r2pipe.pipe(process.argv[2], function(or2) {
    var end, start;
    r2 = or2;

    /* Analyze sym.ServerConnectCli & get its disassembly */
    r2.promise(r2.cmd, 'aei', null)
        .then(r2.cmd,  'aeim', null)
        .then(r2.cmd,  'e io.cache=true', null)
        .then(r2.cmd,  'aer esp=0x00108000', null)
        .then(r2.cmd,  'aer rsp=0x00108000', null)
        .then(r2.cmdj, 'ij', function(data) { info = data; })
        .then(r2.cmdj, 'fj', function(data) {  flags = data; })
        .then(r2.cmd, 'af @ sym.ServerConnectCli')
        .then(r2.cmdj, 'pdfj @ sym.ServerConnectCli', function(res) {

            /* Search for call to AnalysisAddress */
            end = findCall(res.ops, 'sym.AnalysisAddress');
            if (end === null) {
                console.error("Call to AnalysisAddress not found.");
                process.exit(1);
            }

            start = findPreviousCall(res.ops, end);
            emulate(res.ops[start+1].offset, res.ops[end].offset);
        });
});
