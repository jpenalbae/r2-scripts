# radare r2pipe decompiler

r2pipe script to add decompiler capabilities to radare2 using retdec.con REST API. [](https://github.com/jpenalbae/retdec-node)

Retdec is a decompiler that can be utilized for source code recovery, static malware analysis, etc. The decompiler is supposed to be not bounded to any particular target architecture, operating system, or executable file format.
Features

* Handles all the commonly used file formats (ELF, PE).
* Currently supports the Intel x86, ARM, MIPS, PIC32, and PowerPC architectures.
* Can decompile to two output high-level languages: C and a Python-like language.
* Compiler and packer detection.
* Extraction and utilization of debugging information (DWARF, PDB).
* Signature-based removal of statically linked library code.
* Reconstruction of functions, high-level constructs, types, etc.
* Generation of call graphs, control-flow graphs, and various statistics.
* It is actively developed.

# Getting started

First of all you will need to clone this repo and install module dependencies for the decompiler:
```sh
$ git clone https://github.com/jpenalbae/r2-scripts.git
$ cd r2-scripts/decompiler
$ npm install
```

To use retdec.com service, you will need a free API key which can be obtained by registering at their site: [https://retdec.com/registration/](https://retdec.com/registration/)

Once you are registered you must replace the first javascript line of `decompile.js` with your personal key:

```js
#!/usr/bin/env node

var retdec = require('retdec').apiKey('YOUR_API_KEY_KEY_HERE'); <------
var r2pipe = require('r2pipe');
var parseArgs = require('minimist');

```

To make decompiler easier to use, its recommended to create r2 aliases in order to shorten rlangpipe scripts commands. You can add the following line to your `~/.config/radare2/radare2rc` file
```sh
# Alias
$decompile=#!pipe node /home/user/r2-scripts/decompiler/decompile.js
```

This way you can easily use `$decompile` command instead of having to write `#!pipe node /home/user/r2-scripts/decompiler/decompile.js` each time you want to execute the script.


# Usage

```
$ r2 -
 -- Nothing to see here. Move along.
[0x00000000]> $decompile -h

Usage: $decompile [-achs] [-n naming] @ addr
  -a: disable selective decompilation (decompile the hole file)
  -c: clear comments
  -s: silent. Do not display messages
  -h: displays this help menu
  -n naming: select variable naming

Where valid variable namings are:
  readable: Tries to produce as meaningful variable names as possible
  address: Variables are named by their addresses in the binary file
  hungarian: Prefix variables with their type
  simple: Name variables simply by assigning fruit names
  unified: Globals, locals and parameters are named just gX, vX and aX

**********************************************************************
     This will upload the binary being analyzed to retdec.com !!!
                       You have been warned...
**********************************************************************

[0x00000000]> 
```

# Examples

Decompile function at address 0x08048710 (That address must be part of a function defined in radare)
```
[0x00000000]> $decompile @ 0x08048710
```

Decompile function removing comments
```
[0x00000000]> $decompile -c @ 0x08048710
```

Decompile function in silent mode (removes any other output than the decompilation result)
```
[0x00000000]> $decompile -s @ 0x08048710
```

Send decompilation to a file
```
[0x00000000]> $decompile -s @ 0x08048710 > /tmp/destfile
```

Use `simple` variable naming
```
[0x00000000]> $decompile -n simple @ 0x08048710 > /tmp/destfile
```

Disable selective decompilation and decompile the hole binary
```
[0x00000000]> $decompile -a
```


# Demo

Click on the image below to see a demo:

[![demo](http://nixgeneration.com/~jaime/misc/decompiler.png)](https://asciinema.org/a/20904)


