#msfdecode

msfdecode is a simple radare2 rpipe script used during workshop trainings. It decodes shellcodes encoded with metasploit `x86/shikata_ga_nai` encoder by emulating the shellcode itself using radare's ESIL virtual machine.

##Usage
```
$ node msfdecode.js
Usage: node msfdecode.js [encodedfile] [outputfile]
```

Where `encodedfile` is the raw shellcode file encoded using shikata_ga_nai and `ouputfile` is the file where the decoded shellcode will be saved

## Examples

Simple example usage with an execve shellcode:
```
$ ruby1.9.1 /opt/msf/msfpayload linux/x86/exec CMD='cat /etc/passwd' R > execve.shellcode
$ cat execve.shellcode | ruby1.9.1 /opt/msf/msfencode -e x86/shikata_ga_nai -c 7 -t raw > execve.encoded
[*] x86/shikata_ga_nai succeeded with size 78 (iteration=1)

[*] x86/shikata_ga_nai succeeded with size 105 (iteration=2)

[*] x86/shikata_ga_nai succeeded with size 132 (iteration=3)

[*] x86/shikata_ga_nai succeeded with size 159 (iteration=4)

[*] x86/shikata_ga_nai succeeded with size 186 (iteration=5)

[*] x86/shikata_ga_nai succeeded with size 213 (iteration=6)

[*] x86/shikata_ga_nai succeeded with size 240 (iteration=7)

$ msfdecode.js execve.encoded execve.decoded
 0x000000bd    6a0b           push 0xb
 0x000000bf    58             pop eax
 0x000000c0    99             cdq
 0x000000c1    52             push edx
 0x000000c2    66682d63       push 0x632d
 0x000000c6    89e7           mov edi, esp
 0x000000c8    682f736800     push 0x68732f
 0x000000cd    682f62696e     push 0x6e69622f
 0x000000d2    89e3           mov ebx, esp
 0x000000d4    52             push edx
 0x000000d5    e810000000     call 0xea
 0x000000d6    1000           adc byte [eax], al
 0x000000d8    0000           add byte [eax], al
 0x000000da    636174         arpl word [ecx + 0x74], sp
 0x000000dc    7420           je 0xfe
 0x000000de    2f             das
 0x000000df    657463         je 0x145
 0x000000e2    2f             das
 0x000000e3    7061           jo 0x146
 0x000000e5    7373           jae 0x15a
 0x000000e7    7764           ja 0x14d
 0x000000e9    005753         add byte [edi + 0x53], dl
 0x000000ec    89e1           mov ecx, esp
 0x000000ee    cd80           int 0x80

$ radiff2 -d -c execve.shellcode execve.decoded
0
$
```

##Demo

Click on the image below to see a demo:

[![demo](http://nixgeneration.com/~jaime/misc/msfdecoder.png)](https://asciinema.org/a/26594)
