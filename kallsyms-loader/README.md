# kallsyms-loader

Simple r2pipe script to load Linux kernel symbols into radare

## Usage

Using /proc/kallsyms
```
$ r2 /tmp/vmlinux
[0x01000000]> #!pipe node /path/kallsyms-loader/ksymload.js /proc/kallsyms
[0x01000000]> pd 10 @ sym.printk
```

Using System.map file
```
$ r2 /tmp/vmlinux
[0x01000000]> #!pipe node /path/kallsyms-loader/ksymload.js /boot/System.map-4.0.3
[0x01000000]> pd 10 @ sym.printk
```

## Alias
Its recommended to create r2 aliases in order to shorten rlangpipe scripts commands. You can add the following line to your `~/.config/radare2/radare2rc` file

```
# Alias
$ksymload=#!pipe node /home/user/r2-scripts/kallsyms-loader/ksymload.js
```

This way you can call the script just by typing `$ksymload`
```
$ r2 /tmp/vmlinux
[0x01000000]> $ksymload /proc/kallsyms
[0x01000000]> pd 10 @ sym.printk
```


