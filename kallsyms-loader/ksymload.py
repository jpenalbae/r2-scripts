import r2pipe
import sys

r2 = r2pipe.open()
r2.cmd("fs symbols")

ksyms = open(sys.argv[1])
for line in ksyms:
  	entry = line.split(' ')
	if entry[1] == 'A': continue        # skip absolute symbols
	if entry[2][-2:-1] == ']': continue # skip modules

	# Create flag
	addr = int(entry[0], 16)
	name = entry[2].replace('\n', '')
	r2.cmd("f sym.%s @ %d" % (name, addr))

r2.cmd("fs *")
