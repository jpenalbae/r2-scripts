import sys
import r2pipe

r2 = r2pipe.open("-")

print "============================"
print "        IMPORTS"
print "============================"
print r2.syscmdj("rabin2 -j -i %s" % sys.argv[1])

print "============================"
print "        STRINGS"
print "============================"
print r2.syscmdj("rabin2 -j -zz %s" % sys.argv[1])

print "============================"
print "        SECTIONS"
print "============================"
print r2.syscmdj("rabin2 -j -S %s" % sys.argv[1])

print "============================"
print "        SYMBOLS"
print "============================"
print r2.syscmdj("rabin2 -j -s %s" % sys.argv[1])
