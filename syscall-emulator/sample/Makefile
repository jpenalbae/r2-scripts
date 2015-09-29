all:
	nasm -f elf hello.S
	ld -o hello hello.o -melf_i386

clean:
	rm -rf *.o hello
