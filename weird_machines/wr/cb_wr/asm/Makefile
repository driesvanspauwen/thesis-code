.PHONY: all clean test dump

all: test_cache_reg

test_cache_reg: test.o cache_reg.o
	gcc -o test_cache_reg test.o cache_reg.o -no-pie

test.o: test.asm
	nasm -f elf64 test.asm -o test.o

cache_reg.o: cache_reg.asm
	nasm -f elf64 cache_reg.asm -o cache_reg.o

dump: cache_reg.o
	objdump -d cache_reg.o

clean:
	rm -f *.o test_cache_reg

test: test_cache_reg
	./test_cache_reg