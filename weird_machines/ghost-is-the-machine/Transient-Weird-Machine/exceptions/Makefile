# Compilers
CC = gcc-14
CPP = g++-14
AS = as

# Argp paths from brew
ARGP_INCLUDE = /usr/local/Cellar/argp-standalone/1.5.0/include
ARGP_LIB = /usr/local/Cellar/argp-standalone/1.5.0/lib

# Flags
CFLAGS = -O2 -I$(ARGP_INCLUDE)
LFLAGS = -lm -L$(ARGP_LIB) -largp
PFLAGS = -pthread

all: build main.elf

amd: build main-amd.elf

build:
	mkdir -p build

main.elf: main.cpp gates/single.h build/compose.o
	$(CPP) $(CFLAGS) -D INTEL -o main.elf main.cpp build/compose.o $(LFLAGS)

build/compose.o: gates/compose.cpp gates/compose.h gates/single.h gates/gates.h
	$(CPP) $(CFLAGS) -D INTEL -c -o build/compose.o gates/compose.cpp

main-amd.elf: main.cpp gates/single.h build/compose-amd.o
	$(CPP) $(CFLAGS) -o main-amd.elf main.cpp build/compose-amd.o $(LFLAGS)

build/compose-amd.o: gates/compose.cpp gates/compose.h gates/single.h gates/gates.h
	$(CPP) $(CFLAGS) -c -o build/compose-amd.o gates/compose.cpp

clean:
	rm -rf *.o build/ *.elf *~