.PHONY: all clean

OPENSSL=/usr/local/Cellar/openssl@1.1/1.1.1s

CC=clang
CFLAGS=-Wall -Wextra -pedantic
CDEFS=-DUSE_NIST_RAND=1 -DOPENSSL_ROOT_DIR=$(OPENSSL) # -DVERBOSE=1

SRC=src/main.c bike-kem/tests/FromNIST/rng.c src/util.c src/import.c src/export.c
BUILDDIR=build/
BIN=main.bin

INCLUDE=-Ibike-kem/include/internal -Ibike-kem/include/ -I$(OPENSSL)/include
LIBS=-L$(BUILDDIR) -L$(OPENSSL)/lib -lcrypto -lbike

all:
	mkdir -p build/libbike/
	cd build/libbike && cmake ../../bike-kem $(CDEFS)
	cd build/libbike && make
	cp build/libbike/libbike.a build/
	$(CC) $(CFLAGS) $(CDEFS) $(LIBS) $(INCLUDE) $(SRC) -o $(BUILDDIR)$(BIN)

clean:
	rm -rf build/libbike
	rm -rf build/
	rm -rf kat/export.rsp