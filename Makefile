OPENSSL=/usr/local/Cellar/openssl@1.1/1.1.1s
VERBOSE=0
LVL=$(if $(LEVEL),$(LEVEL),1)
CDEFS=-DUSE_NIST_RAND=1 \
	  -DOPENSSL_ROOT_DIR=$(OPENSSL) \
	  -DLEVEL=$(LVL) \
	  -DVERBOSE=$(VERBOSE) \
	  -DUSE_SHA3_AND_SHAKE=1 \
	  -DSTANDALONE_IMPL=1

MKDIR   := mkdir
RMDIR   := rm -rv
CC      := clang
BIN     := ./bin
OBJ     := ./obj
INCLUDE := ./include -I./bike-kem/include/internal -I./bike-kem/include -I$(OPENSSL)/include/ -I./bike-kem/tests \
	    -I./bike-kem/src/third_party_src
SRC     := ./src
SRCS    := $(wildcard $(SRC)/*.c)
OBJS    := $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS))
EXE     := $(BIN)/bike_faulter
LIBBIKE := $(BIN)/libbike.so
CFLAGS  := -I$(INCLUDE) -Wall -Wextra -pedantic -std=c11
LDLIBS  := -lcrypto -lbike
LDFLAGS := -L$(OPENSSL)/lib -L$(BIN)

.PHONY: all run clean

all: $(LIBBIKE) $(EXE)

$(LIBBIKE): $(BIN)
	$(MKDIR) -p build/libbike/
	cd build/libbike && cmake ../../bike-kem $(CDEFS)
	cd build/libbike && make
	cp build/libbike/libbike.a $(BIN)/

$(EXE): $(OBJS) | $(BIN)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(OBJ)/%.o: $(SRC)/%.c | $(OBJ)
	$(CC) $(CFLAGS) -c $< -o $@ $(CDEFS)

$(BIN) $(OBJ):
	$(MKDIR) $@

run: $(EXE)
	$<

clean:
	$(RMDIR) $(OBJ) $(BIN)