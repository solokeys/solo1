include version.mk

ifndef APP_CONFIG
APP_CONFIG=example_app.h
endif

INC = -I./ -I./extensions
INC += -I../tinycbor/src 
INC += -I../crypto/sha256 -I../crypto/micro-ecc -I../crypto/tiny-AES-c
INC += -I../crypto/cifra/src -I../crypto/cifra/src/ext

INT_CFLAGS = -DAPP_CONFIG=\"$(APP_CONFIG)\"
INT_CFLAGS += $(INC)
INT_CFLAGS += $(SOLO_VERSION_FLAGS)

SRC = apdu.c util.c u2f.c test_power.c
SRC += stubs.c log.c  ctaphid.c  ctap.c
SRC += ctap_parse.c crypto.c
SRC += device.c
SRC += version.c
SRC += data_migration.c
SRC += extensions/extensions.c extensions/solo.c
SRC += extensions/wallet.c

# Crypto libs
SRC += ../crypto/sha256/sha256.c ../crypto/micro-ecc/uECC.c ../crypto/tiny-AES-c/aes.c
SRC += ../crypto/cifra/src/sha512.c ../crypto/cifra/src/blockwise.c

OBJ = $(SRC:.c=.o)

all: libsolo.a

libsolo.a: $(OBJ)
	$(AR) cqs $@ $^

%.o: %.c
	$(CC) $^ $(INT_CFLAGS) $(CFLAGS) -c -o $@

../crypto/micro-ecc/uECC.o: ../crypto/micro-ecc/uECC.c
	$(CC) $^ $(INT_CFLAGS) $(ECC_CFLAGS) -c -o $@

clean:
	rm -f $(OBJ) libsolo.a

