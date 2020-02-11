include build/common.mk

# ST related
SRC = src/main.c src/init.c src/redirect.c src/flash.c src/rng.c src/led.c src/device.c
SRC += src/fifo.c src/attestation.c src/nfc.c src/ams.c src/sense.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += $(DRIVER_LIBS) $(USB_LIB)

# FIDO2 lib
SRC += ../../fido2/apdu.c ../../fido2/util.c ../../fido2/u2f.c ../../fido2/test_power.c
SRC += ../../fido2/stubs.c ../../fido2/log.c  ../../fido2/ctaphid.c  ../../fido2/ctap.c
SRC += ../../fido2/ctap_parse.c ../../fido2/crypto.c
SRC += ../../fido2/version.c
SRC += ../../fido2/data_migration.c
SRC += ../../fido2/extensions/extensions.c ../../fido2/extensions/solo.c
SRC += ../../fido2/extensions/wallet.c

# Crypto libs
SRC += ../../crypto/sha256/sha256.c ../../crypto/micro-ecc/uECC.c ../../crypto/tiny-AES-c/aes.c
SRC += ../../crypto/cifra/src/sha512.c ../../crypto/cifra/src/blockwise.c

# spiffs
SP_PATH = ../../openpgp/libs/spiffs/spiffs/src/
SRC += $(SP_PATH)spiffs_nucleus.c $(SP_PATH)spiffs_gc.c $(SP_PATH)spiffs_hydrogen.c 
SRC += $(SP_PATH)spiffs_cache.c $(SP_PATH)spiffs_check.c 

# mbedtls
MBEDTLS_PATH = ../../openpgp/libs/mbedtls/mbedtls/crypto/library/
_SRCS = aes.c asn1parse.c asn1write.c bignum.c \
        ccm.c cipher.c cipher_wrap.c ctr_drbg.c \
        rsa_internal.c platform_util.c \
        sha1.c rsa.c sha256.c sha512.c \
        havege.c dhm.c entropy.c entropy_poll.c \
        ecp.c ecp_curves.c ecdsa.c ecdh.c \
        md.c md2.c md4.c md5.c oid.c
MBEDTLS_SRCS := $(foreach var, $(_SRCS), $(MBEDTLS_PATH)$(var))
SRC += $(MBEDTLS_SRCS)
MBEDTLS_CONFIG= -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

# OpenPGP
OP_SRC_DIRS :=  ../../openpgp/stm32l432 \
                ../../openpgp/src \
                ../../openpgp/src/applets \
                ../../openpgp/src/applets/openpgp
OP_SRC := $(sort $(foreach var, $(OP_SRC_DIRS), $(wildcard $(var)/*.cpp)))
CPP_SRC = $(OP_SRC)

OBJ1=$(SRC:.c=.o)
OBJ1+=$(CPP_SRC:.cpp=.o)
OBJ=$(OBJ1:.s=.o)

INC = -I. -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/

INC+= -I../../fido2/ -I../../fido2/extensions
INC += -I../../tinycbor/src -I../../crypto/sha256 -I../../crypto/micro-ecc
INC += -I../../crypto/tiny-AES-c
INC += -I../../crypto/cifra/src -I../../crypto/cifra/src/ext
INC += -I../../openpgp/libs/spiffs -I../../openpgp/libs/spiffs/spiffs/src/
INC += -I../../openpgp/libs/mbedtls -I../../openpgp/libs/mbedtls/mbedtls/include/ -I../../openpgp/libs/mbedtls/mbedtls/crypto/include/
INC += -I../../openpgp/stm32l432 -I../../openpgp/src

SEARCH=-L../../tinycbor/lib

ifndef LDSCRIPT
LDSCRIPT=linker/stm32l4xx.ld
endif

CFLAGS= $(INC)

TARGET=solo
HW=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb

# Solo or Nucleo board
CHIP=STM32L432xx

ifndef DEBUG
DEBUG=0
endif

DEFINES = -DDEBUG_LEVEL=$(DEBUG) -D$(CHIP) -DAES256=1  -DUSE_FULL_LL_DRIVER -DAPP_CONFIG=\"app.h\" $(EXTRA_DEFINES)

CFLAGS=$(INC) -c $(DEFINES) -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections \
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS) $(MBEDTLS_CONFIG)
CPPFLAGS=$(INC) -c $(DEFINES) -std=c++17 -Os -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections \
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS)
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections -lnosys
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,-Bstatic -ltinycbor

ECC_CFLAGS = $(CFLAGS) -DuECC_PLATFORM=5 -DuECC_OPTIMIZATION_LEVEL=4 -DuECC_SQUARE_FUNC=1 -DuECC_SUPPORT_COMPRESSED_POINT=0


.PRECIOUS: %.o

all: $(TARGET).elf
	$(SZ) $^

%.o: %.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

%.o: %.cpp
	$(CPP) $^ $(HW) -Os $(CPPFLAGS) -o $@

../../crypto/micro-ecc/uECC.o: ../../crypto/micro-ecc/uECC.c
	$(CC) $^ $(HW)  -O3 $(ECC_CFLAGS) -o $@

%.elf: $(OBJ)
	$(CC) $^ $(HW) $(LDFLAGS) -o $@
	@echo "Built version: $(VERSION_FLAGS)"

%.hex: %.elf
	$(SZ) $^
	$(CP) -O ihex $^ $(TARGET).hex

clean:
	rm -f *.o src/*.o *.elf  bootloader/*.o $(OBJ)


cbor:
	cd ../../tinycbor/ && make clean
	cd ../../tinycbor/ && make CC="$(CC)" AR=$(AR) \
LDFLAGS="$(LDFLAGS_LIB)" \
CFLAGS="$(CFLAGS) -Os  -DCBOR_PARSER_MAX_RECURSIONS=3"

