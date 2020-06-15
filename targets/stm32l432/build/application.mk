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

#libsalty
LIBSALTY_PATH = ../../crypto/libsalty
LIBSALTY_LIB = $(LIBSALTY_PATH)/libsalty-asm.a $(LIBSALTY_PATH)/libsalty.a

# bearSSL
BEARSSL_PATH = ../../openpgp/libs/bearssl/
_SRCSB = rsa_i15_modulus.c i15_encode.c i15_decode.c i15_mulacc.c i15_bitlen.c \
         rsa_i15_priv.c i15_sub.c i15_add.c i15_reduce.c i15_modpow.c i15_modpow2.c \
         i15_ninv15.c i15_tmont.c i15_fmont.c i15_montmul.c i15_decred.c i15_muladd.c \
         i15_rshift.c ccopy.c rsa_i15_privexp.c i32_div32.c i15_moddiv.c \
         rsa_i31_keygen_inner.c rsa_i15_keygen.c \
         i15_addon.c rsa_default_keygen.c rsa_default_pkcs1_sign.c \
         ec_keygen.c ec_pubkey.c ec_prime_i15.c ec_c25519_m15.c \
         ec_secp256r1.c ec_secp384r1.c ec_secp521r1.c \
         i15_decmod.c i15_iszero.c \
         ecdsa_i15_sign_raw.c ecdsa_i15_bits.c hmac_drbg.c hmac.c sha2small.c enc32be.c dec32be.c \
         aes_ct.c aes_ct_cbcdec.c aes_ct_cbcenc.c aes_ct_dec.c aes_ct_enc.c

BEARSSL_SRCS = $(foreach var, $(_SRCSB), $(BEARSSL_PATH)$(var))
SRC += $(BEARSSL_SRCS)

# OpenPGP
OP_SRC_DIRS :=  ../../openpgp/stm32l432 \
                ../../openpgp/src \
                ../../openpgp/src/applications \
                ../../openpgp/src/applications/openpgp \
                ../../openpgp/libs/stm32fs
OP_SRC := $(sort $(foreach var, $(OP_SRC_DIRS), $(wildcard $(var)/*.cpp)))
CPP_SRC = $(OP_SRC)

OBJ1=$(SRC:.c=.o)
OBJ1+=$(CPP_SRC:.cpp=.o)
OBJ=$(OBJ1:.s=.o)

INC = -I. -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/

INC += -I../../fido2/ -I../../fido2/extensions
INC += -I../../tinycbor/src -I../../crypto/sha256 -I../../crypto/micro-ecc
INC += -I../../crypto/tiny-AES-c
INC += -I../../crypto/cifra/src -I../../crypto/cifra/src/ext
INC += -I../../openpgp/stm32l432 -I../../openpgp/src
INC += -I../../openpgp/libs/bearssl
INC += -I../../openpgp/libs/stm32fs
INC += -I../../crypto/libsalty

SEARCH=-L../../tinycbor/lib -L$(LIBSALTY_PATH)

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
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS)
CPPFLAGS=$(INC) -c $(DEFINES) -std=c++17 -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections \
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS) -fno-exceptions -fno-rtti
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections -lnosys -lstdc++ 
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,-Bstatic -ltinycbor -Wl,--print-memory-usage  $(LIBSALTY_LIB)

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
	cd ../../tinycbor/ && make CC="$(CC)" AR=$(AR) LDFLAGS="$(LDFLAGS_LIB)" CFLAGS="$(CFLAGS) -Os -DCBOR_PARSER_MAX_RECURSIONS=3"
