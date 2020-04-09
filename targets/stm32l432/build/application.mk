include build/common.mk

# ST related
SRC = src/main.c src/init.c src/redirect.c src/flash.c src/rng.c src/led.c src/device.c
SRC += src/fifo.c src/attestation.c src/nfc.c src/ams.c src/sense.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += $(DRIVER_LIBS) $(USB_LIB)

# FIDO2 lib
SRC += $(LIB_SOLO_PATH)/apdu.c $(LIB_SOLO_PATH)/util.c $(LIB_SOLO_PATH)/u2f.c $(LIB_SOLO_PATH)/test_power.c
SRC += $(LIB_SOLO_PATH)/stubs.c $(LIB_SOLO_PATH)/log.c  $(LIB_SOLO_PATH)/ctaphid.c  $(LIB_SOLO_PATH)/ctap.c
SRC += $(LIB_SOLO_PATH)/ctap_parse.c $(LIB_SOLO_PATH)/crypto.c
SRC += $(LIB_SOLO_PATH)/version.c
SRC += $(LIB_SOLO_PATH)/data_migration.c
SRC += $(LIB_SOLO_PATH)/extensions/extensions.c $(LIB_SOLO_PATH)/extensions/solo.c
SRC += $(LIB_SOLO_PATH)/extensions/wallet.c

# Crypto libs
SRC += $(LIB_SHA256_PATH)/sha256.c $(LIB_MICRO_ECC_PATH)/uECC.c $(LIB_TINY_AES_PATH)/aes.c
SRC += $(LIB_CIFRA_PATH)/src/sha512.c $(LIB_CIFRA_PATH)/src/blockwise.c

OBJ1=$(SRC:.c=.o)
OBJ=$(OBJ1:.s=.o)

INC = -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/

INC+= -I$(LIB_SOLO_PATH)/ -I$(LIB_SOLO_PATH)/extensions
INC += -I$(LIB_TINYCBOR_PATH)/src -I$(LIB_SHA256_PATH)/ -I$(LIB_MICRO_ECC_PATH)
INC += -I$(LIB_TINY_AES_PATH)
INC += -I$(LIB_CIFRA_PATH)/src -I$(LIB_CIFRA_PATH)/src/ext

SEARCH=-L$(LIB_TINYCBOR_PATH)/lib

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

CFLAGS=$(INC) -c $(DEFINES)   -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections \
	-fomit-frame-pointer $(HW) -g $(VERSION_FLAGS)
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections -lnosys
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,-Bstatic -ltinycbor

ECC_CFLAGS = $(CFLAGS) -DuECC_PLATFORM=5 -DuECC_OPTIMIZATION_LEVEL=4 -DuECC_SQUARE_FUNC=1 -DuECC_SUPPORT_COMPRESSED_POINT=0


.PRECIOUS: %.o

all: $(TARGET).elf
	$(SZ) $^

%.o: %.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

$(LIB_MICRO_ECC_PATH)/uECC.o: $(LIB_MICRO_ECC_PATH)/uECC.c
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
	cd $(LIB_TINYCBOR_PATH)/ && make clean
	cd $(LIB_TINYCBOR_PATH)/ && make CC="$(CC)" AR=$(AR) \
LDFLAGS="$(LDFLAGS_LIB)" \
CFLAGS="$(CFLAGS) -Os  -DCBOR_PARSER_MAX_RECURSIONS=3"

