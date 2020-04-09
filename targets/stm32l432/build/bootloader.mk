include build/common.mk

# ST related
SRC = bootloader/main.c bootloader/bootloader.c
SRC += bootloader/pubkey_bootloader.c bootloader/version_check.c
SRC += src/init.c src/redirect.c src/flash.c src/rng.c src/led.c src/device.c
SRC += src/fifo.c src/attestation.c src/sense.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += $(DRIVER_LIBS) $(USB_LIB)

# FIDO2 lib
SRC += $(LIB_SOLO_PATH)/util.c $(LIB_SOLO_PATH)/u2f.c $(LIB_SOLO_PATH)/extensions/extensions.c
SRC += $(LIB_SOLO_PATH)/stubs.c $(LIB_SOLO_PATH)/log.c  $(LIB_SOLO_PATH)/ctaphid.c  $(LIB_SOLO_PATH)/ctap.c
SRC += $(LIB_SOLO_PATH)/crypto.c

# Crypto libs
SRC += $(LIB_SHA256_PATH)/sha256.c $(LIB_MICRO_ECC_PATH)/uECC.c
SRC += $(LIB_CIFRA_PATH)/src/sha512.c $(LIB_CIFRA_PATH)/src/blockwise.c

OBJ1=$(SRC:.c=.o)
OBJ=$(OBJ1:.s=.o)


INC = -Ibootloader/ -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/ -I$(LIB_SOLO_PATH)/ -I$(LIB_SOLO_PATH)/extensions
INC += -I$(LIB_TINYCBOR_PATH)/src -I$(LIB_SHA256_PATH) -I$(LIB_MICRO_ECC_PATH)
INC += -I$(LIB_TINY_AES_PATH)
INC += -I$(LIB_CIFRA_PATH)/src -I$(LIB_CIFRA_PATH)/src/ext

ifndef LDSCRIPT
LDSCRIPT=linker/bootloader_stm32l4xx.ld
endif

CFLAGS= $(INC)

TARGET=bootloader
HW=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb

# Solo or Nucleo board
CHIP=STM32L432xx

ifndef DEBUG
DEBUG=0
endif

DEFINES = -DDEBUG_LEVEL=$(DEBUG) -D$(CHIP) -DAES256=1  -DUSE_FULL_LL_DRIVER -DAPP_CONFIG=\"bootloader.h\" $(EXTRA_DEFINES)
# DEFINES += -DTEST_SOLO_STM32 -DTEST -DTEST_FIFO=1

CFLAGS=$(INC) -c $(DEFINES)   -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -fdata-sections -ffunction-sections $(HW) -g $(VERSION_FLAGS)
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections  -lnosys
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref  -Wl,-Bstatic


.PRECIOUS: %.o

all: $(TARGET).elf
	$(SZ) $^


%.o: %.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

$(LIB_MICRO_ECC_PATH)/uECC.o: $(LIB_MICRO_ECC_PATH)/uECC.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

%.o: %.s
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

%.elf: $(OBJ)
	$(CC) $^ $(HW) $(LDFLAGS) -o $@
	$(SZ) $@

%.hex: %.elf
	$(CP) -O ihex $^ $(TARGET).hex

clean:
	rm -f *.o src/*.o bootloader/*.o *.elf  $(OBJ)
