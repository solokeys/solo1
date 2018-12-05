CC=arm-none-eabi-gcc
CP=arm-none-eabi-objcopy
SZ=arm-none-eabi-size
AR=arm-none-eabi-ar

# ST related
SRC = src/main.c src/init.c src/redirect.c src/flash.c src/rng.c src/led.c src/device.c
SRC += src/fifo.c src/crypto.c src/attestation.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += $(wildcard lib/*.c) $(wildcard lib/usbd/*.c)

# FIDO2 lib
SRC += ../../fido2/util.c ../../fido2/u2f.c ../../fido2/test_power.c
SRC += ../../fido2/stubs.c ../../fido2/log.c  ../../fido2/ctaphid.c  ../../fido2/ctap.c
SRC += ../../fido2/ctap_parse.c ../../fido2/main.c

# Crypto libs
SRC += ../../crypto/sha256/sha256.c ../../crypto/micro-ecc/uECC.c ../../crypto/tiny-AES-c/aes.c


OBJ1=$(SRC:.c=.o)
OBJ=$(OBJ1:.s=.o)

INC = -Isrc/ -Isrc/cmsis/ -Ilib/ -Ilib/usbd/ -I../../fido2/ -I../../fido2/extensions
INC += -I../../tinycbor/src -I../../crypto/sha256 -I../../crypto/micro-ecc
INC += -I../../crypto/tiny-AES-c

SEARCH=-L../../tinycbor/lib

LDSCRIPT=stm32l432xx.ld

CFLAGS= $(INC)

TARGET=solo
HW=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb

# Nucleo board
#CHIP=STM32L432xx
# Solo
CHIP=STM32L442xx

DEFINES = -D$(CHIP) -DAES256=1  -DUSE_FULL_LL_DRIVER -DAPP_CONFIG=\"app.h\"
# DEFINES += -DTEST_SOLO_STM32 -DTEST -DTEST_FIFO=1

CFLAGS=$(INC) -c $(DEFINES)   -Wall -fdata-sections -ffunction-sections $(HW) -g
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections -u _printf_float -lnosys
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -ltinycbor


.PRECIOUS: %.o

all: $(TARGET).elf
	$(SZ) $^

%.o: %.c
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

../../crypto/micro-ecc/uECC.o: ../../crypto/micro-ecc/uECC.c
	$(CC) $^ $(HW)  -O3 $(CFLAGS) -o $@

%.o: %.s
	$(CC) $^ $(HW)  -Os $(CFLAGS) -o $@

%.elf: $(OBJ)
	$(CC) $^ $(HW) $(LDFLAGS) -o $@

%.hex: %.elf
	$(CP) -O ihex $^ $(TARGET).hex

clean:
	rm -f *.o src/*.o src/*.elf  bootloader/*.o $(OBJ)


cbor:
	cd ../../tinycbor/ && make clean
	cd ../../tinycbor/ && make CC="$(CC)" AR=$(AR) \
LDFLAGS="$(LDFLAGS_LIB)" \
CFLAGS="$(CFLAGS)"
