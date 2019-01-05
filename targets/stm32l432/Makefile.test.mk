CC=arm-none-eabi-gcc
CP=arm-none-eabi-objcopy
SZ=arm-none-eabi-size
AR=arm-none-eabi-ar

# ST related
SRC = src/main.c src/init.c src/flash.c src/led.c
SRC += src/startup_stm32l432xx.s src/system_stm32l4xx.c
SRC += lib/stm32l4xx_ll_gpio.c lib/stm32l4xx_ll_pwr.c lib/stm32l4xx_ll_rcc.c lib/stm32l4xx_ll_tim.c lib/stm32l4xx_ll_utils.c

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

# Solo or Nucleo board
CHIP=STM32L432xx

DEFINES = -D$(CHIP) -DAES256=1  -DUSE_FULL_LL_DRIVER
DEFINES += -DTEST_SOLO_STM32 -DTEST

CFLAGS=$(INC) -c $(DEFINES)   -Wall -fdata-sections -ffunction-sections $(HW)
LDFLAGS_LIB=$(HW) $(SEARCH) -specs=nano.specs  -specs=nosys.specs  -Wl,--gc-sections  -lnosys
LDFLAGS=$(HW) $(LDFLAGS_LIB) -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref


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
	$(CP) -O binary $^ $(TARGET).bin

clean:
	rm -f *.o src/*.o src/*.elf *.elf *.hex $(OBJ)

flash: $(TARGET).hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d $(TARGET).hex -rst

detach:
	STM32_Programmer_CLI -c port=usb1 -ob nBOOT0=1

cbor:
	cd ../../tinycbor/ && make clean
	cd ../../tinycbor/ && make CC="$(CC)" AR=$(AR) \
LDFLAGS="$(LDFLAGS_LIB)" \
CFLAGS="$(CFLAGS)"
