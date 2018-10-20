CC=arm-none-eabi-gcc
CP=arm-none-eabi-objcopy
SZ=arm-none-eabi-size

SRC=src/main.c src/startup_stm32l432xx.s src/system_stm32l4xx.c $(wildcard lib/*c)
OBJ=$(SRC:.c=.o)
INC=-Isrc/ -Isrc/cmsis -Ilib/
LDSCRIPT=stm32l432xx.ld

CFLAGS= $(INC)

TARGET=solo
HW=-mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb

# Nucleo board
#CHIP=STM32L432xx
# Solo
CHIP=STM32L442xx

CFLAGS=$(INC) -c -D$(CHIP) -DUSE_FULL_LL_DRIVER -O0  -Wall -fdata-sections -ffunction-sections
LDFLAGS=$(HW) -specs=nano.specs -T$(LDSCRIPT) -Wl,-Map=$(TARGET).map,--cref -Wl,--gc-sections

all: $(TARGET).elf
	$(SZ) $^
	$(CP) -O ihex $^ $(TARGET).hex

%.o: %.c
	$(CC) $^ $(HW) $(CFLAGS) -o $@

%.o: %.s
	$(CC) $^ $(HW) $(CFLAGS) -o $@

%.elf: $(OBJ)
	$(CC) $^ $(HW) $(LDFLAGS) -o $@

clean:
	rm -f *.o src/*.o src/*.elf *.elf

flash:
	STM32_Programmer_CLI -c port=SWD -halt -d $(TARGET).hex -rst
	sleep 0.5
	python dfuse-tool/dfuse-tool.py --leave

