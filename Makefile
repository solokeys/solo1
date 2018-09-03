#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7

platform=2

EFM32_DEBUGGER= -s 440083537 --device EFM32JG1B200F128GM32
#EFM32_DEBUGGER= -s 440121060    #dev board

src = $(wildcard pc/*.c) $(wildcard fido2/*.c) $(wildcard crypto/sha256/*.c) crypto/tiny-AES-c/aes.c
obj = $(src:.c=.o) uECC.o

LDFLAGS = -Wl,--gc-sections ./tinycbor/lib/libtinycbor.a
CFLAGS = -O2 -fdata-sections -ffunction-sections 

INCLUDES = -I./tinycbor/src -I./crypto/sha256 -I./crypto/micro-ecc/ -Icrypto/tiny-AES-c/ -I./fido2/ -I./pc

CFLAGS += $(INCLUDES)

name = main

all: main

cbor:
	cd tinycbor/ && $(MAKE) clean && $(MAKE) -j8

test: testgcm

efm8prog:
	cd '.\efm8\Keil 8051 v9.53 - Debug' && $(MAKE) all
	flashefm8.exe -part EFM8UB10F8G -sn 440105518 -erase
	flashefm8.exe -part EFM8UB10F8G -sn 440105518 -upload '.\efm8\Keil 8051 v9.53 - Debug\efm8.hex'

efm32com:
	cd '.\efm32\GNU ARM v7.2.1 - Debug' && $(MAKE) all
efm32prog:
	cd '.\efm32\GNU ARM v7.2.1 - Debug' && $(MAKE) all
	commander flash '.\efm32\GNU ARM v7.2.1 - Debug\EFM32.hex' $(EFM32_DEBUGGER)  -p "0x1E7FC:0x00000000:4" 
efm32read:
	cd '.\efm32\GNU ARM v7.2.1 - Debug' && $(MAKE) all
	commander swo read $(EFM32_DEBUGGER)



efm32bootprog:
	cd '.\efm32boot\GNU ARM v7.2.1 - Debug' && $(MAKE) all
	commander flash '.\efm32boot\GNU ARM v7.2.1 - Debug\efm32boot.hex' $(EFM32_DEBUGGER) --masserase

$(name):  $(obj)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

testgcm: $(obj)
	$(CC) -c main.c $(CFLAGS) -DTEST -o main.o
	$(CC) -c crypto/aes_gcm.c $(CFLAGS) -DTEST -o crypto/aes_gcm.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDFLAGS)

uECC.o: ./crypto/micro-ecc/uECC.c
	$(CC) -c -o $@ $^ -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(platform) -I./crypto/micro-ecc/

clean:
	rm -f *.o main.exe main $(obj)
