#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7

platform=2

src = $(wildcard *.c) $(wildcard crypto/*.c) crypto/tiny-AES-c/aes.c
obj = $(src:.c=.o) uECC.o

LDFLAGS = -Wl,--gc-sections ./tinycbor/lib/libtinycbor.a
CFLAGS = -O2 -fdata-sections -ffunction-sections -I./tinycbor/src -I./crypto -I./crypto/micro-ecc/ -Icrypto/tiny-AES-c/

name = main

$(name):  $(obj)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

uECC.o: ./crypto/micro-ecc/uECC.c
	$(CC) -c -o $@ $^ -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(platform) -I./crypto/micro-ecc/

clean:
	rm -f *.o main.exe main
