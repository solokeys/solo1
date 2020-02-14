CC=afl-gcc
OPTLEVEL=2

#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7
ecc_platform=2

CFLAGS = -O$(OPTLEVEL) -fdata-sections -ffunction-sections -g 
ECC_CFLAGS = -O$(OPTLEVEL) -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(ecc_platform) 

INCLUDES = -I../fido2/ -I../tinycbor/src -I../fuzz

CFLAGS += $(INCLUDES)
CFLAGS += -DAES256=1  -DSOLO_EXPERIMENTAL=1 -DDEBUG_LEVEL=1

LIBS = ../fido2/libsolo.a ../tinycbor/lib/libtinycbor.a


.PHONY: libsolo libcbor clean

fuzztarget: libsolo libcbor
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(@).c $(LIBS)

libsolo:
	cd ../fido2/ && $(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" ECC_CFLAGS="$(ECC_CFLAGS)" APP_CONFIG=app.h -j8

libcbor:
	cd ../tinycbor/ && $(MAKE) CC="$(CC)" CFLAGS="$(CFLAGS)" LDFLAGS='' -j8

clean:
	rm fuzztarget
	cd ../tinycbor/ && $(MAKE) clean
	cd ../fido2/ && $(MAKE) clean
