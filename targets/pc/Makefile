include ../../libs/libsolo/version.mk

#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7
ecc_platform=2

src = pc/device.c pc/main.c

obj = $(src:.c=.o)

LIBCBOR = libs/tinycbor/lib/libtinycbor.a
LIBSOLO = libs/libsolo/libsolo.a

ifeq ($(shell uname -s),Darwin)
  export LDFLAGS = -Wl,-dead_strip
else
  export LDFLAGS = -Wl,--gc-sections
endif
LDFLAGS += $(LIBSOLO) $(LIBCBOR)


CFLAGS = -O2 -fdata-sections -ffunction-sections -g
ECC_CFLAGS = -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(ecc_platform)

INCLUDES =  -I../ -I./fido2/ -I./pc -I../pc -I./tinycbor/src

CFLAGS += $(INCLUDES)
CFLAGS += -DAES256=1  -DSOLO_EXPERIMENTAL=1 -DDEBUG_LEVEL=1

name = main

.PHONY: all $(LIBCBOR) $(LIBSOLO) black blackcheck cppcheck wink fido2-test clean full-clean travis test clean version
all: main

libs/tinycbor/Makefile libs/crypto/tiny-AES-c/aes.c:
	git submodule update --init

.PHONY: cbor
cbor: $(LIBCBOR)

$(LIBCBOR):
	cd tinycbor/ && $(MAKE)  LDFLAGS='' -j8

$(LIBSOLO):
	cd fido2/ && $(MAKE) CFLAGS="$(CFLAGS)" ECC_CFLAGS="$(ECC_CFLAGS)" APP_CONFIG=app.h -j8

version:
	@git describe

test: venv
	$(MAKE) clean
	$(MAKE) -C . main
	$(MAKE) clean
	$(MAKE) cppcheck

$(name): $(obj) $(LIBCBOR) $(LIBSOLO)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

clean:
	rm -f *.o main.exe main $(obj)
	for f in libs/crypto/tiny-AES-c/Makefile libs/tinycbor/Makefile ; do \
	    if [ -f "$$f" ]; then \
	    	(cd `dirname $$f` ; git checkout -- .) ;\
	    fi ;\
	done
	cd libs/libsolo && $(MAKE) clean
