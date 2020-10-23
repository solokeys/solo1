# Load paths
include ../../common.mk

#define uECC_arch_other 0
#define uECC_x86        1
#define uECC_x86_64     2
#define uECC_arm        3
#define uECC_arm_thumb  4
#define uECC_arm_thumb2 5
#define uECC_arm64      6
#define uECC_avr        7
ecc_platform=2

src = device.c main.c

obj = $(src:.c=.o)

LIBCBOR = $(LIB_TINYCBOR_PATH)/lib/libtinycbor.a
LIBSOLO = $(LIB_SOLO_PATH)/libsolo.a

ifeq ($(shell uname -s),Darwin)
  export LDFLAGS = -Wl,-dead_strip
else
  export LDFLAGS = -Wl,--gc-sections
endif
LDFLAGS += $(LIBSOLO) $(LIBCBOR)


CFLAGS = -O2 -fdata-sections -ffunction-sections -g
ECC_CFLAGS = -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(ecc_platform)

INCLUDES = -I$(LIB_SOLO_PATH) -I$(TARGET_PC_PATH) -I$(LIB_TINYCBOR_PATH)/src

CFLAGS += $(INCLUDES)
CFLAGS += -DAES256=1  -DSOLO_EXPERIMENTAL=1 -DDEBUG_LEVEL=1

name = main

.PHONY: all $(LIBCBOR) $(LIBSOLO) cppcheck clean version
all: main

$(LIB_TINYCBOR_PATH)/Makefile $(LIB_TINY_AES_PATH)/aes.c:
	git submodule update --init

.PHONY: cbor
cbor: $(LIBCBOR)

$(LIBCBOR):
	cd $(LIB_TINYCBOR_PATH) && $(MAKE)  LDFLAGS='' -j8

$(LIBSOLO):
	cd $(LIB_SOLO_PATH) && $(MAKE) CFLAGS="$(CFLAGS)" ECC_CFLAGS="$(ECC_CFLAGS)" APP_CONFIG=app.h -j8

version:
	@git describe

test:
	$(MAKE) clean
	$(MAKE) main
	$(MAKE) clean
	$(MAKE) cppcheck

$(name): $(obj) $(LIBCBOR) $(LIBSOLO)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

cppcheck:
	cppcheck $(CPPCHECK_FLAGS) $(TARGET_PC_PATH)

clean:
	rm -f *.o main.exe main $(obj)
	for f in $(LIB_TINY_AES_PATH)/Makefile $(LIB_TINYCBOR_PATH)/Makefile ; do \
	    if [ -f "$$f" ]; then \
	    	(cd `dirname $$f` ; git checkout -- .) ;\
	    fi ;\
	done
	cd $(LIB_SOLO_PATH) && $(MAKE) clean
