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

LIBCBOR = tinycbor/lib/libtinycbor.a
LDFLAGS = -Wl,--gc-sections $(LIBCBOR)
CFLAGS = -O2 -fdata-sections -ffunction-sections

INCLUDES = -I./tinycbor/src -I./crypto/sha256 -I./crypto/micro-ecc/ -Icrypto/tiny-AES-c/ -I./fido2/ -I./pc -I./fido2/extensions

CFLAGS += $(INCLUDES)
# for crypto/tiny-AES-c
CFLAGS += -DAES256=1

name = main

.PHONY: all
all: main

tinycbor/Makefile crypto/tiny-AES-c/aes.c:
	git submodule update --init

.PHONY: cbor
cbor: $(LIBCBOR)

$(LIBCBOR): tinycbor/Makefile
	cd tinycbor/ && $(MAKE) clean && $(MAKE) -j8

test:
	$(MAKE) -C . main

.PHONY: efm8prog
efm8prog:
	cd './targets/efm8\Keil 8051 v9.53 - Debug' && $(MAKE) all
	flashefm8.exe -part EFM8UB10F8G -sn 440105518 -erase
	flashefm8.exe -part EFM8UB10F8G -sn 440105518 -upload './targets/efm8/Keil 8051 v9.53 - Debug/efm8.hex'

.PHONY: efm32com efm32prog efm32read efm32bootprog
efm32com:
	cd './targets/efm32/GNU ARM v7.2.1 - Debug' && $(MAKE) all
efm32prog: efm32com
	commander flash './targets/efm32/GNU ARM v7.2.1 - Debug/EFM32.hex' $(EFM32_DEBUGGER)  -p "0x1E7FC:0x00000000:4"
efm32read: efm32com
	commander swo read $(EFM32_DEBUGGER)
efm32bootprog: efm32com
	commander flash './efm32boot/GNU ARM v7.2.1 - Debug/efm32boot.hex' $(EFM32_DEBUGGER) --masserase

$(name): $(obj) $(LIBCBOR)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

uECC.o: ./crypto/micro-ecc/uECC.c
	$(CC) -c -o $@ $^ -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(platform) -I./crypto/micro-ecc/


# python virtualenv

venv:
	@if ! which virtualenv >/dev/null ; then \
	    echo "ERR: Sorry, no python virtualenv found. Please consider installing " ;\
	    echo "     it via something like:" ;\
	    echo "   sudo apt install python-virtualenv" ;\
	    echo "     or maybe:" ;\
	    echo "   pip install virtualenv" ;\
	fi
	virtualenv venv
	./venv/bin/pip install wheel

venv/bin/mkdocs: venv
	./venv/bin/pip install mkdocs mkdocs-material

.PHONY: docsrv
docsrv:	venv/bin/mkdocs
	./venv/bin/mkdocs serve

.PHONY: fido2-test
fido2-test:
	./venv/bin/python tools/ctap_test.py

clean:
	rm -f *.o main.exe main $(obj)
	for f in crypto/tiny-AES-c/Makefile tinycbor/Makefile ; do \
	    if [ -f "$$f" ]; then \
	    	(cd `dirname $$f` ; git checkout -- .) ;\
	    fi ;\
	done
