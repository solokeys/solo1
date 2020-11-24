include fido2/version.mk

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

LIBCBOR = tinycbor/lib/libtinycbor.a
LIBSOLO = fido2/libsolo.a

ifeq ($(shell uname -s),Darwin)
  export LDFLAGS = -Wl,-dead_strip
else
  export LDFLAGS = -Wl,--gc-sections
endif
LDFLAGS += $(LIBSOLO) $(LIBCBOR) -lsodium


CFLAGS = -O2 -fdata-sections -ffunction-sections -fcommon -g
ECC_CFLAGS = -O2 -fdata-sections -ffunction-sections -DuECC_PLATFORM=$(ecc_platform)

INCLUDES =  -I../ -I./fido2/ -I./pc -I../pc -I./tinycbor/src

CFLAGS += $(INCLUDES)
CFLAGS += -DAES256=1  -DSOLO_EXPERIMENTAL=1 -DDEBUG_LEVEL=1

name = main

.PHONY: all $(LIBCBOR) $(LIBSOLO) black blackcheck cppcheck wink fido2-test clean full-clean travis test clean version
all: main

tinycbor/Makefile crypto/tiny-AES-c/aes.c:
	git submodule update --init

.PHONY: cbor cborclean
cbor: $(LIBCBOR)

cborclean:
	cd tinycbor && $(MAKE) clean

$(LIBCBOR):
	cd tinycbor/ && $(MAKE)  LDFLAGS='' -j8

$(LIBSOLO):
	cd fido2/ && $(MAKE) CFLAGS="$(CFLAGS)" ECC_CFLAGS="$(ECC_CFLAGS)" APP_CONFIG=app.h -j8

version:
	@git describe

test: venv
	$(MAKE) cborclean
	$(MAKE) clean
	$(MAKE) -C . main
	$(MAKE) clean
	$(MAKE) -C ./targets/stm32l432 test PREFIX=$(PREFIX) "VENV=$(VENV)" VERSION_FULL=${SOLO_VERSION_FULL}
	$(MAKE) clean
	$(MAKE) cppcheck

$(name): $(obj) $(LIBCBOR) $(LIBSOLO)
	$(CC) $(LDFLAGS) -o $@ $(obj) $(LDFLAGS)

venv:
	python3 -m venv venv
	venv/bin/pip -q install --upgrade pip
	venv/bin/pip -q install --upgrade -r tools/requirements.txt
	venv/bin/pip -q install --upgrade black

# selectively reformat our own code
black: venv
	venv/bin/black --skip-string-normalization --check tools/

wink: venv
	venv/bin/solo key wink

fido2-test: venv
	venv/bin/python tools/ctap_test.py

update:
	git fetch --tags
	git checkout master
	git rebase origin/master
	git submodule update --init --recursive

DOCKER_TOOLCHAIN_IMAGE := "solokeys/solo-firmware-toolchain"

docker-build-toolchain:
	docker build -t $(DOCKER_TOOLCHAIN_IMAGE) .
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}.${SOLO_VERSION_MIN}

uncached-docker-build-toolchain:
	docker build --no-cache -t $(DOCKER_TOOLCHAIN_IMAGE) .
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}.${SOLO_VERSION_MIN}

docker-build-all:
	docker run --rm -v "$(CURDIR)/builds:/builds" \
					-v "$(CURDIR):/solo" \
					-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
				    $(DOCKER_TOOLCHAIN_IMAGE) "solo/in-docker-build.sh" ${SOLO_VERSION_FULL}

CPPCHECK_FLAGS=--quiet --error-exitcode=2

cppcheck:
	cppcheck $(CPPCHECK_FLAGS) crypto/aes-gcm
	cppcheck $(CPPCHECK_FLAGS) crypto/sha256
	cppcheck $(CPPCHECK_FLAGS) fido2
	cppcheck $(CPPCHECK_FLAGS) pc

clean:
	rm -f *.o main.exe main $(obj)
	for f in crypto/tiny-AES-c/Makefile tinycbor/Makefile ; do \
	    if [ -f "$$f" ]; then \
	    	(cd `dirname $$f` ; git checkout -- .) ;\
	    fi ;\
	done
	cd fido2 && $(MAKE) clean

full-clean: clean
	rm -rf venv

test-docker:
	rm -rf builds/*
	$(MAKE) uncached-docker-build-toolchain
	# Check if there are 4 docker images/tas named "solokeys/solo-firmware-toolchain"
	NTAGS=$$(docker images | grep -c "solokeys/solo-firmware-toolchain") && [ $$NTAGS -eq 4 ]
	$(MAKE) docker-build-all

travis:
	$(MAKE) test VENV=". ../../venv/bin/activate;"
	$(MAKE) test-docker
	$(MAKE) black
