include libs/libsolo/version.mk


.PHONY: all $(LIBCBOR) $(LIBSOLO) black blackcheck cppcheck wink fido2-test clean full-clean travis test clean version
all: main

pc:
    cd targets/pc
    $(MAKE) all


libs/tinycbor/Makefile libs/crypto/tiny-AES-c/aes.c:
	git submodule update --init

version:
	@git describe

test: venv
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