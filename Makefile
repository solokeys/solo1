#Load commons variables
include common.mk

.PHONY: all $(LIBCBOR) $(LIBSOLO) black blackcheck cppcheck wink clean full-clean travis test clean version pc stm32l432
all: pc stm32l432

pc:
	$(MAKE) -C $(TARGET_PC_PATH) $(ACTION)

stm32l432:
	$(MAKE) -C $(TARGET_STM32L432_PATH) $(ACTION)

$(LIB_TINYCBOR_PATH)/Makefile $(LIB_TINY_AES_PATH)/aes.c:
	git submodule update --init

version:
	@git describe

test: venv
	$(MAKE) clean
	$(MAKE) pc
	$(MAKE) clean
	$(MAKE) -C $(TARGET_STM32L432_PATH) test PREFIX=$(PREFIX) "VENV=$(VENV)" VERSION_FULL=${SOLO_VERSION_FULL}
	$(MAKE) clean
	$(MAKE) cppcheck

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

clean:
	$(MAKE) -C $(LIB_TINYCBOR_PATH) clean
	$(MAKE) pc ACTION=clean
	$(MAKE) stm32l432 ACTION=clean-artifacts

full-clean: clean
	rm -rf venv


docker-build-toolchain:
	docker build -t $(DOCKER_TOOLCHAIN_IMAGE) ./tools/docker/
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}.${SOLO_VERSION_MIN}

uncached-docker-build-toolchain:
	docker build --no-cache -t $(DOCKER_TOOLCHAIN_IMAGE) ./tools/docker/
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}
	docker tag $(DOCKER_TOOLCHAIN_IMAGE):latest $(DOCKER_TOOLCHAIN_IMAGE):${SOLO_VERSION_MAJ}.${SOLO_VERSION_MIN}

CPPCHECK_FLAGS=--quiet --error-exitcode=2
cppcheck:
	cppcheck $(CPPCHECK_FLAGS) $(LIB_AES_GCM_PATH)
	cppcheck $(CPPCHECK_FLAGS) $(LIB_SHA256_PATH)
	cppcheck $(CPPCHECK_FLAGS) $(LIB_SOLO_PATH)
	$(MAKE) pc ACTION=cppcheck

travis:
	$(MAKE) test VENV=". ../../venv/bin/activate;"
	$(MAKE) uncached-docker-build-toolchain
	$(MAKE) stm32l432 ACTION=test-docker
	$(MAKE) black