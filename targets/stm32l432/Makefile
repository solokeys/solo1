ifndef DEBUG
DEBUG=0
endif

APPMAKE=build/application.mk
BOOTMAKE=build/bootloader.mk

merge_hex=solo mergehex

.PHONY: all all-hacker all-locked debugboot-app debugboot-boot boot-sig-checking boot-no-sig build-release-locked build-release build-release build-hacker build-debugboot clean clean2 flash flash_dfu flashboot detach cbor test


# The following are the main targets for reproducible builds.
# TODO: better explanation
firmware-hacker:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=0 EXTRA_DEFINES='-DSOLO_HACKER -DFLASH_ROP=0'

firmware-hacker-debug-1:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=1 EXTRA_DEFINES='-DSOLO_HACKER -DFLASH_ROP=0'

firmware-hacker-debug-2:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=2 EXTRA_DEFINES='-DSOLO_HACKER -DFLASH_ROP=0'

firmware-secure-non-solokeys:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=0 EXTRA_DEFINES='-DFLASH_ROP=2'

firmware-secure:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=0 EXTRA_DEFINES='-DUSE_SOLOKEYS_CERT -DFLASH_ROP=2'

bootloader-nonverifying:
	$(MAKE) -f $(BOOTMAKE) -j8 bootloader.hex PREFIX=$(PREFIX) EXTRA_DEFINES='-DSOLO_HACKER' DEBUG=0

bootloader-verifying:
	$(MAKE) -f $(BOOTMAKE) -j8 bootloader.hex PREFIX=$(PREFIX) DEBUG=0

full-clean: clean2


# The older targets, may be re-organised
all:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=$(DEBUG) EXTRA_DEFINES='-DFLASH_ROP=1'

all-hacker:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) DEBUG=$(DEBUG) EXTRA_DEFINES='-DSOLO_HACKER -DFLASH_ROP=0'

all-locked:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex PREFIX=$(PREFIX) EXTRA_DEFINES='-DFLASH_ROP=2'

debugboot-app:
	$(MAKE) -f $(APPMAKE) -j8 solo.hex DEBUG=2 PREFIX=$(PREFIX) \
	LDSCRIPT=linker/stm32l4xx_extra.ld EXTRA_DEFINES='-DAPPLICATION_START_PAGE=16 -DSOLO_HACKER'

debugboot-boot:
	$(MAKE) -f $(BOOTMAKE) -j8 bootloader.hex PREFIX=$(PREFIX) DEBUG=1 \
	LDSCRIPT=linker/bootloader_stm32l4xx_extra.ld EXTRA_DEFINES='-DAPPLICATION_START_PAGE=16 -DSOLO_HACKER'

boot-sig-checking:
	$(MAKE) -f $(BOOTMAKE) -j8 bootloader.hex PREFIX=$(PREFIX) DEBUG=0

boot-no-sig:
	$(MAKE) -f $(BOOTMAKE) -j8 bootloader.hex PREFIX=$(PREFIX) EXTRA_DEFINES='-DSOLO_HACKER' DEBUG=0

build-release-locked: cbor clean2 boot-sig-checking clean all-locked
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex

build-release: cbor clean2 boot-sig-checking clean all
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex

build-hacker: cbor clean2 boot-no-sig clean all-hacker
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex

build-debugboot: clean2 debugboot-boot clean debugboot-app
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex

clean:
	$(MAKE) -f $(APPMAKE) clean
	$(MAKE) -f $(BOOTMAKE) clean
clean2:
	rm -f solo.hex solo.map bootloader.hex bootloader.map all.hex
	$(MAKE) -f $(APPMAKE) clean
	$(MAKE) -f $(BOOTMAKE) clean

flash: solo.hex bootloader.hex
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst

flash_dfu: solo.hex bootloader.hex
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex
	# STM32_Programmer_CLI -c port=usb1 -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=usb1 -halt -rdu  -d all.hex

flashboot: solo.hex bootloader.hex
	$(VENV) $(merge_hex) solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d bootloader.hex -rst

flash-firmware:
	arm-none-eabi-size -A solo.elf
	solo program aux enter-bootloader
	solo program bootloader solo.hex

# tell ST DFU to enter application
detach:
	STM32_Programmer_CLI -c port=usb1 -ob nBOOT0=1

bootloader.hex:
	echo "You need to build the bootloader first."

solo.hex:
	echo "You need to build the application first."

cbor:
	$(MAKE) -f $(APPMAKE) -j8 cbor

test:
	$(MAKE) build-release-locked
	$(MAKE) build-release
	$(MAKE) build-hacker
	$(MAKE) build-debugboot
	$(MAKE) clean2
