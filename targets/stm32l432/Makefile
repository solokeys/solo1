ifndef DEBUG
DEBUG=0
endif

merge_hex=python ../../tools/solotool.py mergehex

all:
	$(MAKE) -f application.mk -j8 solo.hex DEBUG=$(DEBUG) EXTRA_DEFINES='-DFLASH_ROP=1'

all-hacker:
	$(MAKE) -f application.mk -j8 solo.hex DEBUG=$(DEBUG) EXTRA_DEFINES='-DSOLO_HACKER -DFLASH_ROP=0'

all-locked:
	$(MAKE) -f application.mk -j8 solo.hex EXTRA_DEFINES='-DFLASH_ROP=2'

debugboot-app:
	$(MAKE) -f application.mk -j8 solo.hex DEBUG=2 \
	LDSCRIPT=linker/stm32l4xx_extra.ld EXTRA_DEFINES='-DAPPLICATION_START_PAGE=16 -DSOLO_HACKER'

debugboot-boot:
	$(MAKE) -f bootloader.mk -j8 bootloader.hex DEBUG=1 \
	LDSCRIPT=linker/bootloader_stm32l4xx_extra.ld EXTRA_DEFINES='-DAPPLICATION_START_PAGE=16 -DSOLO_HACKER'

boot-sig-checking:
	$(MAKE) -f bootloader.mk -j8 bootloader.hex DEBUG=0

boot-no-sig:
	$(MAKE) -f bootloader.mk -j8 bootloader.hex EXTRA_DEFINES='-DSOLO_HACKER' DEBUG=0

build-release-locked: clean2 boot-sig-checking clean all-locked
	$(merge_hex) solo.hex bootloader.hex all.hex
	rm -f solo.hex bootloader.hex  # don't program solo.hex ...

build-release: clean2 boot-sig-checking clean all
	$(merge_hex) solo.hex bootloader.hex all.hex

build-hacker: clean2 boot-no-sig clean all-hacker
	$(merge_hex) solo.hex bootloader.hex all.hex

clean:
	$(MAKE) -f application.mk clean
	$(MAKE) -f bootloader.mk clean
clean2:
	rm -f solo.hex bootloader.hex all.hex
	$(MAKE) -f application.mk clean
	$(MAKE) -f bootloader.mk clean


flash: solo.hex bootloader.hex
	$(merge_hex) solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst

flash_dfu: solo.hex bootloader.hex
	$(merge_hex) solo.hex bootloader.hex all.hex
	# STM32_Programmer_CLI -c port=usb1 -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=usb1 -halt -rdu  -d all.hex

flashboot: solo.hex bootloader.hex
	$(merge_hex) solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d bootloader.hex -rst

# tell ST DFU to enter application
detach:
	STM32_Programmer_CLI -c port=usb1 -ob nBOOT0=1

bootloader.hex:
	echo "You need to build the bootloader first."

solo.hex:
	echo "You need to build the application first."

cbor:
	$(MAKE) -f application.mk -j8 cbor
