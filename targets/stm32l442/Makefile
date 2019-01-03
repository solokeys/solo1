ifndef DEBUG
DEBUG=0
endif

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
	$(MAKE) -f bootloader.mk -j8 bootloader.hex

boot-no-sig:
	$(MAKE) -f bootloader.mk -j8 bootloader.hex EXTRA_DEFINES='-DSOLO_HACKER'

clean:
	$(MAKE) -f application.mk clean
	$(MAKE) -f bootloader.mk clean

flash: solo.hex bootloader.hex
	python merge_hex.py solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst

flash_dfu: solo.hex bootloader.hex
	python merge_hex.py solo.hex bootloader.hex all.hex
	# STM32_Programmer_CLI -c port=usb1 -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=usb1 -halt -rdu  -d all.hex

flashboot: solo.hex bootloader.hex
	python merge_hex.py solo.hex bootloader.hex all.hex
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
