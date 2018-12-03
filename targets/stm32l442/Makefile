
all:
	$(MAKE) -f application.mk -j8 solo.hex

boot:
	$(MAKE) -f bootloader.mk -j8 bootloader.hex

clean:
	$(MAKE) -f application.mk clean
	$(MAKE) -f bootloader.mk clean

flash: solo.hex bootloader.hex
	python merge_hex.py solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst

flashboot: solo.hex bootloader.hex
	python merge_hex.py solo.hex bootloader.hex all.hex
	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
	STM32_Programmer_CLI -c port=SWD -halt  -d bootloader.hex -rst

bootloader.hex:
	echo "You need to build the bootloader first."

solo.hex:
	echo "You need to build the application first."

cbor:
	$(MAKE) -f application.mk -j8 cbor
