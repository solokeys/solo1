TOP := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
KERNEL_FULL_VERSION := $(shell uname -r)
KERNEL_VERSION := $(shell uname -r | grep -o "^[^-]*")
KERNEL_MAJOR := $(shell uname -r | cut -d. -f1)
KERNEL_MINOR := $(shell uname -r | cut -d. -f2)

MANUFACTURER = "Solo"
SERIAL = "1234567890"
IDVENDOR = "0x0483"
IDPRODUCT = "0xa2ca"
PRODUCT = "Solo Software Authenticator"
CONFIGFS = /sys/kernel/config
CONFIGFS_FIDO2 = $(CONFIGFS)/usb_gadget/fido2

obj-m := dummy_hcd.o
KVERSION := $(shell uname -r)
SHELL := /bin/bash

all: dummy_hcd.ko

install: dummy_hcd.ko
	modprobe libcomposite
	insmod dummy_hcd.ko
	mkdir -p $(CONFIGFS_FIDO2)
	mkdir -p $(CONFIGFS_FIDO2)/configs/c.1
	mkdir -p $(CONFIGFS_FIDO2)/functions/hid.usb0
	echo 0 > $(CONFIGFS_FIDO2)/functions/hid.usb0/protocol
	echo 0 > $(CONFIGFS_FIDO2)/functions/hid.usb0/subclass
	echo 64 > $(CONFIGFS_FIDO2)/functions/hid.usb0/report_length
	echo -ne "\x06\xd0\xf1\x09\x01\xa1\x01\x09\x20\x15\x00\x26\xff\x00\x75\x08\x95\x40\x81\x02\x09\x21\x15\x00\x26\xff\x00\x75\x08\x95\x40\x91\x02\xc0" > $(CONFIGFS_FIDO2)/functions/hid.usb0/report_desc
	mkdir $(CONFIGFS_FIDO2)/strings/0x409
	mkdir $(CONFIGFS_FIDO2)/configs/c.1/strings/0x409
	echo $(IDPRODUCT) > $(CONFIGFS_FIDO2)/idProduct
	echo $(IDVENDOR) > $(CONFIGFS_FIDO2)/idVendor
	echo $(SERIAL) > $(CONFIGFS_FIDO2)/strings/0x409/serialnumber
	echo $(MANUFACTURER) > $(CONFIGFS_FIDO2)/strings/0x409/manufacturer
	echo $(PRODUCT) > $(CONFIGFS_FIDO2)/strings/0x409/product
	echo "Configuration 1" > $(CONFIGFS_FIDO2)/configs/c.1/strings/0x409/configuration
	echo 120 > $(CONFIGFS_FIDO2)/configs/c.1/MaxPower
	ln -s $(CONFIGFS_FIDO2)/functions/hid.usb0 $(CONFIGFS_FIDO2)/configs/c.1
	echo "dummy_udc.0" > $(CONFIGFS_FIDO2)/UDC

uninstall:
	echo "" > $(CONFIGFS_FIDO2)/UDC
	rm $(CONFIGFS_FIDO2)/configs/c.1/hid.usb0
	rmdir $(CONFIGFS_FIDO2)/configs/c.1/strings/0x409
	rmdir $(CONFIGFS_FIDO2)/configs/c.1
	rmdir $(CONFIGFS_FIDO2)/functions/hid.usb0
	rmdir $(CONFIGFS_FIDO2)/strings/0x409
	rmdir $(CONFIGFS_FIDO2)
	rmmod dummy_hcd.ko

dummy_hcd.ko: dummy_hcd.c
	$(MAKE) -C /lib/modules/$(KERNEL_FULL_VERSION)/build M=$(TOP) modules

dummy_hcd.c: /usr/src/linux-source-$(KERNEL_VERSION).tar.bz2
	tar -xvf $^ linux-source-$(KERNEL_VERSION)/drivers/usb/gadget/udc/dummy_hcd.c
	cp linux-source-$(KERNEL_VERSION)/drivers/usb/gadget/udc/dummy_hcd.c $@

clean:
	$(MAKE) -C /lib/modules/$(KERNEL_FULL_VERSION)/build M=$(TOP) clean
	rm -rf linux-source-$(KERNEL_VERSION)
	rm -f dummy_hcd.c


