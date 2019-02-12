CC=$(PREFIX)arm-none-eabi-gcc
CP=$(PREFIX)arm-none-eabi-objcopy
SZ=$(PREFIX)arm-none-eabi-size
AR=$(PREFIX)arm-none-eabi-ar

VERSION=$(shell git describe --abbrev=0 )
VERSION_FULL=$(shell git describe)
VERSION_MAJ=$(shell python -c 'print("$(VERSION)".split(".")[0])')
VERSION_MIN=$(shell python -c 'print("$(VERSION)".split(".")[1])')
VERSION_PAT=$(shell python -c 'print("$(VERSION)".split(".")[2])')

VERSION_FLAGS= -DSOLO_VERSION_MAJ=$(VERSION_MAJ) -DSOLO_VERSION_MIN=$(VERSION_MIN) \
	-DSOLO_VERSION_PATCH=$(VERSION_PAT) -DVERSION=\"$(VERSION_FULL)\"

_all:
	echo $(VERSION_FULL)
	echo $(VERSION_MAJ)
	echo $(VERSION_MIN)
	echo $(VERSION_PAT)
