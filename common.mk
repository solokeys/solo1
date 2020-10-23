# common.mk
# This defines variable for easier path manipulation in other Makefiles

PROJECT_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

LIBS_PATH := $(PROJECT_ROOT)libs
LIB_SOLO_PATH := $(LIBS_PATH)/libsolo
LIB_TINYCBOR_PATH := $(LIBS_PATH)/tinycbor

LIBS_CRYPTO_PATH := $(LIBS_PATH)/crypto
LIB_CIFRA_PATH := $(LIBS_CRYPTO_PATH)/cifra
LIB_TINY_AES_PATH := $(LIBS_CRYPTO_PATH)/tiny-AES-c
LIB_SHA256_PATH := $(LIBS_CRYPTO_PATH)/sha256
LIB_MICRO_ECC_PATH := $(LIBS_CRYPTO_PATH)/micro-ecc
LIB_AES_GCM_PATH := $(LIBS_CRYPTO_PATH)/aes-gcm

TARGETS_PATH := $(PROJECT_ROOT)/targets
TARGET_PC_PATH := $(TARGETS_PATH)/pc/
TARGET_STM32L432_PATH := $(TARGETS_PATH)/stm32l432/

DOCKER_TOOLCHAIN_IMAGE := "solokeys/solo-firmware-toolchain"

include $(PROJECT_ROOT)/libs/libsolo/version.mk
