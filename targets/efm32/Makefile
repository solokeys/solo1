
CC=arm-none-eabi-gcc

all:
	cd 'GNU ARM v7.2.1 - Debug' && make all


#arm-none-eabi-gcc -g -gdwarf-2 -mcpu=cortex-m4 -mthumb -std=c99 '-DDEBUG=1' '-DEFM32PG1B200F256GM48=1' -IC:/Users/conor/Desktop/u2f-one/crypto/sha256 -IC:/Users/conor/Desktop/u2f-one/crypto/micro-ecc -IC:/Users/conor/Desktop/u2f-one/crypto/tiny-AES-c -I"C:\Users\conor\Desktop\u2f-one\efm32\inc" -IC:/Users/conor/Desktop/u2f-one/fido2 -IC:/Users/conor/Desktop/u2f-one/tinycbor/src -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//platform/CMSIS/Include" -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//hardware/kit/common/drivers" -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//hardware/kit/SLSTK3401A_EFM32PG/config" -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//platform/Device/SiliconLabs/EFM32PG1B/Include" -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//platform/emlib/inc" -I"C:/SiliconLabs/SimplicityStudio/v4/developer/sdks/gecko_sdk_suite/v1.1//hardware/kit/common/bsp" -O0 -Wall -c -fmessage-length=0 -mno-sched-prolog -fno-builtin -ffunction-sections -fdata-sections -mfpu=fpv4-sp-d16 -mfloat-abi=softfp -MMD -MP -MF"src/device.d" -MT"src/device.o" -o "src/device.o" "../src/device.c"


#arm-none-eabi-gcc -g -gdwarf-2 -mcpu=cortex-m4 -mthumb -T "EFM32.ld" -Xlinker --gc-sections -Xlinker -Map="EFM32.map" -mfpu=fpv4-sp-d16 -mfloat-abi=softfp --specs=nano.specs -o EFM32.axf "./CMSIS/EFM32PG1B/startup_gcc_efm32pg1b.o" "./CMSIS/EFM32PG1B/system_efm32pg1b.o" "./crypto/micro-ecc/uECC.o" "./crypto/sha256/sha256.o" "./crypto/tiny-AES-c/aes.o" "./emlib/em_assert.o" "./emlib/em_cmu.o" "./emlib/em_emu.o" "./emlib/em_gpio.o" "./emlib/em_system.o" "./emlib/em_usart.o" "./fido2/crypto.o" "./fido2/ctap.o" "./fido2/ctap_parse.o" "./fido2/ctaphid.o" "./fido2/log.o" "./fido2/main.o" "./fido2/stubs.o" "./fido2/test_power.o" "./fido2/u2f.o" "./fido2/util.o" "./src/InitDevice.o" "./src/device.o" "./src/main.o" "./src/printing.o" "./src/retargetio.o" -Wl,--start-group -lgcc -lc -lnosys -Wl,--end-group


cbor:
	cd ../tinycbor/ && make clean
	cd ../tinycbor/ && make CC="$(CC)" \
LDFLAGS="-lgcc -lc -lnosys --specs=nosys.specs -mcpu=cortex-m4 -mfloat-abi=softfp -mfpu=fpv4-sp-d16 -mthumb " \
CFLAGS="-g -gdwarf-2 -mcpu=cortex-m4 -mthumb -std=c99 -DEFM32PG1B200F256GM48=1 -O3 -Wall -c -fmessage-length=0 -mno-sched-prolog -fno-builtin -ffunction-sections -fdata-sections -mfpu=fpv4-sp-d16 -mfloat-abi=softfp -MMD -MP "



clean:
	cd 'GNU ARM v7.2.1 - Debug' && make clean
