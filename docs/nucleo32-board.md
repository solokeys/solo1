# Nucleo32 board preparation

Additional steps are required to run the firmware on the Nucleo32 board.

## USB-A cable

Board does not provide an USB cable / socket for the target MCU communication.
Own provided USB plug has to be connected in the following way:

| PIN / Arduino PIN | MCU leg | USB wire color | Signal |
| ----------------- | ------- | -------------- | ------ |
| D10 / PA11        | 21      | white          | D-     |
| D2 / PA12         | 22      | green          | D+     |
| GND (near D2)     | ------- | black          | GND    |
| **not connected** | ------- | red            | 5V     |

Each USB plug pin should be connected via the wire in a color defined by the standard. It might be confirmed with a
multimeter for additional safety. USB plug description:

| PIN | USB wire color | Signal |
| --- | -------------- | ------ |
| 4   | black          | GND    |
| 3   | green          | D+     |
| 2   | white          | D-     |
| 1   | red            | 5V     |

See this [USB plug] image, and Wikipedia's [USB plug description].

Plug in [USB-A_schematic.pdf] has wrong wire order, registered as [solo-hw#1].

The power is taken from the debugger / board (unless the board is configured in another way).
Make sure 5V is not connected, and is covered from contacting with the board elements.

Based on [USB-A_schematic.pdf].

## Nucleo board connection illustration
The picture below shows the connection to Nucleo board. If you want to power the Nucleo board over USB connection, you have to add **USB 5V** to **VIN** Pin. In this case you couldn't use the ST-Link for powering the Nucleo board.

<img src="../images/nucleo_board_connection.png" title="Nucleo Board Connection" />

## Firmware modification

Following patch has to be applied to skip the user presence confirmation, for tests. Might be applied at a later stage.

```text
diff --git a/targets/stm32l432/src/app.h b/targets/stm32l432/src/app.h
index c14a7ed..c89c3b5 100644
--- a/targets/stm32l432/src/app.h
+++ b/targets/stm32l432/src/app.h
@@ -71,6 +71,6 @@ void hw_init(void);
 #define SOLO_BUTTON_PIN         LL_GPIO_PIN_0

 #define SKIP_BUTTON_CHECK_WITH_DELAY        0
-#define SKIP_BUTTON_CHECK_FAST              0
+#define SKIP_BUTTON_CHECK_FAST              1

 #endif
```

It is possible to provide a button and connect it to the MCU pins, as instructed in [USB-A_schematic.pdf]&#x3A;

```text
PA0 / pin 6 --> button --> GND
```

In that case the mentioned patch would not be required.

## Development environment setup

Environment: Fedora 29 x64, Linux 4.19.9

See <https://docs.solokeys.dev/building/> for the original guide. Here details not included there will be covered.

### Install ARM tools Linux

1.  Download current [ARM tools] package: [gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2].

2.  Extract the archive.

3.  Add full path to the `./bin` directory as first entry to the `$PATH` variable,
    as in `~/gcc-arm/gcc-arm-none-eabi-8-2018-q4-major/bin/:$PATH`.

### Install ARM tools OsX using brew package manager

```bash
brew tap ArmMbed/homebrew-formulae
brew install arm-none-eabi-gcc
```

### Install flashing software

ST provides a CLI flashing tool - `STM32_Programmer_CLI`. It can be downloaded directly from the vendor's site:
1. Go to [download site URL](https://www.st.com/content/st_com/en/products/development-tools/software-development-tools/stm32-software-development-tools/stm32-programmers/stm32cubeprog.html), go to bottom page and from STM32CubeProg row select Download button.
2. Unzip contents of the archive.
3. Run \*Linux setup
4. In installation directory go to `./bin` - there the `./STM32_Programmer_CLI` is located
5. Add symlink to the STM32 CLI binary to `.local/bin`. Make sure the latter it is in `$PATH`.

If you're on MacOS X and installed the STM32CubeProg, you need to add the following to your path:

```bash
# ~/.bash_profile
export PATH="/Applications/STMicroelectronics/STM32Cube/STM32CubeProgrammer/STM32CubeProgrammer.app/Contents/MacOs/bin/":$PATH
```

### Adding udev rules Linux

On Linux it might be necessary to install udev rules for **ST-Link V2**.<br>
In case you couldn't download your programm to you Nucleoboard you should add the rules for ST-Link.

Add following file:<br>
***/etc/udev/rules.d/49-stlinkv2-1.rules*** with this content.

```
SUBSYSTEMS=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="374a", \
    MODE:="0666", \
    SYMLINK+="stlinkv2-1_%n"

SUBSYSTEMS=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="374b", \
    MODE:="0666", \
    SYMLINK+="stlinkv2-1_%n"
```

After logout and new login, the ST-Link should work.

## Building and flashing

### Building

Please follow <https://docs.solokeys.dev/building/>, as the build way changes rapidly.
Currently (8.1.19) to build the firmware, following lines should be executed

```bash
# while in the main project directory
cd targets/stm32l432
make cbor
make build-hacker DEBUG=1
```

Note: `DEBUG=2` stops the device initialization, until a serial client will be attached to its virtual port.
Do not use it, if you do not plan to do so.

### Flashing via the Makefile command

```bash
# while in the main project directory
# create Python virtual environment with required packages, and activate
make venv
. venv/bin/activate
# Run flashing
cd ./targets/stm32l432
make flash
 # which runs:
 # flash: solo.hex bootloader.hex
 #	python merge_hex.py solo.hex bootloader.hex all.hex (intelhex library required)
 #	STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
 #	STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst
```

### Manual flashing

In case you already have a firmware to flash (named `all.hex`), please run the following:

```bash
STM32_Programmer_CLI -c port=SWD -halt -e all --readunprotect
STM32_Programmer_CLI -c port=SWD -halt  -d all.hex -rst
```

## Testing

### Internal

Project-provided tests.

#### Simulated device

A simulated device is provided to test the HID layer.

##### Build

```bash
make clean
cd tinycbor
make
cd ..
make env2
```

##### Execution

```bash
# run simulated device (will create a network UDP server)
./main
# run test 1
./env2/bin/python tools/ctap_test.py
# run test 2 (or other files in the examples directory)
./env2/bin/python python-fido2/examples/credential.py
```

#### Real device

```bash
# while in the main project directory
# not passing as of 8.1.19, due to test solution issues
make fido2-test
```

### External

#### FIDO2 test sites

1.  <https://www.passwordless.dev/overview>
2.  <https://webauthn.bin.coffee/>
3.  <https://webauthn.org/>

#### U2F test sites

1.  <https://u2f.bin.coffee/>
2.  <https://demo.yubico.com/u2f>

#### FIDO2 standalone clients

1.  <https://github.com/Nitrokey/u2f-ref-code>
2.  <https://github.com/Yubico/libfido2>
3.  <https://github.com/Yubico/python-fido2>
4.  <https://github.com/google/pyu2f>

## USB serial console reading

Device opens an USB-emulated serial port to output its messages. While Nucleo board offers such already,
the Solo device provides its own.

-   Provided Python tool

```bash
python3 ../../tools/solotool.py monitor /dev/solokey-serial
```

-   External application

```bash
sudo picocom -b 115200 /dev/solokey-serial
```

where `/dev/solokey-serial` is an udev symlink to `/dev/ttyACM1`.

## Other

### Dumping firmware

Size is calculated using bash arithmetic.

```bash
STM32_Programmer_CLI -c port=SWD -halt  -u 0x0 $((256*1024)) current.hex
```

### Software reset

```bash
STM32_Programmer_CLI -c port=SWD  -rst
```

### Installing required Python packages

Client script requires some Python packages, which could be easily installed locally to the project
via the Makefile command. It is sufficient to run:

```bash
make env3
```

[solo-hw#1]: https://github.com/solokeys/solo-hw/issues/1

[usb plug]: https://upload.wikimedia.org/wikipedia/commons/thumb/6/67/USB.svg/1200px-USB.svg.png

[usb plug description]: https://en.wikipedia.org/wiki/USB#Receptacle_(socket)_identification

[usb-a_schematic.pdf]: https://github.com/solokeys/solo-hw/releases/download/1.2/USB-A_schematic.pdf

[arm tools]: https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads

[gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2]: https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major
