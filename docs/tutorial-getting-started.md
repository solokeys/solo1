# Tutorial: Getting started with the solo hacker

This is small guide to let you get started with the solo hacker key. In the end you will have set up everything you need and changed the LED from green to red.

## Some additional ressources

This tutorial will take you through all the necessary steps needed to install and get the solo key running. Before we start, I will just list you additional ressources, which might have important information for you:

* [The git repository](https://github.com/solokeys/solo): Here you will find all the code and a quick readme.
* [The Documenation](https://docs.solokeys.io/solo/building/): The official documentation. Especially the [build instructions](https://docs.solokeys.io/solo/building/) are worth a look, if you got stuck.

## Getting the prerequisites

There are two main tools you will need to work on your solo hacker:

* ARM Compiler tool chain
* Solo python tool

The ARM Compiler is used to compile your C-code to a hex file, which can then be deployed onto your solo hacker. The solo tool helps with deploying, updating etc. of the solo hacker. It is a python3 tool. So make sure, that you got Python3 installed on your system \([pip](https://pip.pypa.io/en/stable/) might also come in handy\).  
  
Besides that, you will also need to get the [solo code](https://github.com/solokeys/solo).

### Get the code

The codebase for the solo hacker and other solo keys, can be found at this [git repository](https://github.com/solokeys/solo). So just clone this into your development folder. Make sure, that all the submodules are loaded by using the following command. I forgot to get all the submoules at my first try and the make command failed \(I got an error message telling me, that no solo.elf target can be found\).

```bash
git clone --recurse-submodules https://github.com/solokeys/solo
```

### Getting the ARM Compiler tool chain

Download the Compiler tool chain for your system [here](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm/downloads). After you have downloaded it, you will have to unzip it and add the path to the installation folder.   
  
**Readme**  
There is a readme.txt __ in _gcc-arm-none-eabi-x-yyyy-dd-major/share/doc/gcc-arm-none-eabi_. It contains installation guides for Linux, Windows and Mac.   
  
**Installation**  
As I used Mac, I will guide you through the installation using MacOS. If you have unpacked the folder already, you can skip the first step.

```bash
#Unzip the tarball
cd $install_dir && tar xjf gcc-arm-none-eabi-*-yyyymmdd-mac.tar.bz2

#Set path
export PATH=$PATH:$install_dir/gcc-arm-none-eabi-*/bin

#Test if it works
arm-none-eabi-gcc
```

If everything worked your output should like this:

```bash
arm-none-eabi-gcc: fatal error: no input files
compilation terminated.
```

### Getting the solo tool

There are several ways, which are listed at the [build instructions](https://docs.solokeys.io/solo/building/). If you are familiar with pip, just use this.

```bash
pip install solo-python

#Or
pip3 install solo-python
```

**Install all other requirements**

To do this either do it in the virtual env or directly on your machine. The requirements can be found in the source folder in requirements.txt.

```bash
#Move to source folder
cd solo

#Install requirements, use pip3 otherwise
pip install -r solo/tools/requirements.txt
```

## Let's get a red light blinking

You will find the code for the key in _/solo/targets/stm32l432_ \(The target might have another id for you, so just use that id\). The LED colors can be found in [_/solo/targets/stm32l432 /src/app.h_](https://github.com/solokeys/solo/blob/master/targets/stm32l432/src/app.h)_._ To change the color we will just have to change the hex-value. Out of the box it should look like this:

```c
//                          0xRRGGBB
#define LED_INIT_VALUE          0x000800
#define LED_WINK_VALUE          0x000010
#define LED_MAX_SCALER          15
#define LED_MIN_SCALER          1
```

_LED\_INIT\_VALUE_ is the color, that the LED shows whenever it is plugged in. It normally is a green light. So let's change it to red:

```c
//                          0xRRGGBB
#define LED_INIT_VALUE          0xFF0800
#define LED_WINK_VALUE          0x000010
#define LED_MAX_SCALER          15
#define LED_MIN_SCALER          1
```

_LED\_WINK\_VALUE_ is the color, which is shown, whenever the bottom is pressed. It normally is a blue tone, but let's change it to a yellow:

```c
//                          0xRRGGBB
#define LED_INIT_VALUE          0xFF0800
#define LED_WINK_VALUE          0xFFFF00
#define LED_MAX_SCALER          15
#define LED_MIN_SCALER          1
```

Save the file and then let's try to get the code onto the stick.

## Move code to solo hacker

First we have to build cbor. To do this change into the target folder and use the corresponding command.

```bash
#Change into correct directory
cd solo/targets/stm32l432/

#Make cbor
make cbor
```

You should also make sure to check, that your key has the newest solo firmware installed. To check the firmware on the device, use this command:

```bash
solo key version
```

To update to the newest version, use this command:

```bash
solo key update
```

**Note:** Sometimes the connection between Mac and key seemed to be broken and you might get an error stating: _No solo found_. Just unplug the key and plug it back in.

### General deployment cycle

In general we will always have to go through these steps:

* Compile code and generate new firmware
* Change device into bootloader mode
* Deploy code to device

#### Compile code

To compile the code, we will again have to change into our target directory:

```bash
#Change into correct directory
cd solo/targets/stm32l432/
```

It is important to choose the correct build target. Most explanations focus on the build of the firmware and use:

```bash
make firmware
```

As we are using the solo hacker, we will need to use:

```bash
make build-hacker
```

This will generate a file _solo.hex_, which has the compiled code on it. If you later need to change the bootloader itself, please refer to [the documentation](https://docs.solokeys.io/solo/building/).

#### Deploy code

To deploy the code make sure you are back at the source root. 

```bash
cd ../..
```

First we will have to change into bootload modus:

```bash
solo program aux enter-bootloader
```

This is needed to be able to load the new firmware on the device. If we forget this step, the solo tool will do it for us in the next step.

This is the moment of truth. We delete the old firmware and deploy the new one with the changed LED lights to the solo key. For this step we will also stay in the source root.

```bash
solo program bootloader targets/stm32l432/solo.hex
```

If there is another hex-File, that you want to load, you can just exchange the last argument.  
  
And that's it, now your LED should be red.  
  
To summarize, here are again the steps to update your solo:

1. Change code
2. Run these commands

```bash
#Change into correct directory
cd solo/targets/stm32l432/

#Compile code
make build-hacker

#Change to root
cd ../..

#Enter bootloader mode
solo program aux enter-bootloader

#Deploy code
solo program bootloader targets/stm32l432/solo.hex
```
