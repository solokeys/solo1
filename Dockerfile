# Step 1: build the firmware
FROM debian:stretch-slim
MAINTAINER SoloKeys <hello@solokeys.com>

RUN apt-get update -qq
RUN apt-get install -qq bzip2 git make wget >/dev/null

# get ARM GCC
RUN wget -q -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major
#   from website
RUN echo "f55f90d483ddb3bcf4dae5882c2094cd  gcc.tar.bz2" > gcc.md5
RUN md5sum -c gcc.md5
#   self-generated
RUN echo "fb31fbdfe08406ece43eef5df623c0b2deb8b53e405e2c878300f7a1f303ee52  gcc.tar.bz2" > gcc.sha256
RUN sha256sum -c gcc.sha256
RUN tar -C /opt -xf gcc.tar.bz2

# get Solo source code
RUN git clone --recurse-submodules https://github.com/solokeys/solo

# build Solo
ENV PREFIX=/opt/gcc-arm-none-eabi-8-2018-q4-major/bin/
RUN cd solo/targets/stm32l432 && \
    make cbor boot-no-sig clean all-hacker


# Step 2: combine the firmware
FROM debian:stretch-slim
MAINTAINER SoloKeys <hello@solokeys.com>

RUN apt-get update -qq
RUN apt-get install -qq bzip2 git make wget >/dev/null

# get Python3.7
RUN wget -q -O miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-4.5.12-Linux-x86_64.sh
#   from website
RUN echo "866ae9dff53ad0874e1d1a60b1ad1ef8  miniconda.sh" > miniconda.md5
RUN md5sum -c miniconda.md5
#   self-generated
RUN echo "e5e5b4cd2a918e0e96b395534222773f7241dc59d776db1b9f7fedfcb489157a  miniconda.sh" > miniconda.sha256
RUN sha256sum -c miniconda.sha256

RUN bash ./miniconda.sh -b -p /opt/conda
RUN ln -s /opt/conda/bin/python3 /usr/local/bin/python3

# get Solo source code
RUN git clone --recurse-submodules https://github.com/solokeys/solo

# actually combine the two hex files
COPY --from=0 /solo/targets/stm32l432/solo.elf .
COPY --from=0 /solo/targets/stm32l432/solo.hex .
COPY --from=0 /solo/targets/stm32l432/bootloader.elf .
COPY --from=0 /solo/targets/stm32l432/bootloader.hex .

RUN cd solo && make env3 && . env3/bin/activate && \
    python3 tools/solotool.py mergehex /bootloader.hex /solo.hex /all.hex


# Step 3: copy out firmware, assumes host volume mounted at /out
FROM alpine
MAINTAINER SoloKeys <hello@solokeys.com>

COPY --from=1 /solo.elf .
COPY --from=1 /solo.hex .
COPY --from=1 /bootloader.elf .
COPY --from=1 /bootloader.hex .
COPY --from=1 /all.hex .

CMD cp -v /solo.elf /solo.hex /bootloader.elf /bootloader.hex /all.hex /out
