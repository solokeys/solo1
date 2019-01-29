FROM debian:stretch-slim
MAINTAINER SoloKeys <hello@solokeys.com>

# get build requirements
RUN apt-get update -qq
RUN apt-get install -qq git make wget bzip2 >/dev/null

# get Python3.7
RUN wget -q https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh
RUN bash ./Miniconda3-latest-Linux-x86_64.sh -b -p /tmp/conda
RUN ln -s /tmp/conda/bin/python3 /usr/local/bin/python3

# get ARM GCC
RUN wget -q -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major
RUN echo "f55f90d483ddb3bcf4dae5882c2094cd  gcc.tar.bz2" > gcc.md5
RUN md5sum -c gcc.md5
RUN tar -C /opt -xf gcc.tar.bz2

# get Solo source code
RUN git clone --recurse-submodules https://github.com/solokeys/solo

# build Solo
RUN cd solo && make env3
ENV PREFIX=/opt/gcc-arm-none-eabi-8-2018-q4-major/bin/
RUN . solo/env3/bin/activate && cd solo/targets/stm32l432 && \
    make cbor && \
    make build-hacker

# Would prefer `FROM scratch`, not sure how to copy firmware out though?
FROM alpine
COPY --from=0 /solo/targets/stm32l432/solo.elf .
COPY --from=0 /solo/targets/stm32l432/solo.hex .
COPY --from=0 /solo/targets/stm32l432/bootloader.elf .
COPY --from=0 /solo/targets/stm32l432/bootloader.hex .
COPY --from=0 /solo/targets/stm32l432/all.hex .
