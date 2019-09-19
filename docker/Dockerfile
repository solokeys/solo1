FROM debian:stretch-slim

LABEL maintainer="SoloKeys <hello@solokeys.com>"

RUN apt update \
    && apt install -y \ 
        bzip2 \
        git \
        make \
        wget \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2018q4/gcc-arm-none-eabi-8-2018-q4-major-linux.tar.bz2?revision=d830f9dd-cd4f-406d-8672-cca9210dd220?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2018-q4-major \
    && echo "fb31fbdfe08406ece43eef5df623c0b2deb8b53e405e2c878300f7a1f303ee52  gcc.tar.bz2" > gcc.sha256 \
    && sha256sum -c gcc.sha256 \
    && tar -C /opt -xf gcc.tar.bz2 \
    && rm gcc.sha256 gcc.tar.bz2 \
    && wget -q -O miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-4.5.12-Linux-x86_64.sh \
    && echo "e5e5b4cd2a918e0e96b395534222773f7241dc59d776db1b9f7fedfcb489157a  miniconda.sh" > miniconda.sha256\ 
    && sha256sum -c miniconda.sha256 \
    && rm miniconda.sha256 \
    && bash ./miniconda.sh -b -p /opt/conda \
    && ln -s /opt/conda/bin/python /usr/local/bin/python3 \
    && ln -s /opt/conda/bin/python /usr/local/bin/python \
    && ln -s /opt/conda/bin/pip /usr/local/bin/pip3 \
    && ln -s /opt/conda/bin/pip /usr/local/bin/pip \
    && git clone --recurse-submodules https://github.com/solokeys/solo /solo --config core.autocrlf=input

WORKDIR /solo
