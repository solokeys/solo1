FROM debian:stretch-slim
MAINTAINER SoloKeys <hello@solokeys.com>

RUN apt-get update -qq
RUN apt-get install -qq bzip2 git make wget >/dev/null

# 1. ARM GCC: for compilation
RUN wget -q -O gcc.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2019q3/RC1.1/gcc-arm-none-eabi-8-2019-q3-update-linux.tar.bz2?revision=c34d758a-be0c-476e-a2de-af8c6e16a8a2?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2019-q3-update
#   from website
RUN echo "6341f11972dac8de185646d0fbd73bfc  gcc.tar.bz2" > gcc.md5
RUN md5sum -c gcc.md5
#   self-generated
RUN echo "b50b02b0a16e5aad8620e9d7c31110ef285c1dde28980b1a9448b764d77d8f92  gcc.tar.bz2" > gcc.sha256
RUN sha256sum -c gcc.sha256
RUN tar -C /opt -xf gcc.tar.bz2

# 2. Python3.7: for solo-python (merging etc.)
RUN wget -q -O miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-4.5.12-Linux-x86_64.sh
#   from website
RUN echo "866ae9dff53ad0874e1d1a60b1ad1ef8  miniconda.sh" > miniconda.md5
RUN md5sum -c miniconda.md5
#   self-generated
RUN echo "e5e5b4cd2a918e0e96b395534222773f7241dc59d776db1b9f7fedfcb489157a  miniconda.sh" > miniconda.sha256
RUN sha256sum -c miniconda.sha256

RUN bash ./miniconda.sh -b -p /opt/conda
RUN ln -s /opt/conda/bin/python /usr/local/bin/python3
RUN ln -s /opt/conda/bin/python /usr/local/bin/python
RUN ln -s /opt/conda/bin/pip /usr/local/bin/pip3
RUN ln -s /opt/conda/bin/pip /usr/local/bin/pip

# 3. Source code
RUN git clone --recurse-submodules https://github.com/solokeys/solo /solo --config core.autocrlf=input
