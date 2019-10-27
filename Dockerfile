FROM debian:9.11-slim
MAINTAINER SoloKeys <hello@solokeys.com>

# Install necessary packages
RUN apt-get update  \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    make \
    wget \
    bzip2 \
    git \
  && rm -rf /var/lib/apt/lists/*

# Install ARM compiler
RUN set -eux; \
	url="https://developer.arm.com/-/media/Files/downloads/gnu-rm/8-2019q3/RC1.1/gcc-arm-none-eabi-8-2019-q3-update-linux.tar.bz2?revision=c34d758a-be0c-476e-a2de-af8c6e16a8a2?product=GNU%20Arm%20Embedded%20Toolchain,64-bit,,Linux,8-2019-q3-update"; \
	wget -O gcc.tar.bz2 "$url"; \
  echo "6341f11972dac8de185646d0fbd73bfc gcc.tar.bz2" | md5sum -c -; \
	echo "b50b02b0a16e5aad8620e9d7c31110ef285c1dde28980b1a9448b764d77d8f92 gcc.tar.bz2" | sha256sum -c -; \
	tar -C /opt -xf gcc.tar.bz2; \
	rm gcc.tar.bz2;

# Python3.7: for solo-python (merging etc.)
RUN set -eux; \
	url="https://repo.anaconda.com/miniconda/Miniconda3-4.5.12-Linux-x86_64.sh"; \
	wget -O miniconda.sh "$url"; \
  echo "866ae9dff53ad0874e1d1a60b1ad1ef8 miniconda.sh" | md5sum -c -; \
	echo "e5e5b4cd2a918e0e96b395534222773f7241dc59d776db1b9f7fedfcb489157a miniconda.sh" | sha256sum -c -; \
	bash ./miniconda.sh -b -p /opt/conda; \
  ln -s /opt/conda/bin/python /usr/local/bin/python3; \
  ln -s /opt/conda/bin/python /usr/local/bin/python; \
  ln -s /opt/conda/bin/pip /usr/local/bin/pip3; \
  ln -s /opt/conda/bin/pip /usr/local/bin/pip; \
	rm miniconda.sh; \
  pip install -U pip

# solo-python (Python3.7 script for merging etc.)
RUN pip install -U solo-python