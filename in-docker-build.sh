#!/bin/bash -xe

version=${1:-master}

export PREFIX=/opt/gcc-arm-none-eabi-8-2018-q4-major/bin/

cd /solo/targets/stm32l432
git fetch --tags
git checkout ${version}
git submodule update --init --recursive
version=$(git describe)

make cbor

out_dir="/builds"

function build() {
    part=${1}
    variant=${2}
    output=${3:-${part}}
    what="${part}-${variant}"

    make full-clean

    make ${what}

    out_hex="${what}-${version}.hex"
    out_sha2="${what}-${version}.sha2"

    mv ${output}.hex ${out_hex}
    sha256sum ${out_hex} > ${out_sha2}
    cp ${out_hex} ${out_sha2} ${out_dir}
}

build bootloader nonverifying
build bootloader verifying
build firmware hacker solo
build firmware hacker-debug-1 solo
build firmware hacker-debug-2 solo
build firmware secure solo
build firmware secure-non-solokeys solo

pip install -U pip
pip install -U solo-python
cd ${out_dir}
bundle="bundle-hacker-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-hacker-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2
bundle="bundle-hacker-debug-1-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-hacker-debug-1-${version}.hex ${bundle}.hex
bundle="bundle-hacker-debug-2-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-hacker-debug-2-${version}.hex ${bundle}.hex
bundle="bundle-secure-non-solokeys-${version}"
/opt/conda/bin/solo mergehex bootloader-verifying-${version}.hex firmware-secure-non-solokeys-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2
