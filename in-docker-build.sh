#!/bin/bash -xe
version=$1

export PREFIX=/opt/gcc-arm-none-eabi-8-2019-q3-update/bin/
source ${CARGO_HOME}/env

cd /solo/targets/stm32l432
ls

make cbor
make salty

out_dir="/builds"

function build() {
    part=${1}
    output=${2}
    what="${part}"

    make full-clean

    make ${what} VERSION_FULL=${version}

    out_hex="${what}-${version}.hex"
    out_sha2="${what}-${version}.sha2"

    mv ${output}.hex ${out_hex}
    sha256sum ${out_hex} > ${out_sha2}
    cp ${out_hex} ${out_sha2} ${out_dir}
}

build bootloader-nonverifying bootloader
build bootloader-verifying bootloader
build firmware solo
build firmware-debug-1 solo
build firmware-debug-2 solo
build firmware solo

cd ${out_dir}

bundle="bundle-hacker-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2

bundle="bundle-hacker-debug-1-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-debug-1-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2

bundle="bundle-hacker-debug-2-${version}"
/opt/conda/bin/solo mergehex bootloader-nonverifying-${version}.hex firmware-debug-2-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2

bundle="bundle-secure-non-solokeys-${version}"
/opt/conda/bin/solo mergehex --lock bootloader-verifying-${version}.hex firmware-${version}.hex ${bundle}.hex
sha256sum ${bundle}.hex > ${bundle}.sha2
