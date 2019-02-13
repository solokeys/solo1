#!/bin/bash -xe

version=${1:-master}

export PREFIX=/opt/gcc-arm-none-eabi-8-2018-q4-major/bin/

cd /solo/targets/stm32l432
git checkout ${version}
version=$(git describe)
make cbor
make all-hacker

cd /

out_dir="builds"
out_hex="solo-${version}.hex"
out_sha2="solo-${version}.sha2"
cp /solo/targets/stm32l432/solo.hex ${out_dir}/${out_hex}
cd ${out_dir}
sha256sum ${out_hex} > ${out_sha2}

