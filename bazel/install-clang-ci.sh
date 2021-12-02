#!/bin/bash

LLVM_VERSION=12.0.0
LLVM_TAR=clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-20.04.tar.xz
TARGET_DST=/opt/llvm

wget https://github.com/llvm/llvm-project/releases/download/llvmorg-${LLVM_VERSION}/${LLVM_TAR}

if [[ ! -e "${TARGET_DST}" ]]; then
  mkdir -p ${TARGET_DST}
fi

tar -xvf ${LLVM_TAR} -C ${TARGET_DST} --strip-components 1
