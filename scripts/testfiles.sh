#!/bin/bash
# Test script to generate random and non-random data for testing sandfly-entropyscan
#
# sandfly-entropyscan is a file entropy scanner to spot packed/encrypted binaries and processes on Linux and other platforms.
#
# MIT Licensed (c) 2019-2022 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Creating high entropy random executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./high.entropy.test
head -c 50000 </dev/urandom >> ./high.entropy.test

echo "Creating low entropy executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./low.entropy.test
head -c 50000 </dev/zero >> ./low.entropy.test

echo "Running sandfly-entropyscan to generate entropy and hash values."
../sandfly-entropyscan -dir . -elf