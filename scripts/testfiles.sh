#!/bin/bash
# Test script to generate random and non-random data for testing sandfly-filescan
#
# sandfly-filescan is a file entropy scanner to spot packed/encrypted binaries on Linux and other platforms.
#
# MIT Licensed (c) 2019 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Creating high entropy random executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./high.entropy.test
head -c 50000 </dev/urandom >> ./high.entropy.test

echo "Creating low entropy executable-like file in current directory."
echo -en "\x7f\x45\x4c\x46" > ./low.entropy.test
head -c 50000 </dev/zero >> ./low.entropy.test

echo "Running sandfly-filescan to generate entropy and hash values."
../sandfly-filescan -dir . -elf