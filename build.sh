#!/bin/bash
# Build script for sandfly-entropyscan
#
# sandfly-entropyscan is an entropy scanner to spot packed/encrypted binaries and processes on Linux and other platforms.
#
# MIT Licensed (c) 2019-2022 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for current OS."
go build -ldflags="-s -w" 