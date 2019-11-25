#!/bin/bash
# Build script for sandfly-filescan
#
# sandfly-filescan is a file entropy scanner to spot packed/encrypted binaries on Linux and other platforms.
#
# MIT Licensed (c) 2019 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for current OS."
go build -o sandfly-filescan -ldflags="-s -w" sandfly-filescan
