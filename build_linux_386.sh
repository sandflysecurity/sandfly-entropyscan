#!/bin/bash
# Build script for sandfly-filescan
#
# sandfly-filescan is a file entropy scanner to spot packed/encrypted binaries on Linux and other platforms.
#
# MIT Licensed (c) 2019 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for Linux/386"
env GOOS=linux GOARCH=386 go build -o sandfly-filescan.386 -ldflags="-s -w" sandfly-filescan
