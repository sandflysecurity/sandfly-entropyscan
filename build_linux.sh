#!/bin/bash
# Build script for sandfly-filescan
#
# sandfly-filescan is a file entropy scanner to spot packed/encrypted binaries on Linux and other platforms.
#
# MIT Licensed (c) 2019 Sandfly Security
# https://www.sandflysecurity.com
# @SandflySecurity

echo "Building for Linux/amd64"
env GOOS=linux GOARCH=amd64 go build -o sandfly-filescan -ldflags="-s -w" sandfly-filescan
