// Sandfly filescan file utilities to calculate entropy, crypto hashes, etc
package fileutils

/*
This utility will help find packed or encrypted files on a Linux system by calculating the entropy to see how
random they are. Packed or encrypted malware often appears to be a very random executable file and this utility
can help identify potential problems.

You can calculate entropy on all files, or limit the search just to Linux ELF executables that have an entropy of
your threshold.

Sandfly Security produces an agentless intrusion detection and incident response platform for Linux. You can
find out more about how it works at: https://www.sandflysecurity.com

MIT License

Copyright (c) 2019 Sandfly Security Ltd.
https://www.sandlfysecurity.com

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Version: 1.0
Date: 2019-11-23
Author: Craig H. Rowland  @CraigHRowland  @SandflySecurity
*/

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"os"
)

const (
	// Max file size for entropy, etc. is 2GB
	constMaxFileSize = 2147483648
	// Chunk of data size to read in for entropy calc
	constMaxEntropyChunk = 256000
	// Need 4 bytes to determine basic ELF type
	constMagicNumRead = 4
	// Magic number for basic ELF type
	constMagicNumElf = "7f454c46"
)

// Pass in a path and we'll see if the magic number is Linux ELF type.
func IsElfType(path string) (isElf bool, err error) {
	var hexData [constMagicNumRead]byte

	if path == "" {
		return false, fmt.Errorf("must provide a path to file to get ELF type")
	}

	f, err := os.Open(path)
	if err != nil {
		return false, err
	}

	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return false, err
	}

	// Not a regular file, so can't be ELF
	if !fStat.Mode().IsRegular() {
		return false, nil
	}

	// Too small to be ELF
	if fStat.Size() < constMagicNumRead {
		return false, nil
	}

	err = binary.Read(f, binary.LittleEndian, &hexData)
	if err != nil {
		return false, err
	}

	elfType, err := hex.DecodeString(constMagicNumElf)
	if err != nil {
		return false, err
	}
	if len(elfType) > constMagicNumRead {
		return false, fmt.Errorf("elf magic number string is longer than magic number read bytes")
	}

	if bytes.Equal(hexData[:len(elfType)], elfType) {
		return true, nil
	}

	return false, nil
}

// Calculates entropy of a file.
func Entropy(path string) (entropy float64, err error) {
	var size int64

	if path == "" {
		return entropy, fmt.Errorf("must provide a path to file to get entropy")
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("couldn't open path (%s) to get entropy: %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return 0, err
	}

	if !fStat.Mode().IsRegular() {
		return 0, fmt.Errorf("file (%s) is not a regular file to calculate entropy", path)
	}

	size = fStat.Size()
	// Zero sized file is zero entropy.
	if size == 0 {
		return 0, nil
	}

	if size > int64(constMaxFileSize) {
		return 0, fmt.Errorf("file size (%d) is too large to calculate entropy (max allowed: %d)",
			size, int64(constMaxFileSize))
	}

	dataBytes := make([]byte, constMaxEntropyChunk)
	byteCounts := make([]int, 256)
	for {
		numBytesRead, err := f.Read(dataBytes)
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}

		// For each byte of the data that was read, increment the count
		// of that number of bytes seen in the file in our byteCounts
		// array
		for i := 0; i < numBytesRead; i++ {
			byteCounts[int(dataBytes[i])]++
		}
	}

	for i := 0; i < 256; i++ {
		px := float64(byteCounts[i]) / float64(size)
		if px > 0 {
			entropy += -px * math.Log2(px)
		}
	}

	// Returns rounded to nearest two decimals.
	return math.Round(entropy*100) / 100, nil
}

// Generates MD5 hash of a file
func HashMD5(path string) (hash string, err error) {
	if path == "" {
		return hash, fmt.Errorf("must provide a path to file to hash")
	}

	f, err := os.Open(path)
	if err != nil {
		return hash, fmt.Errorf("couldn't open path (%s): %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return hash, err
	}

	if !fStat.Mode().IsRegular() {
		return hash, fmt.Errorf("file (%s) is not a regular file to calculate hash", path)
	}

	// Zero sized file is no hash.
	if fStat.Size() == 0 {
		return hash, nil
	}

	if fStat.Size() > int64(constMaxFileSize) {
		return hash, fmt.Errorf("file size (%d) is too large to calculate hash (max allowed: %d)",
			fStat.Size(), int64(constMaxFileSize))
	}

	hashMD5 := md5.New()
	_, err = io.Copy(hashMD5, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get MD5 hash: %v", path, err)
	}

	hash = hex.EncodeToString(hashMD5.Sum(nil))

	return hash, nil
}

// Generates SHA1 hash of a file
func HashSHA1(path string) (hash string, err error) {
	if path == "" {
		return hash, fmt.Errorf("must provide a path to file to hash")
	}

	f, err := os.Open(path)
	if err != nil {
		return hash, fmt.Errorf("couldn't open path (%s): %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return hash, err
	}

	if !fStat.Mode().IsRegular() {
		return hash, fmt.Errorf("file (%s) is not a regular file to calculate hash", path)
	}

	// Zero sized file is no hash.
	if fStat.Size() == 0 {
		return hash, nil
	}

	if fStat.Size() > int64(constMaxFileSize) {
		return hash, fmt.Errorf("file size (%d) is too large to calculate hash (max allowed: %d)",
			fStat.Size(), int64(constMaxFileSize))
	}

	hashSHA1 := sha1.New()
	_, err = io.Copy(hashSHA1, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get SHA1 hash: %v", path, err)
	}

	hash = hex.EncodeToString(hashSHA1.Sum(nil))

	return hash, nil
}

// Generates SHA256 hash of a file
func HashSHA256(path string) (hash string, err error) {
	if path == "" {
		return hash, fmt.Errorf("must provide a path to file to hash")
	}

	f, err := os.Open(path)
	if err != nil {
		return hash, fmt.Errorf("couldn't open path (%s): %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return hash, err
	}

	if !fStat.Mode().IsRegular() {
		return hash, fmt.Errorf("file (%s) is not a regular file to calculate hash", path)
	}

	// Zero sized file is no hash.
	if fStat.Size() == 0 {
		return hash, nil
	}

	if fStat.Size() > int64(constMaxFileSize) {
		return hash, fmt.Errorf("file size (%d) is too large to calculate hash (max allowed: %d)",
			fStat.Size(), int64(constMaxFileSize))
	}

	hashSHA256 := sha256.New()
	_, err = io.Copy(hashSHA256, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get SHA256 hash: %v", path, err)
	}

	hash = hex.EncodeToString(hashSHA256.Sum(nil))

	return hash, nil
}

// Generates SHA512 hash of a file
func HashSHA512(path string) (hash string, err error) {
	if path == "" {
		return hash, fmt.Errorf("must provide a path to file to hash")
	}

	f, err := os.Open(path)
	if err != nil {
		return hash, fmt.Errorf("couldn't open path (%s): %v", path, err)
	}
	defer f.Close()

	fStat, err := f.Stat()
	if err != nil {
		return hash, err
	}

	if !fStat.Mode().IsRegular() {
		return hash, fmt.Errorf("file (%s) is not a regular file to calculate hash", path)
	}

	// Zero sized file is no hash.
	if fStat.Size() == 0 {
		return hash, nil
	}

	if fStat.Size() > int64(constMaxFileSize) {
		return hash, fmt.Errorf("file size (%d) is too large to calculate hash (max allowed: %d)",
			fStat.Size(), int64(constMaxFileSize))
	}

	hashSHA512 := sha512.New()
	_, err = io.Copy(hashSHA512, f)
	if err != nil {
		return hash, fmt.Errorf("couldn't read path (%s) to get SHA512 hash: %v", path, err)
	}

	hash = hex.EncodeToString(hashSHA512.Sum(nil))

	return hash, nil
}
