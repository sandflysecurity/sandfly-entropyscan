// Sandfly Security Linux Entropy Scanning Utility
package main

/*
This utility will help find packed or encrypted files or processes on a Linux system by calculating the entropy
to see how random they are. Packed or encrypted malware often appears to be a very random executable file and this
utility can help identify potential intrusions.

You can calculate entropy on all files, or limit the search just to Linux ELF executables that have an entropy of
your threshold. Linux processes can be scanned as well automatically.

Sandfly Security produces an agentless intrusion detection and incident response platform for Linux. You can
find out more about how it works at: https://www.sandflysecurity.com

MIT License

Copyright (c) 2019-2022 Sandfly Security Ltd.
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

Version: 1.1
Author: @SandflySecurity
*/

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strconv"

	"gihub.com/sandflysecurity/sandfly-entropyscan/fileutils"
)

const (
	// constVersion Version
	constVersion = "1.1"
	// constProcDir default /proc dir for processes.
	constProcDir = "/proc"
	// constDelimeterDefault default delimiter for CSV output.
	constDelimeterDefault = ","
	// constMinPID minimum PID value allowed for process checks.
	constMinPID = 1
	// constMaxPID maximum PID value allowed for process checks. 64bit linux is 2^22. This value is a limiter.
	constMaxPID = 4194304
)

type fileData struct {
	path    string
	name    string
	entropy float64
	elf     bool
	hash    hashes
}

type hashes struct {
	md5    string
	sha1   string
	sha256 string
	sha512 string
}

func main() {
	var filePath string
	var dirPath string
	var delimChar string
	var entropyMaxVal float64
	var elfOnly bool
	var procOnly bool
	var csvOutput bool
	var version bool

	flag.StringVar(&filePath, "file", "", "full path to a single file to analyze")
	flag.StringVar(&dirPath, "dir", "", "directory name to analyze")
	flag.StringVar(&delimChar, "delim", constDelimeterDefault, "delimeter for CSV output")
	flag.Float64Var(&entropyMaxVal, "entropy", 0, "show any file with entropy greater than or equal to this value (0.0 - 8.0 max 8.0, default is 0)")
	flag.BoolVar(&elfOnly, "elf", false, "only check ELF executables")
	flag.BoolVar(&procOnly, "proc", false, "check running processes")
	flag.BoolVar(&csvOutput, "csv", false, "output results in CSV format (filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)")
	flag.BoolVar(&version, "version", false, "show version and exit")
	flag.Parse()

	if version {
		fmt.Printf("sandfly-entropyscan Version %s\n", constVersion)
		fmt.Printf("Copyright (c) 2019-2022 Sandlfy Security - www.sandflysecurity.com\n\n")
		os.Exit(0)
	}

	if entropyMaxVal > 8 {
		log.Fatal("max entropy value is 8.0")
	}
	if entropyMaxVal < 0 {
		log.Fatal("min entropy value is 0.0")
	}

	if procOnly {
		// This will do a PID bust of all PID range to help detect hidden PIDs.
		pidPaths, err := genPIDExePaths()
		if err != nil {
			log.Fatalf("error generating PID list: %v\n", err)
		}
		for pid := 0; pid < len(pidPaths); pid++ {
			// Only check elf files which should be all these will be anyway.
			fileInfo, err := checkFilePath(pidPaths[pid], true, entropyMaxVal)
			// anything that is not an error is a valid /proc/*/exe link we could see and process. We will analyze it.
			if err == nil {
				if fileInfo.entropy >= entropyMaxVal {
					printResults(fileInfo, csvOutput, delimChar)
				}
			}
		}
		os.Exit(0)
	}

	if filePath != "" {
		fileInfo, err := checkFilePath(filePath, elfOnly, entropyMaxVal)
		if err != nil {
			log.Fatalf("error processing file (%s): %v\n", filePath, err)
		}

		if fileInfo.entropy >= entropyMaxVal {
			printResults(fileInfo, csvOutput, delimChar)
		}

		os.Exit(0)
	}

	if dirPath != "" {
		var search = func(filePath string, info os.FileInfo, err error) error {
			if err != nil {
				log.Fatalf("error walking directory (%s) inside search function: %v\n", filePath, err)
			}
			// If info comes back as nil we don't want to read it or we panic.
			if info != nil {
				// if not a directory, then check it for a file we want.
				if !info.IsDir() {
					// Only check regular files. Checking devices, etc. won't work.
					if info.Mode().IsRegular() {
						fileInfo, err := checkFilePath(filePath, elfOnly, entropyMaxVal)
						if err != nil {
							log.Fatalf("error processing file (%s): %v\n", filePath, err)
						}

						if fileInfo.entropy >= entropyMaxVal {
							printResults(fileInfo, csvOutput, delimChar)
						}
					}
				}
			}
			return nil
		}
		err := filepath.Walk(dirPath, search)
		if err != nil {
			log.Fatalf("error walking directory (%s): %v\n", dirPath, err)
		}
		os.Exit(0)
	}
}

// Prints results
func printResults(fileInfo fileData, csvFormat bool, delimChar string) {

	if !csvFormat {
		fmt.Printf("filename: %s\npath: %s\nentropy: %.2f\nelf: %v\nmd5: %s\nsha1: %s\nsha256: %s\nsha512: %s\n\n",
			fileInfo.name,
			fileInfo.path,
			fileInfo.entropy,
			fileInfo.elf,
			fileInfo.hash.md5,
			fileInfo.hash.sha1,
			fileInfo.hash.sha256,
			fileInfo.hash.sha512)
	} else {
		fmt.Printf("%s%s%s%s%.2f%s%v%s%s%s%s%s%s%s%s\n",
			fileInfo.name,
			delimChar,
			fileInfo.path,
			delimChar,
			fileInfo.entropy,
			delimChar,
			fileInfo.elf,
			delimChar,
			fileInfo.hash.md5,
			delimChar,
			fileInfo.hash.sha1,
			delimChar,
			fileInfo.hash.sha256,
			delimChar,
			fileInfo.hash.sha512)
	}
}

func checkFilePath(filePath string, elfOnly bool, entropyMaxVal float64) (fileInfo fileData, err error) {
	isElfType, err := fileutils.IsElfType(filePath)
	if err != nil {
		return fileInfo, err
	}
	_, fileName := filepath.Split(filePath)

	fileInfo.path = filePath
	fileInfo.name = fileName
	fileInfo.elf = isElfType
	fileInfo.entropy = -1

	// If they only want Linux ELFs.
	if elfOnly && isElfType {
		entropy, err := fileutils.Entropy(filePath)
		if err != nil {
			log.Fatalf("error calculating entropy for file (%s): %v\n", filePath, err)
		}
		fileInfo.entropy = entropy
	}
	// They want entropy on all files.
	if !elfOnly {
		entropy, err := fileutils.Entropy(filePath)
		if err != nil {
			log.Fatalf("error calculating entropy for file (%s): %v\n", filePath, err)
		}
		fileInfo.entropy = entropy
	}

	if fileInfo.entropy >= entropyMaxVal {
		md5, err := fileutils.HashMD5(filePath)
		if err != nil {
			log.Fatalf("error calculating MD5 hash for file (%s): %v\n", filePath, err)
		}
		sha1, err := fileutils.HashSHA1(filePath)
		if err != nil {
			log.Fatalf("error calculating SHA1 hash for file (%s): %v\n", filePath, err)
		}
		sha256, err := fileutils.HashSHA256(filePath)
		if err != nil {
			log.Fatalf("error calculating SHA256 hash for file (%s): %v\n", filePath, err)
		}
		sha512, err := fileutils.HashSHA512(filePath)
		if err != nil {
			log.Fatalf("error calculating SHA512 hash for file (%s): %v\n", filePath, err)
		}
		fileInfo.hash.md5 = md5
		fileInfo.hash.sha1 = sha1
		fileInfo.hash.sha256 = sha256
		fileInfo.hash.sha512 = sha512
	}

	return fileInfo, nil
}

func genPIDExePaths() (pidPaths []string, err error) {

	for pid := constMinPID; pid < constMaxPID; pid++ {
		pidPaths = append(pidPaths, path.Join(constProcDir, strconv.Itoa(pid), "/exe"))
	}

	return pidPaths, nil
}
