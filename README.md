# What is sandfly-entropyscan?

`sandfly-entropyscan` is a utility to quickly scan files or running processes and report on their entropy (measure 
of randomness) and if they are a Linux/Unix ELF type executable. Some malware for Linux is packed or encrypted and 
shows very high entropy. This tool can quickly find high entropy executable files and processes which often are 
malicious.

# Features

* Written in Golang and is portable across multiple architectures with no modifications.
* Standalone binary requires no dependencies and can be used instanly without loading any libraries on suspect machines.
* Not affected by LD_PRELOAD style rootkits that are cloaking files. 
* Built-in PID busting to find hidden/cloaked processes from certain types of Loadable Kernel Module (LKM) rootkits.
* Generates entropy and also MD5, SHA1, SHA256 and SHA512 hash values of files.
* Can be used in scanning scripts to find problems automatically.
* Can be used by incident responders to quickly scan and zero in on potential malware on a Linux host. 

# Why Scan for Entropy?

Entropy is a measure of randomness. For binary data 0.0 is not-random and 8.0 is perfectly random. Good crypto looks 
like random white noise and will be near 8.0. Good compression removes redundant data making it appear more random 
than if it was uncompressed and usually will be 7.7 or above.

A lot of malware executables are packed to avoid detection and make reverse engineering harder. Most standard Linux 
binaries are not packed because they aren't trying to hide what they are. Searching for high entropy files is a good 
way to find programs that could be malicious just by having these two attributes of high entropy and executable. 

# How Do I Use This?

Usage of `sandfly-entropyscan`:

`  -csv`
    	output results in CSV format (filename, path, entropy, elf_file [true|false], MD5, SHA1, SHA256, SHA512)

`  -delim`
		change the default delimiter for CSV files of "," to one of your choosing ("|", etc.)
    	
`  -dir string`
    	directory name to analyze
    	
`  -file string`
    	full path to a single file to analyze

`  -proc`
		check running processes (defaults to ELF only check)

`  -elf`
    	only check ELF executables
    	
`  -entropy float`
    	show any file/process with entropy greater than or equal to this value (0.0 min - 8.0 max, defaults 0 to show all files)
    	
`   -version`
    	show version and exit

# Examples

Search for any file that is executable under /tmp:

`sandfly-entropyscan -dir /tmp -elf`

Search for high entropy (7.7 and higher) executables (often packed or encrypted) under /var/www:

`sandfly-entropyscan -dir /var/www -elf -entropy 7.7`

Generates entropy and cryptographic hashes of all running processes in CSV format:

`sandfly-entropyscan -proc -csv`

Search for any process with an entropy higher than 7.7 indicating it is likely packed or encrypted:

`sandfly-entropyscan -proc -entropy 7.7`

Generate entropy and cryptographic hash values of all files under /bin and output to CSV format (for instance to save and compare hashes):

`sandfly-entropyscan -dir /bin -csv`

Scan a directory for all files (ELF or not) with entropy greater than 7.7:
(potentially large list of files that are compressed, png, jpg, object files, etc.)

`sandfly-entropyscan -dir /path/to/dir -entropy 7.7`

Quickly check a file and generate entropy, cryptographic hashes and show if it is executable:

`sandfly-entropyscan -file /dev/shm/suspicious_file`

# Use Cases

Do spot checks on systems you think have a malware issue. Or you can automate the scan so you will get an output 
if we find something show up that is high entropy in a place you didn't expect. Or simply flag any executable ELF type 
file that is somewhere strange (e.g. hanging out in /tmp or under a user's HTML directory). For instance:

Did a high entropy binary show up under the system /var/www directory? Could be someone put a malware dropper
on your website:

`sandfly-entropyscan -dir /var/www -elf -entropy 7.7`

Setup a cron task to scan your /tmp, /var/tmp, and /dev/shm directories for any kind of executable file whether it's 
high entropy or not. Executable files under tmp directories can frequently be a malware dropper.

`sandfly-entropyscan -dir /tmp -elf`

`sandfly-entropyscan -dir /var/tmp -elf`

`sandfly-entropyscan -dir /dev/shm -elf`

Setup another cron or automated security sweep to spot check your systems for highly compressed or encrypted binaries that 
are running:

`sandfly-entropyscan -proc -entropy 7.7`

# Build

* Install latest version of golang (www.golang.org)
* Clone the repo:

`git clone https://github.com/sandflysecurity/sandfly-entropyscan.git`

* Go into the repo directory and build it:

`go build`

* Run the binary with your options:

`./sandfly-entropyscan`

## Build Scripts

There are a some basic build scripts that build for various platforms. You can use these to build or modify to suit.
For Incident Responders, it might be useful to keep pre-compiled binaries ready to go on your investigation box.

`build.sh` - Build for current OS you're running on when you execute it.

# ELF Detection

We use a simple method for seeing if a file may be an executable ELF type. We can spot ELF format files for 
multiple platforms. Even if malware has Intel/AMD, MIPS and Arm dropper binaries we will still be able to spot all of 
them.

# False Positives

It's possible to flag a legitimate binary that has a high entropy because of how it was compiled, or because
it was packed for legitimate reasons. Other files like .zip, .gz, .png, .jpg and such also have very high entropy 
because they are compressed formats. Compression removes redundancy in a file which makes it appear to be more 
random and has higher entropy.

On Linux, you may find some kinds of libraries (.so files) get flagged if you scan library directories.

However, it is our experience that executable binaries that also have high entropy are often malicious. This is 
especially true if you find them in areas where executables normally shouldn't be (such as again `tmp` or `html` 
directories).

# Performance

The entropy calculation requires reading in all the bytes of the file and tallying them up to get a final number. It 
can use a lot of CPU and disk I/O, especially on very large file systems or very large files. The program has an 
internal limit where it won't calculate entropy on any file over 2GB, nor will it try to calculate entropy on any
file that is not a regular file type (e.g. won't try to calculate entropy on devices like `/dev/zero`).

Then we calculate MD5, SHA1, SHA256 and SHA512 hashes. Each of these requires going over the file as well. It's 
reasonable speed on modern systems, but if you are crawling a very large file system it can take some time to
complete.

If you tell the program to only look at ELF files, then the entropy/hash calculations won't happen unless it is an
ELF type and this will save a lot of time (e.g. it will ignore massive database files that aren't executable).

If you want to automate this program, it's best to not have it crawl the entire root file system unless you want
that specifically. A targeted approach will be faster and more useful for spot checks. Also, use the ELF flag as that
will drastically reduce search times by only processing executable file types.

# Incident Response 

For incident responders, running `sandfly-entropyscan` against the entire top-level "/" directory may be a good idea just 
to quickly get a list of likely packed candidates to investigate. This will spike CPU and disk I/O. However, you probably 
don't care at that point since the box has been mining cryptocurrency for 598 hours anyway by the time the admins 
noticed. 

Again, use the ELF flag to get to the likely problem candidate executables and ignore the noise. 

# Testing

There is a script called `scripts/testfiles.sh` that will make two files. One will be full of random data and one will not be
random at all. When you run the script it will make the files and run `sandfly-entropyscan` in executable detection mode.
You should see two files. One with very high entropy (at or near 8.0) and one full of non-random data that should
be at 0.00 for low entropy. Example:

`./testfiles.sh`

Creating high entropy random executable-like file in current directory.

Creating low entropy executable-like file in current directory.

high.entropy.test, entropy: 8.00, elf: true

low.entropy.test, entropy: 0.00, elf: true

You can also load up the `upx` utility and compress an executable and see what values it returns.

# Agentless Linux Security

Sandfly Security produces an agentless endpoint detection and incident response platform (EDR) for Linux. Automated
entropy checks are just one of thousands of things we search for to find intruders without loading any software 
on your Linux endpoints.

Get a free license and learn more below:

https://www.sandflysecurity.com
@SandflySecurity



