# GcmCrypt
High speed command-line AES GCM file encryption.

## Overview
This program offers high-speed file encryption from the command-line. The .NET Framework build uses Microsoft's Windows CNG library directly, while the .NET 8 build uses native `System.Security.Cryptography.AesGcm`.

The CNG library for Windows Vista and later leverages hardware-assisted encryption available on modern Intel processor for GCM encryption.

## Version History


- 6/8/2026.   v1.5 Increase the default PBKDF2-HMAC-SHA256 iteration count to 600,000. File format 1.5 stores and authenticates the iteration count, and the `-iter` encryption option permits values from 100,000 through 10,000,000.
- 6/6/2026.   v1.4.1 Retain incomplete decryption output with a `.PARTIAL` suffix and publish the requested output filename only after complete validation.
- 6/5/2026.   v1.4 Add authenticated original plaintext length to file format 1.3 so removal of complete trailing chunks is detected. Use Windows CNG PBKDF2 in the .NET Framework build for faster key derivation.
- 6/5/2026.   v1.3 Add .NET 8 build with native AES-GCM, SDK-style multi-targeting, Visual Studio publish profiles, and GitHub release packaging.
- 5/5/2022.   v1.2 Increase PBKDF2 iterations to 100,000. 
- 8/1/2019.   v1.1 First version. 


## Execution Requirements
- .Net 4.8  (available on the latest Windows 10 release or it can be downloaded)
- Windows version that supports CNG with GCM encryption (Vista or higher)

The codebase can also build for .NET 8, where it uses the native `System.Security.Cryptography.AesGcm` implementation instead of Windows CNG. Files encrypted by either target use the same file format and can be decrypted by the other target.

## Building

The project builds both .NET Framework 4.8 and .NET 8 targets from the same codebase:

    dotnet build GcmCrypt.sln -c Release

Build outputs are written to:

    GcmCrypt\bin\Release\net48\
    GcmCrypt\bin\Release\net8.0\

To build only one target:

    dotnet build GcmCrypt\GcmCrypt.csproj -c Release -f net48
    dotnet build GcmCrypt\GcmCrypt.csproj -c Release -f net8.0

## Publishing

Visual Studio publish profiles are included for the .NET 8 build:

    dotnet publish GcmCrypt\GcmCrypt.csproj -f net8.0 /p:PublishProfile=net8-win-x64-single-trimmed-compressed
    dotnet publish GcmCrypt\GcmCrypt.csproj -f net8.0 /p:PublishProfile=net8-framework-dependent

The trimmed, compressed, self-contained `win-x64` profile produces a standalone `GcmCrypt.exe` under:

    publish\net8-win-x64-single-trimmed-compressed\

The framework-dependent profile is much smaller, but requires the .NET 8 runtime to be installed on the target machine. Its minimum runnable file set is:

    GcmCrypt.exe
    GcmCrypt.dll
    GcmCrypt.deps.json
    GcmCrypt.runtimeconfig.json

Framework-dependent output is written to:

    publish\net8-framework-dependent\

## Performance
High performance will only be achieved if the processor supports hardware-assisted encryption. Most modern desktop processors do except for low-end CPUs (see [https://en.wikipedia.org/wiki/AES_instruction_set](https://en.wikipedia.org/wiki/AES_instruction_set)).  The program will still run properly if this requirement is not met, but at much reduced performance.

I can only report performance for my own system (Intel Core i5 2500K), where I achieve encryption rates approaching 500 MB / second.  

## Usage

For both encryption and decryption, the optional  **-f** parameter forces silent overwrite of the output file.  If not used, the user will be prompted to confirm overwriting the output file.

### Encryption

    gcmcrypt -e [-f] [-compress] [-iter count] password inputfile outputfile

Notes: The *compress* option compresses the input before encryption. This will substantially slow down the processing and is recommended only for special cases.

The optional `-iter` setting controls the PBKDF2-HMAC-SHA256 iteration count for a newly encrypted file. The default is 600,000 and the accepted range is 100,000 through 10,000,000. Decryption reads the iteration count from the authenticated file header.


### Decryption

    gcmcrypt -d [-f] password inputfile outputfile


---------

## Disclaimer
No effort is made to "scrub" memory of sensitive data such as password or to make this program resistant to timing attacks. It may not be suitable for commercial use or with highly-sensitive or valuable data.


## Encrypted File Format

Each encrypted file begins with the following file header:


    3 bytes - 'GCM'
	1 byte - 0x01 (Version Major)
	1 byte - 0x05 (Version Minor)
	16 bytes - Salt for PBKDF2 key derivation
	32 bytes - GCM-encrypted file encryption key (EFEK)
	16 bytes - GCM tag for GCM-encrypted AES key
	1 byte - 0x00 if file is not compressed, 0x01 if file is compressed
	4 bytes - chunk size of file data (big-endian, currently hard-coded at 65536)
	8 bytes - original plaintext file length (big-endian)
	4 bytes - PBKDF2-HMAC-SHA256 iteration count (big-endian, default 600000)

After the 86-byte header, there is:

	16 bytes - GCM tag to authenticate the header   
	n bytes - AES GCM encrypted file data

File formats 1.1 and 1.2 use the earlier 74-byte header without the original-length field. File format 1.3 uses the 82-byte header without an explicit iteration count. All remain readable.


Each chunk of encrypted data is in the following format:

	<encrypted data> <GCM tag>

The encrypted data is 65536 bytes long except for the final chunk which may be smaller.  Each GCM tag is 16 bytes long.

## AES GCM Mode Technical Notes
- Each file uses a random  GCM key of 256 bits (32 bytes).
- 12-byte nonces are used for all encryption as recommended by the GCM specifications
- 16-byte tags (the maximum) are used for all data chunks  
- A nonce of all zero bits is used with a PBKDF2-derived 256-bit key to encrypt the file encryption key.
- A nonce of all ones bits is used to authenticate (but not encrypt) the file header.
- When encrypting chunks, the chunk sequence counter is used as the nonce. The nonce is a 12-byte big-endian value beginning at 1.

A note on the fixed-value nonces:  Nonces should never be re-used with the same key.  On the face of it, this makes the hard-coded
nonce values used here a bad idea. However, unique keys are used for every encryption due to the PBKDF2 salt. Thus,
the nonces are not re-used for the same key.

## Key generation and usage
- The file encryption key (FEK) is generated using a cryptographic random number generator.
- For file format 1.5, the master key (MK) is generated using PBKDF2-HMAC-SHA256 with a 16-byte random salt and an authenticated iteration count. The default is 600,000.
- For legacy file formats, the MK is generated using PBKDF2-HMAC-SHA256 with 10,000 iterations for v1.1 or 100,000 iterations for v1.2 and v1.3.
- The v1.5 iteration count is validated against defensive limits before PBKDF2 runs.

The encrypted FEK (EFEK) is stored in the header.  No other keys are stored in the encrypted file.

## Authentication
All data in the encrypted file is protected via the GCM authentication tags, including all bytes of the file header. The authenticated original plaintext length also detects removal of complete chunks from the end of the encrypted file.

Decryption will end with an error message if the input file is corrupted or modified in any way. Decryption is written to the requested output filename with `.PARTIAL` appended. The file is renamed to the requested filename only after complete authentication and length validation; otherwise, the `.PARTIAL` file is retained for possible recovery or diagnosis.

## Other Ports
There is now a Python port of this program, which is OS-indepedent and file-compatible with this program.

See [GcmCrypt-Python](https://github.com/lellis1936/GcmCrypt-Python)

