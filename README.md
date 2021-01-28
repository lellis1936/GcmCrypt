# GcmCrypt
High speed command-line AES GCM file encryption.

## Overview
This program offers ultra-high speed file encryption from the command-line.  This is accomplished by using Microsoft's Windows CNG library directly rather than native .Net code.  

The CNG library for Windows Vista and later leverages hardware-assisted encryption available on modern Intel processor for GCM encryption.


## Execution Requirements
- .Net 4.8  (available on the latest Windows 10 release or it can be downloaded)
- Windows version that supports CNG with GCM encryption (Vista or higher)

## Performance
High performance will only be achieved if the processor supports hardware-assisted encryption. Most modern desktop processors do except for low-end CPUs (see [https://en.wikipedia.org/wiki/AES_instruction_set](https://en.wikipedia.org/wiki/AES_instruction_set)).  The program will still run properly if this requirement is not met, but at much reduced performance.

I can only report performance for my own system (Intel Core i5 2500K), where I achieve encryption rates approaching 500 MB / second.  

## Usage

For both encryption and decryption, the optional  **-f** parameter forces silent overwrite of the output file.  If not used, the user will be prompted to confirm overwriting the output file.

### Encryption

    gcmcrypt -e [-f] [-compress] password inputfile outputfile

Notes:  The *compress* option compresses the input before encryption.   This will substantially slow down the processing and is recommended only for special cases.


### Decryption

    gcmcrypt -d [-f] password inputfile outputfile


---------

## Disclaimer
No effort is made to "scrub" memory of sensitive data such as password or to make this program resistant to timing attacks. It may not be suitable for commercial use or with highly-sensitive or valuable data.


## Encrypted File Format

Each encrypted file begins with the following file header:


    3 bytes - 'GCM'
	1 byte - 0x01 (Version Major)
	1 byte - 0x01 (Version Minor)
	16 bytes - Salt for PBKDF2 key derivation
	32 bytes - GCM-encrypted file encryption key (EFEK)
	16 bytes - GCM tag for GCM-encrypted AES key
	1 byte - 0x00 if file is not compressed, 0x01 if file is compressed
	4 bytes - chunk size of file data (big-endian, currently hard-coded at 65536)

After the 74-byte header, there is:

	16 bytes - GCM tag to authenticate the header   
	n bytes - AES GCM encrypted file data


Each chunk of encrypted data is in the following format:

	<encrypted data> <GCM tag>

The encrypted data is 65536 bytes long except for the final chunk which may be smaller.  Each GCM tag is 16 bytes long.

## AES GCM Mode Technical Notes
- Each file uses a random  GCM key of 256 bits (32 bytes).
- 12-byte nonces are used for all encryption as recommended by the GCM specifications
- 16-byte tags (the maximum) are used for all data chunks  
- A nonce of all zero bits is used with a PBKDBF2-generated 256-bit key to encrypt the file encryption key.  
- A nonce of all ones bits is used to authenticate (but not encrypt) the file header.
- When encrypting chunks, the chunk sequence counter is used as the nonce. The nonce is a 12-byte big-endian value beginning at 1.

A note on the fixed-value nonces:  Nonces should never be re-used with the same key.  On the face of it, this makes the hard-coded
nonce values used here a bad idea.  However, unique keys are used for every encryption due to the salt of the PBKDF2 function.  Thus,
the nonces are not re-used for the same key.

## Key generation and usage
- The file encryption key (FEK) is generated using a cryptographic random number generator.
- The master key (MK) is generated via the PBKDBF2 function using the password, a 16-byte random salt, SHA256 and an iteration count of 10,000.  This key is used to encrypt the FEK.

The encrypted FEK (EFEK) is stored in the header.  No other keys are stored in the encrypted file.

## Authentication
All data in the encrypted file is protected via the GCM authentication tags, including all bytes of the file header.  

Decryption will end with an error message if the input file is corrupted or modified in any way.  The partial output file will remain and should be properly removed by the user. 

