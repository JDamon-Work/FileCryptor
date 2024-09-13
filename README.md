# File Cryptor Script

## Overview

The **File Cryptor** is a versatile PowerShell script designed to securely encrypt and decrypt files using AES encryption. By employing password-based encryption, it simplifies the process without the need to manage separate key files. The script ensures data integrity by generating and verifying file hashes, supports large file sizes, and provides flexible output file handling.

## Features

- **AES Encryption/Decryption**: Uses AES 256-bit encryption for strong security.
- **Password-Based Encryption**: Derives the encryption key from a user-provided password, eliminating the need for key files.
- **File Integrity Check**: Generates a SHA-256 hash during encryption and validates it during decryption to ensure the file has not been tampered with.
- **Efficient Large File Handling**: Processes large files in chunks, minimizing memory usage.
- **Customizable File Paths**: Use dynamic options like including the system hostname in output file paths.
- **Resource Management & Error Handling**: Cleans up cryptographic resources and provides robust error handling.
- **Overwrite Protection**: Prompts before overwriting existing files to avoid accidental data loss.

## Requirements

- **PowerShell**: PowerShell version 5.0 or later.
- **.NET Framework**: Requires .NET Framework 4.5 or higher for cryptographic functions.

## Installation

1. Download the `FileCryptor.ps1` script.
2. Place the script in a desired directory.
3. Ensure that the execution policy permits running scripts:

   ```powershell
   Powershell -ExecutionPolicy Bypass -File "C:\path\to\FileCryptor.ps1"
   ```

## Usage

The script supports two main modes: **Encryption** and **Decryption**. Command-line arguments are used to specify file paths, passwords, and other options.

### Encrypting a File

To encrypt a file, use the following command:

```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\inputfile.txt" -OutFile "C:\path\to\encryptedfile.txt.enc" -Password "YourStrongPassword"
```

- `-Mode Encrypt`: Indicates that the script should perform encryption.
- `-InFile`: Path to the file to be encrypted.
- `-OutFile`: Path where the encrypted file will be saved.
- `-Password`: User-defined password to derive the encryption key.
- `-HashFile` (optional): Path to store the SHA-256 hash of the original file for integrity verification.

### Decrypting a File

To decrypt an encrypted file, run:

```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\path\to\encryptedfile.txt.enc" -OutFile "C:\path\to\decryptedfile.txt" -Password "YourStrongPassword" -HashFile "C:\path\to\file.hash"
```

- `-Mode Decrypt`: Indicates that the script should perform decryption.
- `-InFile`: Path to the encrypted file.
- `-OutFile`: Path where the decrypted file will be saved.
- `-Password`: The same password used for encryption.
- `-HashFile`: Path to the stored SHA-256 hash for integrity verification.

### Full Command Example

Encrypt a file:
```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\Documents\report.docx" -OutFile "C:\Documents\report.docx.enc" -Password "StrongPassword123"
```

Decrypt a file:
```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\Documents\report.docx.enc" -OutFile "C:\Documents\report_decrypted.docx" -Password "StrongPassword123" -HashFile "C:\Documents\report.hash"
```

### Hash Verification during Decryption

If the hash verification fails during decryption, the script will display both the expected hash (stored hash) and the computed hash, like this:

```
HASH VERIFICATION FAILED. File integrity check failed.
Expected Hash (Stored): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Computed Hash (Found):  d3f1e74229ab7a60f8df01b93e53e7a839c129b282b1c5b2d43d6a16282d1e98
```

### Parameters

| Parameter   | Description                                                                                                  |
|-------------|--------------------------------------------------------------------------------------------------------------|
| `-Mode`     | **Encrypt** or **Decrypt**: Defines whether the script encrypts or decrypts the file.                        |
| `-InFile`   | Path to the input file to be encrypted or decrypted.                                                         |
| `-OutFile`  | Path where the encrypted or decrypted file will be saved.                                                    |
| `-Password` | Password used for both encryption and decryption (password-based encryption).                                |
| `-HashFile` | (Optional) Path to save or verify the SHA-256 hash for file integrity.                                        |

## Notes

- **File Naming**: During encryption, the hash file will be saved with the original file's extension, e.g., `file.txt.hash`.
