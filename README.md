Here is a **README** for the script:

---

# File Cryptor Script

## Overview

The **File Cryptor** is a PowerShell script designed to securely encrypt and decrypt files using the Advanced Encryption Standard (AES). It leverages password-based encryption instead of key files, making it simpler to manage. The script supports large files, ensures file integrity through hashing, and offers customizable file paths.

## Features

- **AES Encryption/Decryption**: Secure your files using AES 256-bit encryption.
- **Password-Based Encryption**: Users provide a password during encryption, removing the need for managing separate key files.
- **File Integrity Check**: Ensures that files are not tampered with by generating and verifying a SHA-256 hash during the encryption and decryption processes.
- **Large File Support**: Efficiently handles large files by processing them in chunks, avoiding memory issues.
- **Customizable Output**: Flexible file naming with dynamic options like including the system hostname in file names.
- **Error Handling & Resource Management**: The script properly handles errors and ensures resources like file streams and cryptographic objects are disposed of correctly.

## Requirements

- **PowerShell**: Ensure that you have PowerShell 5.0 or later installed.
- **.NET Framework**: .NET Framework 4.5 or higher is required for cryptographic functions.

## Installation

1. Download the script file `FileCryptor.ps1`.
2. Place the script in a directory where you will be running it from.
3. Ensure that the execution policy allows for running PowerShell scripts:

   ```Powershell
   Powershell -ExecutionPolicy Bypass -File "C:\path\to\FileCryptor.ps1"
   ```

## Usage

The script offers two modes of operation: **Encryption** and **Decryption**. It uses command-line arguments for specifying input files, passwords, and other options.

### Encryption

To encrypt a file:

```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\inputfile.txt" -OutFile "C:\path\to\encryptedfile.txt.enc" -Password "YourStrongPassword" -HashFile "C:\path\to\file.hash"
```

- `-Mode Encrypt`: Specifies that the script should encrypt the file.
- `-InFile`: Path to the file that needs to be encrypted.
- `-OutFile`: Path where the encrypted file will be saved.
- `-Password`: The password used to derive the encryption key.
-  `-HashFile`: (Optional) Path to save the `.hash` file used to verify file integrity.

### Decryption

To decrypt a file:

```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\path\to\encryptedfile.txt.enc" -OutFile "C:\path\to\decryptedfile.txt" -Password "YourStrongPassword" -HashFile "C:\path\to\file.hash"
```

- `-Mode Decrypt`: Specifies that the script should decrypt the file.
- `-InFile`: Path to the encrypted file.
- `-OutFile`: Path where the decrypted file will be saved.
- `-Password`: The same password used during encryption.
- `-HashFile`: (Optional) Path to the `.hash` file used to verify file integrity.

### Example of Full Command

Encryption:
```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\Documents\report.docx" -OutFile "C:\Documents\report.docx.enc" -Password "StrongPassword123" 
```

Decryption:
```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\Documents\report.docx.enc" -OutFile "C:\Documents\report_decrypted.docx" -Password "StrongPassword123" -HashFile "C:\Documents\report.hash"
```

## Parameters

| Parameter  | Description                                                                                                  |
|------------|--------------------------------------------------------------------------------------------------------------|
| `-Mode`    | **Encrypt** or **Decrypt**. Defines whether the script will encrypt or decrypt the file.                     |
| `-InFile`  | Path to the input file that will be encrypted or decrypted.                                                   |
| `-OutFile` | Path where the encrypted or decrypted file will be saved.                                                    |
| `-Password`| The password used for both encryption and decryption.                                                        |                        
| `-HashFile`| (Optional) Path to save or verify the SHA-256 hash for file integrity.                                        |

## Features

1. **AES Encryption**: Uses the industry-standard AES encryption algorithm.
2. **Password-Based Key Derivation**: Securely derives encryption keys from passwords using PBKDF2.
3. **File Integrity**: Ensures that decrypted files match the original by comparing SHA-256 hashes.
4. **Customizable File Naming**: Allows dynamic output file names with placeholders like `[hn]` for the hostname.
5. **Supports Large Files**: Processes files in chunks, making it suitable for encrypting or decrypting large files without memory issues.
