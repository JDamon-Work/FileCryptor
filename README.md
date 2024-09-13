# File Cryptor Script

## Overview

The **File Cryptor** is a PowerShell script designed to securely encrypt and decrypt files using AES encryption. By using password-based encryption, it simplifies the process without requiring separate key files. The script also ensures data integrity by generating and verifying file hashes, supports large file sizes, and offers customizable output file paths.

## Features

- **AES Encryption/Decryption**: Utilizes AES 256-bit encryption for strong security.
- **Password-Based Encryption**: The encryption key is derived from a user-provided password, removing the need for key files.
- **File Integrity Check**: Verifies file integrity by generating a SHA-256 hash during encryption and validating it during decryption.
- **Efficient Large File Handling**: Processes large files in chunks, minimizing memory usage.
- **Customizable File Paths**: Supports dynamic file naming options, such as inserting the system hostname into output file paths.
- **Error Handling & Resource Management**: Ensures proper cleanup of cryptographic resources and handles errors gracefully.
- **Overwrite Protection**: Prompts before overwriting existing files to prevent accidental data loss.

## Requirements

- **PowerShell**: Version 5.0 or later.
- **.NET Framework**: .NET Framework 4.5 or higher is required for cryptographic operations.

## Installation

1. Download the `FileCryptor.ps1` script.
2. Place the script in a directory where you want to run it.
3. Ensure the execution policy allows scripts to run:

   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   ```
   Or for a One Time Exception 
   
   ```powershell
   powershell -ExecutionPolicy Bypass -File FileCryptor.ps1
   ```
   
## Usage

The script can be run in two main modes: **Encryption** and **Decryption**. You can either pass all parameters directly via command-line arguments or execute the script and provide the inputs interactively.

### Method 1: Command-Line Execution

#### Encrypting a File

```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\inputfile.txt" -OutFile "C:\path\to\encryptedfile.txt.enc" -Password "YourStrongPassword" -HashFile "C:\path\to\file.hash"
```

- `-Mode Encrypt`: Indicates that the file should be encrypted.
- `-InFile`: Path to the file to encrypt.
- `-OutFile`: Path where the encrypted file will be saved.
- `-Password`: Password used to derive the encryption key.
- `-HashFile`: (Optional) Path to save the hash file, used for verifying integrity later.

#### Decrypting a File

```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\path\to\encryptedfile.txt.enc" -OutFile "C:\path\to\decryptedfile.txt" -Password "YourStrongPassword" -HashFile "C:\path\to\file.hash"
```

- `-Mode Decrypt`: Indicates that the file should be decrypted.
- `-InFile`: Path to the encrypted file.
- `-OutFile`: Path where the decrypted file will be saved.
- `-Password`: The same password used during encryption.
- `-HashFile`: Path to the stored SHA-256 hash to verify the file’s integrity.

#### Example of Full Command

Encrypt a file:
```powershell
.\FileCryptor.ps1 -Mode Encrypt -InFile "C:\Documents\report.docx" -OutFile "C:\Documents\DESKTOP-327214\report.docx.enc" -Password "StrongPassword123"
```

Decrypt a file:
```powershell
.\FileCryptor.ps1 -Mode Decrypt -InFile "C:\Documents\DESKTOP-327214\report.docx.enc" -OutFile "C:\Documents\DESKTOP-327214\report.docx" -Password "StrongPassword123"
```

### Method 2: Interactive Line-by-Line Input

If you prefer, you can run the script without specifying any parameters initially. The script will prompt you for the necessary information:

```powershell
.\FileCryptor.ps1
```

After running this, the script will prompt you to:

- Enter the **Mode** (Encrypt or Decrypt).
- Provide the **InFile** (input file path).
- Specify the **OutFile** (output file path).
- Enter the **Password** (used for encryption or decryption).

### Hash Verification during Decryption

If the hash verification fails during decryption, the script will display both the expected (stored) hash and the computed hash, like this:

```
HASH VERIFICATION FAILED. File integrity check failed.
Expected Hash (Stored): e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Computed Hash (Found):  d3f1e74229ab7a60f8df01b93e53e7a839c129b282b1c5b2d43d6a16282d1e98
```

This information helps you understand any discrepancies between the original and decrypted file.

## Parameters

| Parameter   | Description                                                                                                  |
|-------------|--------------------------------------------------------------------------------------------------------------|
| `-Mode`     | **Encrypt** or **Decrypt**: Defines whether the script encrypts or decrypts the file.                        |
| `-InFile`   | Path to the input file to be encrypted or decrypted.                                                         |
| `-OutFile`  | Path where the encrypted or decrypted file will be saved.                                                    |
| `-Password` | Password used for both encryption and decryption (password-based encryption).                                |
| `-KeySize`  | (Optional) Key size for encryption (128, 192, or 256 bits). Default is 256 bits.                             |
| `-HashFile` | (Optional) Path to save or verify the SHA-256 hash for file integrity.                                        |

## Notes

- **File Naming**: During encryption, the hash file is saved with the original file's extension (e.g., `file.txt.hash`).
- **Interactive Mode**: If no parameters are provided, the script will guide you through the encryption or decryption process interactively.
