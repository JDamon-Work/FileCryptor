#Requires -Version 5.0

<#
.SYNOPSIS
    Encrypts or decrypts a file using AES encryption/decryption and verifies the file's integrity by comparing its hash.

.DESCRIPTION
    This script can either encrypt or decrypt a file using AES encryption. When encrypting, it generates a SHA-256 hash of the original file.
    When decrypting, it verifies the integrity of the decrypted file by comparing the hash with the stored hash.

.PARAMETER Mode
    Specifies whether to encrypt or decrypt the file. Acceptable values are `Encrypt` or `Decrypt`.

.PARAMETER InFile
    Path to the input file (file to encrypt or AES-encrypted file to decrypt).

.PARAMETER OutFile
    Path to save the encrypted or decrypted file. You can use '[hn]' or '[hostname]' in the file path, which will be replaced by the system's hostname.

.PARAMETER Password
    Password used to derive the encryption key (for both encryption and decryption).

.PARAMETER HashFile
    (Optional) Path to save the SHA-256 hash of the original file (for encryption) or to validate integrity (for decryption).

.PARAMETER KeySize
    (Optional for encryption) Specifies the bit size of the encryption key for encryption. Acceptable values: 128, 192, 256. Default is 256.

.PARAMETER Show-Help
    Displays the help menu with examples.
#>

################################################################################
# Help Menu
################################################################################

function Show-Help {
    Write-Host @"
Usage: .\FileCryptor.ps1 -Mode <Encrypt|Decrypt> -InFile <InputFilePath> -OutFile <OutputFilePath> -Password <Password> [-HashFile <HashFilePath>] [-h]

Parameters:
    -Mode         : Specifies whether to 'Encrypt' or 'Decrypt' the file.
    -InFile       : Path to the input file (file to encrypt or AES-encrypted file to decrypt).
    -OutFile      : Path to save the encrypted or decrypted file. You can use '[hn]' or '[hostname]' in the file path, which will be replaced by the system's hostname.
    -Password     : Password used to derive the encryption/decryption key (PBKDF2).
    -HashFile     : (Optional) Path to save the SHA-256 hash of the original file (for encryption) or to validate integrity (for decryption).
    -h, -help     : Show this help menu.

Examples:
    Encrypt a file with default settings:
        .\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\file.txt" -OutFile "C:\path\to\file.txt.enc" -Password "YourStrongPassword"

    Decrypt a file:
        .\FileCryptor.ps1 -Mode Decrypt -InFile "C:\path\to\file.txt.enc" -OutFile "C:\path\to\output.docx" -Password "YourStrongPassword"

    Use hostname in output path:
        .\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\file.txt" -OutFile "C:\path\to\[hostname]\file.txt.enc" -Password "YourStrongPassword"
"@
}

################################################################################
# Process Command-line Arguments and Show Help
################################################################################

$Mode = $null
$InFile = $null
$OutFile = $null
$Password = $null
$KeySize = 256
$HashFile = $null

# Parse command-line arguments manually
for ($i = 0; $i -lt $args.Length; $i++) {
    switch ($args[$i]) {
        '-Mode'      { $Mode = $args[$i + 1]; $i++ }
        '-InFile'    { $InFile = $args[$i + 1]; $i++ }
        '-OutFile'   { $OutFile = $args[$i + 1]; $i++ }
        '-Password'  { $Password = $args[$i + 1]; $i++ }
        '-KeySize'   { $KeySize = [int]$args[$i + 1]; $i++ }
        '-HashFile'  { $HashFile = $args[$i + 1]; $i++ }
        '-h'         { Show-Help; return }
        '--help'     { Show-Help; return }
    }
}

# Validate Mode
if (-not $Mode) {
    $Mode = Read-Host "Enter mode ('Encrypt' or 'Decrypt')"
}
if ($Mode -notin 'Encrypt', 'Decrypt') {
    throw "Invalid Mode. Acceptable values are 'Encrypt' or 'Decrypt'."
}

# Validate other parameters
if (-not $InFile) {
    $InFile = Read-Host "Enter the path to the input file (InFile)"
}

if (-not $OutFile) {
    $OutFile = Read-Host "Enter the path to save the output file (OutFile)"
}

if (-not $Password) {
    $Password = Read-Host "Enter the encryption/decryption password (Password)"
}

# Replace [hn] or [hostname] in the OutFile path with the actual hostname
$hostname = [System.Net.Dns]::GetHostName()
$OutFile = $OutFile -replace '\[hn\]', $hostname
$OutFile = $OutFile -replace '\[hostname\]', $hostname

################################################################################
# Helper Functions
################################################################################

function ConvertFrom-HexString {
    param ([String]$String)
    [Byte[]]($String -replace '..', '0x$&,' -split ',' -ne '')
}

function ConvertTo-HexString {
    param ([Byte[]]$Bytes)
    ($Bytes | ForEach-Object { $_.ToString('X2') }) -join ''
}

function Get-Hash {
    param (
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bufferSize = 4MB
    $buffer = New-Object byte[] $bufferSize
    while (($bytesRead = $Stream.Read($buffer, 0, $bufferSize)) -gt 0) {
        $sha256.TransformBlock($buffer, 0, $bytesRead, $buffer, 0) | Out-Null
    }
    $sha256.TransformFinalBlock($buffer, 0, 0) | Out-Null
    return $sha256.Hash
}

# Generates a hash file name in the same directory as OutFile, but using the original base file name
function Get-DefaultHashFilePath {
    param (
        [string] $InFile,
        [string] $OutFile
    )
    # Get the base name and the original extension of the InFile
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InFile)  # Get base name without extension
    $extension = [System.IO.Path]::GetExtension($InFile)  # Get original extension
    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutFile)     # Use directory of the OutFile
    return [System.IO.Path]::Combine($outputDirectory, "$baseName$extension.hash")  # Add .hash suffix with original extension
}

################################################################################
# Overwrite Protection Logic
################################################################################

function Confirm-Overwrite {
    param (
        [string]$Path
    )
    if (Test-Path $Path) {
        $overwrite = Read-Host "The file '$Path' already exists. Do you want to overwrite it? (y/n)"
        if ($overwrite -ne 'y') {
            Write-Warning "Operation canceled. The file was not overwritten."
            return $false
        }
    }
    return $true
}

################################################################################
# Encryption Logic
################################################################################

function Encrypt-File {
    param (
        [string]$InFile,
        [string]$OutFile,
        [string]$Password,
        [int]$KeySize,
        [string]$HashFile
    )

    # Ensure the output directory exists
    $outDir = [System.IO.Path]::GetDirectoryName($OutFile)
    if (-not (Test-Path $outDir)) {
        New-Item -Path $outDir -ItemType Directory | Out-Null
    }

    # Overwrite protection for OutFile
    if (-not (Confirm-Overwrite -Path $OutFile)) {
        return
    }

    # Open file streams
    $inStream = [System.IO.File]::OpenRead($InFile)
    $outStream = New-Object System.IO.FileStream($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)

    # Compute the hash of the original file
    $originalHash = Get-Hash -Stream $inStream
    $originalHashString = -join ($originalHash | ForEach-Object { $_.ToString('x2') })
    $inStream.Position = 0

    # Ensure HashFile is set based on the original filename, but saved in the OutFile's directory
    if (-not $HashFile) {
        $HashFile = Get-DefaultHashFilePath -InFile $InFile -OutFile $OutFile
    }

    # Save original file's hash with overwrite protection
    if (-not (Confirm-Overwrite -Path $HashFile)) {
        return
    }
    [System.IO.File]::WriteAllText($HashFile, $originalHashString)

    # Generate salt and key/IV
    $saltBytes = New-Object Byte[] 8
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($saltBytes)
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $saltBytes, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $pbkdf2.GetBytes($KeySize / 8)
    $ivBytes = $pbkdf2.GetBytes(16)

    # Set up AES encryption
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key = $keyBytes
    $aes.IV = $ivBytes

    # Write salt and encrypt
    $saltPrefix = [System.Text.Encoding]::UTF8.GetBytes('Salted__') + $saltBytes
    $outStream.Write($saltPrefix, 0, $saltPrefix.Length)
    $encryptor = $aes.CreateEncryptor()
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)

    # Encrypt in chunks
    $bufferSize = 1MB
    $buffer = New-Object byte[] $bufferSize
    while (($bytesRead = $inStream.Read($buffer, 0, $bufferSize)) -gt 0) {
        $cryptoStream.Write($buffer, 0, $bytesRead)
    }
    $cryptoStream.FlushFinalBlock()
    $cryptoStream.Dispose()
    $aes.Dispose()

    Write-Host "Encryption completed. Encrypted file: $OutFile"
    Write-Host "Hash saved to: $HashFile"
}

################################################################################
# Decryption Logic
################################################################################

function Decrypt-File {
    param (
        [string]$InFile,
        [string]$OutFile,
        [string]$Password,
        [string]$HashFile
    )

    # Overwrite protection for OutFile
    if (-not (Confirm-Overwrite -Path $OutFile)) {
        return
    }

    $inStream = [System.IO.File]::OpenRead($InFile)
    $outStream = New-Object System.IO.FileStream($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)

    # Read salt (skip 'Salted__')
    $saltBytes = New-Object Byte[] 8
    $inStream.Position = 8
    $null = $inStream.Read($saltBytes, 0, $saltBytes.Length)

    # Derive key and IV using PBKDF2
    $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $saltBytes, 10000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $keyBytes = $pbkdf2.GetBytes(32)  # AES-256
    $ivBytes = $pbkdf2.GetBytes(16)

    # Set up AES decryption
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Mode = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key = $keyBytes
    $aes.IV = $ivBytes

    # Decrypt in chunks
    $decryptor = $aes.CreateDecryptor()
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
    $bufferSize = 1MB
    $buffer = New-Object byte[] $bufferSize
    $bytesRead = 0

    while (($bytesRead = $cryptoStream.Read($buffer, 0, $bufferSize)) -gt 0) {
        $outStream.Write($buffer, 0, $bytesRead)
    }

    $cryptoStream.Close()
    $aes.Dispose()

    Write-Host "Decryption completed. Decrypted file: $OutFile"

    # Hash validation: Ensure the HashFile is saved in the OutFile directory
    if (-not $HashFile) {
        $originalInFile = [System.IO.Path]::ChangeExtension($InFile, $null)  # Strip the .aes extension
        $HashFile = Get-DefaultHashFilePath -InFile $originalInFile -OutFile $OutFile
    }
    
    # If the hash file is not found, prompt the user for an alternative path
    if (-not (Test-Path $HashFile)) {
        Write-Warning "Hash file not found: $HashFile."
        $alternativeHashFile = Read-Host "Please provide the correct path to the hash file or press Enter to cancel"
        if ([string]::IsNullOrEmpty($alternativeHashFile)) {
            Write-Warning "No hash file provided. Integrity check failed. Exiting..."
            return
        } else {
            $HashFile = $alternativeHashFile
            if (-not (Test-Path $HashFile)) {
                Write-Warning "The provided hash file does not exist. Exiting..."
                return
            }
        }
    }

    # Reopen the output file for hash verification
    $outStream.Close()
    $outStream = [System.IO.File]::OpenRead($OutFile)

    # Verify hash
    $computedHashBytes = (Get-Hash -Stream $outStream)
    $computedHash = -join ($computedHashBytes | ForEach-Object { $_.ToString("x2") })
    $storedHash = [System.IO.File]::ReadAllText($HashFile).Trim()

    if ($computedHash -eq $storedHash) {
        Write-Host "HASH VERIFICATION SUCCESSFUL. File integrity verified." -ForegroundColor Green
    } else {
        Write-Host "HASH VERIFICATION FAILED. File integrity check failed." -ForegroundColor Red
        Write-Host "Expected Hash (Stored): $storedHash" -ForegroundColor Yellow
        Write-Host "Computed Hash (Found):  $computedHash" -ForegroundColor Yellow
    }

    $outStream.Close()
}

################################################################################
# Execution Path
################################################################################

try {
    if ($Mode -eq 'Encrypt') {
        Encrypt-File -InFile $InFile -OutFile $OutFile -Password $Password -KeySize $KeySize -HashFile $HashFile
    } elseif ($Mode -eq 'Decrypt') {
        Decrypt-File -InFile $InFile -OutFile $OutFile -Password $Password -HashFile $HashFile
    }
}

finally {
    # Dispose of resources only if they were initialized
    if ($cryptoStream -ne $null) { $cryptoStream.Dispose() }
    if ($inStream -ne $null) { $inStream.Dispose() }
    if ($outStream -ne $null) { $outStream.Dispose() }
    if ($aes -ne $null) { $aes.Dispose() }
}
