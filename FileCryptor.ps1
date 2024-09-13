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
Usage: .\FileCryptor.ps1 -Mode <Encrypt|Decrypt> -InFile <InputFilePath> -OutFile <OutputFilePath> -Password <Password> [-KeySize <KeySize>] [-HashFile <HashFilePath>] [-h]

Parameters:
    -Mode         : Specifies whether to 'Encrypt' or 'Decrypt' the file.
    -InFile       : Path to the input file (file to encrypt or AES-encrypted file to decrypt).
    -OutFile      : Path to save the encrypted or decrypted file. You can use '[hn]' or '[hostname]' in the file path, which will be replaced by the system's hostname.
    -Password     : Password used to derive the encryption/decryption key (PBKDF2).
    -KeySize      : (Optional for encryption) Key size for encryption (128, 192, 256). Default is 256.
    -HashFile     : (Optional) Path to save the SHA-256 hash of the original file (for encryption) or to validate integrity (for decryption).
    -h, -help     : Show this help menu.

Examples:
    Encrypt a file with default settings:
        .\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\file.txt" -OutFile "C:\path\to\file.txt.enc" -Password "YourPassword"

    Decrypt a file:
        .\FileCryptor.ps1 -Mode Decrypt -InFile "C:\path\to\file.enc" -OutFile "C:\path\to\output.docx" -Password "YourPassword"

    Use hostname in output path:
        .\FileCryptor.ps1 -Mode Encrypt -InFile "C:\path\to\file.txt" -OutFile "C:\path\to\[hostname]\file.txt.enc" -Password "YourPassword"
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
    $hashBytes = $sha256.Hash
    $sha256.Dispose()
    return $hashBytes
}

function Get-DefaultHashFilePath {
    param (
        [string] $InFile,
        [string] $OutFile
    )
    # Get the base name and original extension of the file
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InFile)
    $originalExtension = [System.IO.Path]::GetExtension($InFile)

    # For decryption, we need to remove the `.aes` and use the original file extension
    if ($Mode -eq 'Decrypt' -and $originalExtension -eq '.aes') {
        # Remove `.aes` and get the original file's base name and extension
        $baseName = [System.IO.Path]::GetFileNameWithoutExtension($baseName)
        $originalExtension = [System.IO.Path]::GetExtension($OutFile)  # Use the original extension from the OutFile
    }

    # Save the hash file in the same directory as OutFile
    $outputDirectory = [System.IO.Path]::GetDirectoryName($OutFile)
    return [System.IO.Path]::Combine($outputDirectory, "$baseName$originalExtension.hash")
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

    Write-Host "Hash of the original file (SHA-256): $originalHashString"

    # Save the hash to the specified file
    if (-not $HashFile) {
        $HashFile = Get-DefaultHashFilePath -InFile $InFile -OutFile $OutFile
    }
    Set-Content -Path $HashFile -Value $originalHashString
    Write-Host "Hash saved to: $HashFile"

    # Create encryption key and IV using password and salt
    $salt = New-Object byte[] 32
    [void](New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($salt)
    $rfc2898 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = $KeySize
    $aes.Key = $rfc2898.GetBytes($aes.KeySize / 8)
    $aes.IV = $rfc2898.GetBytes($aes.BlockSize / 8)

    # Write salt to the beginning of the output file
    $outStream.Write($salt, 0, $salt.Length)

    # Encrypt and write the data to the output file
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($outStream, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
    $buffer = New-Object byte[] (1MB)
    while (($bytesRead = $inStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $cryptoStream.Write($buffer, 0, $bytesRead)
    }

    # Cleanup
    $cryptoStream.Close()
    $inStream.Close()
    $outStream.Close()
    Write-Host "File encrypted successfully: $OutFile"
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

    # Read the salt from the input file
    $salt = New-Object byte[] 32
    $inStream.Read($salt, 0, $salt.Length) | Out-Null

    # Derive the encryption key and IV using password and salt
    $rfc2898 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 10000)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $rfc2898.GetBytes($aes.KeySize / 8)
    $aes.IV = $rfc2898.GetBytes($aes.BlockSize / 8)

    # Decrypt and write the data to the output file
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($inStream, $aes.CreateDecryptor(), [System.Security.Cryptography.CryptoStreamMode]::Read)
    $buffer = New-Object byte[] (1MB)
    while (($bytesRead = $cryptoStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $outStream.Write($buffer, 0, $bytesRead)
    }

    # Cleanup
    $cryptoStream.Close()
    $outStream.Close()
    $inStream.Close()

    # Check file integrity using the hash
    $decryptedStream = [System.IO.File]::OpenRead($OutFile)
    $decryptedHash = Get-Hash -Stream $decryptedStream
    $decryptedHashString = -join ($decryptedHash | ForEach-Object { $_.ToString('x2') })
    $decryptedStream.Close()

    if (-not $HashFile) {
        $HashFile = Get-DefaultHashFilePath -InFile $InFile -OutFile $OutFile
    }
    if (-not (Test-Path $HashFile)) {
        Write-Host "Warning: No hash file found. Integrity check skipped."
        $HashFile = Read-Host "Please provide an alternate path to the hash file for integrity validation, or press [ENTER] to skip"
        if (-not $HashFile) {
            Write-Warning "Integrity validation skipped."
            return
        }
    }

    $savedHash = Get-Content -Path $HashFile
    if ($decryptedHashString -eq $savedHash) {
        Write-Host "File integrity verified successfully (SHA-256 hash matches)."
    }
    else {
        Write-Warning "File integrity check failed. The decrypted file may be corrupted or tampered with."
    }

    Write-Host "File decrypted successfully: $OutFile"
}

################################################################################
# Main Script Logic
################################################################################

if ($Mode -eq 'Encrypt') {
    Encrypt-File -InFile $InFile -OutFile $OutFile -Password $Password -KeySize $KeySize -HashFile $HashFile
}
elseif ($Mode -eq 'Decrypt') {
    Decrypt-File -InFile $InFile -OutFile $OutFile -Password $Password -HashFile $HashFile
}
else {
    throw "Invalid Mode: $Mode. Acceptable values are 'Encrypt' or 'Decrypt'."
}
