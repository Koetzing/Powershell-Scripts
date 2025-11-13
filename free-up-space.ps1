<#
******************************************************************************************************************
Name:               free-up-space
******************************************************************************************************************
.SYNOPSIS
    Sets downloaded files in the OneDrive folder to "online-only" to free up local disk space.

.DESCRIPTION
    This script scans the user's OneDrive folder and marks files as "online-only" unless they are explicitly pinned
    to stay on the device. Files marked as "Keep on device" will not be changed.

.COMMANDLINE
    PowerShell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile \\server\share\free-up-space.ps1
******************************************************************************************************************
#>

# --- Define extended file attributes ---
$Code = @'
using System;

[FlagsAttribute]
public enum FileAttributesEx : uint {
    Readonly = 0x00000001,
    Hidden = 0x00000002,
    System = 0x00000004,
    Directory = 0x00000010,
    Archive = 0x00000020,
    Device = 0x00000040,
    Normal = 0x00000080,
    Temporary = 0x00000100,
    SparseFile = 0x00000200,
    ReparsePoint = 0x00000400,
    Compressed = 0x00000800,
    Offline = 0x00001000,
    NotContentIndexed = 0x00002000,
    Encrypted = 0x00004000,
    IntegrityStream = 0x00008000,
    Virtual = 0x00010000,
    NoScrubData = 0x00020000,
    EA = 0x00040000,
    Pinned = 0x00080000,
    Unpinned = 0x00100000,
    RecallOnDataAccess = 0x00400000
}
'@
Add-Type $Code

# --- Locate OneDrive folder ---
$OneDrivePath = (Get-ChildItem $env:USERPROFILE -Filter "OneDrive -*").FullName
if (-not $OneDrivePath) {
    Write-Error "No OneDrive folder found."
    exit 1
}

Write-Host "OneDrive folder found: $OneDrivePath"
Write-Host "Starting space cleanup..."

# --- Scan files and apply changes ---
Get-ChildItem -Path $OneDrivePath -Exclude "*.url" -Recurse -File |
    Select-Object FullName, @{Name='Attributes'; Expression={[FileAttributesEx]$_.Attributes.Value__}} |
    Where-Object {
        ($_.Attributes -notmatch "Unpinned") -and
        ($_.Attributes -notmatch "Offline") -and
        ($_.Attributes -notmatch "RecallOnDataAccess")
    } |
    ForEach-Object {
        Write-Host "Setting file to 'online-only': $($_.FullName)"
        attrib.exe $_.FullName +U -P /S
    }

Write-Host "Space cleanup completed."
