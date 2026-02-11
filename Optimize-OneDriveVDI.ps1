<#
.SYNOPSIS
    Optimizes OneDrive disk usage for VDI environments (Logoff Script).

.DESCRIPTION
    This script performs the following actions to minimize FSLogix/Profile container size:
    1. Forcefully terminates the OneDrive process to release file locks.
    2. Uses the native 'attrib.exe' tool to dehydrate all files in the OneDrive folder.
       - Sets attribute +U (Unpinned / Cloud Only).
       - Sets attribute -P (Remove Pinned / Remove "Always keep on this device").
    
    Result: Files occupy 0 bytes on the disk but remain visible in Explorer.

.NOTES
    Name:       Optimize-OneDriveVDI.ps1
    Author:     Thomas Koetzing | www.koetzingit.de
    Date:       2026-02-11
    Version:    2.0 (Native Attribute Version)
    
    Requirements / OS Compatibility:
    - Windows 10 Build 1709 (Fall Creators Update) or newer
    - Windows 11 (all versions)
    - Windows Server 2019 / 2022 / 2025
    - NOT compatible with Server 2016 or older (missing +U switch in attrib.exe)

.EXAMPLE
    Powershell.exe -ExecutionPolicy Bypass -File .\Optimize-OneDriveVDI.ps1
#>

# --- CONFIGURATION ---
$OneDrivePath = $env:OneDrive
$LogTag = "[OneDrive-Opt]"

# --- PRE-CHECK ---
If (-not (Test-Path -Path $OneDrivePath)) {
    Write-Output "$LogTag No OneDrive folder found at '$OneDrivePath'. Script skipped."
    Exit 0
}

# --- STEP 1: Terminate OneDrive Process ---
# Essential to release file handles; otherwise, 'attrib' might fail on locked files.
Write-Output "$LogTag Terminating OneDrive process..."
Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue

# Short delay to allow the OS to release NTFS handles (Race Condition Prevention)
Start-Sleep -Milliseconds 2000

# --- STEP 2: Set Attributes (Dehydration) ---
# Using attrib.exe is approx. 100x faster than PowerShell Get-ChildItem loops.
# +U = Unpinned (Cloud only)
# -P = Unpin (Removes "Always keep on this device" flag)
# /s = Recursive (Subfolders)
# /d = Apply to folders as well

Write-Output "$LogTag Starting dehydration (attrib.exe +U -P)..."

$processInfo = New-Object System.Diagnostics.ProcessStartInfo
$processInfo.FileName = "attrib.exe"
# IMPORTANT: Quotes around path to handle spaces in usernames
$processInfo.Arguments = "+U -P `"$OneDrivePath\*`" /s /d" 
$processInfo.RedirectStandardOutput = $true
$processInfo.UseShellExecute = $false
$processInfo.CreateNoWindow = $true

$process = [System.Diagnostics.Process]::Start($processInfo)
$process.WaitForExit()

# --- COMPLETION ---
If ($process.ExitCode -eq 0) {
    Write-Output "$LogTag Disk space successfully freed. (Exit Code 0)"
} Else {
    Write-Warning "$LogTag Error executing attrib.exe. Exit Code: $($process.ExitCode)"
}
