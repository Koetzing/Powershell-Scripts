<#
.SYNOPSIS
    Microsoft Teams (New Architecture / VDI 2.0) Enterprise Installer
    
.DESCRIPTION
    Automated deployment solution for the new Microsoft Teams (MSIX).
    Designed for Golden Image deployments in Citrix/AVD/VMware environments.

.PLATFORM
    Windows Server 2019, 2022, 2025, Windows 10/11
.VERSION
    1.5.3 (Production Grade - Multi-OS Support)
#>

# ---------------------------------------------------------------------------
# GLOBAL CONFIGURATION
# ---------------------------------------------------------------------------
$WorkDir          = "C:\Temp\TeamsInstall"
$ForceDownload    = $false
$IgnoreUpdates    = $false   
$CleanupAfter     = $true    

# VDI OPTIMIZATIONS
$DisableGPU       = $true    
$DisableAutoStart = $true    

# DOWNLOAD URLS
$UrlBootstrapper = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
$UrlMsix         = "https://go.microsoft.com/fwlink/?linkid=2196106"
$UrlWebView2     = "https://go.microsoft.com/fwlink/p/?LinkId=2124703"
$UrlVCLibs       = "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
$UrlUiXamlNuGet  = "https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.8.6"

# ---------------------------------------------------------------------------
# LOGGING & UI SETUP
# ---------------------------------------------------------------------------
if (!(Test-Path $WorkDir)) { New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null }
$LogFile = Join-Path $WorkDir ("TeamsInstall_" + (Get-Date -Format 'yyyy-MM-dd') + ".log")

# Suppress the default yellow progress bar
$ProgressPreference = 'SilentlyContinue'

Start-Transcript -Path $LogFile -Append -Confirm:$false | Out-Null

function Write-Header {
    param([string]$Title)
    Write-Host "`n==================================================================================================" -ForegroundColor Cyan
    Write-Host "   $Title" -ForegroundColor White
    Write-Host "==================================================================================================`n" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Title)
    Write-Host " [ STEP ] $Title" -ForegroundColor Cyan -BackgroundColor DarkBlue
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","OK","WARN","ERROR","CRITICAL")]
        [string]$Level = "INFO"
    )
    $Time = Get-Date -Format "HH:mm:ss"
    switch ($Level) {
        "INFO"     { $Color = "Gray";   $Tag = "[ INFO ]" }
        "OK"       { $Color = "Green";  $Tag = "[  OK  ]" }
        "WARN"     { $Color = "Yellow"; $Tag = "[ WARN ]" }
        "ERROR"    { $Color = "Red";    $Tag = "[ FAIL ]" }
        "CRITICAL" { $Color = "Red";    $Tag = "[ CRIT ]" }
    }
    Write-Host "$Time $Tag $Message" -ForegroundColor $Color
}

function Install-DownloadFile {
    param ([string]$Url, [string]$Path, [string]$FileName)
    if ((Test-Path $Path) -and (-not $ForceDownload)) {
        Write-Log -Level INFO -Message "Resource already exists: ${FileName}"
        Unblock-File -Path $Path -ErrorAction SilentlyContinue
    } else {
        Write-Log -Level INFO -Message "Downloading ${FileName}..."
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Path -ErrorAction Stop
            Unblock-File -Path $Path
            Write-Log -Level OK -Message "Download successful."
        } catch {
            Write-Log -Level ERROR -Message "Failed to download ${FileName}: $($_.Exception.Message)"
            Stop-Transcript; exit 1
        }
    }
}

# ---------------------------------------------------------------------------
# START EXECUTION
# ---------------------------------------------------------------------------
Clear-Host
Write-Header "MICROSOFT TEAMS VDI INSTALLER (V1.5.3) | FINAL RELEASE"
Write-Log -Message "Log destination: $LogFile"

$OSInfo = Get-CimInstance Win32_OperatingSystem
$IsServer2019 = ($OSInfo.BuildNumber -eq 17763)
Write-Log -Message "Detected OS: $($OSInfo.Caption) (Build $($OSInfo.BuildNumber))"

Write-Step "PRE-FLIGHT CHECKS"
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log -Level CRITICAL -Message "Elevated privileges required."
    Stop-Transcript; exit 1
}

$RebootPending = $false
if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA SilentlyContinue) { $RebootPending = $true }
if (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA SilentlyContinue) { $RebootPending = $true }

if ($RebootPending) {
    Write-Log -Level CRITICAL -Message "System reboot is pending. Please reboot before continuing."
    Stop-Transcript; exit 1
}

# ---------------------------------------------------------------------------
# RESOURCE PREPARATION
# ---------------------------------------------------------------------------
Write-Step "RESOURCE PREPARATION"

# WebView2 Check
$WV2Key = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
if (!((Get-ItemProperty $WV2Key -Name "pv" -EA SilentlyContinue).pv)) {
    $WV2Installer = "$WorkDir\MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
    Install-DownloadFile -Url $UrlWebView2 -Path $WV2Installer -FileName "WebView2 Runtime"
    Write-Log -Level INFO -Message "Installing WebView2 Runtime..."
    Start-Process -FilePath $WV2Installer -ArgumentList "/silent /install" -Wait
} else { Write-Log -Level OK -Message "WebView2 Runtime detected." }

# Dependencies
$VCLibsPath = "$WorkDir\Microsoft.VCLibs.x64.14.00.Desktop.appx"
Install-DownloadFile -Url $UrlVCLibs -Path $VCLibsPath -FileName "VCLibs Framework"

$NuGetPath   = "$WorkDir\ui_xaml.zip"
$ExtractPath = "$WorkDir\ui_xaml_extracted"
Install-DownloadFile -Url $UrlUiXamlNuGet -Path $NuGetPath -FileName "UI Xaml NuGet"

if (!(Test-Path "$ExtractPath\tools")) {
    Write-Log -Message "Extracting UI Xaml dependencies..."
    Expand-Archive -Path $NuGetPath -DestinationPath $ExtractPath -Force
}

$UiXamlPath = (Get-ChildItem -Path $ExtractPath -Recurse -Filter "Microsoft.UI.Xaml*.appx" | 
               Where-Object { $_.FullName -like "*x64*Release*" -and $_.Name -notlike "*scale*" } | 
               Select-Object -First 1).FullName

# Teams Components
$BootstrapperPath = "$WorkDir\teamsbootstrapper.exe"
$MsixPath         = "$WorkDir\MSTeams-x64.msix"
Install-DownloadFile -Url $UrlBootstrapper -Path $BootstrapperPath -FileName "Teams Bootstrapper"
Install-DownloadFile -Url $UrlMsix         -Path $MsixPath         -FileName "Teams MSIX Package"

# ---------------------------------------------------------------------------
# INSTALLATION & CLEANUP
# ---------------------------------------------------------------------------
Write-Step "INSTALLATION & PROVISIONING"

Write-Log -Message "Ensuring Certificate Trust..."
try {
    if (Test-Path $MsixPath) {
        Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPeople -FilePath $MsixPath -ErrorAction SilentlyContinue | Out-Null
    }
} catch { }

Write-Log -Message "Purging orphaned package registrations (0x80004005 Fix)..."
try {
    $Orphaned = Get-AppxProvisionedPackage -Online | Where-Object {$_.DisplayName -match "MSTeams|UI.Xaml.2.8"}
    foreach ($Pkg in $Orphaned) {
        Write-Log -Level WARN -Message "Removing orphaned package: $($Pkg.DisplayName)"
        Remove-AppxProvisionedPackage -Online -PackageName $Pkg.PackageName -EA SilentlyContinue | Out-Null
    }
    Get-AppxPackage -Name "*MSTeams*" -AllUsers | Remove-AppxPackage -AllUsers -EA SilentlyContinue
    Get-AppxPackage -Name "*UI.Xaml.2.8*" -AllUsers | Remove-AppxPackage -AllUsers -EA SilentlyContinue
} catch {
    Write-Log -Level WARN -Message "Cleanup encountered minor issues, proceeding."
}

New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -Value 1 -PropertyType DWORD -Force | Out-Null

if ($IsServer2019) {
    Write-Log -Message "Deploying via Direct DISM Injection (Server 2019 Mode)..."
    $DismLog = "$WorkDir\dism_exec.log"
    $DismArgs = "/Online /Add-ProvisionedAppxPackage /PackagePath:`"$MsixPath`" /DependencyPackagePath:`"$UiXamlPath`" /DependencyPackagePath:`"$VCLibsPath`" /SkipLicense /LogPath:`"$DismLog`" /LogLevel:2"
    $Proc = Start-Process -FilePath "dism.exe" -ArgumentList $DismArgs -Wait -PassThru -NoNewWindow
    if ($Proc.ExitCode -eq 0) { Write-Log -Level OK -Message "Provisioning successful." } 
    else { Write-Log -Level ERROR -Message "Provisioning failed. See $DismLog"; Stop-Transcript; exit 1 }
} else {
    try {
        Add-AppxProvisionedPackage -Online -PackagePath $MsixPath -DependencyPackagePath @($UiXamlPath, $VCLibsPath) -SkipLicense -EA Stop | Out-Null
        Write-Log -Level OK -Message "Provisioning successful."
    } catch {
        Write-Log -Level ERROR -Message "Provisioning failed: $($_.Exception.Message)"
        Stop-Transcript; exit 1
    }
}

# ---------------------------------------------------------------------------
# POST-INSTALL VDI OPTIMIZATIONS
# ---------------------------------------------------------------------------
Write-Step "POST-INSTALL VDI OPTIMIZATIONS"

if ($IsServer2019) {
    Write-Log -Message "Registering Outlook Add-in (Legacy Mode)..."
    # Redirection to hide bootstrapper JSON output on Server 2019
    & $BootstrapperPath -p -o "$MsixPath" *>$null
} else {
    Write-Log -Message "Force installing Teams Meeting Add-in (TMA)..."
    # Using specific TMA flag for modern OS (Server 2025/2022)
    $TmaResult = Start-Process -FilePath $BootstrapperPath -ArgumentList "--installTMA" -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$WorkDir\tma_install.log"
    if ($TmaResult.ExitCode -eq 0) {
        Write-Log -Level OK -Message "TMA registration successful."
    } else {
        Write-Log -Level WARN -Message "Explicit TMA install failed (Code $($TmaResult.ExitCode)). Retrying via provision..."
        & $BootstrapperPath -p -o "$MsixPath" *>$null
    }
}

# Apply Registry VDI Settings
$RegPathTeams = "HKLM:\SOFTWARE\Microsoft\Teams"
if (!(Test-Path $RegPathTeams)) { New-Item -Path $RegPathTeams -Force | Out-Null }
New-ItemProperty -Path $RegPathTeams -Name "disableAutoUpdate" -Value 1 -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $RegPathTeams -Name "IsWVDEnvironment" -Value 1 -PropertyType DWORD -Force | Out-Null

if ($DisableGPU) {
    $RegPathPolicies = "HKLM:\SOFTWARE\Policies\Microsoft\Teams"
    if (!(Test-Path $RegPathPolicies)) { New-Item -Path $RegPathPolicies -Force | Out-Null }
    New-ItemProperty -Path $RegPathPolicies -Name "DisableHardwareAcceleration" -Value 1 -PropertyType DWORD -Force | Out-Null
    Write-Log -Level OK -Message "GPU Policy: [DISABLED]"
}

if ($DisableAutoStart) {
    $RunKey = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    Remove-ItemProperty -Path $RunKey -Name "MSTeams" -EA SilentlyContinue
    Remove-ItemProperty -Path $RunKey -Name "Teams" -EA SilentlyContinue
    Write-Log -Level OK -Message "Auto-Start: [REMOVED]"
}

# ---------------------------------------------------------------------------
# CLEANUP & FINISH
# ---------------------------------------------------------------------------
if ($CleanupAfter) {
    Write-Log -Message "Purging temporary installation files..."
    if (Test-Path $ExtractPath) { Remove-Item $ExtractPath -Recurse -Force -EA SilentlyContinue }
    if (Test-Path $NuGetPath) { Remove-Item $NuGetPath -Force -EA SilentlyContinue }
}

Write-Header "PROVISIONING COMPLETE"
Write-Log -Level OK -Message "The new Microsoft Teams is now ready for use."
Write-Log -Level INFO -Message "Session log saved to: $LogFile"
Write-Host ""

Stop-Transcript
