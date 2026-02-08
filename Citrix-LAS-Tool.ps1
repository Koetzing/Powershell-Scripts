<#
.SYNOPSIS
    Citrix LAS Diagnostic Tool - ULTIMATE EDITION
    Features: Registry-Deep-Scan, Smart Connectivity Check, Version Check, Service Check, Time Sync

.DESCRIPTION
    Diagnostic tool for Citrix Cloud License Server connectivity.
    Checks API endpoints, SSL certificates, proxy configurations, and registry keys.
    Additionally checks services and time synchronization (Time Drift).
    Evaluates HTTP 403/404 status codes correctly as successful connections.

.AUTHOR
    Thomas Koetzing

.URL
    www.koetzingit.de

.VERSION
    2.23.0.0

.DATE
    2026-02-08
#>
param([string]$ManualProxy = "")

# --- SETUP ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "SilentlyContinue"
$regPath64 = "HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319"
$regPath32 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319"

function Write-Banner {
    Clear-Host
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "   CITRIX LAS CONNECTIVITY & HEALTH CHECK v2.23" -ForegroundColor White
    Write-Host "   (c) Koetzing IT - www.koetzingit.de" -ForegroundColor Gray
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "`n"
}

function Show-Spinner {
    param([string]$Activity)
    Write-Host "$Activity " -NoNewline
    $chars = "|","/","-","\"
    for($i=0; $i -lt 10; $i++) {
        foreach($c in $chars) {
            Write-Host $c -NoNewline -ForegroundColor Yellow
            Start-Sleep -Milliseconds 50
            Write-Host "`b" -NoNewline
        }
    }
    Write-Host "DONE" -ForegroundColor Green
}

function Test-RegKey {
    param($Path, $Name)
    $val = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($val -eq 1) { return $true } else { return $false }
}

# --- START ---
Write-Banner

# 1. LICENSE SERVER VERSION
Write-Host " PHASE 1: LICENSE SERVER VERSION" -ForegroundColor Yellow
Write-Host " ------------------------------" -ForegroundColor DarkGray
Show-Spinner "Checking Version Compatibility..."

# Minimum requirement for Cloud/LAS
$minVersion = [version]"11.17.2.0"
$detectedVersion = $null
$displayVersion = $null 
$detectionMethod = ""

# Helper to clean version strings
function Clean-VersionString {
    param($v)
    if (-not $v) { return $null }
    $clean = $v.Split(' ')[0]
    return $clean
}

# Attempt 1: Registry (Prioritized: LicenseServer\Install)
if (-not $detectedVersion) {
    $regPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Citrix\LicenseServer\Install",
        "HKLM:\SOFTWARE\Citrix\LicenseServer\Install",
        "HKLM:\SOFTWARE\WOW6432Node\Citrix\Licensing",
        "HKLM:\SOFTWARE\Citrix\Licensing",
        "HKLM:\SOFTWARE\WOW6432Node\Citrix\Licensing\LS",
        "HKLM:\SOFTWARE\Citrix\Licensing\LS"
    )
    
    foreach ($path in $regPaths) {
        try {
            $rawVer = (Get-ItemProperty $path -Name "Version" -ErrorAction Stop).Version
            if ($rawVer) {
                $displayVersion = $rawVer 
                $cleanVer = Clean-VersionString $rawVer
                if ($cleanVer) { 
                    $detectedVersion = [version]$cleanVer
                    $detectionMethod = "Registry (LicenseServer Key)"
                    break 
                }
            }
        } catch {}
    }
}

# Attempt 2: Uninstall Keys
if (-not $detectedVersion) {
    try {
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($uPath in $uninstallPaths) {
            $pkg = Get-ItemProperty $uPath -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Citrix Licens*" } | Select-Object -First 1
            if ($pkg -and $pkg.DisplayVersion) {
                $displayVersion = $pkg.DisplayVersion
                $cleanVer = Clean-VersionString $pkg.DisplayVersion
                $detectedVersion = [version]$cleanVer
                $detectionMethod = "Registry (Uninstall Info)"
                break
            }
        }
    } catch {}
}

# Attempt 3: WMI
if (-not $detectedVersion) {
    try {
        $wmi = Get-WmiObject -Namespace "ROOT\CitrixLicensing" -Class "Citrix_GT_License_Server" -ErrorAction Stop
        if ($wmi -and $wmi.Version) {
            $displayVersion = $wmi.Version
            $cleanVer = Clean-VersionString $wmi.Version
            $detectedVersion = [version]$cleanVer
            $detectionMethod = "WMI"
        }
    } catch {}
}

# Attempt 4: File
if (-not $detectedVersion) {
    $paths = @(
        "${env:ProgramFiles(x86)}\Citrix\Licensing\LS\lmadmin.exe",
        "${env:ProgramFiles}\Citrix\Licensing\LS\lmadmin.exe"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            try {
                $fvi = (Get-Item $p).VersionInfo
                if ($fvi.FileVersion) { 
                    $rawVer = $fvi.FileVersion -replace ',', '.'
                    $displayVersion = $rawVer
                    $cleanVer = Clean-VersionString $rawVer
                    $detectedVersion = [version]$cleanVer
                    $detectionMethod = "File Version (lmadmin.exe)"
                }
            } catch {}
            break
        }
    }
}

if ($detectedVersion) {
    Write-Host " Installed Version : $displayVersion" -NoNewline
    
    if ($detectedVersion -ge $minVersion) {
        Write-Host " [ OK ]" -ForegroundColor Green
        Write-Host " Compatibility     : Compatible with Citrix Cloud LAS." -ForegroundColor Gray
        Write-Host " Source            : $detectionMethod" -ForegroundColor DarkGray
    } else {
        Write-Host " [ FAIL ]" -ForegroundColor Red
        Write-Host " Compatibility     : OUTDATED! Minimum required: $minVersion" -ForegroundColor Yellow
        Write-Host " Action            : Update License Server immediately." -ForegroundColor Red
        Write-Host " Source            : $detectionMethod" -ForegroundColor DarkGray
    }
} else {
    Write-Host " Version Check     : [ FAIL ]" -ForegroundColor Red
    Write-Host " Details           : Could not determine installed version via Registry or File." -ForegroundColor Gray
}
Write-Host "`n"

# 2. SERVICE STATUS
Write-Host " PHASE 2: SERVICE STATUS" -ForegroundColor Yellow
Write-Host " -----------------------" -ForegroundColor DarkGray
Show-Spinner "Checking critical services..."

$servicesToCheck = @(
    @{ Name="Citrix Licensing"; Label="Citrix Licensing Service" },
    @{ Name="CitrixWebServicesforLicensing"; Label="Citrix Web Services for Licensing" }
)

foreach ($s in $servicesToCheck) {
    $svcName = $s.Name
    $svcLabel = $s.Label.PadRight(35)
    
    Write-Host " $svcLabel : " -NoNewline
    
    $svcObj = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    
    if ($svcObj) {
        if ($svcObj.Status -eq 'Running') {
             Write-Host "[ RUNNING ]" -ForegroundColor Green
        } else {
             Write-Host "[ STOPPED ]" -ForegroundColor Red -NoNewline
             Write-Host " (Attempting start...)" -ForegroundColor Yellow
             try {
                 Start-Service $svcName -ErrorAction Stop
                 Write-Host " -> Started!" -ForegroundColor Green
             } catch {
                 Write-Host " -> Failed to start!" -ForegroundColor Red
             }
        }
    } else {
        Write-Host "[ MISSING ]" -ForegroundColor Red -NoNewline
        Write-Host " (Service '$svcName' not found)" -ForegroundColor Gray
    }
}
Write-Host "`n"


# 3. SYSTEM HEALTH CHECK (CRYPTO)
Write-Host " PHASE 3: SYSTEM HEALTH (CRYPTO)" -ForegroundColor Yellow
Write-Host " -------------------------------" -ForegroundColor DarkGray
Show-Spinner "Analyzing Crypto Settings..."

$crypto64 = Test-RegKey $regPath64 "SchUseStrongCrypto"
$crypto32 = Test-RegKey $regPath32 "SchUseStrongCrypto"

Write-Host " TLS 1.2 (64-Bit) : " -NoNewline
if ($crypto64) { Write-Host "[ OK ]" -ForegroundColor Green } else { Write-Host "[ MISSING ] - Fix required!" -ForegroundColor Red }

Write-Host " TLS 1.2 (32-Bit) : " -NoNewline
if ($crypto32) { Write-Host "[ OK ]" -ForegroundColor Green } else { Write-Host "[ MISSING ] - Fix required!" -ForegroundColor Red }

if (-not $crypto32) {
    Write-Host "`n [!] WARNING: 32-Bit Crypto keys are missing. Citrix Service will fail!" -ForegroundColor Red
}
Write-Host "`n"

# 4. PROXY DETECTION
Write-Host " PHASE 4: NETWORK CONFIGURATION" -ForegroundColor Yellow
Write-Host " ------------------------------" -ForegroundColor DarkGray
Show-Spinner "Detecting Proxy Configuration..."

$activeProxy = $null
if ($ManualProxy) {
    $activeProxy = New-Object System.Net.WebProxy($ManualProxy)
    Write-Host " MODE: MANUAL ($ManualProxy)" -ForegroundColor Cyan
} else {
    $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $sysProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    $testUrl = "https://las.cloud.com"
    $proxyUri = $sysProxy.GetProxy($testUrl)
    
    if (([System.Uri]$testUrl).Host -ne $proxyUri.Host) {
        Write-Host " MODE: SYSTEM PROXY DETECTED ($($proxyUri.Authority))" -ForegroundColor Cyan
        $activeProxy = $sysProxy
    } else {
        Write-Host " MODE: DIRECT CONNECTION (No Proxy)" -ForegroundColor Green
        $activeProxy = $sysProxy
    }
}
Write-Host "`n"

# 5. ENDPOINT ANALYZER & TIME SYNC
Write-Host " PHASE 5: ENDPOINT ANALYZER & TIME SYNC" -ForegroundColor Yellow
Write-Host " --------------------------------------" -ForegroundColor DarkGray
Show-Spinner "Testing Cloud Endpoints..."

$targets = @(
    @{ N="Activation Service";    U="https://las.cloud.com" },
    @{ N="Telemetry / CIS";       U="https://cis.citrix.com" },
    @{ N="Trust API (Network)";   U="https://trust.citrixnetworkapi.net" },
    @{ N="Trust API (Workspace)"; U="https://trust.citrixworkspacesapi.net" },
    @{ N="Core Services";         U="https://core.citrixworkspacesapi.net" },
    @{ N="Customer Services";     U="https://customers.citrixworkspacesapi.net" }
)

$timeChecked = $false

foreach ($t in $targets) {
    $pName = $t.N.PadRight(25)
    Write-Host " $pName : " -NoNewline
    
    # --- COOLNESS FACTOR: ARTIFICIAL SPINNER DELAY ---
    $spin = @("-", "\", "|", "/")
    # Simulates approx. 1.2 seconds "Deep Analysis"
    for ($s=0; $s -lt 15; $s++) {
        Write-Host $spin[$s % 4] -NoNewline -ForegroundColor Cyan
        Start-Sleep -Milliseconds 80
        Write-Host "`b" -NoNewline
    }
    # -------------------------------------------------
    
    try {
        $req = [System.Net.HttpWebRequest]::Create($t.U)
        $req.Timeout = 5000
        $req.Proxy = $activeProxy
        $resp = $req.GetResponse()
        $c = [int]$resp.StatusCode
        
        # TIME CHECK (Only once)
        if (-not $timeChecked -and $resp.Headers["Date"]) {
            # Explicitly convert to UTC before comparison
            $serverTime = [DateTime]::Parse($resp.Headers["Date"]).ToUniversalTime()
            $localTime = [DateTime]::UtcNow
            $diff = ($serverTime - $localTime).TotalSeconds
            
            # Save drift for summary
            $timeChecked = $true
            $timeStatus = "OK"
            $timeColor = "Green"
            
            if ([Math]::Abs($diff) -gt 300) { # > 5 Minutes
                $timeStatus = "FAIL"
                $timeColor = "Red"
            } elseif ([Math]::Abs($diff) -gt 120) { # > 2 Minutes
                $timeStatus = "WARN"
                $timeColor = "Yellow"
            }
            $globalTimeDriftMsg = "Drift: $([Math]::Round($diff, 1)) sec"
            $globalTimeDriftColor = $timeColor
        }
        
        $resp.Close()
        Write-Host "[ PASS ]" -ForegroundColor Green -NoNewline
        Write-Host " (HTTP $c - SSL: Verified)" -ForegroundColor Gray
    } catch {
        $ex = $_.Exception; if($ex.InnerException){$ex=$ex.InnerException}
        $r = $ex.Response
        if ($r) {
            $c = [int]$r.StatusCode
            
            # TIME CHECK on Error Response
            if (-not $timeChecked -and $r.Headers["Date"]) {
                $serverTime = [DateTime]::Parse($r.Headers["Date"]).ToUniversalTime()
                $localTime = [DateTime]::UtcNow
                $diff = ($serverTime - $localTime).TotalSeconds
                $timeChecked = $true
                $timeStatus = "OK"
                $timeColor = "Green"
                 if ([Math]::Abs($diff) -gt 300) { $timeStatus = "FAIL"; $timeColor = "Red" }
                $globalTimeDriftMsg = "Drift: $([Math]::Round($diff, 1)) sec"
                $globalTimeDriftColor = $timeColor
            }

            $r.Close()
            if ($c -eq 403 -or $c -eq 404) {
                Write-Host "[ PASS ]" -ForegroundColor Green -NoNewline
                Write-Host " (HTTP $c - Reachable - SSL: Verified)" -ForegroundColor Gray
            } else {
                Write-Host "[ WARN ]" -ForegroundColor Yellow -NoNewline
                Write-Host " (HTTP $c - SSL: Verified)" -ForegroundColor Gray
            }
        } else {
            Write-Host "[ FAIL ]" -ForegroundColor Red -NoNewline
            Write-Host " $($ex.Message)" -ForegroundColor Red
        }
    }
}
Write-Host "`n"

# Summary for Time Sync
if ($timeChecked) {
    Write-Host " TIME SYNC CHECK : " -NoNewline
    if ($globalTimeDriftColor -eq "Green") {
        Write-Host "[ OK ]" -ForegroundColor Green -NoNewline
    } else {
        Write-Host "[ $timeStatus ]" -ForegroundColor $globalTimeDriftColor -NoNewline
    }
    Write-Host " ($globalTimeDriftMsg)" -ForegroundColor Gray
} else {
    Write-Host " TIME SYNC CHECK : [ SKIP ] (Could not retrieve server time)" -ForegroundColor Gray
}

Write-Host "`n"
Write-Host " DIAGNOSTIC COMPLETE." -ForegroundColor White -BackgroundColor DarkBlue
Write-Host "`n"
$null = Read-Host " Press ENTER to exit..."
