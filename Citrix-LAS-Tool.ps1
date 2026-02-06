<#
.SYNOPSIS
    Citrix LAS Connectivity Check - International Edition

.DESCRIPTION
    Diagnostic tool for Citrix Local Activation Server (LAS) connectivity.
    Checks API endpoints, SSL certificates, and proxy configurations.
    Interprets HTTP 403/404 status codes correctly as successful connectivity.

.AUTHOR
    Thomas Koetzing

.URL
    www.koetzingit.de

.VERSION
    1.0.0.0

.DATE
    2026-02-06
#>

param([string]$ManualProxy = "")

# --- SETUP ---
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ErrorActionPreference = "SilentlyContinue"
$testUrlForProxy = "https://las.cloud.com"

# --- TARGET LIST ---
$targets = @(
    @{ Name="Activation Service";    Url="https://las.cloud.com" },
    @{ Name="Telemetry / CIS";       Url="https://cis.citrix.com" },
    @{ Name="Trust API (Network)";   Url="https://trust.citrixnetworkapi.net" },
    @{ Name="Trust API (Workspace)"; Url="https://trust.citrixworkspacesapi.net" },
    @{ Name="Core Services";         Url="https://core.citrixworkspacesapi.net" },
    @{ Name="Customer Services";     Url="https://customers.citrixworkspacesapi.net" }
)

# --- HEADER & CREDITS ---
Clear-Host
Write-Host "`n==================================================================================" -ForegroundColor Cyan
Write-Host "   CITRIX LICENSE SERVER - CONNECTIVITY DIAGNOSTICS" -ForegroundColor White
Write-Host "==================================================================================" -ForegroundColor Cyan
Write-Host "Author : Thomas Koetzing (www.koetzingit.de)" -ForegroundColor Gray
Write-Host "Version: 1.0.0.0 (2026-02-06)" -ForegroundColor Gray
Write-Host "----------------------------------------------------------------------------------" -ForegroundColor DarkGray

# --- PROXY DETECTION & INTERACTION ---
$activeProxy = $null
$modeInfo = ""
$modeColor = "Green"

# 1. Check CLI Parameter
if ($ManualProxy) {
    $activeProxy = New-Object System.Net.WebProxy($ManualProxy)
    $modeInfo = "MANUAL PROXY (CLI Argument: $ManualProxy)"
    $modeColor = "Yellow"
} 
else {
    # 2. Check System/IE Proxy
    $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $sysProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
    $proxyUri = $sysProxy.GetProxy($testUrlForProxy)
    
    # Compare Hosts (Avoids string mismatch due to trailing slashes)
    $origHost = ([System.Uri]$testUrlForProxy).Host
    $proxyHost = $proxyUri.Host

    if ($origHost -ne $proxyHost) {
        # System Proxy Detected
        $modeInfo = "SYSTEM PROXY DETECTED ($($proxyUri.Authority))"
        $modeColor = "Cyan"
        $activeProxy = $sysProxy
    } 
    else {
        # 3. No System Proxy -> ASK USER
        Write-Host "`nNo system proxy detected (Direct Connection)." -ForegroundColor Gray
        Write-Host "Do you want to enter a manual proxy? (e.g. http://192.168.1.1:8080)" -ForegroundColor Yellow
        $userInput = Read-Host "Enter Proxy or press ENTER to skip"

        if ($userInput -ne "") {
            try {
                $activeProxy = New-Object System.Net.WebProxy($userInput)
                $modeInfo = "MANUAL PROXY (User Input: $userInput)"
                $modeColor = "Yellow"
            } catch {
                Write-Host "Invalid Proxy Format! Fallback to Direct." -ForegroundColor Red
                $modeInfo = "DIRECT CONNECTION (Fallback)"
            }
        } else {
            $modeInfo = "DIRECT CONNECTION (No Proxy)"
            $modeColor = "Green"
            $activeProxy = $sysProxy
        }
    }
}

Write-Host "`nConnection Mode : " -NoNewline
Write-Host "$modeInfo" -ForegroundColor $modeColor
Write-Host "----------------------------------------------------------------------------------`n"

# --- TABLE HEADER ---
Write-Host "SERVICE NAME                    STATUS    DETAILS" -ForegroundColor DarkGray
Write-Host "----------------------------    ------    ----------------------------------------" -ForegroundColor DarkGray

# --- MAIN LOOP ---
foreach ($t in $targets) {
    $status = "FAIL"
    $color = "Red"
    $msg = ""

    try {
        $req = [System.Net.HttpWebRequest]::Create($t.Url)
        $req.Timeout = 5000 
        $req.Proxy = $activeProxy
        
        # Execute Request
        $resp = $req.GetResponse()
        
        # HTTP 200 OK
        $code = [int]$resp.StatusCode
        $resp.Close()
        
        $status = " OK "
        $color = "Green"
        $msg = "HTTP $code - Content OK - SSL: Verified"

    } catch {
        $ex = $_.Exception
        # Drill down to InnerException for accurate status codes
        if ($ex.InnerException) { $ex = $ex.InnerException }
        
        $webResp = $ex.Response

        if ($webResp) {
            $code = [int]$webResp.StatusCode
            $webResp.Close()

            # LOGIC: 403 & 404 are VALID for Connectivity Checks
            if ($code -eq 403 -or $code -eq 404) {
                $status = " OK "
                $color = "Green"
                $msg = "HTTP $code - Reachable - SSL: Verified"
            }
            elseif ($code -ge 500) {
                $status = "WARN"
                $color = "Yellow"
                $msg = "HTTP $code - Server Side Error - SSL: Verified"
            }
            else {
                $status = "FAIL"
                $color = "Red"
                $msg = "HTTP $code - Unexpected response"
            }
        }
        else {
            # --- NETWORK / SSL FAILURE ---
            $status = "FAIL"
            $color = "Red"
            
            if ($ex.Status -eq "NameResolutionFailure") { 
                $msg = "DNS Error (Host not found)" 
            }
            elseif ($ex.Status -eq "TrustFailure" -or $ex.Message -match "trust") { 
                $msg = "SSL ERROR: Certificate Untrusted (Check Proxy/Inspection)" 
            }
            elseif ($ex.Status -eq "Timeout") { 
                $msg = "Network Timeout (Firewall Block)" 
            }
            else { 
                $msg = $ex.Message 
            }
        }
    }

    # --- OUTPUT ROW ---
    $outName = $t.Name.PadRight(28)
    Write-Host "$outName" -NoNewline
    Write-Host "[$status]" -ForegroundColor $color -NoNewline
    Write-Host "    $msg" -ForegroundColor Gray
}
Write-Host "`n"
Write-Host "Press ENTER to exit..." -ForegroundColor DarkGray
$null = Read-Host
