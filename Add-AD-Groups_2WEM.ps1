<#
.DESCRIPTION
    Bulk creates WEM Conditions and Filters (Rules) based on selected AD Security Groups.
    Includes an automatic installation routine for the Citrix.WEMSDK module.
    
.AUTHOR
    Thomas koetzing, www.koetzingit.de
    
.DATE
    2026-03-12
    
.VERSION
    1.2
    
.NOTES
    - Uses 'Active Directory Group Match' type as validated in previous tests.
#>

# --- Configuration ---
$SQLServer = "SQL-Server\SQLEXPRESS"
$DBName    = "Your_WEM_DB"

# Naming prefixes
$C_Prefix  = "InGroup_"
$F_Prefix  = "MemberOf_"

# 1. Automatic SDK Installation Check
if (-not (Get-Module -ListAvailable -Name Citrix.WEMSDK)) {
    Write-Host "Citrix.WEMSDK not found. Starting installation..." -ForegroundColor Cyan
    
    # Ensure TLS 1.2 for PowerShell Gallery connectivity
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    
    try {
        # Ensure NuGet provider is present
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Confirm:$false -ErrorAction SilentlyContinue
        
        # Install module from PSGallery for current user
        Install-Module -Name Citrix.WEMSDK -Scope CurrentUser -Force -Confirm:$false
        Write-Host "Module installed successfully." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install Citrix.WEMSDK: $($_.Exception.Message)"
        return
    }
}

Import-Module Citrix.WEMSDK

# 2. Database Connection and Site Selection
try {
    # Establish direct SQL connection object
    $db = New-WEMDatabaseConnection -Server $SQLServer -Database $DBName
    
    # Retrieve Sites for selection
    $sites = Get-WEMConfiguration -Connection $db
    $selectedSite = $sites | Out-GridView -Title "WEM: Select Configuration Set (Site)" -PassThru
    
    if ($null -eq $selectedSite) { 
        Write-Host "No Site selected. Aborting." -ForegroundColor Yellow
        return 
    }
    
    $idSite = $selectedSite.IdSite
    Write-Host "Connected to $SQLServer\$DBName | Site: $($selectedSite.Name)" -ForegroundColor Green
} catch {
    Write-Error "SQL connection failed: $($_.Exception.Message)"
    return
}

# 3. AD Group Selection
if (-not (Get-Module -ListAvailable ActiveDirectory)) {
    Write-Error "Active Directory module (RSAT) is missing."
    return
}

$groups = Get-ADGroup -Filter 'GroupCategory -eq "Security"' | 
          Select-Object Name, SID | 
          Sort-Object Name |
          Out-GridView -Title "WEM: Select AD Groups for Filter creation" -PassThru

if ($null -eq $groups) { return }

# 4. Main Processing Logic
foreach ($g in $groups) {
    $groupName = $g.Name
    Write-Host "`n--- Processing Group: $groupName ---" -ForegroundColor Cyan
    
    try {
        # A) Condition Creation
        # Note: Using 'Active Directory Group Match' as exact type string
        $condName = "$C_Prefix$groupName"
        $cond = $null
        
        # Try creating the condition
        $cond = New-WEMCondition -Name $condName -Type 'Active Directory Group Match' -TestResult $groupName -Connection $db -IdSite $idSite -ErrorAction SilentlyContinue
        
        # If already exists, fetch the existing condition object to get its ID
        if ($null -eq $cond) {
            $cond = Get-WEMCondition -Connection $db -IdSite $idSite | Where-Object Name -eq $condName
        }

        # B) Rule (Filter) Creation
        if ($null -ne $cond) {
            $ruleName = "$F_Prefix$groupName"
            
            # The SDK requires an array of condition objects @($cond)
            New-WEMRule -IdSite $idSite -Name $ruleName -Conditions @($cond) -Connection $db -ErrorAction SilentlyContinue
            
            Write-Host "Success: Rule '$ruleName' created." -ForegroundColor Green
        } else {
            Write-Warning "Condition '$condName' could not be created or retrieved."
        }
    }
    catch {
        Write-Warning "Error processing $groupName : $($_.Exception.Message)"
    }
}

Write-Host "`nBulk import completed." -ForegroundColor Cyan
