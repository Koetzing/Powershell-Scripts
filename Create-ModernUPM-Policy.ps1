<#
.SYNOPSIS
    Creates a modern Citrix UPM Container policy (CVAD 2402+).
    Enables VHDX, Reattachment, Local Cache, and sets essential exclusions.

.NOTES
    Author:  Thomas Kötzing | www.koetzingit.de
    Version: 1.4 (Fixed: Added ProfileContainer_Part wildcard)
#>

# --- CONFIGURATION ---
$PolicyName        = "UPM - Modern ProfileDisk"
$StorePath         = "\\FileServer\Profiles$\#SAMAccountName#"
$DeliveryGroupName = "" # Optional: Name of the Delivery Group
$IsPolicyEnabled   = $false # Disabled by default for safety
# ---------------------

Write-Host "--- Initializing Citrix 2402 Environment ---" -ForegroundColor Cyan
if (-not (Get-PSSnapin Citrix.* -ErrorAction SilentlyContinue)) { Add-PSSnapin Citrix.* -ErrorAction SilentlyContinue }

# 1. Cleanup old policies
if (Get-BrokerGpoPolicy -Name $PolicyName -ErrorAction SilentlyContinue) {
    Remove-BrokerGpoPolicy -Name $PolicyName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
}

# 2. Create Policy Shell
$PolicySet = Get-BrokerGpoPolicySet | Where-Object { $_.Name -eq "DefaultSitePolicies" } | Select-Object -First 1
if (-not $PolicySet) { $PolicySet = Get-BrokerGpoPolicySet | Select-Object -First 1 }

$NewPolicy = New-BrokerGpoPolicy -Name $PolicyName -PolicySetGuid $PolicySet.PolicySetGuid -IsEnabled $IsPolicyEnabled
$Guid = $NewPolicy.PolicyGuid

# 3. Enable Features
Write-Host "Configuring UPM Features..." -ForegroundColor Gray

# NOTE: 'ProfileContainer_Part' defines the content. '[" *"]' forces Full Profile Mode.
$UPMSettings = @(
    @{ N = "ServiceActive"; V = "1" }
    @{ N = "DATPath_Part"; V = $StorePath }
    @{ N = "FSLogixProfileContainerSupport"; V = "1" }  # VHDX Container Engine
    @{ N = "ProfileContainer_Part"; V = '[" *"]' }      # IMPORTANT: Wildcard for full profile!
    @{ N = "EnableVolumeReattach"; V = "1" }            # Reattachment (Network resilience)
    @{ N = "EnableVHDDiskCompaction"; V = "1" }         # Save storage space
    @{ N = "LogonExclusionCheck_Part"; V = "Delete" }   # Deletes excluded folders in container
    # Optional: Local caching for unstable networks (Pro-Tip)
    # @{ N = "OfflineProfileSupport"; V = "1" }
)

foreach ($S in $UPMSettings) {
    New-BrokerGpoSetting -PolicyGuid $Guid -SettingName $S.N -SettingValue $S.V -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 50 
}

# 4. Exclusion List (JSON Format for 2402+)
# Defines what should NOT be in the container (Cache, Temp, etc.)
$ExclusionList = @(
    "Downloads", "Saved Games", "Contacts", "Searches", "Links", "Music", "Videos", ".Citrix", "Tracing",
    "AppData\Local\Temp", "AppData\Local\CrashDumps", 
    "AppData\Local\Microsoft\OneDrive\cache", "AppData\Local\Microsoft\Edge\User Data\Default\Cache",
    "AppData\Local\Google\Chrome\User Data\Default\Cache", "AppData\Local\Microsoft\Teams\Current\Locales",
    "AppData\Local\Microsoft\Terminal Server Client\Cache"
)
$ExclusionJson = $ExclusionList | ConvertTo-Json -Compress

New-BrokerGpoSetting -PolicyGuid $Guid -SettingName "ProfileContainerExclusionListDir_Part" -SettingValue $ExclusionJson

# 5. Studio Refresh & Assignment
Set-BrokerGpoPolicy -Name $PolicyName -Description "UPM VHDX Policy (Auto-Created v1.4)"

if (-not [string]::IsNullOrWhiteSpace($DeliveryGroupName)) {
    $DG = Get-BrokerDesktopGroup -Name $DeliveryGroupName -ErrorAction SilentlyContinue
    if ($DG) {
        New-BrokerGpoFilter -PolicyGuid $Guid -Type DesktopGroup -Value $DG.Uid -IsAllowed $true -ErrorAction Stop
        Write-Host " -> Assigned to $($DG.Name)" -ForegroundColor Green
    }
}

Write-Host "DONE. Policy '$PolicyName' created." -ForegroundColor Green
