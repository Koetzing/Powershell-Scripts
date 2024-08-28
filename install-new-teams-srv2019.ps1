    <#
        .SYNOPSIS
            Installs the new Microsoft Teams x64 on Windows Server 2019, including the Outlook Add-in
            and sets required registry keys. The new Teams is based on EdgeWebView Runtime and will
            be installed as well. With Server 2019, additional updates and .NET 4.8.x are required.

            You must set per User registry keys to load the Outlook Add-in via GPO, WEM etc. For GPO
            find the xml file at https://www.koetzingit.de with the article to this script.

        
        .Author
            Thomas@koetzingit.de
            https://www.koetzingit.de
        
        .LINKS
        
            https://learn.microsoft.com/en-us/microsoftteams/new-teams-vdi-requirements-deploy
            https://learn.microsoft.com/en-us/microsoftteams/troubleshoot/meetings/resolve-teams-meeting-add-in-issues
            https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/multimedia/opt-ms-teams.html
            
                        
        .NOTES
            - Sources are downloaded into the script location, make sure its writeable.
            - You must run the script as administrator but will be chechked by the script.
            - You need free internet access, because the script downloads the required sources.
            - If asked, you must install the PendingReboots Powershell module



        .Version
        - 1.0 Creation 04/10/24
        - 1.1 Include download of sources
        - 1.2 Check for .NET Framework and pending reboots
        - 1.3 Alternatve download because of dynmaic content for the nativ utility
        - 1.4 Extracting the MSU package to speedup the installation
        - 1.5 Temas register timeout 

        
    #>


#
# Set install path were the script is located
#
$InstallPath = (Get-Location).Path



#
# Check Admin function
#
Function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       #Exit from the current, unelevated, process
       Exit
 
    }
}

# 
# Check Script is running with Elevated Privileges
#
Check-RunAsAdministrator | Out-Null


# 
# Check .NET Framework Version
#
$NetVersion = (Get-ItemProperty "HKLM:Software\Microsoft\NET Framework Setup\NDP\v4\Full").Version
if ($NetVersion -ge 4.8){

#
# Download and install Windows Update kb5035849
#
Start-BitsTransfer -Source 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu' -Destination $InstallPath -Description "Download Windows Update KB5035849"
Write-Host "`nExtract msu file to speedup the installtion of the Windoes Update`n"
Start-Process "expand.exe" -ArgumentList @("-f:* ""$InstallPath\windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu"" $InstallPath") -Wait -NoNewWindow

Write-Host "`nInstall Windows Update kb5035849. This takes some time, 15min. Please wait. If reboot is required, say No and reboot after the script finished.`n"
Add-WindowsPackage -Online -PackagePath "$InstallPath\ssu-17763.5568-x64.cab" -LogPath "$InstallPath\ssu-17763.5568-x64.log" -PreventPending -NoRestart -WarningAction SilentlyContinue | Out-Null
Add-WindowsPackage -Online -PackagePath "$InstallPath\Windows10.0-KB5035849-x64.cab" -LogPath "$InstallPath\Windows10.0-KB5035849-x64.log" -PreventPending -NoRestart -WarningAction SilentlyContinue | Out-Null


#
# Set Appx Keyes to not block the teams installation
#
Write-Host "`nSet Appx Keys`n"
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v AllowAllTrustedApps /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v BlockNonAdminUserInstall /t REG_DWORD /d 0x00000000 /f") -Wait -NoNewWindow | Out-Null


#
# Enable feature Overwrite
#
Write-Host "`nEnable Feature Overwrite`n"
Start-Process "reg.exe" -ArgumentList @("add HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides /v 191176410 /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null


#
# Install MS Teams native utility
#
#Start-BitsTransfer -Source 'https://statics.teams.cdn.office.net/evergreen-assets/DesktopClient/MSTeamsNativeUtility.msi'  -Destination $InstallPath -Description "Download MS Teams Nativ Utility"
(New-Object Net.WebClient).DownloadFile("https://statics.teams.cdn.office.net/evergreen-assets/DesktopClient/MSTeamsNativeUtility.msi","$InstallPath\MSTeamsNativeUtility.msi")
Write-Host "`nInstall MS Teams native utility`n"
Start-Process "msiexec" -ArgumentList @("/i ""$InstallPath\MSTeamsNativeUtility.msi""","/qn","/norestart ALLUSERS=1""") -Wait


#
# Install EdgeWebView Runtime
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2124701' -Destination "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Description "Download latest EdgeWebView Runtime"
Write-Host "`nInstall EdgeWebView Runtime. Please wait.`n"
Start-Process -wait -FilePath "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Args "/silent /install"


#
# Install new Teams
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2196106' -Destination "$InstallPath\MSTeams-x64.msix" -Description "Download latest Microsoft teams version"
Write-Host "`nInstall new Teams`n"
Start-Process -wait -NoNewWindow -FilePath DISM.exe -Args "/Online /Add-ProvisionedAppxPackage /PackagePath:$InstallPath\MSTeams-x64.msix /SkipLicense"

#
# Time to fully register MSIX package
#
Write-Host "30 seconds Timout for the MSIX package to fully register."
Start-Sleep -Seconds 30


#
# Set Registry values for VDI and Citrix
#
Write-Host "`nSet registry keys for VDI and Citrix.`n"
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Type dword  -Value 1 -force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Name "IsWVDEnvironment" -Type dword  -Value 1 -force | Out-Null
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\WebSocketService" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\WebSocketService" -Name "ProcessWhitelist" -Type MultiString  -Value "msedgewebview2.exe" -force | Out-Null


#
# Install and register MS Teams Outlook Add-In
#
Write-Host "`nInstall Microsoft Teams Add-in for Outlook.`n"
$MSTappx = (Get-AppxPackage | Where-Object -Property Name -EQ -Value MSTeams)
$MSTappVer = $MSTappx.Version
$MSTappxPath = $MSTappx.InstallLocation
$MSIname = "MicrosoftTeamsMeetingAddinInstaller.msi"
$MSTAddinMSI = "$MSTappxPath\$MSIName"
$applockerinfo = (Get-AppLockerFileInformation -Path $MSTAddinMSI | Select -ExpandProperty Publisher)
$MSTbinVer = $applockerinfo.BinaryVersion
$targetDir = "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\$MSTbinVer"

#
# Pre-creation of the log file and folder.
#
New-Item -ItemType Directory -Path "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin" -Force | Out-Null
New-Item -ItemType File  "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\MSTMeetingAddin.log" -Force | Out-Null

Start-Process "msiexec" -ArgumentList @("/i ""$MSTAddinMSI""","/qn","/norestart ALLUSERS=1 TARGETDIR=""$targetDir"" /L*V ""C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\MSTMeetingAddin.log""") -Wait
Start-Process "c:\windows\System32\regsvr32.exe" -ArgumentList @("/s","/n","/i:user ""$targetDir\x64\Microsoft.Teams.AddinLoader.dll""")  -wait

Write-Host "`nFinished! Reboot, if required by the Windows Udpate!`n"

}
 else
{
# 
# Import module
#
if ((Get-Module -Name "PendingReboot")) {
   
}
else {
   Install-Module PendingReboot -Confirm:$False -Force
}


# 
# Check for pendig reboots otherwise .NET Framework 4.8 will not install.
#
$PendReboot= Test-PendingReboot -SkipConfigurationManagerClientCheck
if ($PendReboot -eq "true") { 
  Write-Host "There is a pendig reboot. Reboot the system first and run the script again!"
 } else { 

#
# Download and install .NET Framework 4.8
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2088631' -Destination "$InstallPath\ndp48-x86-x64-allos-enu.exe" -Description "Download .NET Framework 4.8.x, required for the Outlook Add-in"
Write-Host "`nInstall .NET Framework 4.8, this can take some time.`n"
Start-Process "$InstallPath\ndp48-x86-x64-allos-enu.exe" -ArgumentList @("/q /norestart /ChainingPackage ADMINDEPLOYMENT") -Wait

#
# Download and install Windows Update kb5035849
#
Start-BitsTransfer -Source 'https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/03/windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu' -Destination $InstallPath -Description "Download Windows Update KB5035849"
Write-Host "`nExtract msu file to speedup the installtion of the Windoes Update`n"
Start-Process "expand.exe" -ArgumentList @("-f:* ""$InstallPath\windows10.0-kb5035849-x64_eb960a140cd0ba04dd175df1b3268295295bfefa.msu"" $InstallPath") -Wait -NoNewWindow

Write-Host "`nInstall Windows Update kb5035849. This takes some time, 15min. Please wait. If reboot is required, say No and reboot after the script finished.`n"
Add-WindowsPackage -Online -PackagePath "$InstallPath\ssu-17763.5568-x64.cab" -LogPath "$InstallPath\ssu-17763.5568-x64.log" -PreventPending -NoRestart -WarningAction SilentlyContinue | Out-Null
Add-WindowsPackage -Online -PackagePath "$InstallPath\Windows10.0-KB5035849-x64.cab" -LogPath "$InstallPath\Windows10.0-KB5035849-x64.log" -PreventPending -NoRestart -WarningAction SilentlyContinue | Out-Null


#
# Set Appx Keyes to not block the teams installation
#
Write-Host "`nSet Appx Keys`n"
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v AllowAllTrustedApps /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v AllowDevelopmentWithoutDevLicense /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null
Start-Process "reg.exe" -ArgumentList @("add HKLM\Software\Policies\Microsoft\Windows\Appx /v BlockNonAdminUserInstall /t REG_DWORD /d 0x00000000 /f") -Wait -NoNewWindow | Out-Null


#
# Enable feature Overwrite
#
Write-Host "`nEnable Feature Overwrite`n"
Start-Process "reg.exe" -ArgumentList @("add HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides /v 191176410 /t REG_DWORD /d 0x00000001 /f") -Wait -NoNewWindow | Out-Null


#
# Install MS Teams native utility
#
#Start-BitsTransfer -Source 'https://statics.teams.cdn.office.net/evergreen-assets/DesktopClient/MSTeamsNativeUtility.msi'  -Destination $InstallPath -Description "Download MS Teams native utility"
(New-Object Net.WebClient).DownloadFile("https://statics.teams.cdn.office.net/evergreen-assets/DesktopClient/MSTeamsNativeUtility.msi","$InstallPath\MSTeamsNativeUtility.msi")
Write-Host "`nInstall MS Teams native utility`n"
Start-Process "msiexec" -ArgumentList @("/i ""$InstallPath\MSTeamsNativeUtility.msi""","/qn","/norestart ALLUSERS=1""") -Wait


#
# Install EdgeWebView Runtime
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2124701' -Destination "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Description "Download EdgeWebView Runtime"
Write-Host "`nInstall EdgeWebView Runtime. Please wait.`n"
Start-Process -wait -FilePath "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Args "/silent /install"


#
# Install new Teams
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2196106' -Destination "$InstallPath\MSTeams-x64.msix" -Description "Download latest Microsoft teams version"
Write-Host "`nInstall new Teams`n"
Start-Process -wait -NoNewWindow -FilePath DISM.exe -Args "/Online /Add-ProvisionedAppxPackage /PackagePath:$InstallPath\MSTeams-x64.msix /SkipLicense"



#
# Set Registry values for VDI and Citrix
#
Write-Host "`nSet registry keys for VDI and Citrix.`n"
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Name "disableAutoUpdate" -Type dword  -Value 1 -force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" -Name "IsWVDEnvironment" -Type dword  -Value 1 -force | Out-Null
New-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\WebSocketService" -Force | Out-Null
New-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Citrix\WebSocketService" -Name "ProcessWhitelist" -Type MultiString  -Value "msedgewebview2.exe" -force | Out-Null


#
# Install and register MS Teams Outlook Add-In
#
Write-Host "`nInstall Microsoft Teams Add-in for Outlook.`n"
$MSTappx = (Get-AppxPackage | Where-Object -Property Name -EQ -Value MSTeams)
$MSTappVer = $MSTappx.Version
$MSTappxPath = $MSTappx.InstallLocation
$MSIname = "MicrosoftTeamsMeetingAddinInstaller.msi"
$MSTAddinMSI = "$MSTappxPath\$MSIName"
$applockerinfo = (Get-AppLockerFileInformation -Path $MSTAddinMSI | Select -ExpandProperty Publisher)
$MSTbinVer = $applockerinfo.BinaryVersion
$targetDir = "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\$MSTbinVer"

#
# Pre-creation of the log file and folder.
#
New-Item -ItemType Directory -Path "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin" -Force | Out-Null
New-Item -ItemType File  "C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\MSTMeetingAddin.log" -Force | Out-Null

Start-Process "msiexec" -ArgumentList @("/i ""$MSTAddinMSI""","/qn","/norestart ALLUSERS=1 TARGETDIR=""$targetDir"" /L*V ""C:\Program Files (x86)\Microsoft\TeamsMeetingAddin\MSTMeetingAddin.log""") -Wait
Start-Process "c:\windows\System32\regsvr32.exe" -ArgumentList @("/s","/n","/i:user ""$targetDir\x64\Microsoft.Teams.AddinLoader.dll""")  -wait

Write-Host "`n Finished! Reboot, if required by the Windows Udpate!`n"

}


}




