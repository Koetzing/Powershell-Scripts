    <#
        .SYNOPSIS
            Installs the new Microsoft Teams x64 on Windows Server 2022, Windows 10 and Windows 11 multiuser,
            including the Outlook Add-in and sets required registry keys for Citrix VDA as well. 
            The new Teams is based on EdgeWebView Runtime and willbe installed as well. 
            
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
            - You must run the script as administrator but will be chechked by the script.
            - You need free internet access to download the resources



        .Version
        - 1.0 creation 03/30/24
        - 2.0 Download source media

        
    #>


#
# Set install path with containing MSTeams-x64.msix,teamsbootstrapper.exe and MicrosoftEdgeWebView2RuntimeInstallerX64.exe
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
#Check Script is running with Elevated Privileges
#
Check-RunAsAdministrator | Out-Null


#
# Add .NET 3.x Feature as required for the Outlook Add-in
#
Write-Host "`nEnable .NET 3.x Feature`n"
Start-Process -wait -NoNewWindow -FilePath DISM.exe -Args "/Online /Enable-Feature /FeatureName:NetFx3 /All"


#
# Download and Install EdgeWebView Runtime
#
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2124701' -Destination "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Description "Download latest EdgeWebView Runtime"
Write-Host "`nInstall EdgeWebView Runtime. Please wait.`n"
Start-Process -wait -FilePath "$InstallPath\MicrosoftEdgeWebView2RuntimeInstallerX64.exe" -Args "/silent /install" | Out-Null



#
# Install New MS Teams MSIX
#
Write-Host "`nDownload and Install New Microsoft Teams. Please wait.`n"
Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=2196106" -Destination "$InstallPath\MSTeams-x64.msix" -Description "Download latest Microsoft teams version" | Out-Null
Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=2243204" -Destination "$InstallPath\teamsbootstrapper.exe" -Description "Download teams bootstrapper" | Out-Null
Start-Process -wait -FilePath "$InstallPath\teamsbootstrapper.exe" -Args "-p -o ""$InstallPath\MSTeams-x64.msix""" -NoNewWindow| Out-Null


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

Write-Host "`n Finished!`n"
