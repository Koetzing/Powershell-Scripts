
<#
        .SYNOPSIS
            Bereinigt die Registrierung von temorären Profilen (BAK) und das zugehörige Benutzerverzeichnis, wenn dieses existiert.
 
        .Author
            Thomas@koetzingit.de
            https://www.koetzingit.de
        
        .LINKS                      
                        
        .NOTES
            - Das Skript muss mit administrativen Rechten ausgeführt werden, wird aber geprüft.

        .Version
        - 1.0 Erstellung 09/08/24        
    #>


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



$Count = 0
$PListPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList"
$PGuidPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileGuid"

Clear-Host
Write-Host "Benutzer mit temporären Profilen`n============================="

ForEach ($Item in Get-ChildItem $PListPath) {
   $Name = $Item.PSChildName
   
   $PIP = Get-ItemProperty -Path "$PListPath\$Name"


      If ($Name.EndsWith("bak") = "True" ) {
      $Guid = $PIP.Guid
         Write-Host "Enterne temporäres Profil von " -NoNewLine; Write-Host "" $PIP.ProfileImagePath.TrimStart("C:\Users\")

         #Löscht BAK Profile aus der Registierung
         Remove-Item -Path "$PListPath\$Name" -Recurse -ErrorAction SilentlyContinue | Out-Null

         #Löscht die zugehörige GUID des Benutzer aus dem ProfileGuid Zweig

         if ("$PGuidPath\$Guid") {
         Remove-Item -Path "$PGuidPath\$Guid" -Recurse -ErrorAction SilentlyContinue | Out-Null
          } else {
            #GUID Referenz nicht vorhanden
         }

         #Löscht den Benutzerordner aus den lokalen Profilen        
         if ($PIP.ProfileImagePath) {
         Remove-Item -Path $PIP.ProfileImagePath -Recurse -ErrorAction SilentlyContinue| Out-Null
          } else {
            #Profilverzeichnis nicht mehr vorhanden
         }
 
         $Count++ 
      }
   }
Write-Host "`nGesamte Anzahl an Temporären Profilen entfernt" -NoNewLine; Write-Host "" $Count
