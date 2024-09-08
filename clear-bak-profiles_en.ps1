
<#
        .SYNOPSIS
            Clears the registry from temorary profile (BAK) and the user directory, if it exist.

        
        .Author
            Thomas@koetzingit.de
            https://www.koetzingit.de
        
        .LINKS
        
                        
                        
        .NOTES
            - You must run the script as administrator but will be chechked by the script.



        .Version
        - 1.0 Creation 09/08/24

        
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
Write-Host "User with temporary profiles`n=============================" -ForegroundColor

ForEach ($Item in Get-ChildItem $PListPath) {
   $Name = $Item.PSChildName
   
   $PIP = Get-ItemProperty -Path "$PListPath\$Name"


      If ($Name.EndsWith("bak") = "True" ) {
      $Guid = $PIP.Guid
         Write-Host "Remove profile of: " -NoNewLine; Write-Host "" $PIP.ProfileImagePath.TrimStart("C:\Users\")

         #Deletes BAK profile from the registry
         Remove-Item -Path "$PListPath\$Name" -Recurse -ErrorAction SilentlyContinue | Out-Null

         #Deletes the corrosponding GUID of the user from the ProfileGuid branch.

         if ("$PGuidPath\$Guid") {
         Remove-Item -Path "$PGuidPath\$Guid" -Recurse -ErrorAction SilentlyContinue | Out-Null
          } else {
            #GUID doesn't exist
         }

         #Löscht den Benutzerordner aus den lokalen Profilen.        
         if ($PIP.ProfileImagePath) {
         Remove-Item -Path $PIP.ProfileImagePath -Recurse -ErrorAction SilentlyContinue| Out-Null
          } else {
            #Profile folder doesn't exist.
         }
 
         $Count++ 
      }
   }
Write-Host "`nTotal amoiunt of tmporary profiles removed: " -NoNewLine; Write-Host "" $Count
