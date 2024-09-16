<#
        .SYNOPSIS
            Removes unwanted policies generaed by a bug and sets a registry key that addresses an issue 
            that slows server performance or causes the server to stop responding because of numerous Windows firewall rules

        
        .LINKS
         - https://support.microsoft.com/en-us/topic/march-26-2019-kb4490481-os-build-17763-402-c323e5c1-d524-dbdb-04a0-c3b5c8c8f2fd          
                        
        .NOTES
            - You must run the script as administrator but will be chechked by the script.
    
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
#Check Script is running with Elevated Privileges
#
Check-RunAsAdministrator | Out-Null


$profiles = get-wmiobject -class win32_userprofile
cls
Write-Host "`n`n`n`n`n`n`n`n"
Write-Host "Getting Firewall Rules..."

#
# deleting rules with no owner would be disastrous
#
$Rules1 = Get-NetFirewallRule -All | 
  Where-Object {$profiles.sid -notcontains $_.owner -and $_.owner }
$Rules1Count = $Rules1.count
Write-Host "" $Rules1Count "Rules`n"

Write-Host "Getting Firewall Rules from ConfigurableServiceStore Store..."
$Rules2 = Get-NetFirewallRule -All -PolicyStore ConfigurableServiceStore | 
  Where-Object { $profiles.sid -notcontains $_.owner -and $_.owner }
$Rules2Count = $Rules2.count
Write-Host "" $Rules2Count "Rules`n"

$Total = $Rules1.count + $Rules2.count
Write-Host "Deleting" $Total "Firewall Rules:" -ForegroundColor Green

$Result = measure-command {

  $start = (Get-Date)
  $i = 0.0

  foreach($rule1 in $Rules1){

    # 
    # action
    #
    remove-itemproperty -path "HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" -name $rule1.name

    # 
    # progress
    #
    $i = $i + 1.0
    $prct = $i / $total * 100.0
    $elapsed = (Get-Date) - $start
    $totaltime = ($elapsed.TotalSeconds) / ($prct / 100.0)
    $remain = $totaltime - $elapsed.TotalSeconds
    $eta = (Get-Date).AddSeconds($remain)

    # 
    # display
    #
    $prctnice = [math]::round($prct,2) 
    $elapsednice = $([string]::Format("{0:d2}:{1:d2}:{2:d2}", $elapsed.hours, $elapsed.minutes, $elapsed.seconds))
    $speed = $i/$elapsed.totalminutes
    $speednice = [math]::round($speed,2) 
    Write-Progress -Activity "Deleting Rules1 ETA $eta elapsed $elapsednice loops/min $speednice" -Status "$prctnice" -PercentComplete $prct -secondsremaining $remain
  }

  foreach($rule2 in $Rules2) {

    # 
    # action  
    #
    remove-itemproperty -path "HKLM:\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Configurable\System" -name $rule2.name

    # 
    # progress
    #
    $i = $i + 1.0
    $prct = $i / $total * 100.0
    $elapse = (Get-Date) - $start
    $totaltime = ($elapsed.TotalSeconds) / ($prct / 100.0)
    $remain = $totaltime - $elapsed.TotalSeconds
    $eta = (Get-Date).AddSeconds($remain)

    # 
    # display
    #
    $prctnice = [math]::round($prct,2) 
    $elapsednice = $([string]::Format("{0:d2}:{1:d2}:{2:d2}", $elapsed.hours, $elapsed.minutes, $elapsed.seconds))
    $speed = $i/$elapsed.totalminutes
    $speednice = [math]::round($speed,2) 
    Write-Progress -Activity "Deleting Rules2 ETA $eta elapsed $elapsednice loops/min $speednice" -Status "$prctnice" -PercentComplete $prct -secondsremaining $remain
  }
}

#
# Set value to Delete User AppContainers On Logoff
#
New-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" -Name "DeleteUserAppContainersOnLogoff" -Type dword  -Value 1 -force | Out-Null

$end = get-date
write-host end $end 
write-host eta $eta

write-host $result.minutes min $result.seconds sec
