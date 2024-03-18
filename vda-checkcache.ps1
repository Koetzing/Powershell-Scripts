    <#
        .SYNOPSIS
            Shows the current usage of the Device RAM Cache and the RAM Cache Size.
            Also it shows the current size of the Cache Disk file (mcsdif.vhdx). 
            Since the cache disk holds some other data as well, like eventlogs, FSLogix stuff, WEM cache etc.
            the script shows also the fixed size, used space and free space. 

        
        .LINKS
            https://www.koetzingit.de
            
                        
        .NOTES
        - You must set the variable $MC with the name of a Machine Catalog that has write cache enabled.
        - You must execute the powershell script on a Citrix delivery controller
        - You must run the script as administrator of the VDAs and you must be a Citrix administrator as well.


        .Version
        - 1.0 creation 03/18/24

        
    #>

#
# Adding Citrix Snapins
#
Add-PSSnapin Citrix*


#
# Set Machine Catalog
#
$MC= "Your-Machine-Catalog-Name"

#
# Get Values and Machine list
#
$RAMCache = Get-ProvScheme -ProvisioningSchemeName $MC | select -exp "WriteBackCacheMemorySize"
$DiskCache = Get-ProvScheme -ProvisioningSchemeName $MC | select -exp "WriteBackCacheDiskSize"
$UseCache = Get-ProvScheme -ProvisioningSchemeName $MC | select -exp "UseWriteBackCache"
$MachineList= Get-BrokerDesktop -Filter { CatalogName -eq $MC}|  Select-Object @{N="Name";E={$_.MachineName -replace ".+\\"}}

#
# Output characters for view purpose only
#
$RowSign="|"
$RowSign1="||"
cls


#
# Check if write chache is enabled
#
if ("$UseCache" -eq "true")
{

#
# Execute command on all computers within the list. On error it will continue (e.g. server not available)
#
Invoke-Command -ErrorAction SilentlyContinue -Computer $MachineList.Name -ScriptBlock { 
                $availablemem = [math]::Round((Get-counter '\Citrix MCS(*)\RAM Cache Bytes').countersamples[0].cookedvalue / 1mb)
                $availabledisk=[math]::Round((Get-counter '\Citrix MCS(*)\File Bytes').countersamples[0].cookedvalue / 1gb,2)
                
                $cachedrivefree=([Math]::Round((get-psdrive d).free /1gb, 2))
                $cachedriveused=([Math]::Round((get-psdrive d).used /1gb, 2))
                                                              
                $object = New-Object PSObject -Property @{
                "Used RAM (mb)" = $availablemem
                "Used Cache (gb)" = $availabledisk
                "Free Space (gb)" = $cachedrivefree
                "Used Space (gb)" = $cachedriveused
                }
                $object | select  "Used RAM (mb)", "Used Cache (gb)", "Free Space (gb)", "Used Space (gb)"
 } | Select @{E={$_.PSComputerName}; L='Citrix Server   '}, @{Name="||"; Expression = {$RowSign1}}, @{Name="RAM-Cache (mb)"; Expression = {$RAMCache}}, "Used RAM (mb)",@{Name="|"; Expression = {$RowSign}}, @{Name="Disk (gb)"; Expression = {$DiskCache}}, "Used Cache (gb)", "Used Space (gb)", "Free Space (gb)" | Format-Table

 } else {
 cls
 Write-Host "`n The machine catalogue $MC has the cache mode not enabled!`n"
 }
