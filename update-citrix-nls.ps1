    <#
        .SYNOPSIS
            Updates Citrix Cloud Network Locations with the current external dynamic IP-adress
        
        .LINKS
            https://www.koetzingit.de
            https://docs.citrix.com/en-us/citrix-workspace/optimize-cvad/workspace-network-location.html#configure-network-locations
                        
        .NOTES
        - frist download the "nls2.psm1" file from https://github.com/citrix/sample-scripts/blob/master/workspace/NLS2.psm1
        - Modify the NLS2.psm1 to reflect your location: Open a browser and use the URL https://trust.citrixworkspacesapi.net/root/tokens/clients
          and find the Bad request to endpoint for examlple: https://trust-westeurope-release-b.citrixworkspacesapi.net
          Replace in NLS2.psm1 the $script:trustBaseUrl variable with your endpoint URL. Save the file.
        - Change the path below at Import-Module with your location of NLS2.psm1
        - Fill out the required parameters with customer id, client id and client secret.
        - Done. Run the script
    #>

#
# Get the current publich ip adress
#
$CurrentPubIP = (Invoke-WebRequest ifconfig.me/ip).Content.Trim()

#
# Import Citrix Network Locations module
#
Import-Module c:\path\nls2.psm1 -Force

#
# Set required parameters
#
$clientId = "<Citrix Cloud client ID"
$customer = "<Citrix customer ID"
$clientSecret = "<Citrix Cloud client secret>"

#
# Connect to Citrix API for Network Locations
#
Connect-NLS -clientId $clientId -clientSecret $clientSecret -customer $customer -Verbose

#
# Change the first [0] Network Location with the current external IP
#
(Get-NLSSite)[0] | Set-NLSSite -ipv4Ranges @("$CurrentPubIP/32")

