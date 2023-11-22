    <#
        .SYNOPSIS
            Updates Azure IP Named Locations with the current external dynamic IP-adress
        
        .LINKS
            https://www.koetzingit.de        
                
        .NOTES
        - Fill out the required parameters with SecPWD, TenantID, AppID and IPNamedLocation.

    #>
#
# Powershell Azure Login
#
$SecurePassword = ConvertTo-SecureString -String "<SecPWD>" -AsPlainText -Force
$TenantId = '<TenantID>'
$ApplicationId = '<AppID>'
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $ApplicationId, $SecurePassword
Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $Credential | out-null

#
# Get the current publich ip address
#
$CurrentPubIP = (Invoke-WebRequest ifconfig.me/ip).Content.Trim()

#
# Connect to MS Graph
#
Connect-MgGraph -Scopes 'Policy.ReadWrite.ConditionalAccess' -NoWelcome | out-null

#
# Set IPLocation with current IP
#
$body = @{
	"@odata.type" = "#microsoft.graph.ipNamedLocation"
	displayName = "<IPNamedLocation>"
	isTrusted = $true
	ipRanges = @(
		@{
			"@odata.type" = "#microsoft.graph.iPv4CidrRange"
			cidrAddress = "$CurrentPubIP/32"
		}
	)
}

#
# Update the IPLocation
#
Update-MgIdentityConditionalAccessNamedLocation -NamedLocationId 'ipNL' -BodyParameter $body

Write-Host "New IP address for location Hetzles: $CurrentPubIP"
