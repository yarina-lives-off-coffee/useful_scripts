<# 
for microsoft exchange server 2013-2016
configures Exchange Server Client Access URLs

.desc
configures internal and external URLs for Exchange virtual directories,
including OWA, ECP, ActiveSync, EWS, OAB, MAPI/HTTP, and Outlook Anywhere.
clso configures the internal Autodiscover Service URL.

.PARAMETER Server
One or more Exchange Client Access servers to configure.

.PARAMETER InternalURL
The internal Exchange namespace used by clients.

.PARAMETER ExternalURL
The external Exchange namespace used by clients.

.PARAMETER AutodiscoverSCP
Optional Autodiscover Service URL. Defaults to the InternalURL.

.PARAMETER InternalSSL
Specifies whether internal Outlook Anywhere clients require SSL.

.PARAMETER ExternalSSL
Specifies whether external Outlook Anywhere clients require SSL.

.note
before running it on a production server, I'd first inspect the current configuration with:
Get-OwaVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-EcpVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-ActiveSyncVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-WebServicesVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-OabVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-MapiVirtualDirectory -Server EXCH01 | Format-List InternalUrl,ExternalUrl
Get-OutlookAnywhere -Server EXCH01 | Format-List InternalHostname,ExternalHostname

.example
.\PS-ExchangeServerConfigURL.ps1 `
    -Server "EXCH01" `
    -InternalURL "mail.yourdomain.local" `
    -ExternalURL "mail.yourdomain.com"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string[]]$Server,
    [Parameter(Mandatory = $true)]
    [string]$InternalURL,
    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$ExternalURL,
    [string]$AutodiscoverSCP,
    [bool]$InternalSSL = $true,
    [bool]$ExternalSSL = $true
)

Begin {
    # Load Exchange Management Shell
    if (Test-Path "$env:ExchangeInstallPath\bin\RemoteExchange.ps1") {
        . "$env:ExchangeInstallPath\bin\RemoteExchange.ps1"
        Connect-ExchangeServer -Auto -AllowClobber
    }
    else {
        Write-Warning "Exchange Server management tools are not installed on this PC."
        exit
    }
}

Process {
    foreach ($ServerName in $Server) {
        if ((Get-ExchangeServer $ServerName -ErrorAction SilentlyContinue).IsClientAccessServer) {
            Write-Host "`nConfiguring $ServerName`n"
            Write-Host "Internal URL: $InternalURL"
            Write-Host "External URL: $ExternalURL"
            Write-Host "Internal SSL: $InternalSSL"
            Write-Host "External SSL: $ExternalSSL`n"

            # Configure Outlook Anywhere
            Write-Host "Configuring Outlook Anywhere..."
            $OutlookAnywhere = Get-OutlookAnywhere -Server $ServerName
            $OutlookAnywhere | Set-OutlookAnywhere `
                -ExternalHostname $ExternalURL `
                -InternalHostname $InternalURL `
                -ExternalClientsRequireSsl $ExternalSSL `
                -InternalClientsRequireSsl $InternalSSL `
                -ExternalClientAuthenticationMethod $OutlookAnywhere.ExternalClientAuthenticationMethod

            # Configure virtual directories
            if ($ExternalURL -eq "") {
                Write-Host "Configuring Outlook Web App..."
                Get-OwaVirtualDirectory -Server $ServerName |
                    Set-OwaVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/owa"
                Write-Host "Configuring Exchange Control Panel..."
                Get-EcpVirtualDirectory -Server $ServerName |
                    Set-EcpVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/ecp"

                Write-Host "Configuring ActiveSync..."
                Get-ActiveSyncVirtualDirectory -Server $ServerName |
                    Set-ActiveSyncVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/Microsoft-Server-ActiveSync"

                Write-Host "Configuring Exchange Web Services..."
                Get-WebServicesVirtualDirectory -Server $ServerName |
                    Set-WebServicesVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/EWS/Exchange.asmx"

                Write-Host "Configuring Offline Address Book..."
                Get-OabVirtualDirectory -Server $ServerName |
                    Set-OabVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/OAB"

                Write-Host "Configuring MAPI/HTTP..."
                Get-MapiVirtualDirectory -Server $ServerName |
                    Set-MapiVirtualDirectory `
                        -ExternalUrl $null `
                        -InternalUrl "https://$InternalURL/mapi"
            }
            else {

                Write-Host "Configuring Outlook Web App..."
                Get-OwaVirtualDirectory -Server $ServerName |
                    Set-OwaVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/owa" `
                        -InternalUrl "https://$InternalURL/owa"

                Write-Host "Configuring Exchange Control Panel..."
                Get-EcpVirtualDirectory -Server $ServerName |
                    Set-EcpVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/ecp" `
                        -InternalUrl "https://$InternalURL/ecp"

                Write-Host "Configuring ActiveSync..."
                Get-ActiveSyncVirtualDirectory -Server $ServerName |
                    Set-ActiveSyncVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/Microsoft-Server-ActiveSync" `
                        -InternalUrl "https://$InternalURL/Microsoft-Server-ActiveSync"

                Write-Host "Configuring Exchange Web Services..."
                Get-WebServicesVirtualDirectory -Server $ServerName |
                    Set-WebServicesVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/EWS/Exchange.asmx" `
                        -InternalUrl "https://$InternalURL/EWS/Exchange.asmx"

                Write-Host "Configuring Offline Address Book..."
                Get-OabVirtualDirectory -Server $ServerName |
                    Set-OabVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/OAB" `
                        -InternalUrl "https://$InternalURL/OAB"

                Write-Host "Configuring MAPI/HTTP..."
                Get-MapiVirtualDirectory -Server $ServerName |
                    Set-MapiVirtualDirectory `
                        -ExternalUrl "https://$ExternalURL/mapi" `
                        -InternalUrl "https://$InternalURL/mapi"
            }

            # Configure Autodiscover
            Write-Host "Configuring Autodiscover..."

            if ($AutodiscoverSCP) {
                Get-ClientAccessServer $ServerName |
                    Set-ClientAccessServer `
                        -AutoDiscoverServiceInternalUri "https://$AutodiscoverSCP/Autodiscover/Autodiscover.xml"
            }
            else {
                Get-ClientAccessServer $ServerName |
                    Set-ClientAccessServer `
                        -AutoDiscoverServiceInternalUri "https://$InternalURL/Autodiscover/Autodiscover.xml"
            }

            Write-Host "`nFinished configuring $ServerName.`n"
        }
        else {
            Write-Host -ForegroundColor Yellow "$ServerName is not a Client Access server."
        }
    }
}

End {
    Write-Host "Finished processing all specified servers."
    Write-Host "Consider running Get-CASHealthCheck.ps1 to verify the Client Access configuration."
}
