
<#
.SYNOPSIS
    Retrieves and analyzes failed Microsoft Entra ID sign-in events
    for a specified user.

.DESCRIPTION
    Uses Microsoft Graph PowerShell to retrieve interactive sign-in
    events for a specified user within a configurable time window.

    Features:
      - Retrieves failed sign-in events.
      - Identifies source IP addresses.
      - Displays application and client information.
      - Reports authentication failure codes and descriptions.
      - Displays Conditional Access results.
      - Provides device and geographic context.
      - Summarizes activity by source IP and failure code.
      - Supports optional CSV export.
      - Returns structured PowerShell objects.

    This is a READ-ONLY investigation script.

    It does not:
      - Disable or delete user accounts.
      - Reset passwords.
      - Revoke authentication sessions.
      - Modify authentication policies.

.PARAMETER UserPrincipalName
    User Principal Name (UPN) of the account to investigate.

.PARAMETER LookbackHours
    Number of hours to look back.
    Default: 24.
    Allowed range: 1-720.

.PARAMETER ExportPath
    Optional destination path for CSV export.

.EXAMPLE
    .\Get-FailedLoginUser.ps1 -UserPrincipalName user@contoso.com

    Retrieves failed interactive sign-ins from the previous 24 hours.

.EXAMPLE
    .\Get-FailedLoginUser.ps1 `
        -UserPrincipalName user@contoso.com `
        -LookbackHours 72
    Retrieves failed sign-ins from the previous 72 hours.

.EXAMPLE
    .\Get-FailedLoginUser.ps1 `
        -UserPrincipalName user@contoso.com `
        -LookbackHours 48 `
        -ExportPath ".\FailedLoginReport.csv"
    Retrieves and exports the investigation results.

.EXAMPLE
    $Results = .\Get-FailedLoginUser.ps1 `
        -UserPrincipalName user@contoso.com
    Stores the returned investigation objects for further processing.

.NOTES
    Required module:
        Microsoft.Graph.Reports

    Required delegated Microsoft Graph permission:
        AuditLog.Read.All

    An appropriate Entra role is also required, such as:
        Reports Reader
        Security Reader

    API:
        Microsoft Graph v1.0

    Sign-in coverage:
        Interactive sign-in events.

    Non-interactive sign-in events are not explicitly retrieved.

    Sign-in log availability depends on tenant licensing,
    configuration, and retention.

    No account modifications are performed.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [ValidateRange(1, 720)]
    [int]$LookbackHours = 24,

    [ValidateNotNullOrEmpty()]
    [string]$ExportPath
)


$ErrorActionPreference = 'Stop'

$RequiredModule = 'Microsoft.Graph.Reports'
$RequiredScope = 'AuditLog.Read.All'

$UserPrincipalName = $UserPrincipalName.Trim().ToLowerInvariant()

Write-Host "`n=== Entra ID Failed Login Investigation ===" `
    -ForegroundColor Cyan

Write-Host "Target user:   $UserPrincipalName"
Write-Host "Lookback:      $LookbackHours hours"
Write-Host "Investigation: READ-ONLY" -ForegroundColor Green


if ($PSBoundParameters.ContainsKey('ExportPath')) {

    $ExportPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($ExportPath)

    $ExportDirectory = Split-Path -Path $ExportPath -Parent

    if (-not (Test-Path -LiteralPath $ExportDirectory -PathType Container)) {
        throw "Export directory does not exist: $ExportDirectory"
    }

    if (Test-Path -LiteralPath $ExportPath -PathType Container) {
        throw "Export path points to a directory, not a file."
    }

    if ([System.IO.Path]::GetExtension($ExportPath) -ine '.csv') {
        throw "ExportPath must have a .csv extension."
    }
}


if (-not (Get-Module -ListAvailable -Name $RequiredModule)) {

    throw @"
Required module is not installed: $RequiredModule

Install it using:

Install-Module Microsoft.Graph.Reports -Scope CurrentUser
"@
}

Import-Module $RequiredModule -ErrorAction Stop


Write-Host "`nConnecting to Microsoft Graph..." `
    -ForegroundColor Yellow

Connect-MgGraph -Scopes $RequiredScope -NoWelcome

$GraphContext = Get-MgContext

if (-not $GraphContext) {
    throw "Microsoft Graph authentication failed."
}

if ($GraphContext.Scopes -notcontains $RequiredScope) {
    throw "Required Graph permission '$RequiredScope' is not available in the current session."
}

Write-Verbose "Connected to tenant: $($GraphContext.TenantId)"
Write-Host "Connected successfully." -ForegroundColor Green


$EndTime = [DateTime]::UtcNow
$StartTime = $EndTime.AddHours(-$LookbackHours)

$InvariantCulture = [System.Globalization.CultureInfo]::InvariantCulture

$StartTimeFilter = $StartTime.ToString(
    "yyyy-MM-ddTHH:mm:ssZ",
    $InvariantCulture
)

$EndTimeFilter = $EndTime.ToString(
    "yyyy-MM-ddTHH:mm:ssZ",
    $InvariantCulture
)

Write-Verbose "Investigation start UTC: $StartTimeFilter"
Write-Verbose "Investigation end UTC:   $EndTimeFilter"


$EscapedUPN = $UserPrincipalName.Replace("'", "''")

$Filter = @(
    "userPrincipalName eq '$EscapedUPN'"
    "createdDateTime ge $StartTimeFilter"
    "createdDateTime le $EndTimeFilter"
) -join ' and '

Write-Verbose "Graph filter: $Filter"


$Properties = @(
    'id'
    'createdDateTime'
    'userPrincipalName'
    'userDisplayName'
    'ipAddress'
    'appDisplayName'
    'resourceDisplayName'
    'clientAppUsed'
    'status'
    'conditionalAccessStatus'
    'isInteractive'
    'location'
    'deviceDetail'
    'correlationId'
)


Write-Host "`nRetrieving sign-in events..." `
    -ForegroundColor Yellow

try {

    $SignInEvents = @(
        Get-MgAuditLogSignIn `
            -Filter $Filter `
            -Property $Properties `
            -All `
            -ErrorAction Stop
    )

}
catch {

    throw "Failed to retrieve sign-in events: $($_.Exception.Message)"
}


$FailedSignInEvents = @(
    $SignInEvents | Where-Object {
        $_.Status.ErrorCode -ne 0 -and
        $_.IsInteractive -eq $true
    }
)

Write-Verbose "Retrieved sign-in events: $($SignInEvents.Count)"
Write-Verbose "Failed interactive events: $($FailedSignInEvents.Count)"


if ($FailedSignInEvents.Count -eq 0) {

    Write-Host "`nNo failed interactive sign-ins were found." `
        -ForegroundColor Green

    Write-Host "User: $UserPrincipalName"
    Write-Host "Period: $StartTimeFilter - $EndTimeFilter (UTC)"

    return
}


$FailedLogins = @(
    foreach ($Event in $FailedSignInEvents) {

        $Location = $Event.Location
        $Device = $Event.DeviceDetail
        $Status = $Event.Status

        $LocationParts = @(
            $Location.City
            $Location.State
            $Location.CountryOrRegion
        ) | Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        }

        $LocationText = $LocationParts -join ', '

        [PSCustomObject]@{
            DateTimeUTC             = $Event.CreatedDateTime
            UserPrincipalName       = $Event.UserPrincipalName
            DisplayName             = $Event.UserDisplayName
            IPAddress               = $Event.IpAddress
            Application             = $Event.AppDisplayName
            Resource                = $Event.ResourceDisplayName
            ClientApp               = $Event.ClientAppUsed
            ErrorCode               = $Status.ErrorCode
            FailureReason           = $Status.FailureReason
            AdditionalDetails       = $Status.AdditionalDetails
            ConditionalAccessStatus = $Event.ConditionalAccessStatus
            IsInteractive           = $Event.IsInteractive
            Location                = $LocationText
            OperatingSystem         = $Device.OperatingSystem
            Browser                 = $Device.Browser
            DeviceName              = $Device.DisplayName
            DeviceId                = $Device.DeviceId
            CorrelationId           = $Event.CorrelationId
            SignInId                = $Event.Id
        }
    }
)

$FailedLogins = @(
    $FailedLogins | Sort-Object DateTimeUTC -Descending
)


$DistinctIPs = @(
    $FailedLogins.IPAddress |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
)

Write-Host "`n=== Investigation Results ===" `
    -ForegroundColor Cyan

Write-Host "User:             $UserPrincipalName"
Write-Host "Failed attempts:  $($FailedLogins.Count)"
Write-Host "Distinct IPs:     $($DistinctIPs.Count)"
Write-Host "Period start UTC: $StartTimeFilter"
Write-Host "Period end UTC:   $EndTimeFilter"


Write-Host "`n=== Failed Sign-In Events ===" `
    -ForegroundColor Cyan

$FailedLogins |
    Format-Table `
        DateTimeUTC,
        IPAddress,
        Application,
        ErrorCode,
        ConditionalAccessStatus,
        Location `
        -AutoSize |
    Out-Host


Write-Host "`n=== Activity by Source IP ===" `
    -ForegroundColor Cyan

$IPSummary = @(
    $FailedLogins |
        Group-Object IPAddress |
        Sort-Object Count -Descending |
        Select-Object @{
            Name = 'IPAddress'
            Expression = { $_.Name }
        }, @{
            Name = 'FailedAttempts'
            Expression = { $_.Count }
        }
)

$IPSummary | Format-Table -AutoSize | Out-Host


Write-Host "`n=== Failure Code Summary ===" `
    -ForegroundColor Cyan

$FailureSummary = @(
    $FailedLogins |
        Group-Object ErrorCode |
        Sort-Object Count -Descending |
        Select-Object @{
            Name = 'ErrorCode'
            Expression = { $_.Name }
        }, @{
            Name = 'Occurrences'
            Expression = { $_.Count }
        }, @{
            Name = 'FailureReason'
            Expression = {
                ($_.Group | Select-Object -First 1).FailureReason
            }
        }
)

$FailureSummary | Format-Table -AutoSize | Out-Host


if ($PSBoundParameters.ContainsKey('ExportPath')) {

    try {

        $FailedLogins |
            Export-Csv `
                -Path $ExportPath `
                -NoTypeInformation `
                -Encoding UTF8 `
                -ErrorAction Stop

        Write-Host "`nReport exported successfully:" `
            -ForegroundColor Green

        Write-Host $ExportPath
    }
    catch {

        throw "CSV export failed: $($_.Exception.Message)"
    }
}


Write-Host "`nInvestigation completed." `
    -ForegroundColor Green

Write-Output $FailedLogins
