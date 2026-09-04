<#
.SYNOPSIS
    generates a detailed report of Active Directory user accounts.

.DESCRIPTION
    the script queries Active Directory and generates a structured report
    containing account status, identity information, logon activity,
    password information, account expiration, and organizational details.

    the report can be displayed in the console and optionally exported
    to a CSV file for further analysis in Excel or other automation tools.

    the script is designed for administrative auditing and reporting
    WITHOUT modifying any Active Directory objects.

.PARAMETER SearchBase
    optional distinguished name (DN) of the OU where the search should begin.
    if omitted, the entire Active Directory domain is searched.

.PARAMETER InactiveDays
    optional number of days used to identify potentially stale accounts.
    a user is considered inactive when their LastLogonDate is older than
    the specified number of days.

.PARAMETER IncludeDisabled
    includes disabled user accounts in the report.
    by default, only enabled accounts are included.

.PARAMETER OutputPath
    optional path for exporting the report to a CSV file.

.PARAMETER Credential
    optional credential used to query Active Directory.

.EXAMPLE
    .\Get-ADUserReport.ps1
    generates a report containing all enabled AD users.

.EXAMPLE
    .\Get-ADUserReport.ps1 -IncludeDisabled
    generates a report containing both enabled and disabled users.

.EXAMPLE
    .\Get-ADUserReport.ps1 -InactiveDays 90
    gnerates a report and identifies accounts that have not logged on
    during the last 90 days.

.EXAMPLE
    .\Get-ADUserReport.ps1 -SearchBase "OU=Users,DC=contoso,DC=local"
    generates a report only for users located below the specified OU.

.EXAMPLE
    .\Get-ADUserReport.ps1 -OutputPath ".\ADUserReport.csv"
    generates the report and exports it to a CSV file.

.EXAMPLE
    .\Get-ADUserReport.ps1 -InactiveDays 90 -IncludeDisabled `
        -OutputPath ".\ADUserAudit.csv"
    generates a complete account audit including disabled and inactive
    accounts and exports the results to CSV.

.NOTES
    the script performs read-only operations and does not modify
    Active Directory objects.
#>


[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$SearchBase,
 
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays,
 
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,
 
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
 
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)
 
# verify that the Active Directory module is available before doing anything else.
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is not installed."
    return
}
 
Import-Module ActiveDirectory -ErrorAction Stop
# fail fast: validate the output location BEFORE querying AD
if ($OutputPath) {
    $OutputDir = Split-Path -Path $OutputPath -Parent
    if ($OutputDir -and -not (Test-Path -Path $OutputDir)) {
        Write-Error "Output directory does not exist: $OutputDir"
        return
    }
}
 
Write-Host ""
Write-Host "============================================"
Write-Host " Active Directory User Report"
Write-Host "============================================"
 
# build the parameters used by Get-ADUser.
# using a hashtable keeps optional parameters from being passed when they were not specified by the administrator.
$GetADUserParams = @{
    Properties = @(
        "DisplayName"
        "GivenName"
        "Surname"
        "Mail"
        "Department"
        "Title"
        "Company"
        "Manager"
        "Enabled"
        "LastLogonDate"
        "PasswordLastSet"
        "PasswordNeverExpires"
        "PasswordExpired"
        "AccountExpirationDate"
        "whenCreated"
        "whenChanged"
        "DistinguishedName"
    )
    ErrorAction = "Stop"
}
 
if ($SearchBase) {
    $GetADUserParams["SearchBase"] = $SearchBase
}
 
if ($Credential) {
    $GetADUserParams["Credential"] = $Credential
}
 
# by default, only enabled accounts are reported.
if (-not $IncludeDisabled) {
    $GetADUserParams["Filter"] = 'Enabled -eq $true'
}
else {
    $GetADUserParams["Filter"] = '*'
}
 
try {
    Write-Host "[INFO] Querying Active Directory..."
    # wrap in @() so a single-result query still behaves like an array
    # (a bare result would otherwise report an unreliable .Count).
    $ADUsers = @(Get-ADUser @GetADUserParams)
    Write-Host "[PASS] Retrieved $($ADUsers.Count) user account(s)"
}
catch {
    Write-Error "Failed to query Active Directory: $($_.Exception.Message)"
    return
}
 
# calculate the inactivity threshold only when the administrator requested it
$InactiveDate = $null
if ($InactiveDays) {
    $InactiveDate = (Get-Date).AddDays(-$InactiveDays)
    Write-Host "[INFO] Inactive threshold: $InactiveDate"
}
 
# Manager resolution cache. (important)
# Manager is stored on the user object as a Distinguished Name rather than
# a human-readable name. many users share the same manager, so instead of
# calling Get-ADUser once per user (an N+1 query pattern that can mean
# thousands of extra AD round-trips in a large environment), each unique
# manager DN is resolved only once and cached here.
$ManagerCache = @{}
 
function Resolve-ManagerName {
    param (
        [string]$ManagerDN,
        [hashtable]$Cache,
        [System.Management.Automation.PSCredential]$Credential
    )
 
    if (-not $ManagerDN) {
        return $null
    }
 
    if ($Cache.ContainsKey($ManagerDN)) {
        return $Cache[$ManagerDN]
    }
    $GetManagerParams = @{
        Identity    = $ManagerDN
        Properties  = "DisplayName"
        ErrorAction = "SilentlyContinue"
    }
 
    # only add -Credential when one was actually supplied; passing $null
    # explicitly to a PSCredential parameter can throw a binding error
    if ($Credential) {
        $GetManagerParams["Credential"] = $Credential
    }
    $ManagerName = $null
    try {
        $ManagerObj = Get-ADUser @GetManagerParams
        $ManagerName = if ($ManagerObj) { $ManagerObj.DisplayName } else { $ManagerDN }
    }
    catch {
        $ManagerName = $ManagerDN
    }
    $Cache[$ManagerDN] = $ManagerName
    return $ManagerName
}
 
Write-Host "[INFO] Building report..."
$Report = New-Object System.Collections.Generic.List[object]
$Total = $ADUsers.Count
$Index = 0
 
foreach ($User in $ADUsers) {
    $Index++
    if ($Total -gt 0) {
        Write-Progress -Activity "Building AD user report" `
            -Status "Processing $Index of $Total" `
            -PercentComplete (($Index / $Total) * 100)
    }
 
    $ManagerName = Resolve-ManagerName -ManagerDN $User.Manager -Cache $ManagerCache -Credential $Credential
    # users who have never logged on have a null LastLogonDate and are
    # classified separately as "NeverLoggedOn"
    $ActivityStatus = "Active"
 
    if ($InactiveDays) {
        if (-not $User.LastLogonDate) {
            $ActivityStatus = "NeverLoggedOn"
        }
        elseif ($User.LastLogonDate -lt $InactiveDate) {
            $ActivityStatus = "Inactive"
        }
    }
 
    # checks for expiration date.
    $AccountStatus = if (-not $User.Enabled) {
        "Disabled"
    }
    elseif ($User.AccountExpirationDate -and
            $User.AccountExpirationDate -lt (Get-Date)) {
        "Expired"
    }
    else {
        "Enabled"
    }
 
    $Report.Add([PSCustomObject]@{
        SamAccountName        = $User.SamAccountName
        UserPrincipalName     = $User.UserPrincipalName
        DisplayName           = $User.DisplayName
        GivenName             = $User.GivenName
        Surname               = $User.Surname
        Email                 = $User.Mail
        Department            = $User.Department
        Title                 = $User.Title
        Company               = $User.Company
        Manager               = $ManagerName
        AccountStatus         = $AccountStatus
        Enabled               = $User.Enabled
        LastLogonDate         = $User.LastLogonDate
        ActivityStatus        = $ActivityStatus
        PasswordLastSet       = $User.PasswordLastSet
        PasswordNeverExpires  = $User.PasswordNeverExpires
        PasswordExpired       = $User.PasswordExpired
        AccountExpirationDate = $User.AccountExpirationDate
        Created               = $User.whenCreated
        Modified              = $User.whenChanged
        DistinguishedName     = $User.DistinguishedName
    })
}
 
Write-Progress -Activity "Building AD user report" -Completed
Write-Host "[PASS] Report generated successfully"
Write-Host ""
Write-Host "============================================"
Write-Host " Report Summary"
Write-Host "============================================"
$Report |
    Select-Object `
        SamAccountName,
        DisplayName,
        AccountStatus,
        ActivityStatus,
        LastLogonDate,
        PasswordLastSet |
    Format-Table -AutoSize
 
Write-Host ""
Write-Host "============================================"
Write-Host " Account Statistics"
Write-Host "============================================"
 
$EnabledCount = @($Report | Where-Object { $_.AccountStatus -eq "Enabled" }).Count
$DisabledCount = @($Report | Where-Object { $_.AccountStatus -eq "Disabled" }).Count
$ExpiredCount = @($Report | Where-Object { $_.AccountStatus -eq "Expired" }).Count
 
Write-Host "Total accounts : $($Report.Count)"
Write-Host "Enabled        : $EnabledCount"
Write-Host "Disabled       : $DisabledCount"
Write-Host "Expired        : $ExpiredCount"
 
if ($InactiveDays) {
    $InactiveCount = @(
        $Report | Where-Object { $_.ActivityStatus -eq "Inactive" }
    ).Count
 
    $NeverLoggedOnCount = @(
        $Report | Where-Object { $_.ActivityStatus -eq "NeverLoggedOn" }
    ).Count
 
    Write-Host "Inactive       : $InactiveCount"
    Write-Host "Never logged on: $NeverLoggedOnCount"
}
 
if ($OutputPath) {
    try {
        $Report |
            Export-Csv `
                -Path $OutputPath `
                -NoTypeInformation `
                -Encoding UTF8 `
                -ErrorAction Stop
        Write-Host ""
        Write-Host "[PASS] Report exported to: $OutputPath"
    }
    catch {
        Write-Error "Failed to export report: $($_.Exception.Message)"
        return
    }
}
 
Write-Host ""
Write-Host "============================================"
Write-Host " Report Complete"
Write-Host "============================================"
Write-Host ""
