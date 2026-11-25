
<#
.SYNOPSIS
    Configures Microsoft Entra ID Smart Lockout settings.

.DESCRIPTION
    Uses Microsoft Graph PowerShell to configure the tenant-wide
    Password Rule Settings directory setting.

    Cloud-specific default thresholds:
      - Azure Public:       10 attempts
      - Azure US Government: 3 attempts

    Default lockout duration:
      - 60 seconds

    The script:
      - Reads existing Password Rule Settings.
      - Preserves unrelated settings.
      - Previews requested changes by default.
      - Applies changes only when -Apply is specified.
      - Supports -WhatIf and -Confirm.
      - Verifies the configuration after applying changes.

    This script does not disable or modify individual user accounts.

.PARAMETER LockoutThreshold
    Number of failed sign-in attempts before initial lockout.
    Valid range: 1-10.
    Defaults according to the selected Microsoft cloud.

.PARAMETER LockoutDurationSeconds
    Minimum initial lockout duration in seconds.
    Minimum supported baseline: 60 seconds.
    Default: 60 seconds.

.PARAMETER Environment
    Microsoft Graph environment.
    Supported values: Global, USGov, USGovDoD, China.
    Default: Global.

.PARAMETER Apply
    Explicitly permits configuration changes.

.EXAMPLE
    .\Configure-EntraSmartLockout.ps1
    Connects to Microsoft Graph and previews the configuration.

.EXAMPLE
    .\Configure-EntraSmartLockout.ps1 -Apply
    Applies the default configuration after confirmation.

.EXAMPLE
    .\Configure-EntraSmartLockout.ps1 -LockoutThreshold 5 -Apply
    Applies a threshold of 5 attempts and a duration of 60 seconds.

.EXAMPLE
    .\Configure-EntraSmartLockout.ps1 -Apply -WhatIf
    Shows what would change without applying modifications.

.NOTES
    Required modules:
      Microsoft.Graph.Authentication
      Microsoft.Graph.Identity.DirectoryManagement

    Required delegated Graph permission:
      GroupSettings.ReadWrite.All

    Required Entra role:
      Authentication Policy Administrator

    Custom Smart Lockout configuration requires
    Microsoft Entra ID P1 or higher licensing for applicable users.

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [ValidateRange(1, 10)]
    [int]$LockoutThreshold,

    [ValidateRange(60, 2147483647)]
    [int]$LockoutDurationSeconds = 60,

    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',

    [switch]$Apply
)


$ErrorActionPreference = 'Stop'

$RequiredModules = @(
    'Microsoft.Graph.Authentication',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScope = 'GroupSettings.ReadWrite.All'
$TargetTemplateName = 'Password Rule Settings'

Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host " Microsoft Entra Smart Lockout Configuration" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan


if ($Environment -eq 'China') {

    throw @"
Custom Smart Lockout configuration is not supported
in Microsoft Azure operated by 21Vianet.

No changes have been made.
"@
}

Write-Host "Selected Microsoft cloud: $Environment"


if (-not $PSBoundParameters.ContainsKey('LockoutThreshold')) {

    switch ($Environment) {

        'Global' {
            $LockoutThreshold = 10
        }

        { $_ -in 'USGov', 'USGovDoD' } {
            $LockoutThreshold = 3
        }
    }
}

Write-Host "Lockout threshold: $LockoutThreshold attempts"
Write-Host "Lockout duration:  $LockoutDurationSeconds seconds"


foreach ($Module in $RequiredModules) {

    if (-not (Get-Module -ListAvailable -Name $Module)) {

        throw @"
Required module not installed: $Module

Install the required modules using:

Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
"@
    }

    Import-Module $Module -ErrorAction Stop
}


Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Yellow

Connect-MgGraph `
    -Environment $Environment `
    -Scopes $RequiredScope `
    -NoWelcome

$GraphContext = Get-MgContext

if (-not $GraphContext) {
    throw "Microsoft Graph authentication failed."
}

if ($GraphContext.Environment -ne $Environment) {

    throw @"
The authenticated Microsoft Graph environment does not match
the requested environment.

Requested:    $Environment
Authenticated: $($GraphContext.Environment)

No configuration changes have been made.
"@
}

Write-Host "Successfully connected to Microsoft Graph." `
    -ForegroundColor Green

Write-Host "Tenant ID: $($GraphContext.TenantId)"


Write-Host "`nRetrieving Password Rule Settings template..."

$Templates = Get-MgGroupSettingTemplate -All

$Template = $Templates | Where-Object {
    $_.DisplayName -eq $TargetTemplateName
}

if (-not $Template) {

    throw "The '$TargetTemplateName' template was not found."
}


Write-Host "Retrieving existing tenant settings..."

$ExistingSettings = @(
    Get-MgGroupSetting -All | Where-Object {
        $_.TemplateId -eq $Template.Id
    }
)

if ($ExistingSettings.Count -gt 1) {

    throw @"
Multiple Password Rule Settings objects were found.

Manual investigation is required before making changes.
"@
}

$ExistingSetting = $ExistingSettings | Select-Object -First 1


$SettingValues = @{}

if ($ExistingSetting) {

    Write-Host "Existing custom configuration found." `
        -ForegroundColor Green

    foreach ($Value in $ExistingSetting.Values) {

        $SettingValues[$Value.Name] = [string]$Value.Value
    }

}
else {

    Write-Host "No custom configuration found. Loading template defaults." `
        -ForegroundColor Yellow

    foreach ($Value in $Template.Values) {

        $SettingValues[$Value.Name] = [string]$Value.DefaultValue
    }
}


$CurrentThreshold = $SettingValues['LockoutThreshold']
$CurrentDuration = $SettingValues['LockoutDurationInSeconds']

if ($null -eq $CurrentThreshold -or $null -eq $CurrentDuration) {

    throw @"
Could not retrieve the existing Smart Lockout values.

The template may not expose the expected settings.
No changes have been made.
"@
}


$SettingValues['LockoutThreshold'] = [string]$LockoutThreshold

$SettingValues['LockoutDurationInSeconds'] = [string]$LockoutDurationSeconds

$UpdatedValues = @(
    foreach ($Name in $SettingValues.Keys) {

        @{
            name  = $Name
            value = $SettingValues[$Name]
        }
    }
)


Write-Host "`n========== CONFIGURATION PREVIEW ==========" `
    -ForegroundColor Cyan

$Preview = @(
    [PSCustomObject]@{
        Setting        = 'LockoutThreshold'
        CurrentValue   = $CurrentThreshold
        RequestedValue = $LockoutThreshold
    }

    [PSCustomObject]@{
        Setting        = 'LockoutDurationInSeconds'
        CurrentValue   = $CurrentDuration
        RequestedValue = $LockoutDurationSeconds
    }
)

$Preview | Format-Table -AutoSize

Write-Host "Microsoft cloud: $Environment"
Write-Host "Tenant ID:       $($GraphContext.TenantId)"


if (-not $Apply) {

    Write-Host "`nPreview completed. No changes were made." `
        -ForegroundColor Yellow

    Write-Host "Use -Apply to authorize configuration changes."

    return
}


$RequestBody = @{
    values = @($UpdatedValues)
}


$TargetDescription = "Tenant $($GraphContext.TenantId)"

$ActionDescription = "Configure Entra Smart Lockout threshold and duration"

if (-not $PSCmdlet.ShouldProcess(
    $TargetDescription,
    $ActionDescription
)) {

    Write-Host "`nOperation skipped. No changes were made." `
        -ForegroundColor Yellow

    return
}

if ($ExistingSetting) {

    Write-Host "`nUpdating existing Password Rule Settings..." `
        -ForegroundColor Yellow

    Update-MgGroupSetting `
        -GroupSettingId $ExistingSetting.Id `
        -BodyParameter $RequestBody `
        -ErrorAction Stop

}
else {

    Write-Host "`nCreating Password Rule Settings..." `
        -ForegroundColor Yellow

    $RequestBody.templateId = $Template.Id

    New-MgGroupSetting `
        -BodyParameter $RequestBody `
        -ErrorAction Stop
}


Write-Host "`nVerifying updated configuration..." `
    -ForegroundColor Yellow

$VerifiedSetting = @(
    Get-MgGroupSetting -All | Where-Object {
        $_.TemplateId -eq $Template.Id
    }
)

if ($VerifiedSetting.Count -ne 1) {

    throw "Could not uniquely identify the updated Password Rule Settings object."
}

$VerifiedValues = @{}

foreach ($Value in $VerifiedSetting[0].Values) {

    $VerifiedValues[$Value.Name] = [string]$Value.Value
}

$VerifiedThreshold = $VerifiedValues['LockoutThreshold']
$VerifiedDuration = $VerifiedValues['LockoutDurationInSeconds']

if (
    $VerifiedThreshold -ne [string]$LockoutThreshold -or
    $VerifiedDuration -ne [string]$LockoutDurationSeconds
) {

    throw @"
Configuration verification failed.

Expected threshold: $LockoutThreshold
Actual threshold:   $VerifiedThreshold

Expected duration: $LockoutDurationSeconds
Actual duration:   $VerifiedDuration
"@
}


Write-Host "`n============================================" -ForegroundColor Green
Write-Host " SMART LOCKOUT CONFIGURATION VERIFIED" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green

[PSCustomObject]@{
    TenantId                = $GraphContext.TenantId
    Environment             = $Environment
    LockoutThreshold        = $VerifiedThreshold
    LockoutDurationSeconds  = $VerifiedDuration
    Verification            = 'Successful'
} | Format-List

Write-Host "Configuration completed successfully." `
    -ForegroundColor Green
