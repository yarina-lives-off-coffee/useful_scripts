
<#
.SYNOPSIS
    Safely disables a Microsoft Entra ID user account.

.DESCRIPTION
    Uses Microsoft Graph PowerShell to disable a specified user
    by setting accountEnabled to false.

    Security controls:
      - Requires an explicit tenant ID.
      - Verifies the connected tenant.
      - Uses delegated Microsoft Graph authentication.
      - Previews the operation by default.
      - Requires the -Disable switch.
      - Requires exact UPN confirmation.
      - Supports ShouldProcess, -WhatIf and -Confirm.
      - Prevents disabling the authenticated administrator.
      - Checks direct active Entra directory role assignments.
      - Protects administrator-defined accounts.
      - Blocks accounts currently synchronized from on-premises AD.
      - Verifies the account state after the operation.
      - Returns an audit-friendly result object.
      - Supports optional JSON Lines audit logging.

    This script does not:
      - Delete accounts.
      - Reset passwords.
      - Revoke authentication sessions.
      - Remove group memberships.
      - Remove directory role assignments.
      - Modify on-premises Active Directory accounts.

.PARAMETER TenantId
    Required Microsoft Entra tenant ID (GUID).

.PARAMETER UserPrincipalName
    User Principal Name of the account to disable.

.PARAMETER Disable
    Explicitly requests the account-disable operation.

.PARAMETER ConfirmUserPrincipalName
    Exact UPN confirmation required when using -Disable.

.PARAMETER ProtectedUserPrincipalNames
    Administrator-maintained list of protected accounts.

.PARAMETER AllowProtectedAccount
    Allows an account in the protected list to proceed.
    Does not override privileged-role or self-disable protections.

.PARAMETER AuditLogPath
    Optional JSON Lines (.jsonl) audit log destination.

.EXAMPLE
    .\Disable-EntraUser.ps1 `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -UserPrincipalName user@contoso.com

    Previews the target account without making changes.

.EXAMPLE
    .\Disable-EntraUser.ps1 `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -UserPrincipalName user@contoso.com `
        -Disable `
        -ConfirmUserPrincipalName user@contoso.com

    Requests account disabling after explicit confirmation.

.EXAMPLE
    .\Disable-EntraUser.ps1 `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -UserPrincipalName user@contoso.com `
        -Disable `
        -ConfirmUserPrincipalName user@contoso.com `
        -WhatIf

    Previews the requested operation without making changes.

.EXAMPLE
    .\Disable-EntraUser.ps1 `
        -TenantId '00000000-0000-0000-0000-000000000000' `
        -UserPrincipalName user@contoso.com `
        -ProtectedUserPrincipalNames @(
            'admin@contoso.com',
            'breakglass@contoso.com'
        )

    Previews the target while protecting the specified accounts.

.NOTES
    Required modules:
        Microsoft.Graph.Users
        Microsoft.Graph.Identity.DirectoryManagement

    Required delegated Microsoft Graph permissions:
        User.Read.All
        User.EnableDisableAccount.All
        RoleManagement.Read.Directory

    Required administrative privileges:
        Appropriate Entra role for the target account.
        Privileged Authentication Administrator is the
        documented least-privileged role for changing
        accountEnabled across all administrators.

    Role protection:
        Checks direct active directory role assignments.
        Does not fully evaluate group-inherited roles or
        eligible-but-inactive PIM assignments.

    Hybrid identity:
        Blocks accounts where onPremisesSyncEnabled is true.
        Accounts whose source of authority has been transferred
        to the cloud may have onPremisesSyncEnabled set to null.

    Authentication:
        Delegated authentication only.
        App-only authentication is not supported.

    Existing sessions are not automatically revoked.

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNull()]
    [guid]$TenantId,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
    [string]$UserPrincipalName,

    [switch]$Disable,

    [string]$ConfirmUserPrincipalName,

    [string[]]$ProtectedUserPrincipalNames = @(),

    [switch]$AllowProtectedAccount,

    [ValidateNotNullOrEmpty()]
    [string]$AuditLogPath
)


$ErrorActionPreference = 'Stop'

$RequiredModules = @(
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Identity.DirectoryManagement'
)

$RequiredScopes = @(
    'User.Read.All'
    'User.EnableDisableAccount.All'
    'RoleManagement.Read.Directory'
)

$UserPrincipalName = $UserPrincipalName.Trim().ToLowerInvariant()
$TenantIdString = $TenantId.ToString()

Write-Host "`n=== Microsoft Entra User Containment ===" `
    -ForegroundColor Cyan

Write-Host "Target user: $UserPrincipalName"
Write-Host "Tenant ID:   $TenantIdString"
Write-Host "Mode:        $(if ($Disable) { 'EXECUTION REQUESTED' } else { 'PREVIEW ONLY' })"


if ($Disable) {

    if ([string]::IsNullOrWhiteSpace($ConfirmUserPrincipalName)) {
        throw @"
Account disabling requires explicit UPN confirmation.

Re-run using:

-Disable -ConfirmUserPrincipalName '$UserPrincipalName'
"@
    }

    $ConfirmedUPN = $ConfirmUserPrincipalName.Trim().ToLowerInvariant()

    if ($ConfirmedUPN -cne $UserPrincipalName) {
        throw "Confirmation UPN does not match the target account."
    }
}
elseif ($PSBoundParameters.ContainsKey('ConfirmUserPrincipalName')) {

    Write-Warning "Confirmation UPN supplied without -Disable. No changes will be made."
}


$ProtectedUPNs = @(
    $ProtectedUserPrincipalNames |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim().ToLowerInvariant() }
)

$IsProtectedAccount = $ProtectedUPNs -contains $UserPrincipalName

if ($IsProtectedAccount -and -not $AllowProtectedAccount) {

    throw @"
The target account is in the protected account list.

Account: $UserPrincipalName

No changes were made.

An authorized administrator must review this account
before considering the -AllowProtectedAccount override.
"@
}

if ($IsProtectedAccount) {
    Write-Warning "Protected-account override supplied."
}


if ($PSBoundParameters.ContainsKey('AuditLogPath')) {

    $AuditLogPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($AuditLogPath)

    if ([System.IO.Path]::GetExtension($AuditLogPath) -ine '.jsonl') {
        throw "AuditLogPath must use the .jsonl extension."
    }

    $AuditDirectory = Split-Path -Path $AuditLogPath -Parent

    if (-not (Test-Path -LiteralPath $AuditDirectory -PathType Container)) {
        throw "Audit log directory does not exist: $AuditDirectory"
    }

    if (Test-Path -LiteralPath $AuditLogPath -PathType Container) {
        throw "Audit log path points to a directory."
    }
}


foreach ($Module in $RequiredModules) {

    if (-not (Get-Module -ListAvailable -Name $Module)) {

        throw @"
Required module is not installed: $Module

Install using:

Install-Module $Module -Scope CurrentUser
"@
    }

    Import-Module $Module -ErrorAction Stop
}


Write-Host "`nConnecting to Microsoft Graph..." `
    -ForegroundColor Yellow

Connect-MgGraph `
    -TenantId $TenantIdString `
    -Scopes $RequiredScopes `
    -NoWelcome

$GraphContext = Get-MgContext

if (-not $GraphContext) {
    throw "Microsoft Graph authentication failed."
}


if ($GraphContext.TenantId -ne $TenantIdString) {
    throw "Connected tenant ID does not match the requested tenant ID."
}

if ($GraphContext.AuthType -ne 'Delegated') {
    throw "This script supports delegated authentication only."
}

if ([string]::IsNullOrWhiteSpace($GraphContext.Account)) {
    throw "Unable to identify the authenticated delegated user."
}

foreach ($Scope in $RequiredScopes) {

    if ($GraphContext.Scopes -notcontains $Scope) {
        throw "Required Graph permission '$Scope' is missing."
    }
}

Write-Host "Tenant verification successful." -ForegroundColor Green
Write-Host "Connected tenant: $($GraphContext.TenantId)"
Write-Host "Authenticated account: $($GraphContext.Account)"


try {

    $AuthenticatedUser = Get-MgUser `
        -UserId $GraphContext.Account `
        -Property @(
            'id'
            'userPrincipalName'
        ) `
        -ErrorAction Stop

}
catch {

    throw "Unable to resolve the authenticated administrator: $($_.Exception.Message)"
}

if (-not $AuthenticatedUser.Id) {
    throw "Could not retrieve the authenticated administrator's object ID."
}


Write-Host "`nRetrieving target account..." `
    -ForegroundColor Yellow

try {

    $TargetUser = Get-MgUser `
        -UserId $UserPrincipalName `
        -Property @(
            'id'
            'displayName'
            'userPrincipalName'
            'accountEnabled'
            'userType'
            'onPremisesSyncEnabled'
        ) `
        -ErrorAction Stop

}
catch {

    throw "Unable to retrieve target account '$UserPrincipalName': $($_.Exception.Message)"
}

if (-not $TargetUser) {
    throw "Target account was not found."
}


if ($TargetUser.Id -eq $AuthenticatedUser.Id) {

    throw @"
Self-disable protection triggered.

The target account is the authenticated administrator.

Target object ID: $($TargetUser.Id)

Use a separate authorized administrator account.
"@
}


$IsSyncedAccount = $TargetUser.OnPremisesSyncEnabled -eq $true

if ($IsSyncedAccount) {

    throw @"
The target account is currently synchronized from on-premises AD.

Account: $($TargetUser.UserPrincipalName)

The script will not disable this account.

Investigate the authoritative identity source and perform
the containment operation through the appropriate process.

Cloud-managed users whose source of authority has been
transferred may have onPremisesSyncEnabled set to null.
"@
}


Write-Host "`nChecking direct directory role assignments..." `
    -ForegroundColor Yellow

try {

    $RoleAssignments = @(
        Get-MgRoleManagementDirectoryRoleAssignment `
            -All `
            -ErrorAction Stop
    )

}
catch {

    throw @"
Unable to verify directory role assignments.

The script will not continue because privileged-account
protection could not be completed.

Check the RoleManagement.Read.Directory permission
and the administrator's directory permissions.

Details: $($_.Exception.Message)
"@
}

$TargetRoleAssignments = @(
    $RoleAssignments | Where-Object {
        $_.PrincipalId -eq $TargetUser.Id
    }
)

if ($TargetRoleAssignments.Count -gt 0) {

    try {

        $RoleDefinitions = @(
            Get-MgRoleManagementDirectoryRoleDefinition `
                -All `
                -ErrorAction Stop
        )

    }
    catch {

        throw "Unable to resolve role definitions. Privileged-account verification cannot continue."
    }

    $RoleDefinitionLookup = @{}

    foreach ($Definition in $RoleDefinitions) {
        $RoleDefinitionLookup[$Definition.Id] = $Definition.DisplayName
    }

    $AssignedRoleNames = @(
        foreach ($Assignment in $TargetRoleAssignments) {

            if ($RoleDefinitionLookup.ContainsKey($Assignment.RoleDefinitionId)) {
                $RoleDefinitionLookup[$Assignment.RoleDefinitionId]
            }
            else {
                "Unknown role ($($Assignment.RoleDefinitionId))"
            }
        }
    )

    throw @"
The target account has direct active Entra directory role assignments.

Account: $($TargetUser.UserPrincipalName)

Assigned roles:
$($AssignedRoleNames -join "`n")

No changes were made.

Privileged directory accounts are blocked by this script.
"@
}

Write-Host "No direct active directory role assignments found." `
    -ForegroundColor Green


Write-Host "`n=== Target Account ===" -ForegroundColor Cyan

$AccountSummary = [PSCustomObject]@{
    DisplayName       = $TargetUser.DisplayName
    UserPrincipalName = $TargetUser.UserPrincipalName
    ObjectId          = $TargetUser.Id
    UserType          = $TargetUser.UserType
    AccountEnabled    = $TargetUser.AccountEnabled
    IsSyncedAccount   = $IsSyncedAccount
    IsProtected       = $IsProtectedAccount
    TenantId          = $TenantIdString
}

$AccountSummary | Format-List | Out-Host


if ($TargetUser.AccountEnabled -eq $false) {

    Write-Warning "The target account is already disabled."

    $Result = [PSCustomObject]@{
        TimestampUTC      = [DateTime]::UtcNow.ToString('o')
        TenantId          = $TenantIdString
        Actor              = $AuthenticatedUser.UserPrincipalName
        UserPrincipalName = $TargetUser.UserPrincipalName
        ObjectId           = $TargetUser.Id
        PreviousState      = 'Disabled'
        CurrentState       = 'Disabled'
        Action             = 'No action required'
        Verification       = 'Already disabled'
    }

    Write-Output $Result
    return
}


if (-not $Disable) {

    Write-Host "`nPREVIEW: No account modifications will be performed." `
        -ForegroundColor Yellow

    Write-Host "To request disabling, use:"
    Write-Host "-Disable -ConfirmUserPrincipalName '$UserPrincipalName'"

    return
}


$ActionDescription = "Disable Entra ID account $UserPrincipalName"

if (-not $PSCmdlet.ShouldProcess(
    $TargetUser.UserPrincipalName,
    $ActionDescription
)) {

    Write-Host "`nOperation not approved or previewed using -WhatIf." `
        -ForegroundColor Yellow

    return
}

Write-Host "`nDisabling account..." -ForegroundColor Yellow

try {

    Update-MgUser `
        -UserId $TargetUser.Id `
        -AccountEnabled:$false `
        -ErrorAction Stop

}
catch {

    throw "Failed to disable account '$UserPrincipalName': $($_.Exception.Message)"
}


Write-Host "Verifying account state..." -ForegroundColor Yellow

try {

    $UpdatedUser = Get-MgUser `
        -UserId $TargetUser.Id `
        -Property @(
            'id'
            'userPrincipalName'
            'accountEnabled'
        ) `
        -ErrorAction Stop

}
catch {

    throw @"
The update request was submitted, but verification failed.

Account: $UserPrincipalName

Check the account state in Microsoft Entra admin center
before attempting another operation.

Details: $($_.Exception.Message)
"@
}

if ($UpdatedUser.AccountEnabled -ne $false) {

    throw @"
Account disable verification failed.

Microsoft Graph still reports the account as enabled.

Account: $UserPrincipalName

Investigate the account state before retrying.
"@
}


$Result = [PSCustomObject]@{
    TimestampUTC      = [DateTime]::UtcNow.ToString('o')
    TenantId          = $TenantIdString
    Actor              = $AuthenticatedUser.UserPrincipalName
    UserPrincipalName = $UpdatedUser.UserPrincipalName
    ObjectId           = $UpdatedUser.Id
    PreviousState      = 'Enabled'
    CurrentState       = 'Disabled'
    Action             = 'Account disabled'
    Verification       = 'Successful'
}

Write-Host "`nAccount successfully disabled and verified." `
    -ForegroundColor Green

$Result | Format-List | Out-Host


if ($PSBoundParameters.ContainsKey('AuditLogPath')) {

    try {

        $AuditRecord = $Result | ConvertTo-Json -Compress

        Add-Content `
            -LiteralPath $AuditLogPath `
            -Value $AuditRecord `
            -Encoding UTF8 `
            -ErrorAction Stop

        Write-Host "Audit record written to: $AuditLogPath" `
            -ForegroundColor Green

    }
    catch {

        Write-Warning @"
The account was successfully disabled, but the local audit
record could not be written.

Preserve the execution result and investigate the logging failure.

Details: $($_.Exception.Message)
"@
    }
}


Write-Output $Result
