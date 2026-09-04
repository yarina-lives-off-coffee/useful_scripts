<#
.SYNOPSIS
    audits privileged Active Directory group membership.

.DESCRIPTION
    the script identifies accounts with membership in configurable
    privileged Active Directory groups.

    it checks both direct and nested group membership, allowing the
    administrator to identify users who receive privileged access
    indirectly through nested security groups. For nested members, the
    actual chain of groups leading to the privileged group is resolved
    and reported.

    The report includes:
        - User identity
        - Enabled / disabled status
        - Privileged group
        - Direct or nested membership
        - Membership path (real nested-group chain, when applicable)
        - Department
        - Title
        - Email
        - Last logon date

    results are displayed in the console and can optionally be exported
    to a CSV file.
    the script performs read-only Active Directory queries and does not
    modify users, groups, or permissions.

.PARAMETER PrivilegedGroups
    one or more Active Directory security groups that should be treated
    as privileged.
    if omitted, a default set of common privileged groups is used.

.PARAMETER IncludeDisabled
    includes disabled accounts in the report.
    by default, disabled accounts are excluded.

.PARAMETER SearchBase
    optional distinguished name (DN) under which results are restricted.
    Users whose DistinguishedName does not fall under this DN are
    excluded from the report.

.PARAMETER OutputPath
    optional path for exporting the report to CSV.

.PARAMETER Credential
    optional credential used for Active Directory queries.

.EXAMPLE
    .\Get-PrivilegedADUsers.ps1
    audits the default set of privileged Active Directory groups.

.EXAMPLE
    .\Get-PrivilegedADUsers.ps1 -IncludeDisabled
    audits privileged groups and includes disabled accounts.

.EXAMPLE
    .\Get-PrivilegedADUsers.ps1 -PrivilegedGroups "Domain Admins","Enterprise Admins"
    audits only the specified privileged groups.

.EXAMPLE
    .\Get-PrivilegedADUsers.ps1 -SearchBase "OU=Corp Users,DC=contoso,DC=com"
    audits privileged group membership, restricted to users under the given OU.

.EXAMPLE
    .\Get-PrivilegedADUsers.ps1 `
        -PrivilegedGroups "Domain Admins" `
        -OutputPath ".\PrivilegedUsers.csv"
    audits Domain Admin membership and exports the results to CSV.

.NOTES
    requires the ActiveDirectory PowerShell module.
    the script performs read-only operations.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$PrivilegedGroups = @(
        "Domain Admins"
        "Enterprise Admins"
        "Schema Admins"
        "Administrators"
        "Account Operators"
        "Server Operators"
        "Backup Operators"
        "Print Operators"
        "Group Policy Creator Owners"
    ),

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,
    [Parameter(Mandatory = $false)]
    [string]$SearchBase,
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential
)

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "The ActiveDirectory PowerShell module is not installed."
    return
}

Import-Module ActiveDirectory -ErrorAction Stop

if ($OutputPath) {
    $OutputDirectory = Split-Path -Path $OutputPath -Parent
    if ($OutputDirectory -and -not (Test-Path -Path $OutputDirectory)) {
        Write-Error "Output directory does not exist: $OutputDirectory"
        return
    }
}

Write-Host "============================================"
Write-Host " Privileged Active Directory Audit"
Write-Host "============================================"

# Credential is only added when explicitly supplied so that $null is never
# passed to the -Credential parameter.
$ADQueryParams = @{
    ErrorAction = "Stop"
}
if ($Credential) {
    $ADQueryParams["Credential"] = $Credential
}

# Cache objects so the same one does not need to be queried
# repeatedly when it appears in multiple privileged areas.
$UserCache = @{}
$GroupCache = @{}
# cache the set of DIRECT member DNs for each privileged group, computed
# once per group instead of once per user (this was previously the main
# performance problem: a fresh Get-ADGroupMember call was being made for
# every single user, in every group).
$DirectMemberCache = @{}
# Cache of DN -> memberOf values, used when walking up the group chain to
# resolve the real nested-membership path. avoids re-querying the same
# group's memberOf attribute multiple times across different users/groups.
$MemberOfCache = @{}
$GroupNameCache = @{}

try {
    $Domain = Get-ADDomain @ADQueryParams
}
catch {
    Write-Error "Unable to retrieve Active Directory domain information: $($_.Exception.Message)"
    return
}

if (-not $SearchBase) {
    $SearchBase = $Domain.DistinguishedName
}

function Get-MemberOfCached {
    param([string]$DistinguishedName)

    if ($MemberOfCache.ContainsKey($DistinguishedName)) {
        return $MemberOfCache[$DistinguishedName]
    }

    try {
        $Obj = Get-ADObject -Identity $DistinguishedName -Properties memberOf @ADQueryParams
        $MemberOf = @($Obj.memberOf)
    }
    catch {
        $MemberOf = @()
    }

    $MemberOfCache[$DistinguishedName] = $MemberOf
    return $MemberOf
}

function Get-GroupNameCached {
    param([string]$DistinguishedName)

    if ($GroupNameCache.ContainsKey($DistinguishedName)) {
        return $GroupNameCache[$DistinguishedName]
    }

    try {
        $GroupObj = Get-ADGroup -Identity $DistinguishedName @ADQueryParams
        $Name = $GroupObj.Name
    }
    catch {
        # fall back to a readable fragment of the DN if the lookup fails
        $Name = ($DistinguishedName -split ",")[0] -replace "^CN=", ""
    }

    $GroupNameCache[$DistinguishedName] = $Name
    return $Name
}

# performs a breadth-first search up the memberOf chain from the user to
# the target privileged group, returning the actual chain of nested groups
# that grants access (rather than a generic placeholder string).
function Find-NestedMembershipPath {
    param(
        [string]$StartDistinguishedName,
        [string]$TargetGroupDistinguishedName
    )

    $Visited = [System.Collections.Generic.HashSet[string]]::new()
    $Visited.Add($StartDistinguishedName) | Out-Null

    $Queue = [System.Collections.Generic.Queue[object]]::new()
    $Queue.Enqueue([PSCustomObject]@{
        DistinguishedName = $StartDistinguishedName
        Path              = @()
    })

    while ($Queue.Count -gt 0) {
        $Current = $Queue.Dequeue()
        $MemberOf = Get-MemberOfCached -DistinguishedName $Current.DistinguishedName

        foreach ($GroupDN in $MemberOf) {
            if ($GroupDN -eq $TargetGroupDistinguishedName) {
                return $Current.Path + @($GroupDN)
            }
            if (-not $Visited.Contains($GroupDN)) {
                $Visited.Add($GroupDN) | Out-Null
                $Queue.Enqueue([PSCustomObject]@{
                    DistinguishedName = $GroupDN
                    Path              = $Current.Path + @($GroupDN)
                })
            }
        }
    }

    # no path found (can happen if membership changed between the
    # recursive lookup and this resolution, or with foreign security
    # principals). return an empty path; caller handles the fallback.
    return @()
}

$Results = [System.Collections.Generic.List[object]]::new()

foreach ($PrivilegedGroup in $PrivilegedGroups) {
    Write-Host ""
    Write-Host "[INFO] Processing privileged group: $PrivilegedGroup"

    if ($GroupCache.ContainsKey($PrivilegedGroup)) {
        $Group = $GroupCache[$PrivilegedGroup]
    }
    else {
        try {
            $Group = Get-ADGroup `
                -Identity $PrivilegedGroup `
                @ADQueryParams `
                -Properties DistinguishedName
        }
        catch {
            Write-Warning "Unable to find privileged group '$PrivilegedGroup'. Skipping."
            continue
        }
        $GroupCache[$PrivilegedGroup] = $Group
    }

    # recursive membership is important because a user can be privileged
    # without being directly added to Domain Admins. For example:
    #
    # User -> Helpdesk-Admins -> Server-Admins -> Domain Admins
    #
    # Get-ADGroupMember -Recursive resolves nested membership.
    try {
        $Members = Get-ADGroupMember `
            -Identity $Group.DistinguishedName `
            -Recursive `
            @ADQueryParams `
            -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to retrieve members of '$PrivilegedGroup': $($_.Exception.Message)"
        continue
    }

    $MemberCount = @($Members).Count
    Write-Host "[PASS] Found $MemberCount member(s)"

    # compute the DIRECT membership set for this group exactly once,
    # instead of re-querying it for every user (was previously the main
    # performance bottleneck).
    if (-not $DirectMemberCache.ContainsKey($Group.DistinguishedName)) {
        try {
            $DirectMembers = Get-ADGroupMember `
                -Identity $Group.DistinguishedName `
                @ADQueryParams `
                -ErrorAction Stop

            $DirectSet = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($DirectMember in @($DirectMembers)) {
                $DirectSet.Add($DirectMember.DistinguishedName) | Out-Null
            }
        }
        catch {
            Write-Warning "Unable to determine direct membership for '$PrivilegedGroup': $($_.Exception.Message)"
            $DirectSet = [System.Collections.Generic.HashSet[string]]::new()
        }
        $DirectMemberCache[$Group.DistinguishedName] = $DirectSet
    }
    $DirectSet = $DirectMemberCache[$Group.DistinguishedName]

    foreach ($Member in @($Members)) {
        # computers, groups and other object types are ignored.
        if ($Member.objectClass -ne "user") {
            continue
        }

        # uses the DistinguishedName as the cache key because it uniquely
        # identifies the AD object.
        $UserKey = $Member.DistinguishedName
        if ($UserCache.ContainsKey($UserKey)) {
            $User = $UserCache[$UserKey]
        }
        else {
            try {
                $User = Get-ADUser `
                    -Identity $Member.DistinguishedName `
                    @ADQueryParams `
                    -Properties `
                        DisplayName,
                        Mail,
                        Department,
                        Title,
                        Enabled,
                        LastLogonDate,
                        UserPrincipalName,
                        DistinguishedName
            }
            catch {
                Write-Warning "Unable to retrieve user '$($Member.SamAccountName)'."
                continue
            }
            $UserCache[$UserKey] = $User
        }

        if (-not $IncludeDisabled -and -not $User.Enabled) {
            continue
        }

        if ($User.DistinguishedName -notlike "*$SearchBase") {
            continue
        }

        $DirectMember = $DirectSet.Contains($User.DistinguishedName)
        $MembershipType = if ($DirectMember) { "Direct" } else { "Nested" }

        if ($DirectMember) {
            $MembershipPath = $User.SamAccountName
        }
        else {
            $PathDNs = Find-NestedMembershipPath `
                -StartDistinguishedName $User.DistinguishedName `
                -TargetGroupDistinguishedName $Group.DistinguishedName

            if ($PathDNs.Count -gt 0) {
                $PathNames = $PathDNs | ForEach-Object { Get-GroupNameCached -DistinguishedName $_ }
                $MembershipPath = ($User.SamAccountName, $PathNames) -join " -> "
            }
            else {
                # fallback for the rare case where the chain could not be
                # reconstructed (for ex. membership changed mid-run, or via a
                # foreign security principal).
                $MembershipPath = "$($User.SamAccountName) -> [Unresolved Nested Path] -> $PrivilegedGroup"
            }
        }

        $Results.Add(
            [PSCustomObject]@{
                SamAccountName    = $User.SamAccountName
                UserPrincipalName = $User.UserPrincipalName
                DisplayName       = $User.DisplayName
                Enabled           = $User.Enabled
                AccountStatus     = if ($User.Enabled) { "Enabled" } else { "Disabled" }
                PrivilegedGroup   = $PrivilegedGroup
                MembershipType    = $MembershipType
                MembershipPath    = $MembershipPath
                Department        = $User.Department
                Title             = $User.Title
                Email             = $User.Mail
                LastLogonDate     = $User.LastLogonDate
                DistinguishedName = $User.DistinguishedName
            }
        )
    }
}

# removes duplicate user/group combinations.
# a user can potentially be discovered through multiple paths.
$Results = @(
    $Results |
        Sort-Object SamAccountName, PrivilegedGroup -Unique
)

Write-Host ""
Write-Host "============================================"
Write-Host " Audit Summary"
Write-Host "============================================"

$UniqueUsers = @(
    $Results |
        Select-Object -ExpandProperty SamAccountName -Unique
)

$DirectCount = @(
    $Results |
        Where-Object { $_.MembershipType -eq "Direct" }
).Count

$NestedCount = @(
    $Results |
        Where-Object { $_.MembershipType -eq "Nested" }
).Count

$DisabledCount = @(
    $Results |
        Where-Object { -not $_.Enabled }
).Count

Write-Host "Privileged users : $($UniqueUsers.Count)"
Write-Host "Direct members   : $DirectCount"
Write-Host "Nested members   : $NestedCount"

if ($IncludeDisabled) {
    Write-Host "Disabled accounts: $DisabledCount"
}

Write-Host ""
Write-Host "============================================"
Write-Host " Privileged Accounts"
Write-Host "============================================"

$Results |
    Select-Object `
        SamAccountName,
        DisplayName,
        AccountStatus,
        PrivilegedGroup,
        MembershipType,
        MembershipPath,
        Department,
        LastLogonDate |
    Format-Table -AutoSize

if ($OutputPath) {
    try {
        $Results |
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
Write-Host " Audit Complete"
Write-Host "============================================"
