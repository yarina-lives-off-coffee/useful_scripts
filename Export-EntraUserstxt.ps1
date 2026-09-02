<#
    Exports all Entra ID users to a TXT file.

.desc
    Connects to Microsoft Graph using read-only permissions,
    retrieves all users from Microsoft Entra ID, and saves
    selected user properties to a text file.

.note
    Required Microsoft Graph permission:
    User.Read.All
#>

Connect-MgGraph -Scopes "User.Read.All"

$users = Get-MgUser -All -Property DisplayName,UserPrincipalName,Mail,AccountEnabled

$users |
    Select-Object DisplayName, UserPrincipalName, Mail, AccountEnabled |
    Format-Table -AutoSize |
    Out-File "C:\Temp\EntraUsers.txt"

    
