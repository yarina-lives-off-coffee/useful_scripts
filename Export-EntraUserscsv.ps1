<#
    This script is similar to Export-EntraUserstxt.ps1, but uses Export-Csv
    instead of Out-File.
    Export-Csv creates structured CSV data.
    Each user becomes a row and each property becomes a column.
    This makes the output much easier to open in Excel, import
    into another script, or process automatically.

.desc
    Connects to Microsoft Graph using read-only permissions,
    retrieves all users from Microsoft Entra ID, and saves
    selected user properties to a csv file.

.note
    Required Microsoft Graph permission:
    User.Read.All
#>

Connect-MgGraph -Scopes "User.Read.All"

Get-MgUser -All -Property DisplayName, UserPrincipalName, Mail, AccountEnabled |
    Select-Object DisplayName, UserPrincipalName, Mail, AccountEnabled |
    Export-Csv "C:\Temp\EntraUsers.csv" -NoTypeInformation -Encoding UTF8
