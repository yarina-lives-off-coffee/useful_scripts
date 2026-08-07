<#

* adds logging to other scripts, writes an output to a specified log file and location including the timestamp
* creates path and file in location if it does not already exist

example
Write-Log -Message "Starting AD audit..." 
would create the file and append smth like:
2026-08-07 13:21:42 INFO: Starting AD audit...

Write-Log -Message "Disabled account detected" -Level Warn
Write-Log -Message "Failed to read OU" -Level Error
the output would be:
2026-08-07 13:33:07 WARNING: Disabled account detected
2026-08-07 13:33:09 ERROR: Failed to read OU

#>

function Write-Log
{
    [CmdletBinding()]
    #[Alias('wl')]
    [OutputType([int])]
    Param
    (
        # message written to log
        [Parameter(Mandatory=$true,
                   ValueFromPipelineByPropertyName=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        [Alias("LogContent")]
        [string]$Message,

        # path to log file
        [Parameter(Mandatory=$false,
                   ValueFromPipelineByPropertyName=$true,
                   Position=1)]
        [Alias('LogPath')]
        [string]$Path="C:\Logs\PSLog.log",

        [Parameter(Mandatory=$false,
                    ValueFromPipelineByPropertyName=$true,
                    Position=3)]
        [ValidateSet("Error","Warn","Info")]
        [string]$Level="Info",

        [Parameter(Mandatory=$false)]
        [switch]$NoClobber
    )

    Begin
    {
    }
    Process
    {
        
        if ((Test-Path $Path) -AND $NoClobber) {
            Write-Warning "log file $Path already exists! erase the file or rename it"
            Return
            }

        # if you write to a log file in a folder/path that doesn't exist
        # creates the file including path
        elseif (!(Test-Path $Path)) {
            Write-Verbose "Creating $Path."
            $NewLogFile = New-Item $Path -Force -ItemType File
            }

        else {
            # WIP
            }

        # logging and extra output by $Level
        switch ($Level) {
            'Error' {
                Write-Error $Message
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") ERROR: $Message" | Out-File -FilePath $Path -Append
                }
            'Warn' {
                Write-Warning $Message
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") WARNING: $Message" | Out-File -FilePath $Path -Append
                }
            'Info' {
                Write-Verbose $Message
                Write-Output "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") INFO: $Message" | Out-File -FilePath $Path -Append
                }
            }
    }
    End
    {
    }
} 
