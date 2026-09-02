<#
    performs a basic health check against one or more Windows servers.

.desc
    Test-ServerHealth.ps1 checks the availability and health of remote
    Windows servers.

    the script performs the following checks:
        - ICMP connectivity (Ping)
        - DNS resolution
        - TCP connectivity to common Windows administration ports
        - Disk space
        - CPU utilization
        - Memory utilization
        - Important Windows services
        - Pending reboot status

    results are displayed in the console and can optionally be exported
    to a CSV file.

.PARAMETER ComputerName
    one or more Windows server names or IP addresses to check.

.PARAMETER OutputPath
    optional path for exporting the results to CSV.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01
    checks the health of SERVER01.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01,SERVER02
    checks multiple servers.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01 -OutputPath ".\ServerHealth.csv"
    checks SERVER01 and exports the results to a CSV file.

.note
    this script is intended for Windows environments where PowerShell
    remoting and appropriate administrative permissions are available.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]$ComputerName,
    [Parameter(Mandatory = $false)]
    [string]$OutputPath
)

# basic configuration
$PortsToTest = @{
    "RDP"   = 3389
    "SMB"   = 445
    "WinRM" = 5985
}
$ServicesToCheck = @(
    "WinRM",
    "Spooler",
    "EventLog"
)

# store all results here so that they can later be exported to CSV.
$Results = @()
function Test-ServerHealth {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server
    )
    Write-Host ""
    Write-Host "============================================"
    Write-Host " Server Health Check: $Server"
    Write-Host "============================================"

# connectivity, ICMP
    Write-Host "`n[Connectivity]"
    $PingResult = Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($PingResult) {
        Write-Host "[PASS] Ping: Server is reachable"
        $PingStatus = "PASS"
    }
    else {
        Write-Host "[FAIL] Ping: Server is unreachable"
        $PingStatus = "FAIL"
    }

# DNS
    try {
        $DnsResult = Resolve-DnsName -Name $Server -ErrorAction Stop
        Write-Host "[PASS] DNS: Resolution successful"
        $DnsStatus = "PASS"
    }
    catch {
        Write-Host "[FAIL] DNS: Resolution failed"
        $DnsStatus = "FAIL"
    }

# TCP connection
    Write-Host "`n[TCP Ports]"
    $PortResults = @{}
    foreach ($Service in $PortsToTest.Keys) {
        $Port = $PortsToTest[$Service]
        $TcpResult = Test-NetConnection `
            -ComputerName $Server `
            -Port $Port `
            -InformationLevel Quiet `
            -WarningAction SilentlyContinue
        if ($TcpResult) {
            Write-Host "[PASS] $Service`: TCP $Port is reachable"
            $PortResults[$Service] = "PASS"
        }
        else {
            Write-Host "[FAIL] $Service`: TCP $Port is unreachable"
            $PortResults[$Service] = "FAIL"
        }
    }

<# Remote Server Information
Get-CimInstance uses CIM/WMI to retrieve information from
the remote Windows server.
unlike running Get-CimInstance without -ComputerName, this
queries the target server rather than the local computer. #>   
    Write-Host "`n[System Resources]"
    try {
        $OperatingSystem = Get-CimInstance `
            -ClassName Win32_OperatingSystem `
            -ComputerName $Server `
            -ErrorAction Stop
        $ComputerSystem = Get-CimInstance `
            -ClassName Win32_ComputerSystem `
            -ComputerName $Server `
            -ErrorAction Stop
        $Processor = Get-CimInstance `
            -ClassName Win32_Processor `
            -ComputerName $Server `
            -ErrorAction Stop

# CPU
        $CpuUsage = [math]::Round(
            ($Processor | Measure-Object -Property LoadPercentage -Average).Average,
            2
        )
        if ($CpuUsage -lt 80) {
            Write-Host "[PASS] CPU: $CpuUsage%"
            $CpuStatus = "PASS"
        }
        elseif ($CpuUsage -lt 90) {
            Write-Host "[WARNING] CPU: $CpuUsage%"
            $CpuStatus = "WARNING"
        }
        else {
            Write-Host "[FAIL] CPU: $CpuUsage%"
            $CpuStatus = "FAIL"
        }

<# Memory
Win32_OperatingSystem exposes total and free physical memory
in bytes. gets converted into GB for readability. #>
        $TotalMemoryGB = [math]::Round(
            $ComputerSystem.TotalPhysicalMemory / 1GB,
            2
        )
        $FreeMemoryGB = [math]::Round(
            $OperatingSystem.FreePhysicalMemory / 1MB,
            2
        )
        $UsedMemoryGB = [math]::Round(
            $TotalMemoryGB - $FreeMemoryGB,
            2
        )
        $MemoryUsagePercent = [math]::Round(
            ($UsedMemoryGB / $TotalMemoryGB) * 100,
            2
        )
        if ($MemoryUsagePercent -lt 80) {
            Write-Host "[PASS] Memory: $MemoryUsagePercent%"
            $MemoryStatus = "PASS"
        }
        elseif ($MemoryUsagePercent -lt 90) {
            Write-Host "[WARNING] Memory: $MemoryUsagePercent%"
            $MemoryStatus = "WARNING"
        }
        else {
            Write-Host "[FAIL] Memory: $MemoryUsagePercent%"
            $MemoryStatus = "FAIL"
        }

# disk space
        Write-Host "`n[Disk Space]"
        $Disks = Get-CimInstance `
            -ClassName Win32_LogicalDisk `
            -Filter "DriveType = 3" `
            -ComputerName $Server `
            -ErrorAction Stop
        $DiskStatus = "PASS"
        foreach ($Disk in $Disks) {
            $FreePercent = [math]::Round(
                ($Disk.FreeSpace / $Disk.Size) * 100,
                2
            )
            $FreeGB = [math]::Round(
                $Disk.FreeSpace / 1GB,
                2
            )
            if ($FreePercent -lt 10) {
                Write-Host "[FAIL] Disk $($Disk.DeviceID): $FreeGB GB free ($FreePercent%)"
                $DiskStatus = "FAIL"
            }
            elseif ($FreePercent -lt 20) {
                Write-Host "[WARNING] Disk $($Disk.DeviceID): $FreeGB GB free ($FreePercent%)"
                if ($DiskStatus -eq "PASS") {
                    $DiskStatus = "WARNING"
                }
            }
            else {
                Write-Host "[PASS] Disk $($Disk.DeviceID): $FreeGB GB free ($FreePercent%)"
            }
        }

# services
        Write-Host "`n[Services]"
        $ServiceStatus = "PASS"
        foreach ($ServiceName in $ServicesToCheck) {
            try {
                $Service = Get-Service `
                    -Name $ServiceName `
                    -ComputerName $Server `
                    -ErrorAction Stop
                if ($Service.Status -eq "Running") {
                    Write-Host "[PASS] Service $ServiceName`: Running"
                }
                else {
                    Write-Host "[FAIL] Service $ServiceName`: $($Service.Status)"
                    $ServiceStatus = "FAIL"
                }
            }
            catch {
                Write-Host "[INFO] Service $ServiceName`: Not installed"
            }
        }

# pending reboot
# windows can indicate that a reboot is required through registry keys. useful after patching or software installation.       
        Write-Host "`n[System Status]"
        $RebootRequired = $false
        $RebootPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        foreach ($Path in $RebootPaths) {
            try {
                $RebootCheck = Invoke-Command `
                    -ComputerName $Server `
                    -ScriptBlock {
                        param ($RegistryPath)
                        Test-Path $RegistryPath
                    } `
                    -ArgumentList $Path `
                    -ErrorAction SilentlyContinue
                if ($RebootCheck) {
                    $RebootRequired = $true
                }
            }
            catch {
# ignore registry paths that cannot be queried
            }
        }
        if ($RebootRequired) {
            Write-Host "[WARNING] System requires a reboot"
            $RebootStatus = "WARNING"
        }
        else {
            Write-Host "[PASS] No pending reboot detected"
            $RebootStatus = "PASS"
        }

# overall status
        if (
            $PingStatus -eq "FAIL" -or
            $DnsStatus -eq "FAIL" -or
            $CpuStatus -eq "FAIL" -or
            $MemoryStatus -eq "FAIL" -or
            $DiskStatus -eq "FAIL" -or
            $ServiceStatus -eq "FAIL"
        ) {
            $OverallStatus = "FAIL"
        }
        elseif (
            $CpuStatus -eq "WARNING" -or
            $MemoryStatus -eq "WARNING" -or
            $DiskStatus -eq "WARNING" -or
            $RebootStatus -eq "WARNING"
        ) {
            $OverallStatus = "WARNING"
        }
        else {
            $OverallStatus = "HEALTHY"
        }
        Write-Host ""
        Write-Host "Overall Status: $OverallStatus"

# return structured data
        return [PSCustomObject]@{
            ComputerName       = $Server
            Ping               = $PingStatus
            DNS                = $DnsStatus
            RDP                = $PortResults["RDP"]
            SMB                = $PortResults["SMB"]
            WinRM              = $PortResults["WinRM"]
            CPUPercent         = $CpuUsage
            MemoryPercent      = $MemoryUsagePercent
            DiskStatus         = $DiskStatus
            Services           = $ServiceStatus
            PendingReboot      = $RebootStatus
            OverallStatus      = $OverallStatus
            Timestamp          = Get-Date
        }

    }
    catch {

# return a failed result instead of terminating the entire script.
        Write-Host "[FAIL] Unable to retrieve remote server information."
        Write-Host "       $($_.Exception.Message)"
        return [PSCustomObject]@{
            ComputerName  = $Server
            Ping          = $PingStatus
            DNS           = $DnsStatus
            OverallStatus = "FAIL"
            Error         = $_.Exception.Message
            Timestamp     = Get-Date
        }
    }
}

# main
foreach ($Server in $ComputerName) {
    $Result = Test-ServerHealth -Server $Server
    $Results += $Result
}

# CSV export so it can open in excel or be used by another automation process
if ($OutputPath) {
    $Results | Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -Encoding UTF8
    Write-Host ""
    Write-Host "Results exported to: $OutputPath"
}

# end summary
Write-Host ""
Write-Host "============================================"
Write-Host " Health Check Summary"
Write-Host "============================================"
$Results |
    Select-Object ComputerName, OverallStatus, CPUPercent, MemoryPercent |
    Format-Table -AutoSize
