<#
.SYNOPSIS
    performs a basic health check against one or more Windows servers.

.DESCRIPTION
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
    all remote system data (CIM classes, services, registry) is collected
    with a single Invoke-Command call per server instead of many separate
    remote calls, and multiple servers can be checked concurrently.

.PARAMETER ComputerName
    one or more Windows server names or IP addresses to check.

.PARAMETER OutputPath
    optional path for exporting the results to CSV.

.PARAMETER Credential
    optional credential to use for CIM/WinRM connections to the remote servers.

.PARAMETER PortTimeoutMs
    timeout, in milliseconds, for each TCP port check. Default is 1000.

.PARAMETER ThrottleLimit
    maximum number of servers to check concurrently. Default is 5.
    requires PowerShell 7+; on Windows PowerShell 5.1 servers are checked
    sequentially regardless of this value.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01
    checks the health of SERVER01.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01,SERVER02
    checks multiple servers concurrently.

.EXAMPLE
    .\Test-ServerHealth.ps1 -ComputerName SERVER01 -OutputPath ".\ServerHealth.csv"
    checks SERVER01 and exports the results to a CSV file.

.NOTES
    This script is intended for Windows environments where PowerShell
    remoting and appropriate administrative permissions are available.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string[]]$ComputerName,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [int]$PortTimeoutMs = 1000,

    [Parameter(Mandatory = $false)]
    [int]$ThrottleLimit = 5
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

# single scriptblock that gathers ALL remote system data in one Invoke-Command call
# (previously this was ~7+ separate remote calls. fixed it)
$RemoteInfoScriptBlock = {
    param ($ServiceNames)

    $Result = [ordered]@{
        CpuUsage        = $null
        MemoryPercent   = $null
        Disks           = @()
        Services        = @()
        RebootRequired  = $false
        Error           = $null
    }

    try {
        $Os        = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $System    = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        $Processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $Disks     = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType = 3" -ErrorAction Stop

        $Result.CpuUsage = [math]::Round(
            ($Processor | Measure-Object -Property LoadPercentage -Average).Average,
            2
        )

        $TotalMemoryGB = [math]::Round($System.TotalPhysicalMemory / 1GB, 2)
        $FreeMemoryGB  = [math]::Round($Os.FreePhysicalMemory / 1MB, 2)
        $UsedMemoryGB  = [math]::Round($TotalMemoryGB - $FreeMemoryGB, 2)
        $Result.MemoryPercent = if ($TotalMemoryGB -gt 0) {
            [math]::Round(($UsedMemoryGB / $TotalMemoryGB) * 100, 2)
        } else {
            0
        }

        $Result.Disks = foreach ($Disk in $Disks) {
            $FreePercent = if ($Disk.Size -gt 0) {
                [math]::Round(($Disk.FreeSpace / $Disk.Size) * 100, 2)
            } else {
                0
            }
            [PSCustomObject]@{
                DeviceID    = $Disk.DeviceID
                FreeGB      = [math]::Round($Disk.FreeSpace / 1GB, 2)
                FreePercent = $FreePercent
            }
        }

        $Result.Services = foreach ($Name in $ServiceNames) {
            $Svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                Name   = $Name
                Status = if ($Svc) { $Svc.Status.ToString() } else { "NotInstalled" }
            }
        }

        $RebootPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        foreach ($Path in $RebootPaths) {
            if (Test-Path $Path -ErrorAction SilentlyContinue) {
                $Result.RebootRequired = $true
                break
            }
        }
    }
    catch {
        $Result.Error = $_.Exception.Message
    }

    return [PSCustomObject]$Result
}

# the whole per-server check is a scriptblock (rather than a function) so it can be
# handed to remote/parallel runspaces via $using: without relying on cross-runspace
# function transfer, which is fragile. Test-TcpPort is nested inside it so it's always
# defined in whatever runspace this scriptblock actually executes in.
$TestServerHealthScriptBlock = {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [System.Management.Automation.PSCredential]$Credential,
        [int]$PortTimeoutMs,
        [hashtable]$PortsToTest,
        [string[]]$ServicesToCheck,
        [scriptblock]$RemoteInfoScriptBlock
    )

# fast TCP port test - avoids the overhead of Test-NetConnection for a simple reachability check
    function Test-TcpPort {
        param (
            [string]$ComputerName,
            [int]$Port,
            [int]$TimeoutMs = 1000
        )
        $Client = New-Object System.Net.Sockets.TcpClient
        try {
            $AsyncResult = $Client.BeginConnect($ComputerName, $Port, $null, $null)
            $Connected = $AsyncResult.AsyncWaitHandle.WaitOne($TimeoutMs)
            if ($Connected -and $Client.Connected) {
                $Client.EndConnect($AsyncResult)
                return $true
            }
            return $false
        }
        catch {
            return $false
        }
        finally {
            $Client.Close()
        }
    }

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Server Health Check: $Server"
    Write-Host "============================================"

# default shape - every field is always present so CSV/table output stays consistent
# regardless of how far the checks got before something failed
    $Output = [ordered]@{
        ComputerName  = $Server
        Ping          = "N/A"
        DNS           = "N/A"
        RDP           = "N/A"
        SMB           = "N/A"
        WinRM         = "N/A"
        CPUPercent    = "N/A"
        MemoryPercent = "N/A"
        DiskStatus    = "N/A"
        Services      = "N/A"
        PendingReboot = "N/A"
        OverallStatus = "N/A"
        Error         = $null
        Timestamp     = Get-Date
    }

# connectivity, ICMP
    Write-Host "`n[Connectivity]"
    $PingResult = Test-Connection -ComputerName $Server -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($PingResult) {
        Write-Host "[PASS] Ping: Server is reachable"
        $Output.Ping = "PASS"
    }
    else {
        Write-Host "[FAIL] Ping: Server is unreachable"
        $Output.Ping = "FAIL"
    }

# DNS - using .NET resolution directly instead of Resolve-DnsName to avoid the
# DnsClient module load overhead
    try {
        [void][System.Net.Dns]::GetHostEntry($Server)
        Write-Host "[PASS] DNS: Resolution successful"
        $Output.DNS = "PASS"
    }
    catch {
        Write-Host "[FAIL] DNS: Resolution failed"
        $Output.DNS = "FAIL"
    }

# TCP ports
    Write-Host "`n[TCP Ports]"
    foreach ($Service in $PortsToTest.Keys) {
        $Port = $PortsToTest[$Service]
        $Reachable = Test-TcpPort -ComputerName $Server -Port $Port -TimeoutMs $PortTimeoutMs
        if ($Reachable) {
            Write-Host "[PASS] $Service`: TCP $Port is reachable"
            $Output[$Service] = "PASS"
        }
        else {
            Write-Host "[FAIL] $Service`: TCP $Port is unreachable"
            $Output[$Service] = "FAIL"
        }
    }

# remote system data - gathers CPU, memory, disk,
# services and reboot status together
    Write-Host "`n[System Resources]"
    $InvokeParams = @{
        ComputerName = $Server
        ScriptBlock  = $RemoteInfoScriptBlock
        ArgumentList = @(, $ServicesToCheck)
        ErrorAction  = "Stop"
    }
    if ($Credential) { $InvokeParams["Credential"] = $Credential }

    try {
        $RemoteData = Invoke-Command @InvokeParams

        if ($RemoteData.Error) {
            throw $RemoteData.Error
        }

        # CPU
        $CpuUsage = $RemoteData.CpuUsage
        $Output.CPUPercent = $CpuUsage
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

        # memory
        $MemoryUsagePercent = $RemoteData.MemoryPercent
        $Output.MemoryPercent = $MemoryUsagePercent
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
        $DiskStatus = "PASS"
        foreach ($Disk in $RemoteData.Disks) {
            if ($Disk.FreePercent -lt 10) {
                Write-Host "[FAIL] Disk $($Disk.DeviceID): $($Disk.FreeGB) GB free ($($Disk.FreePercent)%)"
                $DiskStatus = "FAIL"
            }
            elseif ($Disk.FreePercent -lt 20) {
                Write-Host "[WARNING] Disk $($Disk.DeviceID): $($Disk.FreeGB) GB free ($($Disk.FreePercent)%)"
                if ($DiskStatus -eq "PASS") { $DiskStatus = "WARNING" }
            }
            else {
                Write-Host "[PASS] Disk $($Disk.DeviceID): $($Disk.FreeGB) GB free ($($Disk.FreePercent)%)"
            }
        }
        $Output.DiskStatus = $DiskStatus

        # services
        Write-Host "`n[Services]"
        $ServiceStatus = "PASS"
        foreach ($Svc in $RemoteData.Services) {
            if ($Svc.Status -eq "Running") {
                Write-Host "[PASS] Service $($Svc.Name): Running"
            }
            elseif ($Svc.Status -eq "NotInstalled") {
                Write-Host "[INFO] Service $($Svc.Name): Not installed"
            }
            else {
                Write-Host "[FAIL] Service $($Svc.Name): $($Svc.Status)"
                $ServiceStatus = "FAIL"
            }
        }
        $Output.Services = $ServiceStatus

# pending reboot
        Write-Host "`n[System Status]"
        if ($RemoteData.RebootRequired) {
            Write-Host "[WARNING] System requires a reboot"
            $RebootStatus = "WARNING"
        }
        else {
            Write-Host "[PASS] No pending reboot detected"
            $RebootStatus = "PASS"
        }
        $Output.PendingReboot = $RebootStatus

# overall status
        if (
            $Output.Ping -eq "FAIL" -or
            $Output.DNS -eq "FAIL" -or
            $CpuStatus -eq "FAIL" -or
            $MemoryStatus -eq "FAIL" -or
            $DiskStatus -eq "FAIL" -or
            $ServiceStatus -eq "FAIL"
        ) {
            $Output.OverallStatus = "FAIL"
        }
        elseif (
            $CpuStatus -eq "WARNING" -or
            $MemoryStatus -eq "WARNING" -or
            $DiskStatus -eq "WARNING" -or
            $RebootStatus -eq "WARNING"
        ) {
            $Output.OverallStatus = "WARNING"
        }
        else {
            $Output.OverallStatus = "HEALTHY"
        }
        Write-Host ""
        Write-Host "Overall Status: $($Output.OverallStatus)"
    }
    catch {
        Write-Host "[FAIL] Unable to retrieve remote server information."
        Write-Host "       $($_.Exception.Message)"
        $Output.OverallStatus = "FAIL"
        $Output.Error = $_.Exception.Message
        Write-Host ""
        Write-Host "Overall Status: $($Output.OverallStatus)"
    }

    return [PSCustomObject]$Output
}

# main - check servers concurrently on PowerShell 7+, sequentially on Windows PowerShell 5.1
# (ForEach-Object -Parallel runs each iteration in its own runspace, so everything the
# scriptblock needs is passed explicitly via $using: rather than relying on shared state)
$Results = if ($PSVersionTable.PSVersion.Major -ge 7 -and $ComputerName.Count -gt 1) {
    $ComputerName | ForEach-Object -Parallel {
        $Sb = $using:TestServerHealthScriptBlock
        & $Sb `
            -Server $_ `
            -Credential $using:Credential `
            -PortTimeoutMs $using:PortTimeoutMs `
            -PortsToTest $using:PortsToTest `
            -ServicesToCheck $using:ServicesToCheck `
            -RemoteInfoScriptBlock $using:RemoteInfoScriptBlock
    } -ThrottleLimit $ThrottleLimit
}
else {
    foreach ($Server in $ComputerName) {
        & $TestServerHealthScriptBlock `
            -Server $Server `
            -Credential $Credential `
            -PortTimeoutMs $PortTimeoutMs `
            -PortsToTest $PortsToTest `
            -ServicesToCheck $ServicesToCheck `
            -RemoteInfoScriptBlock $RemoteInfoScriptBlock
    }
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
