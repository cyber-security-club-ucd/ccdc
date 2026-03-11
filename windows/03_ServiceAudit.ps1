#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Service & Port Audit
.DESCRIPTION
    - List all running services (flag suspicious ones)
    - Full port scan (all listening ports with owning process)
    - Established outbound connections (C2 detection)
    - Flag known dangerous services
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

$LogDir = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd_HHmm"

Write-Banner "SERVICE & PORT AUDIT" "Cyan"

# -- Known dangerous services to flag -----------------------------------------
$dangerousServices = @(
    "Telnet", "TlntSvr", "RemoteRegistry", "SSDPSRV", "upnphost",
    "WinRM",
    "W3SVC",
    "FTPSVC",
    "SharedAccess", "icsdl"
)

$knownDangerous = @("Telnet", "TlntSvr", "RemoteRegistry")

# -- 1. Running Services ------------------------------------------------------
Write-STEP "Running Services"

$running = Get-Service | Where-Object { $_.Status -eq "Running" } |
    Sort-Object DisplayName

$serviceLog = "$LogDir\Services_$Stamp.csv"
$running | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv -Path $serviceLog -NoTypeInformation

Write-INFO "Total running: $($running.Count)   Log: $serviceLog"
Write-Host ""
Write-Host "  Name                         DisplayName" -ForegroundColor DarkGray
Write-Host "  --------------------------   -------------------------------------" -ForegroundColor DarkGray

foreach ($svc in $running) {
    $color = "White"
    $flag  = ""
    if ($knownDangerous -contains $svc.Name) {
        $color = "Red"; $flag = " << DANGEROUS - DISABLE THIS"
    } elseif ($dangerousServices -contains $svc.Name) {
        $color = "Yellow"; $flag = " << Review"
    }
    $nameStr = $svc.Name.PadRight(30)
    Write-Host "  $nameStr $($svc.DisplayName)$flag" -ForegroundColor $color
}

# -- 2. Prompt to Disable Dangerous Services ----------------------------------
Write-STEP "Dangerous Service Check"

foreach ($svcName in $knownDangerous) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Write-CRIT "$svcName is RUNNING - this should almost never be on"
        $disable = Read-Host "  Disable $svcName now? (y/N)"
        if ($disable -eq 'y') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-OK "$svcName stopped and disabled"
        }
    }
}

# PrintNightmare check
$spooler = Get-Service -Name Spooler -ErrorAction SilentlyContinue
if ($spooler -and $spooler.Status -eq "Running") {
    Write-WARN "Print Spooler is running (PrintNightmare risk - CVE-2021-34527)"
    $disableSpooler = Read-Host "  Disable Print Spooler? (only safe if no printing needed) (y/N)"
    if ($disableSpooler -eq 'y') {
        Stop-Service -Name Spooler -Force
        Set-Service -Name Spooler -StartupType Disabled
        Write-OK "Print Spooler disabled"
    }
}

# SMBv1 check
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1) {
    Write-CRIT "SMBv1 is ENABLED (EternalBlue / WannaCry risk!)"
    $disableSMBv1 = Read-Host "  Disable SMBv1 now? (y/N)"
    if ($disableSMBv1 -eq 'y') {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-OK "SMBv1 disabled"
    }
} else {
    Write-OK "SMBv1 is already disabled"
}

# -- 3. Listening Ports -------------------------------------------------------
Write-STEP "All Listening Ports (with Process)"

$portLog = "$LogDir\Ports_$Stamp.csv"

$knownPorts = @{
    80   = "HTTP / IIS"
    443  = "HTTPS / IIS"
    21   = "FTP"
    22   = "SSH"
    25   = "SMTP"
    53   = "DNS"
    88   = "Kerberos (DC)"
    389  = "LDAP (DC)"
    445  = "SMB"
    636  = "LDAPS (DC)"
    1433 = "MSSQL"
    3306 = "MySQL"
    3389 = "RDP"
    5985 = "WinRM HTTP"
    5986 = "WinRM HTTPS"
    8080 = "Alt HTTP"
    8443 = "Alt HTTPS"
}

$suspiciousPorts = @(23, 4444, 4445, 1234, 31337, 9001, 6666, 7777, 8888)

$connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

$portData = foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    $desc = if ($knownPorts.ContainsKey([int]$conn.LocalPort)) { $knownPorts[[int]$conn.LocalPort] } else { "Unknown" }
    [PSCustomObject]@{
        Port       = $conn.LocalPort
        Address    = $conn.LocalAddress
        PID        = $conn.OwningProcess
        Process    = if ($proc) { $proc.Name } else { "UNKNOWN" }
        Executable = if ($proc) { try { $proc.MainModule.FileName } catch { "N/A" } } else { "N/A" }
        KnownDesc  = $desc
    }
}

$portData | Export-Csv -Path $portLog -NoTypeInformation
Write-INFO "Port log: $portLog"
Write-Host ""
Write-Host "  Port   Address          PID    Process            Description" -ForegroundColor DarkGray
Write-Host "  -----  ---------------  -----  -----------------  ----------------------" -ForegroundColor DarkGray

foreach ($p in $portData | Sort-Object Port) {
    $color = "White"
    $flag  = ""
    if ($suspiciousPorts -contains [int]$p.Port) {
        $color = "Red"; $flag = " << SUSPICIOUS PORT"
    } elseif ($p.KnownDesc -eq "Unknown") {
        $color = "Yellow"; $flag = " << Unknown - investigate"
    } elseif ($p.Address -eq "0.0.0.0") {
        $color = "Cyan"; $flag = " (exposed on all interfaces)"
    }

    $portStr = $p.Port.ToString().PadRight(6)
    $addrStr = $p.Address.PadRight(16)
    $pidStr  = $p.PID.ToString().PadRight(6)
    $procStr = $p.Process.PadRight(18)

    Write-Host "  $portStr $addrStr $pidStr $procStr $($p.KnownDesc)$flag" -ForegroundColor $color
}

# -- 4. Established Outbound Connections (C2 detection) -----------------------
Write-STEP "Established Outbound Connections (C2 / Beaconing Check)"

$established = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1|0\.0\.0\.0)" }

$c2Ports = @(4444, 4445, 1234, 6666, 7777, 8888, 9001, 9002, 31337)

Write-Host ""
Write-Host "  Remote Address            Remote Port  Process           Flag" -ForegroundColor DarkGray
Write-Host "  ------------------------  -----------  ----------------  --------------------" -ForegroundColor DarkGray

foreach ($conn in $established) {
    $proc  = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    $color = "White"
    $flag  = ""

    if ($c2Ports -contains [int]$conn.RemotePort) {
        $color = "Red"; $flag = "<< LIKELY C2 BEACON"
    } elseif ($conn.RemotePort -notin @(80, 443, 53, 25, 587, 993, 995)) {
        $color = "Yellow"; $flag = "<< Unusual port"
    }

    $remoteStr = $conn.RemoteAddress.PadRight(25)
    $portStr   = $conn.RemotePort.ToString().PadRight(12)
    $procName  = if ($proc) { $proc.Name } else { "PID:$($conn.OwningProcess)" }
    $procStr   = $procName.PadRight(17)
    Write-Host "  $remoteStr $portStr $procStr $flag" -ForegroundColor $color
}

# -- 5. SMB Shares ------------------------------------------------------------
Write-STEP "SMB Shares"

$shares = Get-SmbShare
$adminShares = @("ADMIN$", "C$", "IPC$", "D$", "E$")

foreach ($share in $shares) {
    $color = if ($adminShares -contains $share.Name) { "DarkGray" } else { "Yellow" }
    $flag  = if ($adminShares -notcontains $share.Name) { " << Non-default share - verify!" } else { " (default admin share)" }
    Write-Host "  $($share.Name.PadRight(20)) Path: $($share.Path)$flag" -ForegroundColor $color
}

# -- Done ---------------------------------------------------------------------
Write-Host ""
Write-OK "Service & port audit complete"
Write-Host ""
