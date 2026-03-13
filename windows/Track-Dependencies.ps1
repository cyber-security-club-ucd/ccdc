<#
.SYNOPSIS
    Safely tracks Windows network dependencies using temporary Firewall Success Logging.
.DESCRIPTION
    Temporarily enables Windows Firewall success logging, sets a safe 20MB limit,
    captures data for 60 seconds, parses pfirewall.log for TCP SYNs and UDP flows,
    and guarantees restoration of original firewall settings via a try/finally block.
.PARAMETER Duration
    How many seconds to capture traffic. Default: 60.
.PARAMETER Threshold
    Minimum occurrences to appear in output. Default: 5.
.EXAMPLE
    .\Track-Dependencies.ps1
    .\Track-Dependencies.ps1 -Duration 120 -Threshold 3
#>
param (
    [int]$Duration  = 60,
    [int]$Threshold = 5
)

# ── 1. Pre-flight Checks ──────────────────────────────────────────────────────

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

$LocalIPs = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' } |
    Select-Object -ExpandProperty IPAddress

if (-not $LocalIPs) {
    Write-Host "[-] Could not detect local IPv4 addresses." -ForegroundColor Red
    exit 1
}

# Check firewall is actually on - exit cleanly if not
$FWProfiles = Get-NetFirewallProfile
$AnyEnabled = $FWProfiles | Where-Object { $_.Enabled -eq $true }
if (-not $AnyEnabled) {
    Write-Host "[-] Windows Firewall is OFF on all profiles." -ForegroundColor Red
    Write-Host "[-] Enable the firewall via Group Policy and re-run this script." -ForegroundColor Red
    exit 1
}

# ── 2. Backup Current Firewall Logging State ──────────────────────────────────

Write-Host "[*] Backing up current Windows Firewall logging configurations..." -ForegroundColor Cyan
$Profiles      = Get-NetFirewallProfile
$OriginalState = @{}

foreach ($Profile in $Profiles) {
    $OriginalState[$Profile.Name] = @{
        LogAllowed          = $Profile.LogAllowed
        LogBlocked          = $Profile.LogBlocked
        LogMaxSizeKilobytes = $Profile.LogMaxSizeKilobytes
        LogFileName         = [Environment]::ExpandEnvironmentVariables($Profile.LogFileName)
    }
}

# Find a valid log path across all profiles (default unconfigured value is "-")
$LogPath = $null
foreach ($ProfileName in @("Domain", "Private", "Public")) {
    $Candidate = $OriginalState[$ProfileName].LogFileName
    if ($Candidate -and $Candidate -ne "-") {
        $LogPath = $Candidate
        break
    }
}

# Fall back to the Windows default path if nothing is configured
if (-not $LogPath -or $LogPath -eq "-") {
    $LogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    Write-Host "[*] No custom log path configured. Using default: $LogPath" -ForegroundColor Cyan
}

# Create log directory if it doesn't exist yet (first-time logging)
$LogDir = Split-Path $LogPath -Parent
if (-not (Test-Path $LogDir)) {
    Write-Host "[*] Log directory not found. Creating: $LogDir" -ForegroundColor Cyan
    try {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
        Write-Host "[+] Directory created successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to create log directory: $_" -ForegroundColor Red
        exit 1
    }
}

# ── 3. Capture ────────────────────────────────────────────────────────────────

# Use LOCAL time - pfirewall.log writes in local time, not UTC
$StartTimeLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

Write-Host "[*] Local IPs : $($LocalIPs -join ', ')" -ForegroundColor Cyan
Write-Host "[*] Log file  : $LogPath" -ForegroundColor Cyan
Write-Host "[*] Enabling success logging (20MB limit) for $Duration seconds..." -ForegroundColor Yellow

try {
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogAllowed True `
        -LogMaxSizeKilobytes 20480

    Write-Host "[*] Capturing traffic. DO NOT close this window. (Ctrl+C is safe)..." -ForegroundColor Yellow

    # Countdown progress bar
    for ($i = 1; $i -le $Duration; $i++) {
        $Remaining = $Duration - $i
        $Pct       = [math]::Round(($i / $Duration) * 100)
        $Status    = "Elapsed: " + $i + "s  |  Remaining: " + $Remaining + "s"
        Write-Progress -Activity "Capturing firewall traffic..." -Status $Status -PercentComplete $Pct
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity "Capturing firewall traffic..." -Completed

} finally {
    # ── 4. GUARANTEED RESTORATION ─────────────────────────────────────────────
    Write-Host "[*] Restoring original Windows Firewall logging settings..." -ForegroundColor Cyan
    foreach ($Profile in $Profiles) {
        $Old = $OriginalState[$Profile.Name]
        Set-NetFirewallProfile -Name $Profile.Name `
            -LogAllowed          $Old.LogAllowed `
            -LogBlocked          $Old.LogBlocked `
            -LogMaxSizeKilobytes $Old.LogMaxSizeKilobytes
    }
    Write-Host "[+] Firewall settings safely restored." -ForegroundColor Green
}

# ── 5. Copy and Parse the Log ─────────────────────────────────────────────────

Write-Host "[*] Processing captured data..." -ForegroundColor Cyan
$TempLog = "$env:TEMP\pfirewall_temp.log"

Copy-Item -Path $LogPath -Destination $TempLog -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $TempLog)) {
    Write-Host "[-] Failed to copy firewall log. Is the firewall service running?" -ForegroundColor Red
    exit 1
}

$Incoming = @{}
$Outgoing = @{}

# pfirewall.log format (space-delimited):
# 0:date  1:time  2:action  3:protocol  4:src-ip  5:dst-ip
# 6:src-port  7:dst-port  8:size  9:tcpflags  10:tcpsyn ...

$LogLines = Get-Content $TempLog -ErrorAction SilentlyContinue

foreach ($Line in $LogLines) {
    if ($Line.StartsWith("#") -or [string]::IsNullOrWhiteSpace($Line)) { continue }

    $Parts = $Line -split '\s+'
    if ($Parts.Count -lt 10) { continue }

    $LogTimeStr = "$($Parts[0]) $($Parts[1])"
    $Action     = $Parts[2]
    $Protocol   = $Parts[3]
    $SrcIP      = $Parts[4]
    $DstIP      = $Parts[5]
    $SrcPort    = $Parts[6]
    $DstPort    = $Parts[7]
    $TcpFlags   = $Parts[9]

    # Only look at entries logged after we started
    if ($Action -ne "ALLOW" -or $LogTimeStr -lt $StartTimeLocal) { continue }

    # TCP: SYN without ACK = new connection, not a reply
    # UDP: capture all flows (stateless protocol)
    $IsTcpSyn = ($Protocol -eq "TCP" -and $TcpFlags -match "S" -and $TcpFlags -notmatch "A")
    $IsUdp    = ($Protocol -eq "UDP")

    if (-not ($IsTcpSyn -or $IsUdp)) { continue }

    if ($LocalIPs -contains $SrcIP -and $LocalIPs -notcontains $DstIP) {
        # Outgoing: this machine initiated to an external target
        $Key = "${DstIP}:${DstPort}/$Protocol"
        $Outgoing[$Key]++

    } elseif ($LocalIPs -contains $DstIP -and $LocalIPs -notcontains $SrcIP) {
        # Incoming: skip UDP on ephemeral ports (likely outbound response traffic)
        if ($IsUdp -and [int]$DstPort -ge 32768) { continue }
        $Key = "${SrcIP}:${DstPort}/$Protocol"
        $Incoming[$Key]++
    }
}

Remove-Item $TempLog -Force -ErrorAction SilentlyContinue

# ── 6. Output Results ─────────────────────────────────────────────────────────

$LineLong  = "=================================================================="
$LineShort = "------------------------------------------------------------------"

Write-Host "`n$LineLong"
Write-Host " [OUTGOING] DEPENDENCIES  (This machine relies on...)"
Write-Host $LineLong
Write-Host ("{0,-25} {1,-20} {2}" -f "Remote Target IP", "Port/Protocol", "Occurrences")
Write-Host $LineShort

$OutFound = $false
$Outgoing.GetEnumerator() |
    Where-Object { $_.Value -ge $Threshold } |
    Sort-Object Name |
    ForEach-Object {
        if ($_.Name -match '^(.+):(\d+/(TCP|UDP))$') {
            Write-Host ("{0,-25} {1,-20} {2}" -f $Matches[1], $Matches[2], $_.Value)
            $OutFound = $true
        }
    }

if (-not $OutFound) {
    Write-Host "  None found meeting the threshold of $Threshold." -ForegroundColor DarkGray
    Write-Host "  (Try a longer -Duration, lower -Threshold, or generate more traffic.)" -ForegroundColor DarkGray
}

Write-Host "`n$LineLong"
Write-Host " [INCOMING] DEPENDENCIES  (Others rely on this machine...)"
Write-Host $LineLong
Write-Host ("{0,-25} {1,-20} {2}" -f "Remote Source IP", "Local Port/Proto", "Occurrences")
Write-Host $LineShort

$InFound = $false
$Incoming.GetEnumerator() |
    Where-Object { $_.Value -ge $Threshold } |
    Sort-Object Name |
    ForEach-Object {
        if ($_.Name -match '^(.+):(\d+/(TCP|UDP))$') {
            Write-Host ("{0,-25} {1,-20} {2}" -f $Matches[1], $Matches[2], $_.Value)
            $InFound = $true
        }
    }

if (-not $InFound) {
    Write-Host "  None found meeting the threshold of $Threshold." -ForegroundColor DarkGray
}

Write-Host "`n[+] Done." -ForegroundColor Green
Write-Host ""
