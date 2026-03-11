<#
.SYNOPSIS
    Safely tracks Windows network dependencies using temporary Firewall Success Logging.
.DESCRIPTION
    Temporarily enables Windows Firewall success logging, sets a safe 20MB limit, 
    captures data for 60 seconds, parses pfirewall.log for TCP SYNs and UDP flows, 
    and guarantees restoration of original firewall settings via a try/finally block.
#>
param (
    [int]$Duration = 60,
    [int]$Threshold = 5
)

# 1. Pre-flight Checks
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] Error: This script must be run as Administrator to modify firewall logs." -ForegroundColor Red
    exit
}

$LocalIPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' } | Select-Object -ExpandProperty IPAddress
if (-not $LocalIPs) {
    Write-Host "[-] Could not detect local IPv4 addresses." -ForegroundColor Red
    exit
}

# 2. Backup Current Firewall Logging State
Write-Host "[*] Backing up current Windows Firewall logging configurations..." -ForegroundColor Cyan
$Profiles = Get-NetFirewallProfile
$OriginalState = @{}

foreach ($Profile in $Profiles) {
    $OriginalState[$Profile.Name] = @{
        LogAllowed          = $Profile.LogAllowed
        LogMaxSizeKilobytes = $Profile.LogMaxSizeKilobytes
        LogFileName         = [Environment]::ExpandEnvironmentVariables($Profile.LogFileName)
    }
}

# FIX #2 & #3: Find a valid log path by checking all profiles instead of hardcoding "Domain".
# The default unconfigured value is "-", so we skip that.
$LogPath = $null
foreach ($ProfileName in @("Domain", "Private", "Public")) {
    $CandidatePath = $OriginalState[$ProfileName].LogFileName
    if ($CandidatePath -and $CandidatePath -ne "-") {
        $LogPath = $CandidatePath
        break
    }
}

# If no profile has a configured path, fall back to the Windows default.
if (-not $LogPath -or $LogPath -eq "-") {
    $LogPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    Write-Host "[*] No custom log path configured. Using default: $LogPath" -ForegroundColor Cyan
}

# FIX #3: Validate the log path is reachable BEFORE starting the timed capture.
$LogDir = Split-Path $LogPath -Parent
if (-not (Test-Path $LogDir)) {
    Write-Host "[-] Firewall log directory does not exist: $LogDir" -ForegroundColor Red
    Write-Host "[-] Ensure the Windows Firewall service is running." -ForegroundColor Red
    exit
}

# FIX #1: Use LOCAL time for the start timestamp to match pfirewall.log's format.
$StartTimeLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

Write-Host "[*] Local IPs: $($LocalIPs -join ', ')" -ForegroundColor Cyan
Write-Host "[*] Log file: $LogPath" -ForegroundColor Cyan
Write-Host "[*] Enabling success logging (20MB limit) for $Duration seconds..." -ForegroundColor Yellow

try {
    # 3. Apply Temporary Logging Settings
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogMaxSizeKilobytes 20480
    
    Write-Host "[*] Capturing traffic. DO NOT close this window. (Ctrl+C is safe)..." -ForegroundColor Yellow
    Start-Sleep -Seconds $Duration

} finally {
    # 4. GUARANTEED RESTORATION
    Write-Host "[*] Restoring original Windows Firewall logging settings..." -ForegroundColor Cyan
    foreach ($Profile in $Profiles) {
        $Old = $OriginalState[$Profile.Name]
        Set-NetFirewallProfile -Name $Profile.Name -LogAllowed $Old.LogAllowed -LogMaxSizeKilobytes $Old.LogMaxSizeKilobytes
    }
    Write-Host "[+] Firewall settings safely restored." -ForegroundColor Green
}

# 5. Safely Copy and Parse the Log
Write-Host "[*] Processing captured data..." -ForegroundColor Cyan
$TempLog = "$env:TEMP\pfirewall_temp.log"

Copy-Item -Path $LogPath -Destination $TempLog -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $TempLog)) {
    Write-Host "[-] Failed to read or copy the firewall log. Is the firewall service running?" -ForegroundColor Red
    exit
}

$Incoming = @{}
$Outgoing = @{}

# Standard Windows Firewall Log Format (Space delimited):
# 0:date 1:time 2:action 3:protocol 4:src-ip 5:dst-ip 6:src-port 7:dst-port 8:size 9:tcpflags
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

    # FIX #1: Compare against local time ($StartTimeLocal) instead of UTC.
    if ($Action -eq "ALLOW" -and $LogTimeStr -ge $StartTimeLocal) {
        
        if (($Protocol -eq "TCP" -and $TcpFlags -match "S" -and $TcpFlags -notmatch "A") -or ($Protocol -eq "UDP")) {
            
            if ($LocalIPs -contains $SrcIP) {
                $Key = "${DstIP}:$DstPort/$Protocol"
                $Outgoing[$Key]++
            } elseif ($LocalIPs -contains $DstIP) {
                if ($Protocol -eq "UDP" -and [int]$DstPort -ge 32768) { continue }
                $Key = "${SrcIP}:$DstPort/$Protocol"
                $Incoming[$Key]++
            }
        }
    }
}

Remove-Item $TempLog -Force -ErrorAction SilentlyContinue

# 6. Apply Threshold and Output
Write-Host "`n=================================================================="
Write-Host " [OUTGOING] DEPENDENCIES (This server relies on...)"
Write-Host "=================================================================="
Write-Host ("{0,-25} {1,-15} {2,-10}" -f "Remote Target IP", "Target Port/Proto", "Occurrences")
Write-Host "------------------------------------------------------------------"
$OutFound = $false
foreach ($Key in $Outgoing.Keys) {
    if ($Outgoing[$Key] -ge $Threshold) {
        $Parts = $Key -split ':'
        Write-Host ("{0,-25} {1,-15} {2,-10}" -f $Parts[0], $Parts[1], $Outgoing[$Key])
        $OutFound = $true
    }
}
if (-not $OutFound) { Write-Host "None found meeting the threshold." -ForegroundColor DarkGray }

Write-Host "`n=================================================================="
Write-Host " [INCOMING] DEPENDENCIES (Others rely on this server...)"
Write-Host "=================================================================="
Write-Host ("{0,-25} {1,-15} {2,-10}" -f "Remote Source IP", "Local Port/Proto", "Occurrences")
Write-Host "------------------------------------------------------------------"
$InFound = $false
foreach ($Key in $Incoming.Keys) {
    if ($Incoming[$Key] -ge $Threshold) {
        $Parts = $Key -split ':'
        Write-Host ("{0,-25} {1,-15} {2,-10}" -f $Parts[0], $Parts[1], $Incoming[$Key])
        $InFound = $true
    }
}
if (-not $InFound) { Write-Host "None found meeting the threshold." -ForegroundColor DarkGray }
Write-Host ""
