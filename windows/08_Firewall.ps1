#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Firewall Hardening
.DESCRIPTION
    - Enable Windows Firewall on all profiles
    - Restrict RDP / WinRM / admin services to inside IPs only
    - Block known dangerous ports
    - Remove overly permissive rules
    - Log firewall events
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

Write-Banner "FIREWALL HARDENING" "Blue"

# ── Get inside IP ranges from user ───────────────────────────────────────────
Write-INFO "You need to specify which IP ranges are 'inside' (trusted) for admin access."
Write-INFO "Examples: 10.0.0.0/8   172.16.0.0/12   192.168.1.0/24"
Write-INFO "For CCDC this is usually the competition LAN subnet — check ipconfig."
Write-Host ""
Write-Host "  Your current IP configuration:" -ForegroundColor DarkGray
$myIPs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "^127\." }
foreach ($ip in $myIPs) {
    Write-Host "  $($ip.InterfaceAlias.PadRight(30)) $($ip.IPAddress)/$($ip.PrefixLength)" -ForegroundColor Cyan
}
Write-Host ""

$insideRanges = Read-Host "Enter inside IP ranges (comma-separated, e.g. '10.0.0.0/8,192.168.1.0/24')"
$insideArray  = $insideRanges -split "," | ForEach-Object { $_.Trim() }

if (-not $insideArray) {
    Write-WARN "No inside ranges provided — admin restriction rules will be skipped"
}

# ── 1. Enable Firewall ────────────────────────────────────────────────────────
Write-STEP "Enabling Windows Firewall (All Profiles)"

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Write-OK "Firewall enabled on Domain, Public, Private profiles"

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private `
    -LogAllowed True -LogBlocked True `
    -LogFileName "%SystemRoot%\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 4096
Write-OK "Firewall logging enabled → %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log"

# ── 2. Block Dangerous Ports ─────────────────────────────────────────────────
Write-STEP "Blocking Dangerous Inbound Ports"

$blockRules = @(
    @{ Name = "CCDC-Block-Telnet";      Port = 23;   Desc = "Telnet (plaintext)" },
    @{ Name = "CCDC-Block-NetBIOS137";  Port = 137;  Desc = "NetBIOS Name Service" },
    @{ Name = "CCDC-Block-NetBIOS138";  Port = 138;  Desc = "NetBIOS Datagram" },
    @{ Name = "CCDC-Block-LLMNR5355";   Port = 5355; Desc = "LLMNR (used for poisoning)" },
    @{ Name = "CCDC-Block-mDNS5353";    Port = 5353; Desc = "mDNS (potential responder target)" },
    @{ Name = "CCDC-Block-Netcat4444";  Port = 4444; Desc = "Common Netcat/Metasploit port" },
    @{ Name = "CCDC-Block-Netcat4445";  Port = 4445; Desc = "Common C2 port" }
)

foreach ($rule in $blockRules) {
    # Remove existing rule with same name first
    Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue

    New-NetFirewallRule -DisplayName $rule.Name `
        -Direction Inbound -Protocol TCP -LocalPort $rule.Port `
        -Action Block -Enabled True -ErrorAction SilentlyContinue | Out-Null
    # Also block UDP for those that use it
    New-NetFirewallRule -DisplayName "$($rule.Name)-UDP" `
        -Direction Inbound -Protocol UDP -LocalPort $rule.Port `
        -Action Block -Enabled True -ErrorAction SilentlyContinue | Out-Null

    Write-OK "Blocked port $($rule.Port) — $($rule.Desc)"
}

# LLMNR disable via registry (firewall isn't enough)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f 2>$null
Write-OK "LLMNR disabled via registry"

# ── 3. Restrict Admin Services to Inside IPs ─────────────────────────────────
Write-STEP "Restricting Admin Services to Inside IPs Only"

if ($insideArray) {
    $insideString = $insideArray -join ","

    $adminPortRules = @(
        @{ Name = "CCDC-RDP-InsideOnly";    Port = 3389; Desc = "RDP (Remote Desktop)" },
        @{ Name = "CCDC-WinRM-InsideOnly";  Port = 5985; Desc = "WinRM HTTP (PowerShell Remoting)" },
        @{ Name = "CCDC-WinRMS-InsideOnly"; Port = 5986; Desc = "WinRM HTTPS" },
        @{ Name = "CCDC-SMB-InsideOnly";    Port = 445;  Desc = "SMB (file shares)" },
        @{ Name = "CCDC-MSSQL-InsideOnly";  Port = 1433; Desc = "MSSQL (if running)" },
        @{ Name = "CCDC-MySQL-InsideOnly";  Port = 3306; Desc = "MySQL (if running)" }
    )

    foreach ($rule in $adminPortRules) {
        # Remove existing
        Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue

        # Create inside-only rule
        New-NetFirewallRule -DisplayName $rule.Name `
            -Direction Inbound -Protocol TCP -LocalPort $rule.Port `
            -RemoteAddress $insideArray `
            -Action Allow -Enabled True | Out-Null

        # Block same port from everywhere else
        New-NetFirewallRule -DisplayName "$($rule.Name)-BLOCK-External" `
            -Direction Inbound -Protocol TCP -LocalPort $rule.Port `
            -Action Block -Enabled True | Out-Null

        Write-OK "Port $($rule.Port) ($($rule.Desc)) — Allow from: $insideString, Block all others"
    }
} else {
    Write-WARN "Skipped admin IP restrictions (no inside IPs provided)"
}

# ── 4. SSH Restriction (if OpenSSH running) ──────────────────────────────────
$sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshService) {
    Write-STEP "SSH Service Detected — Restricting to Inside IPs"
    if ($insideArray) {
        Remove-NetFirewallRule -DisplayName "CCDC-SSH-InsideOnly" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "CCDC-SSH-InsideOnly" `
            -Direction Inbound -Protocol TCP -LocalPort 22 `
            -RemoteAddress $insideArray `
            -Action Allow -Enabled True | Out-Null
        New-NetFirewallRule -DisplayName "CCDC-SSH-Block-External" `
            -Direction Inbound -Protocol TCP -LocalPort 22 `
            -Action Block -Enabled True | Out-Null
        Write-OK "SSH port 22 restricted to inside IPs"
    }
}

# ── 5. Check & Remove Overly Permissive Rules ─────────────────────────────────
Write-STEP "Checking for Overly Permissive Firewall Rules"

$permissiveRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
    Where-Object { $_.DisplayName -notlike "CCDC-*" } |
    Get-NetFirewallRule | ForEach-Object {
        $ruleFilter = $_ | Get-NetFirewallAddressFilter
        $portFilter = $_ | Get-NetFirewallPortFilter
        [PSCustomObject]@{
            Name        = $_.DisplayName
            LocalPort   = $portFilter.LocalPort
            RemoteAddr  = $ruleFilter.RemoteAddress
            Profile     = $_.Profile
        }
    }

# Find rules that allow ANY remote address on admin ports
$adminPorts = @("3389", "5985", "5986", "445", "22", "1433", "3306")
$wideOpenAdmin = $permissiveRules | Where-Object {
    $_.RemoteAddr -eq "Any" -and
    ($adminPorts | Where-Object { $permissiveRules.LocalPort -contains $_ })
}

if ($wideOpenAdmin) {
    Write-WARN "Rules allowing admin ports from ANY address:"
    foreach ($r in $wideOpenAdmin) {
        Write-WARN "$($r.Name)  Port: $($r.LocalPort)  Remote: $($r.RemoteAddr)"
    }
    Write-INFO "Consider: Disable-NetFirewallRule -DisplayName '<name>'"
} else {
    Write-OK "No obviously overly-permissive admin port rules found"
}

# ── 6. Show Final Firewall Status ─────────────────────────────────────────────
Write-STEP "Current Firewall Profile Status"

Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked |
    Format-Table | Out-String | Write-Host -ForegroundColor Cyan

# ── 7. CCDC-Specific: Anti-Responder Hardening ───────────────────────────────
Write-STEP "Anti-Responder / MITM Hardening"

# Disable WPAD
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoDetect /t REG_DWORD /d 0 /f 2>$null
Write-OK "WPAD auto-detect disabled (prevents WPAD MITM)"

# Disable LLMNR via registry (belt and suspenders)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f 2>$null
Write-OK "LLMNR disabled via Group Policy registry"

# NBT-NS disable
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }
foreach ($a in $adapters) {
    $a.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
}
Write-OK "NetBIOS over TCP/IP disabled on all adapters (prevents NBT-NS poisoning)"

Write-Host ""
Write-OK "Firewall hardening complete!"
Write-WARN "Verify scored services still work after applying firewall rules!"
Write-Host ""
