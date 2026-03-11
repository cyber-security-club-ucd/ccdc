#Requires -RunAsAdministrator
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
<#
.SYNOPSIS
    CCDC Blue Team - Windows First 30 Minutes Launcher
.DESCRIPTION
    Main menu to launch all blue team scripts in order.
    Run this FIRST at competition start.
#>

$ErrorActionPreference = "SilentlyContinue"
$Global:LogPath = "C:\CCDC_Logs\$(Get-Date -Format 'yyyyMMdd_HHmm')"
New-Item -ItemType Directory -Path $Global:LogPath -Force | Out-Null

# ─────────────────────────────────────────────
#  COLOUR HELPERS  (used by ALL scripts)
# ─────────────────────────────────────────────
function Write-Banner {
    param([string]$Text, [string]$Color = "Cyan")
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor $Color
    Write-Host "  $Text" -ForegroundColor $Color
    Write-Host "$line`n" -ForegroundColor $Color
}

function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

# Export helpers so dot-sourced scripts can use them
Export-ModuleMember -Function * -ErrorAction SilentlyContinue

# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────
Clear-Host
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host "   CCDC BLUE TEAM                      " -ForegroundColor Cyan
Write-Host "   Windows First 30 Minutes  v1.0      " -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "  Log directory: $Global:LogPath" -ForegroundColor DarkGray
Write-Host ""

$scripts = @(
    @{ Key="1"; Name="User & Admin Audit";          File="01_UserAudit.ps1";       Desc="List users, kick non-admins, snapshot userlist" },
    @{ Key="2"; Name="Password Reset";               File="02_PasswordReset.ps1";   Desc="Change Administrator + service account passwords" },
    @{ Key="3"; Name="Service & Port Audit";         File="03_ServiceAudit.ps1";    Desc="Running services, open ports, suspicious listeners" },
    @{ Key="4"; Name="Backup (DNS/Web/Shares)";      File="04_Backup.ps1";          Desc="DNS zones, IIS, fileshares, registry Run keys" },
    @{ Key="5"; Name="PII Scanner";                  File="05_PIIScanner.ps1";      Desc="Find CSVs, SSN patterns, credit card numbers" },
    @{ Key="6"; Name="Hidden File Hunt";             File="06_HiddenFiles.ps1";     Desc="Hidden files, webshells, suspicious filenames" },
    @{ Key="7"; Name="AD Security (Kerberos/ASREP)"; File="07_ADSecurity.ps1";     Desc="AS-REP roasting, Kerberoasting, AdminSDHolder" },
    @{ Key="8"; Name="Firewall Hardening";           File="08_Firewall.ps1";        Desc="Enable FW, restrict Admin login to inside IPs" },
    @{ Key="9"; Name="Non-Windows Service Audit";    File="09_NonWinServices.ps1";  Desc="PHP, config files, version checks, hardening" },
    @{ Key="A"; Name="RUN ALL (Audit Only)";         File="";                       Desc="Run scripts 1,3,4,5,6,7 silently and log" },
    @{ Key="Q"; Name="Quit";                         File="";                       Desc="" }
)

foreach ($s in $scripts) {
    if ($s.Key -eq "Q") { Write-Host "" }
    $keyColor = if ($s.Key -eq "A") { "Yellow" } elseif ($s.Key -eq "Q") { "DarkGray" } else { "White" }
    Write-Host "  [$($s.Key)] " -NoNewline -ForegroundColor $keyColor
    Write-Host "$($s.Name)" -NoNewline -ForegroundColor Cyan
    if ($s.Desc) { Write-Host "  - $($s.Desc)" -ForegroundColor DarkGray }}

Write-Host ""
$choice = Read-Host "Select option"

$scriptDir = $PSScriptRoot

switch ($choice.ToUpper()) {
    "A" {
        foreach ($s in $scripts | Where-Object { $_.File -and $_.Key -notin @("2","8") }) {
            $path = Join-Path $scriptDir $s.File
            if (Test-Path $path) {
                Write-Banner "Running: $($s.Name)"
                & $path
            }
        }
    }
    "Q" { exit }
    default {
        $selected = $scripts | Where-Object { $_.Key -eq $choice.ToUpper() }
        if ($selected -and $selected.File) {
            $path = Join-Path $scriptDir $selected.File
            if (Test-Path $path) {
                Write-Banner "Running: $($selected.Name)"
                & $path
            } else {
                Write-Host "  Script not found: $path" -ForegroundColor Red
            }
        }
    }
}

Write-Host "`nPress any key to return to menu..." -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
& $MyInvocation.MyCommand.Path  # re-launch menu
