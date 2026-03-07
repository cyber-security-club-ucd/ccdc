#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Download common security tools
.DESCRIPTION
    Downloads the following security tools for use
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

Write-Banner "WINDOWS TOOL DOWNLOAD" "Magenta"

# ─────────────────────────────────────────────────────────────────────────────
# 1. Enable TLS Fix and disable progress bar to download faster
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Fixing TLS"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-STEP "Setting Silent Downloads"
$ProgressPreference = 'SilentlyContinue'

# curl nmap
Invoke-WebRequest https://nmap.org/dist/nmap-7.98-setup.exe -OutFile "nmap-setup.exe"
./nmap-setup.exe

# curl everything and install silently
Invoke-WebRequest https://ninite.com/everything/ -OutFile "everything-setup.exe"
./everything-setup.exe /S

# curl malwarebytes
Invoke-WebRequest https://downloads.malwarebytes.com/file/mb-windows -OutFile "mbsetup.exe"
./mbsetup.exe

# curl ad-peas light
Invoke-WebRequest https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1 -OutFile "adPEAS-Light.ps1"
Start-Process powershell {
    . ./adPEAS-light.ps1
    Invoke-adPEAS -NoColor -OutputFile ".\adPEAS_output.txt"
}

# curl sysinternals
Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile "SysinternalsSuite.zip"
Expand-Archive -Path SysinternalsSuite.zip -DestinationPath .\Sysinternals\ -Force

# setup sysmon
Set-Location .\Sysinternals
Invoke-WebRequest https://raw.githubusercontent.com/cyber-security-club-ucd/ccdc/refs/heads/main/windows/sysmonconfig.xml -OutFile config.xml
.\sysmon.exe -accepteula -i config.xml

# curl pingcastle (USE AN OLDER VERSION ON SERVER 2016!!)
Invoke-WebRequest https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip -OutFile "PingCastle_3.3.0.1.zip"
Expand-Archive -Path PingCastle_3.3.0.1.zip -DestinationPath .\PingCastle\ -Force
Start-Process powershell {
    .\PingCastle\PingCastle.exe --healthcheck
}

