<# 
Ridge Checked: Yes
Ran on a test box: NO  
Needs modification?: YES  
- Look into the 4, 5, 3
#>


#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Backup Script
.DESCRIPTION
    Backs up:
    - DNS zones (if DNS server role installed)
    - IIS configuration + web root
    - Important fileshares / folders
    - Registry Run keys (persistence baseline)
    - Scheduled tasks (baseline)
    - Service configurations
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

$Stamp     = Get-Date -Format "yyyyMMdd_HHmm"
$BackupRoot = "C:\CCDC_Backups\$Stamp"
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$LogDir     = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Write-Banner "BACKUP SCRIPT" "Green"
Write-INFO "Backup destination: $BackupRoot"

# ── Helper: safe copy ────────────────────────────────────────────────────────
function Backup-Path {
    param([string]$Source, [string]$Dest, [string]$Label)
    if (Test-Path $Source) {
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        try {
            Copy-Item -Path $Source -Destination $Dest -Recurse -Force -ErrorAction Stop
            Write-OK "$Label → $Dest"
        } catch {
            Write-WARN "$Label backup partial: $_"
        }
    } else {
        Write-INFO "$Label — path not found, skipping: $Source"
    }
}


# ── 1. DNS Zones ─────────────────────────────────────────────────────────────
Write-STEP "DNS Backup"

$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if ($dnsService) { # Check if the server has the DNS role installed before trying to back it up
    $dnsBackupDir = "$BackupRoot\DNS"
    New-Item -ItemType Directory -Path $dnsBackupDir -Force | Out-Null

    # Method 1: Export each zone
    try {
        Import-Module DnsServer -ErrorAction Stop
        $zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsReverseLookupZone -or $_.ZoneName -notmatch "0.in-addr" }
        foreach ($zone in $zones) {
            $zoneFile = "$dnsBackupDir\$($zone.ZoneName).txt"
            try {
                Export-DnsServerZone -Name $zone.ZoneName -FileName "ccdc_backup_$($zone.ZoneName).dns" -ErrorAction Stop
                # Also export records as readable text
                Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue |
                    Select-Object HostName, RecordType, RecordData, TimeToLive |
                    Export-Csv -Path $zoneFile -NoTypeInformation
                Write-OK "DNS zone: $($zone.ZoneName) → $zoneFile"
            } catch {
                Write-WARN "Could not export zone $($zone.ZoneName): $_"
            }
        }
    } catch {
        Write-WARN "DnsServer module not available, trying file copy"
        # Method 2: Copy DNS zone files directly
        Backup-Path "C:\Windows\System32\dns" "$dnsBackupDir\dns_files" "DNS zone files"
    }

    Write-OK "DNS backup complete"
} else {
    Write-INFO "DNS Server role not detected on this machine"
}

# ── 2. IIS Backup ────────────────────────────────────────────────────────────
Write-STEP "IIS Backup"

$iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($iisService) { # Check if IIS is installed before trying to back it up 
    $iisBackupDir = "$BackupRoot\IIS"
    New-Item -ItemType Directory -Path $iisBackupDir -Force | Out-Null

    # Method 1: appcmd backup (most complete)
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        $backupName = "CCDC_$Stamp"
        & $appcmd add backup $backupName 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-OK "IIS config backup created: '$backupName' (restore with: appcmd restore backup '$backupName')"
        } else {
            Write-WARN "appcmd backup failed — falling back to file copy"
        }
    }

    # Method 2: Copy applicationHost.config directly
    $ahConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
    Backup-Path $ahConfig "$iisBackupDir\applicationHost.config" "applicationHost.config"

    # Method 3: Backup web root (inetpub)
    $inetpub = "C:\inetpub"
    if (Test-Path $inetpub) {
        Write-INFO "Backing up inetpub (this may take a moment)..."
        Backup-Path $inetpub "$iisBackupDir\inetpub" "IIS web root (inetpub)"
    }

    # Log all IIS sites
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Get-Website | Select-Object Name, State, PhysicalPath, Bindings |
            Export-Csv -Path "$iisBackupDir\IIS_Sites.csv" -NoTypeInformation
        Write-OK "IIS sites list → $iisBackupDir\IIS_Sites.csv"
    } catch {
        Write-INFO "WebAdministration module not available for site list"
    }

    Write-OK "IIS backup complete"
} else {
    Write-INFO "IIS (W3SVC) not detected on this machine"
}

# ── 3. Fileshares / Critical Folders ───────────────────────────────────────── 

### LOOKINTO THIS?  
Write-STEP "Fileshare & Critical Folder Backup" 

# Get all non-admin SMB shares and back them up
$shares = Get-SmbShare | Where-Object {
    $_.Name -notmatch "^(ADMIN|IPC|C|D|E|F)\$$" -and $_.Path -ne ""
}

if ($shares) {
    $shareBackupDir = "$BackupRoot\Shares"
    foreach ($share in $shares) {
        Write-INFO "Backing up share: $($share.Name) → $($share.Path)"
        $shareDest = "$shareBackupDir\$($share.Name)"
        Backup-Path $share.Path $shareDest "Share: $($share.Name)"
    }
} else {
    Write-INFO "No non-default shares found"
}

# ── 4. Registry Run Keys (Persistence Baseline) ───────────────────────────────
Write-STEP "Registry Persistence Baseline"

$regBackupDir = "$BackupRoot\Registry"
New-Item -ItemType Directory -Path $regBackupDir -Force | Out-Null

$regPaths = @{
    "HKLM_Run"         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKLM_RunOnce"     = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKCU_Run"         = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKCU_RunOnce"     = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM_Run_Wow64"   = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    "HKLM_Winlogon"    = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    "HKLM_Services"    = "HKLM:\SYSTEM\CurrentControlSet\Services"
}

$allRegEntries = @()
foreach ($key in $regPaths.GetEnumerator()) {
    try {
        $props = Get-ItemProperty -Path $key.Value -ErrorAction SilentlyContinue
        if ($props) {
            $props.PSObject.Properties |
                Where-Object { $_.Name -notmatch "^PS" } |
                ForEach-Object {
                    $allRegEntries += [PSCustomObject]@{
                        HivePath  = $key.Key
                        ValueName = $_.Name
                        Data      = $_.Value
                    }
                }
        }
    } catch {}
}

$allRegEntries | Export-Csv -Path "$regBackupDir\RegRunKeys_Baseline.csv" -NoTypeInformation
Write-OK "Registry Run keys baseline → $regBackupDir\RegRunKeys_Baseline.csv"
Write-INFO "($($allRegEntries.Count) entries recorded — compare later to detect added persistence)"

# Also export full reg hives as .reg files for restore
$hives = @{
    "HKLM_Run.reg"  = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    "HKCU_Run.reg"  = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    "Winlogon.reg"  = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
}
foreach ($hive in $hives.GetEnumerator()) {
    reg export $hive.Value "$regBackupDir\$($hive.Key)" /y 2>$null
    if ($LASTEXITCODE -eq 0) { Write-OK "Exported $($hive.Key)" }
}


# ── 5. Scheduled Tasks Baseline ───────────────────────────────────────────────

# Run a baseline backup of all scheduled tasks, including their actions and run-as accounts. This can be used later to detect any new tasks created by red team activity. Note that some tasks may be normal but uncommon, so review the output carefully.
Write-STEP "Scheduled Tasks Baseline"

$taskLog = "$BackupRoot\ScheduledTasks_Baseline.csv"
Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{N="RunAs"; E={ $_.Principal.UserId }},
    @{N="Actions"; E={ ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; " }} |
    Export-Csv -Path $taskLog -NoTypeInformation

$nonMsTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
Write-OK "Scheduled tasks baseline → $taskLog"
Write-INFO "$($nonMsTasks.Count) non-Microsoft tasks (review these for red team persistence)"

if ($nonMsTasks) {
    Write-Host ""
    Write-Host "  Non-Microsoft scheduled tasks:" -ForegroundColor White
    foreach ($t in $nonMsTasks) {
        $color = if ($t.State -eq "Ready" -or $t.State -eq "Running") { "Yellow" } else { "DarkGray" }
        Write-Host "  [$($t.State)] $($t.TaskPath)$($t.TaskName)" -ForegroundColor $color
    }
}

# ── 6. Service Configurations ─────────────────────────────────────────────────
Write-STEP "Service Configuration Backup" 

# Back up all service configurations, including their startup type, run-as account, and description. This can be used to detect any new services created by red team activity or changes to existing services. Note that some services may be normal but uncommon, so review the output carefully.
$svcLog = "$BackupRoot\ServiceConfigs.csv"
Get-WmiObject Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
    Export-Csv -Path $svcLog -NoTypeInformation
Write-OK "Service configs → $svcLog"

# ── 7. Active Directory Backup (if DC) ───────────────────────────────────────
Write-STEP "Active Directory Backup"

$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
if ($isDC) {
    Write-INFO "DC detected — backing up AD"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adBackupDir = "$BackupRoot\ActiveDirectory"
        New-Item -ItemType Directory -Path $adBackupDir -Force | Out-Null

        # Export all GPOs as HTML report
        Get-GPO -All | ForEach-Object {
            $gpoName = $_.DisplayName -replace '[\\/:*?"<>|]', '_'
            Get-GPOReport -Guid $_.Id -ReportType HTML -Path "$adBackupDir\GPO_$gpoName.html" -ErrorAction SilentlyContinue
        }
        Write-OK "GPO reports exported to $adBackupDir"

        # Export AD users
        Get-ADUser -Filter * -Properties * |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordNeverExpires, MemberOf, Description |
            Export-Csv -Path "$adBackupDir\ADUsers.csv" -NoTypeInformation
        Write-OK "AD users → $adBackupDir\ADUsers.csv"

        # Export AD groups
        Get-ADGroup -Filter * -Properties Members |
            Select-Object Name, GroupCategory, GroupScope,
                @{N="Members"; E={ ($_.Members | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join "; " }} |
            Export-Csv -Path "$adBackupDir\ADGroups.csv" -NoTypeInformation
        Write-OK "AD groups → $adBackupDir\ADGroups.csv"

    } catch {
        Write-WARN "AD backup failed: $_"
    }
} else {
    Write-INFO "Not a DC — skipping AD backup"
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-OK "All backups complete!"
Write-INFO "Location: $BackupRoot"
$size = (Get-ChildItem $BackupRoot -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
Write-INFO "Total backup size: $([Math]::Round($size, 2)) MB"
Write-Host ""
Write-WARN "Tip: Copy $BackupRoot to a USB drive or network location for safekeeping!"
Write-Host ""
