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
    - Active Directory (if DC)
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta    }

$Stamp      = Get-Date -Format "yyyyMMdd_HHmm"
$BackupRoot = "C:\CCDC_Backups\$Stamp"
New-Item -ItemType Directory -Path $BackupRoot -Force | Out-Null
$LogDir     = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

Write-Banner "BACKUP SCRIPT" "Green"
Write-INFO "Backup destination: $BackupRoot"

# ---------------------------------------------------------------------------
# HELPER: Safe recursive copy
# ---------------------------------------------------------------------------
function Backup-Path {
    param([string]$Source, [string]$Dest, [string]$Label)
    if (Test-Path $Source) {
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        try {
            Copy-Item -Path $Source -Destination $Dest -Recurse -Force -ErrorAction Stop
            Write-OK "$Label -> $Dest"
        } catch {
            Write-WARN "$Label backup partial: $_"
        }
    } else {
        Write-INFO "$Label -- path not found, skipping: $Source"
    }
}

# FIX: Helper to run reg export without 2>$null stderr redirect issues in PS 5.1
function Export-RegKey {
    param([string]$KeyPath, [string]$OutFile)
    $result = Start-Process -FilePath "reg" `
        -ArgumentList "export `"$KeyPath`" `"$OutFile`" /y" `
        -Wait -PassThru -NoNewWindow `
        -RedirectStandardError "$LogDir\reg_err_tmp.txt"
    return $result.ExitCode -eq 0
}

# ---------------------------------------------------------------------------
# HELPER: Fast zip using Windows Shell COM object
# ---------------------------------------------------------------------------
# This uses the same underlying API as Explorer's "Send To > Compressed folder".
# It is significantly faster than Compress-Archive (which is a slow .NET wrapper)
# because it calls the native Win32 shell implementation directly.
#
# IMPORTANT: CopyHere() is asynchronous -- the call returns immediately while
# the copy is still happening in the background. We must poll the zip's file
# count until it stabilises, otherwise the script moves on before the zip
# is finished. The $TimeoutSec guard prevents infinite hangs on locked files.
function Invoke-ShellZip {
    param(
        [string]$SourceFolder,
        [string]$DestZip,
        [int]$TimeoutSec = 120
    )

    # Shell.CopyHere requires the destination zip to already exist as a valid
    # (but empty) zip file. We create the 22-byte ZIP stub manually.
    $zipHeader = [byte[]](80,75,5,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    [System.IO.File]::WriteAllBytes($DestZip, $zipHeader)

    $shell   = New-Object -ComObject Shell.Application
    $zipObj  = $shell.NameSpace($DestZip)
    $srcObj  = $shell.NameSpace($SourceFolder)

    if (-not $zipObj -or -not $srcObj) {
        Write-WARN "Shell.Application could not open source or destination -- aborting ShellZip"
        return $false
    }

    # Flag 4 = suppress progress dialogs; 16 = answer Yes to all; 1024 = no error UI
    $zipObj.CopyHere($srcObj.Items(), 4 -bor 16 -bor 1024)

    # Poll until the file count in the zip stabilises or we time out.
    $deadline    = (Get-Date).AddSeconds($TimeoutSec)
    $lastCount   = -1
    $stableRounds = 0

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        try {
            $currentCount = $shell.NameSpace($DestZip).Items().Count
        } catch {
            $currentCount = 0
        }
        if ($currentCount -eq $lastCount) {
            $stableRounds++
            # Require 4 consecutive stable readings (~2 seconds) before declaring done
            if ($stableRounds -ge 4) { break }
        } else {
            $stableRounds = 0
        }
        $lastCount = $currentCount
    }

    if ((Get-Date) -ge $deadline) {
        Write-WARN "ShellZip timed out after ${TimeoutSec}s for $SourceFolder"
        return $false
    }

    return $true
}

# ---------------------------------------------------------------------------
# 1. DNS Zones
# ---------------------------------------------------------------------------
Write-STEP "DNS Backup"

$dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
if ($dnsService) {
    $dnsBackupDir = "$BackupRoot\DNS"
    New-Item -ItemType Directory -Path $dnsBackupDir -Force | Out-Null

    try {
        Import-Module DnsServer -ErrorAction Stop
        $zones = Get-DnsServerZone -ErrorAction Stop |
            Where-Object { -not $_.IsReverseLookupZone -or $_.ZoneName -notmatch "0.in-addr" }

        foreach ($zone in $zones) {
            $zoneFile = "$dnsBackupDir\$($zone.ZoneName).csv"
            try {
                Export-DnsServerZone -Name $zone.ZoneName -FileName "ccdc_backup_$($zone.ZoneName).dns" -ErrorAction Stop
                Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ErrorAction SilentlyContinue |
                    Select-Object HostName, RecordType, RecordData, TimeToLive |
                    Export-Csv -Path $zoneFile -NoTypeInformation
                Write-OK "DNS zone: $($zone.ZoneName) -> $zoneFile"
            } catch {
                Write-WARN "Could not export zone $($zone.ZoneName): $_"
            }
        }
    } catch {
        Write-WARN "DnsServer module not available, falling back to file copy"
        Backup-Path "C:\Windows\System32\dns" "$dnsBackupDir\dns_files" "DNS zone files"
    }

    Write-OK "DNS backup complete"
} else {
    Write-INFO "DNS Server role not detected on this machine"
}

# ---------------------------------------------------------------------------
# 2. IIS Backup
# ---------------------------------------------------------------------------
Write-STEP "IIS Backup"

$iisService = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
if ($iisService) {
    $iisBackupDir = "$BackupRoot\IIS"
    New-Item -ItemType Directory -Path $iisBackupDir -Force | Out-Null

    # Method 1: appcmd backup (most complete, restores with one command)
    $appcmd = "$env:SystemRoot\System32\inetsrv\appcmd.exe"
    if (Test-Path $appcmd) {
        $backupName   = "CCDC_$Stamp"
        $appcmdResult = Start-Process -FilePath $appcmd `
            -ArgumentList "add backup `"$backupName`"" `
            -Wait -PassThru -NoNewWindow `
            -RedirectStandardError "$LogDir\appcmd_err_tmp.txt"
        if ($appcmdResult.ExitCode -eq 0) {
            Write-OK "IIS config backup created: '$backupName'"
            Write-INFO "Restore with: appcmd restore backup '$backupName'"
        } else {
            Write-WARN "appcmd backup failed -- falling back to file copy"
        }
    }

    # Method 2: Direct config file copy as fallback
    $ahConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
    Backup-Path $ahConfig "$iisBackupDir\applicationHost.config" "applicationHost.config"

    # Method 3: Zip inetpub subdirectories using Shell COM (same engine as Explorer
    # "Send To > Compressed folder"). Dramatically faster than Compress-Archive
    # because it calls the native Win32 shell implementation directly rather than
    # the slow .NET ZipArchive wrapper. No background job / extra process needed.
    if (Test-Path "C:\inetpub") {
        $inetpubSubDirs = Get-ChildItem "C:\inetpub" -Directory -ErrorAction SilentlyContinue

        foreach ($subDir in $inetpubSubDirs) {
            $subZip = "$iisBackupDir\inetpub_$($subDir.Name)_$Stamp.zip"
            Write-INFO "Zipping $($subDir.FullName) -> $subZip ..."

            $zipOK = Invoke-ShellZip -SourceFolder $subDir.FullName -DestZip $subZip -TimeoutSec 120

            if ($zipOK -and (Test-Path $subZip)) {
                $zipSizeMB = [Math]::Round((Get-Item $subZip).Length / 1MB, 1)
                Write-OK "inetpub\$($subDir.Name) zipped -> $subZip ($zipSizeMB MB)"
            } else {
                # Fallback: robocopy skips locked files instead of blocking
                Write-INFO "Falling back to robocopy for $($subDir.Name)..."
                $roboDest   = "$iisBackupDir\inetpub_$($subDir.Name)"
                $roboLog    = "$LogDir\robocopy_inetpub_$($subDir.Name)_$Stamp.txt"
                $roboArgs   = @($subDir.FullName, $roboDest, "/E", "/R:0", "/W:0", "/NFL", "/NDL", "/NP", "/LOG:$roboLog")
                $roboResult = Start-Process -FilePath "robocopy" -ArgumentList $roboArgs -Wait -PassThru -NoNewWindow
                if ($roboResult.ExitCode -le 7) {
                    Write-OK "inetpub\$($subDir.Name) copied via robocopy -> $roboDest"
                } else {
                    Write-WARN "robocopy also failed for $($subDir.Name) (exit: $($roboResult.ExitCode)) -- check $roboLog"
                }
            }
        }
    }

    # Log all IIS sites
    try {
        Import-Module WebAdministration -ErrorAction Stop
        Get-Website | Select-Object Name, State, PhysicalPath, Bindings |
            Export-Csv -Path "$iisBackupDir\IIS_Sites.csv" -NoTypeInformation
        Write-OK "IIS sites list -> $iisBackupDir\IIS_Sites.csv"
    } catch {
        Write-INFO "WebAdministration module not available for site list"
    }

    Write-OK "IIS backup complete"
} else {
    Write-INFO "IIS (W3SVC) not detected on this machine"
}

# ---------------------------------------------------------------------------
# 3. Fileshares / Critical Folders
# ---------------------------------------------------------------------------
Write-STEP "Fileshare & Critical Folder Backup"

$shares = Get-SmbShare | Where-Object {
    $_.Name -notlike "ADMIN$" -and $_.Name -notlike "IPC$" -and $_.Name -notlike "C$" -and $_.Name -notlike "D$" -and $_.Name -notlike "E$" -and $_.Name -notlike "F$" -and $_.Path -ne ""
}

if ($shares) {
    $shareBackupDir = "$BackupRoot\Shares"
    foreach ($share in $shares) {
        Write-INFO "Backing up share: $($share.Name) -> $($share.Path)"
        $shareDest = "$shareBackupDir\$($share.Name)"
        Backup-Path $share.Path $shareDest "Share: $($share.Name)"
    }
} else {
    Write-INFO "No non-default shares found"
}

# ---------------------------------------------------------------------------
# 4. Registry Run Keys (Persistence Baseline)
# ---------------------------------------------------------------------------
Write-STEP "Registry Persistence Baseline"

$regBackupDir = "$BackupRoot\Registry"
New-Item -ItemType Directory -Path $regBackupDir -Force | Out-Null

$regPaths = @{
    "HKLM_Run"       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKLM_RunOnce"   = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKCU_Run"       = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    "HKCU_RunOnce"   = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    "HKLM_Run_Wow64" = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    "HKLM_Winlogon"  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
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
Write-OK "Registry Run keys baseline -> $regBackupDir\RegRunKeys_Baseline.csv"
Write-INFO "($($allRegEntries.Count) entries recorded -- compare later to detect added persistence)"

$hives = @{
    "HKLM_Run.reg" = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    "HKCU_Run.reg" = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    "Winlogon.reg" = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
}
foreach ($hive in $hives.GetEnumerator()) {
    $outFile = "$regBackupDir\$($hive.Key)"
    if (Export-RegKey -KeyPath $hive.Value -OutFile $outFile) {
        Write-OK "Exported $($hive.Key)"
    } else {
        Write-WARN "Failed to export $($hive.Key)"
    }
}

# ---------------------------------------------------------------------------
# 5. Scheduled Tasks Baseline
# ---------------------------------------------------------------------------
Write-STEP "Scheduled Tasks Baseline"

$taskLog = "$BackupRoot\ScheduledTasks_Baseline.csv"
Get-ScheduledTask | Select-Object TaskName, TaskPath, State,
    @{N="RunAs";   E={ $_.Principal.UserId }},
    @{N="Actions"; E={ ($_.Actions | ForEach-Object { $_.Execute + " " + $_.Arguments }) -join "; " }} |
    Export-Csv -Path $taskLog -NoTypeInformation

$nonMsTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft\*" }
Write-OK "Scheduled tasks baseline -> $taskLog"
Write-INFO "$($nonMsTasks.Count) non-Microsoft tasks (review for red team persistence)"

if ($nonMsTasks) {
    Write-Host ""
    Write-Host "  Non-Microsoft scheduled tasks:" -ForegroundColor White
    foreach ($t in $nonMsTasks) {
        $color = if ($t.State -eq "Ready" -or $t.State -eq "Running") { "Yellow" } else { "DarkGray" }
        Write-Host "  [$($t.State)] $($t.TaskPath)$($t.TaskName)" -ForegroundColor $color
    }
}

# ---------------------------------------------------------------------------
# 6. Service Configurations
# ---------------------------------------------------------------------------
Write-STEP "Service Configuration Backup"

$svcLog = "$BackupRoot\ServiceConfigs.csv"
Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName, StartName, Description |
    Export-Csv -Path $svcLog -NoTypeInformation
Write-OK "Service configs -> $svcLog"

# ---------------------------------------------------------------------------
# 7. Active Directory Backup (if DC)
# ---------------------------------------------------------------------------
Write-STEP "Active Directory Backup"

$domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$isDC = $domainRole -ge 4

if ($isDC) {
    Write-INFO "DC detected (DomainRole=$domainRole) -- backing up AD"
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

        # FIX: Replaced -Properties * with explicit list -- fetching every attribute
        # for every user is extremely slow on large domains. Only pull what we need.
        Get-ADUser -Filter * -Properties LastLogonDate, PasswordNeverExpires, MemberOf, Description |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordNeverExpires, MemberOf, Description |
            Export-Csv -Path "$adBackupDir\ADUsers.csv" -NoTypeInformation
        Write-OK "AD users -> $adBackupDir\ADUsers.csv"

        # Export AD groups and members
        Get-ADGroup -Filter * -Properties Members |
            Select-Object Name, GroupCategory, GroupScope,
                @{N="Members"; E={ ($_.Members | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join "; " }} |
            Export-Csv -Path "$adBackupDir\ADGroups.csv" -NoTypeInformation
        Write-OK "AD groups -> $adBackupDir\ADGroups.csv"

    } catch {
        Write-WARN "AD backup failed: $_"
    }
} else {
    Write-INFO "Not a DC -- skipping AD backup"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-OK "All backups complete!"
Write-INFO "Location: $BackupRoot"
$size = (Get-ChildItem $BackupRoot -Recurse -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum).Sum / 1MB
Write-INFO "Total backup size: $([Math]::Round($size, 2)) MB"
Write-Host ""
Write-WARN "Tip: Copy $BackupRoot to a USB drive or network share for safekeeping!"
Write-Host ""
