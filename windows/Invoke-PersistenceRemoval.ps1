# =============================================================================
# Invoke-PersistenceRemoval.ps1
# CCDC Blue Team - Interactive Persistence Removal Tool
# WARNING: Review all findings before removal. Test in lab first!
# Run as: Administrator
# =============================================================================

#Requires -RunAsAdministrator

param(
    [switch]$AutoMode,       # Auto-remove HIGH/CRITICAL without prompting (USE WITH CAUTION)
    [switch]$DryRun,         # Show what would be removed, but don't actually remove
    [string]$LogPath = "C:\BlueTeam\RemovalLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
)

$removedItems = @()

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $entry = "$(Get-Date -Format 'HH:mm:ss') | $Message"
    Write-Host $entry -ForegroundColor $Color
    Add-Content -Path $LogPath -Value $entry -ErrorAction SilentlyContinue
}

function Confirm-Action {
    param([string]$Prompt)
    if ($AutoMode) { return $true }
    $response = Read-Host "$Prompt [y/N]"
    return ($response -eq 'y' -or $response -eq 'Y')
}

$null = New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force -ErrorAction SilentlyContinue
Write-Log "=== CCDC PERSISTENCE REMOVAL TOOL ===" "Cyan"
Write-Log "DryRun: $DryRun | AutoMode: $AutoMode" "Gray"
Write-Log "Host: $env:COMPUTERNAME | User: $env:USERNAME" "Gray"

if ($DryRun) { Write-Log "[DRY RUN MODE - Nothing will actually be removed]" "Yellow" }

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Remove a Registry Value
# ─────────────────────────────────────────────────────────────────────────────
function Remove-RegistryPersistence {
    param([string]$KeyPath, [string]$ValueName)
    Write-Log "Removing registry value: $KeyPath\$ValueName" "Yellow"
    if (-not $DryRun) {
        try {
            Remove-ItemProperty -Path $KeyPath -Name $ValueName -Force -ErrorAction Stop
            Write-Log "  [REMOVED] $ValueName" "Green"
            $script:removedItems += "REG: $KeyPath\$ValueName"
        } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Remove a Scheduled Task
# ─────────────────────────────────────────────────────────────────────────────
function Remove-MaliciousTask {
    param([string]$TaskPath, [string]$TaskName)
    Write-Log "Removing scheduled task: $TaskPath$TaskName" "Yellow"
    if (-not $DryRun) {
        try {
            Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false -ErrorAction Stop
            Write-Log "  [REMOVED] $TaskName" "Green"
            $script:removedItems += "TASK: $TaskPath$TaskName"
        } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Stop and Remove a Service
# ─────────────────────────────────────────────────────────────────────────────
function Remove-MaliciousService {
    param([string]$ServiceName)
    Write-Log "Removing service: $ServiceName" "Yellow"
    if (-not $DryRun) {
        try {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            sc.exe delete $ServiceName | Out-Null
            Write-Log "  [REMOVED] $ServiceName" "Green"
            $script:removedItems += "SVC: $ServiceName"
        } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Disable a Local User
# ─────────────────────────────────────────────────────────────────────────────
function Disable-SuspiciousUser {
    param([string]$UserName)
    Write-Log "Disabling user: $UserName" "Yellow"
    if (-not $DryRun) {
        try {
            Disable-LocalUser -Name $UserName -ErrorAction Stop
            Write-Log "  [DISABLED] $UserName" "Green"
            $script:removedItems += "USER: $UserName"
        } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Remove user from Administrators
# ─────────────────────────────────────────────────────────────────────────────
function Remove-FromAdmins {
    param([string]$UserName)
    Write-Log "Removing $UserName from Administrators group" "Yellow"
    if (-not $DryRun) {
        try {
            Remove-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction Stop
            Write-Log "  [REMOVED FROM ADMINS] $UserName" "Green"
            $script:removedItems += "ADMIN_REMOVE: $UserName"
        } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
    }
}

# =============================================================================
# 1. CLEAN REGISTRY RUN KEYS
# =============================================================================
Write-Log "--- SCANNING REGISTRY RUN KEYS ---" "Cyan"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)

$suspiciousPatterns = '(temp|appdata\\local\\temp|public|downloads|\.vbs|\.ps1|\.bat|cmd\.exe|mshta|wscript|cscript|rundll32.*http|regsvr32.*http|certutil.*-decode|bitsadmin.*transfer)'

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
            if ($_.Value -match $suspiciousPatterns) {
                Write-Log "SUSPICIOUS RunKey: $($_.Name) = $($_.Value)" "Red"
                if (Confirm-Action "Remove this registry run key?") {
                    Remove-RegistryPersistence -KeyPath $key -ValueName $_.Name
                }
            }
        }
    }
}

# =============================================================================
# 2. CLEAN SCHEDULED TASKS
# =============================================================================
Write-Log "" "White"
Write-Log "--- SCANNING SCHEDULED TASKS ---" "Cyan"

$legitimateTaskPaths = @('\Microsoft\', '\Adobe\', '\Google\', '\MicrosoftEdgeUpdate\')

$tasks = Get-ScheduledTask | Where-Object {
    $taskPath = $_.TaskPath
    -not ($legitimateTaskPaths | Where-Object { $taskPath -match [regex]::Escape($_) })
}

foreach ($task in $tasks) {
    $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
    $actionStr = $actions -join " | "

    if ($actionStr -match '(powershell.*-enc|powershell.*bypass|cmd.*http|wscript|cscript|mshta|certutil.*-decode|bitsadmin)') {
        Write-Log "SUSPICIOUS Task: $($task.TaskPath)$($task.TaskName)" "Red"
        Write-Log "  Action: $actionStr" "Gray"
        if (Confirm-Action "Remove this scheduled task?") {
            Remove-MaliciousTask -TaskPath $task.TaskPath -TaskName $task.TaskName
        }
    }
}

# =============================================================================
# 3. CLEAN SERVICES
# =============================================================================
Write-Log "" "White"
Write-Log "--- SCANNING SERVICES ---" "Cyan"

$services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne 'Disabled' }
$suspiciousServicePattern = '(temp|appdata|public|downloads|\.vbs|\.ps1|rundll32.*http|mshta|cmd\.exe /c|powershell.*-enc)'

foreach ($svc in $services) {
    if ($svc.PathName -match $suspiciousServicePattern) {
        Write-Log "SUSPICIOUS Service: $($svc.Name)" "Red"
        Write-Log "  Path: $($svc.PathName)" "Gray"
        Write-Log "  Account: $($svc.StartName)" "Gray"
        if (Confirm-Action "Stop and remove this service?") {
            Remove-MaliciousService -ServiceName $svc.Name
        }
    }
}

# =============================================================================
# 4. CLEAN WMI SUBSCRIPTIONS
# =============================================================================
Write-Log "" "White"
Write-Log "--- SCANNING WMI SUBSCRIPTIONS ---" "Cyan"

try {
    $wmiFilters = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $wmiConsumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $wmiBinders = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

    foreach ($binding in $wmiBinders) {
        Write-Log "SUSPICIOUS WMI Binding found!" "Red"
        if (Confirm-Action "Remove WMI FilterToConsumerBinding?") {
            if (-not $DryRun) {
                $binding | Remove-WmiObject
                Write-Log "  [REMOVED] WMI Binding" "Green"
                $script:removedItems += "WMI: Binding removed"
            }
        }
    }
    foreach ($filter in $wmiFilters) {
        Write-Log "SUSPICIOUS WMI Filter: $($filter.Name)" "Red"
        if (Confirm-Action "Remove WMI Event Filter?") {
            if (-not $DryRun) {
                $filter | Remove-WmiObject
                Write-Log "  [REMOVED] WMI Filter: $($filter.Name)" "Green"
                $script:removedItems += "WMI: Filter $($filter.Name)"
            }
        }
    }
    foreach ($consumer in $wmiConsumers) {
        Write-Log "SUSPICIOUS WMI Consumer: $($consumer.Name)" "Red"
        if (Confirm-Action "Remove WMI Event Consumer?") {
            if (-not $DryRun) {
                $consumer | Remove-WmiObject
                Write-Log "  [REMOVED] WMI Consumer: $($consumer.Name)" "Green"
                $script:removedItems += "WMI: Consumer $($consumer.Name)"
            }
        }
    }
    if (-not $wmiFilters -and -not $wmiConsumers) {
        Write-Log "  [CLEAN] No WMI subscriptions found" "Green"
    }
} catch { Write-Log "Error scanning WMI: $($_.Exception.Message)" "Red" }

# =============================================================================
# 5. CLEAN STARTUP FOLDER
# =============================================================================
Write-Log "" "White"
Write-Log "--- SCANNING STARTUP FOLDERS ---" "Cyan"

$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
)

foreach ($startPath in $startupPaths) {
    $files = Get-ChildItem -Path $startPath -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -match '\.(exe|bat|vbs|ps1|cmd|scr)' }
    foreach ($file in $files) {
        Write-Log "SUSPICIOUS Startup file: $($file.FullName)" "Red"
        if (Confirm-Action "Delete this startup file?") {
            if (-not $DryRun) {
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    Write-Log "  [DELETED] $($file.FullName)" "Green"
                    $script:removedItems += "FILE: $($file.FullName)"
                } catch { Write-Log "  [FAILED] $($_.Exception.Message)" "Red" }
            }
        }
    }
}

# =============================================================================
# 6. AUDIT USER ACCOUNTS
# =============================================================================
Write-Log "" "White"
Write-Log "--- AUDITING USER ACCOUNTS ---" "Cyan"

$legitUsers = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')
# Add your competition team user accounts here:
$teamUsers  = @('') # e.g. @('blueadmin', 'sysadmin')
$allLegit   = $legitUsers + $teamUsers

$users = Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin $allLegit }
foreach ($user in $users) {
    Write-Log "UNKNOWN Enabled User: $($user.Name) | LastLogin: $($user.LastLogon)" "Yellow"
    if (Confirm-Action "Disable this user?") {
        Disable-SuspiciousUser -UserName $user.Name
    }
}

# Check admin group members
$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
foreach ($admin in $admins) {
    $shortName = $admin.Name -replace '.*\\', ''
    if ($shortName -notin ($allLegit + @('Administrator'))) {
        Write-Log "UNEXPECTED Admin: $($admin.Name)" "Red"
        if (Confirm-Action "Remove from Administrators?") {
            Remove-FromAdmins -UserName $admin.Name
        }
    }
}

# =============================================================================
# 7. HARDENING FIXES
# =============================================================================
Write-Log "" "White"
Write-Log "--- APPLYING HARDENING FIXES ---" "Cyan"

# Disable WDigest (prevents cleartext password caching)
$wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
if ($wdigest.UseLogonCredential -ne 0) {
    Write-Log "Disabling WDigest cleartext credential caching..." "Yellow"
    if (-not $DryRun) {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force
        Write-Log "  [FIXED] WDigest disabled" "Green"
        $script:removedItems += "HARDEN: WDigest disabled"
    }
}

# Disable SMBv1
$smb1 = Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol
if ($smb1) {
    Write-Log "Disabling SMBv1..." "Yellow"
    if (-not $DryRun) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        Write-Log "  [FIXED] SMBv1 disabled" "Green"
        $script:removedItems += "HARDEN: SMBv1 disabled"
    }
}

# Ensure PS logging is enabled
Write-Log "Enabling PowerShell Script Block Logging..." "Yellow"
if (-not $DryRun) {
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force
    Write-Log "  [FIXED] PS Script Block Logging enabled" "Green"
    $script:removedItems += "HARDEN: PS ScriptBlock logging enabled"
}

# =============================================================================
# SUMMARY
# =============================================================================
Write-Log "" "White"
Write-Log "=== REMOVAL SUMMARY ===" "Cyan"
Write-Log "Total actions taken: $($removedItems.Count)" "White"
foreach ($item in $removedItems) { Write-Log "  [+] $item" "Green" }
Write-Log "Log saved to: $LogPath" "Gray"
