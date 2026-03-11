# =============================================================================
# Invoke-AttackResponse.ps1
# CCDC Blue Team - Real-Time Attack Detection & Acknowledgement
# Monitors event logs, fires alerts, and logs incidents for scoring evidence
# Run as: Administrator | Best used as a persistent background monitor
# =============================================================================

#Requires -RunAsAdministrator

param(
    [int]$PollIntervalSeconds = 30,
    [string]$LogPath = "C:\BlueTeam\AttackLog_$(Get-Date -Format 'yyyyMMdd').txt",
    [string]$ScoringEvidencePath = "C:\BlueTeam\ScoringEvidence",
    [switch]$OneShot   # Run once instead of looping (useful for manual checks)
)

$null = New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $ScoringEvidencePath -Force -ErrorAction SilentlyContinue

# Track what we've already alerted on to avoid duplicates
$alertedEvents = [System.Collections.Generic.HashSet[string]]::new()
$startTime   = Get-Date
$selfPID     = $PID   # This script's own PowerShell process ID
$selfScripts = @(
    'Invoke-AttackResponse',
    'Invoke-ThreatMonitor',
    'Invoke-PersistenceHunt',
    'Invoke-PersistenceRemoval'
)  # Our own blue team scripts - never alert on these

function Write-Alert {
    param(
        [string]$Type,       # ATTACK, INFO, RESPONSE
        [string]$Severity,   # CRITICAL, HIGH, MEDIUM, LOW
        [string]$Message,
        [string]$Detail = ""
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "LOW"      { "Cyan" }
        default    { "White" }
    }

    $line = "$ts | [$Type] [$Severity] $Message"
    if ($Detail) { $line += " | $Detail" }

    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue
}

function Save-ScoringEvidence {
    param([string]$IncidentName, [object]$Data)
    $filename = "$ScoringEvidencePath\$(Get-Date -Format 'HHmmss')_$IncidentName.txt"
    $Data | Out-File -FilePath $filename -Encoding UTF8 -ErrorAction SilentlyContinue
    Write-Alert -Type "INFO" -Severity "LOW" -Message "Evidence saved: $filename"
}

# =============================================================================
# EVENT ID REFERENCE (Windows Security Log)
# 4624 - Successful logon
# 4625 - Failed logon
# 4648 - Logon with explicit credentials (lateral movement indicator)
# 4672 - Special privileges assigned (admin logon)
# 4697 - Service installed
# 4698 - Scheduled task created
# 4700 - Scheduled task enabled
# 4702 - Scheduled task updated
# 4720 - User account created
# 4732 - Member added to security-enabled local group
# 4756 - Member added to universal security group
# 7045 - New service installed (System log)
# 1102 - Audit log cleared (CRITICAL!)
# =============================================================================

function Get-RecentSecurityEvents {
    param([int]$MaxEvents = 100)
    try {
        return Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = (Get-Date).AddSeconds(-($PollIntervalSeconds * 2))
            Id        = @(4624, 4625, 4648, 4672, 4697, 4698, 4700, 4702, 4720, 4722, 4732, 4756, 1102)
        } -MaxEvents $MaxEvents -ErrorAction SilentlyContinue
    } catch { return @() }
}

function Get-RecentSystemEvents {
    try {
        return Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            StartTime = (Get-Date).AddSeconds(-($PollIntervalSeconds * 2))
            Id        = @(7045, 7040)
        } -MaxEvents 50 -ErrorAction SilentlyContinue
    } catch { return @() }
}

function Get-RecentPSEvents {
    try {
        return Get-WinEvent -FilterHashtable @{
            LogName   = 'Microsoft-Windows-PowerShell/Operational'
            StartTime = (Get-Date).AddSeconds(-($PollIntervalSeconds * 2))
            Id        = @(4103, 4104)  # Script block logging
        } -MaxEvents 50 -ErrorAction SilentlyContinue
    } catch { return @() }
}

function Analyze-SecurityEvent {
    param($Event)

    $key = "$($Event.Id)-$($Event.TimeCreated)-$($Event.RecordId)"
    if ($alertedEvents.Contains($key)) { return }
    $alertedEvents.Add($key) | Out-Null

    $msg = $Event.Message

    switch ($Event.Id) {

        # --- Log Cleared -----------------------------------------------------
        1102 {
            Write-Alert -Type "ATTACK" -Severity "CRITICAL" `
                -Message "AUDIT LOG CLEARED - Active attacker covering tracks!" `
                -Detail "Time: $($Event.TimeCreated)"
            Save-ScoringEvidence -IncidentName "AuditLogCleared" -Data $Event
        }

        # --- Account Created -------------------------------------------------
        4720 {
            $targetUser = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            $subjectUser = if ($msg -match 'Subject:.*?Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            Write-Alert -Type "ATTACK" -Severity "HIGH" `
                -Message "NEW USER ACCOUNT CREATED: $targetUser by $subjectUser" `
                -Detail "Time: $($Event.TimeCreated)"
            Save-ScoringEvidence -IncidentName "NewUser_$targetUser" -Data $msg
        }

        # --- User Added to Group ---------------------------------------------
        4732 {
            if ($msg -match 'Administrators') {
                Write-Alert -Type "ATTACK" -Severity "CRITICAL" `
                    -Message "USER ADDED TO ADMINISTRATORS GROUP!" `
                    -Detail $msg.Substring(0, [Math]::Min(200, $msg.Length))
                Save-ScoringEvidence -IncidentName "AdminGroupAdd" -Data $msg
            }
        }

        # --- Service Installed -----------------------------------------------
        4697 {
            Write-Alert -Type "ATTACK" -Severity "HIGH" `
                -Message "NEW SERVICE INSTALLED via Security Log" `
                -Detail $msg.Substring(0, [Math]::Min(300, $msg.Length))
            Save-ScoringEvidence -IncidentName "ServiceInstalled" -Data $msg
        }

        # --- Scheduled Task Created/Modified ---------------------------------
        { $_ -in @(4698, 4700, 4702) } {
            $severity = if ($Event.Id -eq 4698) { "HIGH" } else { "MEDIUM" }
            $action = switch ($Event.Id) { 4698 {"CREATED"} 4700 {"ENABLED"} 4702 {"MODIFIED"} }
            Write-Alert -Type "ATTACK" -Severity $severity `
                -Message "SCHEDULED TASK $action" `
                -Detail $msg.Substring(0, [Math]::Min(300, $msg.Length))
            Save-ScoringEvidence -IncidentName "SchedTask$action" -Data $msg
        }

        # --- Brute Force / Password Spray ------------------------------------
        4625 {
            $targetUser = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            $sourceIP = if ($msg -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { "unknown" }
            Write-Alert -Type "ATTACK" -Severity "MEDIUM" `
                -Message "FAILED LOGON: $targetUser from $sourceIP" `
                -Detail "Time: $($Event.TimeCreated)"
        }

        # --- Explicit Credential Logon (PtH/lateral movement) ----------------
        4648 {
            $targetUser = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            $targetServer = if ($msg -match 'Target Server Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            if ($targetServer -notmatch 'localhost|127\.0\.0\.1') {
                Write-Alert -Type "ATTACK" -Severity "HIGH" `
                    -Message "EXPLICIT CREDENTIAL USE (possible lateral movement)" `
                    -Detail "User: $targetUser -> Server: $targetServer"
            }
        }

        # --- Successful Logon ------------------------------------------------
        4624 {
            # Only alert on logon types 3 (network) and 10 (RemoteInteractive/RDP)
            $logonType = if ($msg -match 'Logon Type:\s+(\d+)') { $matches[1] } else { "0" }
            $sourceIP = if ($msg -match 'Source Network Address:\s+(\S+)') { $matches[1] } else { "unknown" }
            $targetUser = if ($msg -match 'Account Name:\s+(\S+)') { $matches[1] } else { "unknown" }
            if ($logonType -in @('3', '10') -and $sourceIP -notin @('-', '::1', '127.0.0.1', '')) {
                Write-Alert -Type "INFO" -Severity "LOW" `
                    -Message "NETWORK/RDP LOGON: $targetUser from $sourceIP (Type $logonType)"
            }
        }
    }
}

function Analyze-SystemEvent {
    param($Event)
    $key = "SYS-$($Event.Id)-$($Event.RecordId)"
    if ($alertedEvents.Contains($key)) { return }
    $alertedEvents.Add($key) | Out-Null

    if ($Event.Id -eq 7045) {
        $msg = $Event.Message
        Write-Alert -Type "ATTACK" -Severity "HIGH" `
            -Message "NEW SERVICE INSTALLED (System Log)" `
            -Detail $msg.Substring(0, [Math]::Min(300, $msg.Length))
        Save-ScoringEvidence -IncidentName "NewService_SysLog" -Data $msg
    }
}

function Analyze-PSEvent {
    param($Event)
    $key = "PS-$($Event.Id)-$($Event.RecordId)"
    if ($alertedEvents.Contains($key)) { return }
    $alertedEvents.Add($key) | Out-Null

    $msg = $Event.Message

    # Skip events generated by our own blue team scripts
    foreach ($scriptName in $selfScripts) {
        if ($msg -match [regex]::Escape($scriptName)) { return }
    }

    # Skip events from our own PID
    if ($msg -match "ProcessId\s*=\s*$selfPID") { return }

    # Skip script block logging events that are just loading a file from disk
    # (these fire on initial script load, not on malicious execution)
    if ($msg -match 'Creating Scriptblock text \(1 of 1\)' -and $msg -match '# =====') { return }

    $suspiciousPatterns = @(
        'Invoke-Expression', 'IEX\s*\(', 'DownloadString', 'Net\.WebClient',
        'FromBase64String', '-EncodedCommand', '-enc ', 'bypass',
        'AmsiUtils', 'amsiInitFailed', 'System\.Reflection\.Assembly',
        'VirtualAlloc', 'WriteProcessMemory', 'CreateThread'
    )

    foreach ($pattern in $suspiciousPatterns) {
        if ($msg -match $pattern) {
            Write-Alert -Type "ATTACK" -Severity "HIGH" `
                -Message "SUSPICIOUS POWERSHELL: Matched '$pattern'" `
                -Detail $msg.Substring(0, [Math]::Min(400, $msg.Length))
            Save-ScoringEvidence -IncidentName "SuspiciousPS" -Data $msg
            break
        }
    }
}

function Check-BruteForce {
    # Count failed logons in the last 2 minutes
    try {
        $cutoff = (Get-Date).AddMinutes(-2)
        $failures = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            StartTime = $cutoff
            Id        = 4625
        } -ErrorAction SilentlyContinue

        if ($failures.Count -gt 10) {
            Write-Alert -Type "ATTACK" -Severity "CRITICAL" `
                -Message "BRUTE FORCE DETECTED: $($failures.Count) failed logons in last 2 minutes!" `
                -Detail "Consider blocking via: netsh advfirewall firewall add rule name='Block BF' dir=in action=block remoteip=<IP>"
            Save-ScoringEvidence -IncidentName "BruteForce_$(Get-Date -Format HHmmss)" -Data ($failures | Select-Object TimeCreated, Message | Out-String)
        }
    } catch {}
}

function Check-ActiveConnections {
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 1234, 9999, 31337, 1337)
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemotePort -in $suspiciousPorts -or $_.LocalPort -in $suspiciousPorts }

    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $key = "CONN-$($conn.RemoteAddress)-$($conn.RemotePort)-$($conn.OwningProcess)"
        if (-not $alertedEvents.Contains($key)) {
            $alertedEvents.Add($key) | Out-Null
            Write-Alert -Type "ATTACK" -Severity "CRITICAL" `
                -Message "C2 PORT CONNECTION: $($proc.Name) (PID $($conn.OwningProcess))" `
                -Detail "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort)"
        }
    }
}

# =============================================================================
# MAIN LOOP
# =============================================================================
Write-Alert -Type "INFO" -Severity "LOW" `
    -Message "Attack Response Monitor STARTED" `
    -Detail "Host: $env:COMPUTERNAME | Log: $LogPath | Poll: ${PollIntervalSeconds}s"

Write-Host ""
Write-Host "  Monitoring for attacks. Press CTRL+C to stop." -ForegroundColor Green
Write-Host "  Evidence will be saved to: $ScoringEvidencePath" -ForegroundColor Gray
Write-Host ""

do {
    try {
        # Poll event logs
        Get-RecentSecurityEvents | ForEach-Object { Analyze-SecurityEvent $_ }
        Get-RecentSystemEvents   | ForEach-Object { Analyze-SystemEvent $_ }
        Get-RecentPSEvents       | ForEach-Object { Analyze-PSEvent $_ }

        # Active checks
        Check-BruteForce
        Check-ActiveConnections

    } catch {
        Write-Alert -Type "INFO" -Severity "LOW" -Message "Poll error: $($_.Exception.Message)"
    }

    if (-not $OneShot) {
        Start-Sleep -Seconds $PollIntervalSeconds
    }
} while (-not $OneShot)

Write-Alert -Type "INFO" -Severity "LOW" -Message "Monitor stopped. Total unique alerts: $($alertedEvents.Count)"
