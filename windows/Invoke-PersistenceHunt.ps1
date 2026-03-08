# =============================================================================
# Invoke-PersistenceHunt.ps1
# CCDC Blue Team - Red Team Persistence Detection
# Scans all major Windows persistence mechanisms and outputs a threat report
# Run as: Administrator
# =============================================================================

#Requires -RunAsAdministrator

param(
    [string]$OutputPath = "C:\BlueTeam\PersistenceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    [switch]$Verbose
)

$findings = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-Finding {
    param([string]$Category, [string]$Severity, [string]$Detail, [string]$Value)
    $obj = [PSCustomObject]@{
        Time     = (Get-Date -Format "HH:mm:ss")
        Category = $Category
        Severity = $Severity
        Detail   = $Detail
        Value    = $Value
    }
    $script:findings += $obj
    $color = switch ($Severity) {
        "CRITICAL" { "Red" }
        "HIGH"     { "Magenta" }
        "MEDIUM"   { "Yellow" }
        "INFO"     { "Cyan" }
        default    { "White" }
    }
    Write-Host "[$($obj.Time)] [$Severity] $Category :: $Detail" -ForegroundColor $color
    if ($Value) { Write-Host "    -> $Value" -ForegroundColor DarkGray }
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Blue
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Blue
}

# Known-legitimate scheduled task paths (adjust for your environment)
$legitimateTaskPaths = @('\Microsoft\', '\Adobe\', '\Google\')

# Known-good service account names (add yours as needed)
$knownServiceAccounts = @('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'NT AUTHORITY\SYSTEM')

# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  CCDC BLUE TEAM - PERSISTENCE HUNTER" -ForegroundColor Green
Write-Host "  Started: $timestamp" -ForegroundColor Gray
Write-Host ""

# =============================================================================
# 1. REGISTRY RUN KEYS
# =============================================================================
Write-Section "REGISTRY RUN KEYS"

$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
    "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"  # Load/Run values
)

foreach ($key in $runKeys) {
    try {
        if (Test-Path $key) {
            $props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($props) {
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $severity = if ($_.Value -match '(temp|appdata|public|downloads|\.vbs|\.ps1|\.bat|cmd\.exe|powershell|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin)') { "HIGH" } else { "INFO" }
                    Write-Finding -Category "RunKey" -Severity $severity -Detail "$key\$($_.Name)" -Value $_.Value
                }
            }
        }
    } catch { Write-Finding -Category "RunKey" -Severity "INFO" -Detail "Could not read $key" -Value $_.Exception.Message }
}

# =============================================================================
# 2. SCHEDULED TASKS
# =============================================================================
Write-Section "SCHEDULED TASKS"

try {
    $tasks = Get-ScheduledTask | Where-Object {
        $_.TaskPath -notmatch ($legitimateTaskPaths -join '|')
    }

    foreach ($task in $tasks) {
        $info = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        $actions = $task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }
        $actionStr = $actions -join " | "

        $severity = "INFO"
        if ($actionStr -match '(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|\.vbs|\.ps1|\.bat|temp|appdata|public)') {
            $severity = "HIGH"
        } elseif ($task.Principal.RunLevel -eq "Highest") {
            $severity = "MEDIUM"
        }

        Write-Finding -Category "SchedTask" -Severity $severity `
            -Detail "[$($task.State)] $($task.TaskPath)$($task.TaskName)" `
            -Value "Action: $actionStr | User: $($task.Principal.UserId)"
    }
} catch {
    Write-Finding -Category "SchedTask" -Severity "INFO" -Detail "Error enumerating tasks" -Value $_.Exception.Message
}

# =============================================================================
# 3. SERVICES
# =============================================================================
Write-Section "SERVICES"

try {
    $services = Get-WmiObject Win32_Service | Where-Object { $_.StartMode -ne 'Disabled' }

    foreach ($svc in $services) {
        $severity = "INFO"
        $path = $svc.PathName

        if ($path -match '(temp|appdata|public|downloads|\.vbs|\.ps1|rundll32|regsvr32|mshta|cmd\.exe /c)') {
            $severity = "CRITICAL"
        } elseif ($path -match '(powershell|wscript|cscript)') {
            $severity = "HIGH"
        } elseif ($svc.StartName -notin $knownServiceAccounts -and $svc.StartName -notmatch 'NT SERVICE\\') {
            $severity = "MEDIUM"
        }

        if ($severity -ne "INFO") {
            Write-Finding -Category "Service" -Severity $severity `
                -Detail "$($svc.Name) [$($svc.State)]" `
                -Value "Path: $path | Account: $($svc.StartName)"
        }
    }

    # List all non-Microsoft services as INFO
    $services | Where-Object { $_.PathName -notmatch 'System32|SysWOW64' } | ForEach-Object {
        Write-Finding -Category "Service" -Severity "INFO" `
            -Detail "$($_.Name) [$($_.State)] - Non-System32" `
            -Value $_.PathName
    }
} catch {
    Write-Finding -Category "Service" -Severity "INFO" -Detail "Error enumerating services" -Value $_.Exception.Message
}

# =============================================================================
# 4. STARTUP FOLDERS
# =============================================================================
Write-Section "STARTUP FOLDERS"

$startupPaths = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
    "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
)

foreach ($startPath in $startupPaths) {
    $files = Get-Item $startPath -ErrorAction SilentlyContinue | Get-ChildItem -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $severity = if ($file.Extension -match '\.(exe|bat|vbs|ps1|lnk|cmd|scr)') { "HIGH" } else { "MEDIUM" }
        Write-Finding -Category "Startup" -Severity $severity -Detail $file.FullName -Value "Size: $($file.Length) | Modified: $($file.LastWriteTime)"
    }
}

# =============================================================================
# 5. WMI SUBSCRIPTIONS (Advanced Persistence)
# =============================================================================
Write-Section "WMI EVENT SUBSCRIPTIONS"

try {
    $wmiFilters = Get-WMIObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue
    $wmiConsumers = Get-WMIObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue
    $wmiBinders = Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue

    if ($wmiFilters) {
        foreach ($f in $wmiFilters) {
            Write-Finding -Category "WMI-Filter" -Severity "CRITICAL" -Detail "Filter: $($f.Name)" -Value $f.Query
        }
    } else { Write-Host "  [OK] No WMI Event Filters found" -ForegroundColor Green }

    if ($wmiConsumers) {
        foreach ($c in $wmiConsumers) {
            Write-Finding -Category "WMI-Consumer" -Severity "CRITICAL" -Detail "Consumer: $($c.Name)" -Value ($c.CommandLineTemplate -or $c.ScriptText)
        }
    } else { Write-Host "  [OK] No WMI Event Consumers found" -ForegroundColor Green }
} catch {
    Write-Finding -Category "WMI" -Severity "INFO" -Detail "Error querying WMI subscriptions" -Value $_.Exception.Message
}

# =============================================================================
# 6. LOCAL USER ACCOUNTS
# =============================================================================
Write-Section "LOCAL USER ACCOUNTS"

try {
    $users = Get-LocalUser
    foreach ($user in $users) {
        $severity = "INFO"
        $detail = "$($user.Name) | Enabled: $($user.Enabled) | LastLogin: $($user.LastLogon)"

        if ($user.Enabled -and $user.Name -notin @('Administrator','DefaultAccount','Guest','WDAGUtilityAccount')) {
            $severity = "MEDIUM"
        }
        if ($user.Name -match '(admin|root|svc|service|backdoor|hack|test)' -and $user.Enabled) {
            $severity = "HIGH"
        }

        Write-Finding -Category "LocalUser" -Severity $severity -Detail $user.Name -Value $detail
    }

    # Check Administrators group membership
    Write-Host ""
    Write-Host "  [ Administrators Group Members ]" -ForegroundColor Yellow
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    foreach ($admin in $admins) {
        Write-Finding -Category "AdminGroup" -Severity "HIGH" -Detail $admin.Name -Value "PrincipalSource: $($admin.PrincipalSource)"
    }
} catch {
    Write-Finding -Category "LocalUser" -Severity "INFO" -Detail "Error enumerating users" -Value $_.Exception.Message
}

# =============================================================================
# 7. ACTIVE NETWORK CONNECTIONS
# =============================================================================
Write-Section "SUSPICIOUS NETWORK CONNECTIONS"

try {
    $connections = Get-NetTCPConnection -State Established,Listen -ErrorAction SilentlyContinue
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 1234, 9999, 31337, 1337, 4321, 8080, 8443, 2222)

    foreach ($conn in $connections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        $isSuspiciousPort = $conn.LocalPort -in $suspiciousPorts -or $conn.RemotePort -in $suspiciousPorts
        $isSuspiciousProc = $proc.Name -match '(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|nc|ncat|netcat)'

        if ($isSuspiciousPort -or $isSuspiciousProc) {
            $severity = if ($isSuspiciousProc) { "CRITICAL" } else { "HIGH" }
            Write-Finding -Category "Network" -Severity $severity `
                -Detail "$($proc.Name) (PID $($conn.OwningProcess))" `
                -Value "$($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$($conn.State)]"
        }
    }

    # Listening on non-standard ports
    $listening = $connections | Where-Object { $_.State -eq 'Listen' -and $_.LocalPort -notin @(80,443,445,139,135,3389,5985,5986,53,88,389,636,49152..65535) }
    foreach ($l in $listening) {
        $proc = Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue
        Write-Finding -Category "Network" -Severity "MEDIUM" `
            -Detail "Listening: Port $($l.LocalPort)" `
            -Value "Process: $($proc.Name) (PID $($l.OwningProcess))"
    }
} catch {
    Write-Finding -Category "Network" -Severity "INFO" -Detail "Error checking connections" -Value $_.Exception.Message
}

# =============================================================================
# 8. RECENTLY MODIFIED FILES IN SENSITIVE LOCATIONS
# =============================================================================
Write-Section "RECENTLY MODIFIED SENSITIVE FILES"

$sensitivePaths = @(
    "C:\Windows\System32\drivers",
    "C:\Windows\System32\Tasks",
    "C:\Windows\SysWOW64",
    "C:\ProgramData",
    "C:\Users\Public"
)

$cutoff = (Get-Date).AddHours(-24)

foreach ($path in $sensitivePaths) {
    try {
        $recent = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -gt $cutoff -and $_.Extension -match '\.(exe|dll|sys|bat|ps1|vbs|cmd|scr)' }
        foreach ($f in $recent) {
            Write-Finding -Category "RecentFile" -Severity "HIGH" `
                -Detail $f.FullName `
                -Value "Modified: $($f.LastWriteTime) | Size: $($f.Length)"
        }
    } catch {}
}

# =============================================================================
# 9. LSASS / CREDENTIAL ACCESS INDICATORS
# =============================================================================
Write-Section "CREDENTIAL ACCESS INDICATORS"

# Check if WDigest is enabled (allows cleartext cred extraction)
try {
    $wdigest = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue
    if ($wdigest.UseLogonCredential -eq 1) {
        Write-Finding -Category "Credential" -Severity "CRITICAL" -Detail "WDigest UseLogonCredential is ENABLED" -Value "Cleartext passwords may be cached in LSASS memory!"
    } else {
        Write-Host "  [OK] WDigest UseLogonCredential is disabled" -ForegroundColor Green
    }
} catch { Write-Host "  [OK] WDigest key not found (safe)" -ForegroundColor Green }

# Check for Mimikatz artifacts / known dump tool processes
$dumpTools = @('procdump', 'mimikatz', 'wce', 'pwdump', 'fgdump', 'gsecdump', 'lsass', 'outflank')
$runningProcs = Get-Process -ErrorAction SilentlyContinue
foreach ($tool in $dumpTools) {
    $match = $runningProcs | Where-Object { $_.Name -match $tool -and $_.Name -ne 'lsass' }
    if ($match) {
        Write-Finding -Category "Credential" -Severity "CRITICAL" `
            -Detail "Suspicious process: $($match.Name) (PID $($match.Id))" `
            -Value $match.Path
    }
}

# =============================================================================
# 10. POWERSHELL TRANSCRIPTS & HISTORY
# =============================================================================
Write-Section "POWERSHELL ACTIVITY"

try {
    # Check PS history for all users
    $historyFiles = Get-Item "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
    foreach ($hist in $historyFiles) {
        $content = Get-Content $hist.FullName -ErrorAction SilentlyContinue | Select-Object -Last 30
        $suspicious = $content | Where-Object { $_ -match '(Invoke-Expression|IEX|DownloadString|Net\.WebClient|Start-BitsTransfer|certutil|bitsadmin|mshta|regsvr32|rundll32|bypass|EncodedCommand|-enc |-e )' }
        if ($suspicious) {
            foreach ($line in $suspicious) {
                Write-Finding -Category "PSHistory" -Severity "HIGH" -Detail $hist.FullName -Value $line.Trim()
            }
        }
    }
} catch {}

# Check PS Execution Policy
$policy = Get-ExecutionPolicy -List
foreach ($p in $policy) {
    if ($p.ExecutionPolicy -in @('Bypass', 'Unrestricted') -and $p.Scope -ne 'MachinePolicy') {
        Write-Finding -Category "PSPolicy" -Severity "HIGH" `
            -Detail "Execution Policy: $($p.ExecutionPolicy)" `
            -Value "Scope: $($p.Scope)"
    }
}

# =============================================================================
# SUMMARY REPORT
# =============================================================================
Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor White
Write-Host ("=" * 70) -ForegroundColor Cyan

$critical = $findings | Where-Object { $_.Severity -eq "CRITICAL" }
$high     = $findings | Where-Object { $_.Severity -eq "HIGH" }
$medium   = $findings | Where-Object { $_.Severity -eq "MEDIUM" }
$info     = $findings | Where-Object { $_.Severity -eq "INFO" }

Write-Host "  CRITICAL : $($critical.Count)" -ForegroundColor Red
Write-Host "  HIGH     : $($high.Count)"     -ForegroundColor Magenta
Write-Host "  MEDIUM   : $($medium.Count)"   -ForegroundColor Yellow
Write-Host "  INFO     : $($info.Count)"     -ForegroundColor Cyan
Write-Host ""

# Save report to file
$null = New-Item -ItemType Directory -Path (Split-Path $OutputPath) -Force -ErrorAction SilentlyContinue
$report = @"
CCDC BLUE TEAM - PERSISTENCE HUNT REPORT
Generated: $timestamp
Hostname:  $env:COMPUTERNAME
User:      $env:USERNAME

CRITICAL ($($critical.Count)):
$($critical | Format-Table -AutoSize | Out-String)

HIGH ($($high.Count)):
$($high | Format-Table -AutoSize | Out-String)

MEDIUM ($($medium.Count)):
$($medium | Format-Table -AutoSize | Out-String)

INFO ($($info.Count)):
$($info | Format-Table -AutoSize | Out-String)
"@

$report | Out-File -FilePath $OutputPath -Encoding UTF8
Write-Host "  [+] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host ""
