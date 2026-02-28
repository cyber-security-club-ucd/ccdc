#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Non-Windows Service Audit
.DESCRIPTION
    Audits services that aren't native Windows services:
    - PHP version and configuration hardening
    - MySQL/MariaDB security
    - Apache httpd (if installed)
    - FileZilla FTP
    - OpenSSH
    - Node.js / Python services
    - Config file finder
    - Version checker (for known vulns)
    - Port-to-service correlation
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

$LogDir = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Stamp  = Get-Date -Format "yyyyMMdd_HHmm"

Write-Banner "NON-WINDOWS SERVICE AUDIT" "Magenta"

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Version check against known bad versions
# ─────────────────────────────────────────────────────────────────────────────
function Check-Version {
    param([string]$Product, [string]$Version)
    Write-INFO "$Product version: $Version"
    # Very rough heuristic — flag anything EOL or known old
    if ($Version -match "^5\." -and $Product -match "PHP") { Write-CRIT "PHP 5.x is END OF LIFE and has many known RCE vulns!" }
    if ($Version -match "^7\.[0-3]\." -and $Product -match "PHP") { Write-WARN "PHP $Version is EOL — upgrade to 8.x if possible" }
    if ($Version -match "^5\.[0-6]\." -and $Product -match "MySQL") { Write-CRIT "MySQL $Version is very old and EOL" }
    if ($Version -match "^2\.2\." -and $Product -match "Apache") { Write-CRIT "Apache 2.2 is EOL — many known vulns" }
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. PHP Detection & Hardening
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "PHP Detection & Hardening"

$phpPaths = @(
    "C:\php\php.exe", "C:\PHP\php.exe",
    "C:\xampp\php\php.exe", "C:\wamp\bin\php\*\php.exe",
    "C:\Program Files\PHP\php.exe"
)

$phpExe = $null
foreach ($p in $phpPaths) {
    $found = Get-Item $p -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $phpExe = $found.FullName; break }
}

if (-not $phpExe) {
    # Try PATH
    $phpExe = (Get-Command php.exe -ErrorAction SilentlyContinue)?.Source
}

if ($phpExe) {
    Write-INFO "PHP found: $phpExe"
    $phpVersion = & $phpExe -r "echo phpversion();" 2>$null
    Check-Version "PHP" $phpVersion

    # Find php.ini
    $phpIniPath = & $phpExe -r "echo php_ini_loaded_file();" 2>$null
    Write-INFO "php.ini: $phpIniPath"

    if ($phpIniPath -and (Test-Path $phpIniPath)) {
        $ini = Get-Content $phpIniPath

        # Backup php.ini first
        Copy-Item $phpIniPath "$LogDir\php.ini.backup" -Force
        Write-OK "php.ini backed up → $LogDir\php.ini.backup"

        # Check dangerous settings
        $phpChecks = @(
            @{ Setting = "expose_php"; Safe = "Off";  Current = ($ini | Select-String "^expose_php\s*=").ToString() },
            @{ Setting = "allow_url_fopen"; Safe = "Off"; Current = ($ini | Select-String "^allow_url_fopen\s*=").ToString() },
            @{ Setting = "allow_url_include"; Safe = "Off"; Current = ($ini | Select-String "^allow_url_include\s*=").ToString() },
            @{ Setting = "display_errors"; Safe = "Off"; Current = ($ini | Select-String "^display_errors\s*=").ToString() },
            @{ Setting = "log_errors"; Safe = "On";  Current = ($ini | Select-String "^log_errors\s*=").ToString() },
            @{ Setting = "disable_functions"; Safe = "Not empty"; Current = ($ini | Select-String "^disable_functions\s*=").ToString() }
        )

        Write-Host ""
        Write-Host "  PHP security settings:" -ForegroundColor DarkGray
        foreach ($check in $phpChecks) {
            $val = $check.Current
            $color = "Green"
            $flag  = ""
            if ($check.Setting -in @("expose_php","allow_url_fopen","allow_url_include","display_errors")) {
                if ($val -match "On") { $color = "Red"; $flag = " ◄ Should be Off!" }
            }
            if ($check.Setting -eq "disable_functions" -and ($val -match "=\s*$" -or -not $val)) {
                $color = "Yellow"; $flag = " ◄ Consider disabling: exec,passthru,shell_exec,system,popen,proc_open"
            }
            Write-Host "  $($check.Setting.PadRight(25)) $val $flag" -ForegroundColor $color
        }

        # Suggest critical changes
        Write-Host ""
        $fixPHP = Read-Host "  Apply recommended PHP hardening to php.ini? (y/N)"
        if ($fixPHP -eq 'y') {
            $iniContent = Get-Content $phpIniPath -Raw
            $changes = @{
                'expose_php\s*=.*'            = 'expose_php = Off'
                'allow_url_fopen\s*=.*'       = 'allow_url_fopen = Off'
                'allow_url_include\s*=.*'     = 'allow_url_include = Off'
                'display_errors\s*=.*'        = 'display_errors = Off'
                'log_errors\s*=.*'            = 'log_errors = On'
            }
            foreach ($change in $changes.GetEnumerator()) {
                $iniContent = $iniContent -replace $change.Key, $change.Value
            }

            # Add dangerous function disabling if not set
            if ($iniContent -notmatch 'disable_functions\s*=\s*\S') {
                $iniContent += "`n; CCDC Hardening`ndisable_functions = exec,passthru,shell_exec,system,popen,proc_open,curl_exec,curl_multi_exec,parse_ini_file,show_source`n"
            }
            Set-Content -Path $phpIniPath -Value $iniContent
            Write-OK "php.ini hardened — restart your web server for changes to take effect!"
        }
    }
} else {
    Write-INFO "PHP not detected on this system"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. MySQL / MariaDB
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "MySQL / MariaDB"

$mysqlPaths = @(
    "C:\xampp\mysql\bin\mysql.exe",
    "C:\mysql\bin\mysql.exe",
    "C:\Program Files\MySQL\MySQL Server*\bin\mysql.exe",
    "C:\wamp\bin\mysql\*\bin\mysql.exe",
    "C:\MariaDB*\bin\mysql.exe"
)

$mysqlExe = $null
foreach ($p in $mysqlPaths) {
    $found = Get-Item $p -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $mysqlExe = $found.FullName; break }
}
if (-not $mysqlExe) { $mysqlExe = (Get-Command mysql.exe -ErrorAction SilentlyContinue)?.Source }

if ($mysqlExe) {
    Write-INFO "MySQL/MariaDB found: $mysqlExe"
    $mysqlVersion = & $mysqlExe --version 2>$null
    Write-INFO "Version: $mysqlVersion"

    # Find my.ini / my.cnf
    $myiniPaths = @("C:\xampp\mysql\bin\my.ini","C:\ProgramData\MySQL\MySQL Server*\my.ini","C:\mysql\my.ini")
    foreach ($mp in $myiniPaths) {
        $myfound = Get-Item $mp -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($myfound) {
            Write-INFO "MySQL config: $($myfound.FullName)"
            Copy-Item $myfound.FullName "$LogDir\my.ini.backup" -Force
            Write-OK "my.ini backed up"

            $myiniContent = Get-Content $myfound.FullName -Raw
            if ($myiniContent -notmatch "skip-networking" -and $myiniContent -notmatch "bind-address\s*=\s*127\.0\.0\.1") {
                Write-WARN "MySQL may be listening on all interfaces! Add 'bind-address = 127.0.0.1' to my.ini if external access not needed"
            }
            if ($myiniContent -notmatch "local-infile\s*=\s*0") {
                Write-WARN "Consider adding 'local-infile = 0' to prevent file read via MySQL"
            }
        }
    }

    Write-Host ""
    Write-Host "  MANUAL STEPS for MySQL hardening (run in mysql shell):" -ForegroundColor Yellow
    Write-Host "  mysql -u root -p" -ForegroundColor White
    Write-Host "  DELETE FROM mysql.user WHERE User='';" -ForegroundColor Cyan
    Write-Host "  DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" -ForegroundColor Cyan
    Write-Host "  ALTER USER 'root'@'localhost' IDENTIFIED BY 'NewStr0ngP@ssword!';" -ForegroundColor Cyan
    Write-Host "  FLUSH PRIVILEGES;" -ForegroundColor Cyan
} else {
    Write-INFO "MySQL not detected"
}

# ─────────────────────────────────────────────────────────────────────────────
# 3. FileZilla FTP
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "FileZilla FTP Server"

$filezillaConfig = @(
    "C:\Program Files (x86)\FileZilla Server\FileZilla Server.xml",
    "C:\Program Files\FileZilla Server\FileZilla Server.xml"
)
$fzService = Get-Service -Name "FileZilla Server" -ErrorAction SilentlyContinue

if ($fzService) {
    Write-INFO "FileZilla Server service found (Status: $($fzService.Status))"
    foreach ($fzPath in $filezillaConfig) {
        if (Test-Path $fzPath) {
            Copy-Item $fzPath "$LogDir\FileZilla_config.xml.backup" -Force
            Write-OK "FileZilla config backed up → $LogDir\FileZilla_config.xml.backup"

            $fzContent = Get-Content $fzPath -Raw
            # Check for anonymous FTP
            if ($fzContent -match "Anonymous") {
                Write-CRIT "Anonymous FTP may be configured in FileZilla — check and disable!"
            }
            if ($fzContent -notmatch "TLS|SSL") {
                Write-WARN "TLS/FTPS not detected in FileZilla config — plain FTP sends passwords in cleartext!"
            }
        }
    }
} else {
    Write-INFO "FileZilla Server not detected"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. OpenSSH Server
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "OpenSSH Server"

$sshdService = Get-Service -Name sshd -ErrorAction SilentlyContinue
if ($sshdService) {
    Write-INFO "OpenSSH sshd service found (Status: $($sshdService.Status))"
    $sshdConfig = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $sshdConfig) {
        Copy-Item $sshdConfig "$LogDir\sshd_config.backup" -Force
        Write-OK "sshd_config backed up"
        $sshContent = Get-Content $sshdConfig -Raw

        $sshChecks = @(
            @{ Setting = "PermitRootLogin";           Safe = "no";  Pattern = "^PermitRootLogin\s+(\S+)" },
            @{ Setting = "PasswordAuthentication";    Safe = "yes"; Pattern = "^PasswordAuthentication\s+(\S+)" },
            @{ Setting = "MaxAuthTries";              Safe = "3";   Pattern = "^MaxAuthTries\s+(\S+)" },
            @{ Setting = "PermitEmptyPasswords";      Safe = "no";  Pattern = "^PermitEmptyPasswords\s+(\S+)" },
            @{ Setting = "X11Forwarding";             Safe = "no";  Pattern = "^X11Forwarding\s+(\S+)" },
            @{ Setting = "AllowTcpForwarding";        Safe = "no";  Pattern = "^AllowTcpForwarding\s+(\S+)" }
        )

        foreach ($check in $sshChecks) {
            $m = [regex]::Match($sshContent, $check.Pattern, [System.Text.RegularExpressions.RegexOptions]::Multiline)
            $current = if ($m.Success) { $m.Groups[1].Value } else { "(not set — default applies)" }
            $isSafe = $current -eq $check.Safe -or (-not $m.Success -and $check.Setting -eq "PasswordAuthentication")
            $color = if ($isSafe) { "Green" } else { "Yellow" }
            Write-Host ("  {0,-30} Current: {1,-15} Recommended: {2}" -f $check.Setting, $current, $check.Safe) -ForegroundColor $color
        }
    }
} else {
    Write-INFO "OpenSSH sshd not detected"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. Config File Finder (All Services)
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Config File Discovery"

$configPatterns = @("*.conf", "*.config", "*.ini", "*.cfg", "*.env", "*.yaml", "*.yml",
                    "web.config", "appsettings*.json", "database.yml", "settings.py",
                    "wp-config.php", "config.php", ".htaccess", "httpd.conf")
$configSearchPaths = @("C:\", "D:\")

Write-INFO "Searching for config files containing credentials..."
$configReport = "$LogDir\ConfigFiles_$Stamp.csv"
$configFindings = @()

foreach ($root in $configSearchPaths) {
    if (-not (Test-Path $root)) { continue }
    foreach ($pat in $configPatterns) {
        Get-ChildItem -Path $root -Filter $pat -Recurse -ErrorAction SilentlyContinue -Force |
            Where-Object { $_.Length -lt 500KB } |
            ForEach-Object {
                $configFindings += [PSCustomObject]@{
                    Path     = $_.FullName
                    Size_KB  = [Math]::Round($_.Length/1KB, 1)
                    Modified = $_.LastWriteTime
                }
            }
    }
}

$configFindings | Export-Csv -Path $configReport -NoTypeInformation
Write-OK "$($configFindings.Count) config files found → $configReport"
Write-WARN "Review these files for hardcoded passwords and sensitive settings"

# ─────────────────────────────────────────────────────────────────────────────
# 6. Running Process → Service Correlation
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Unknown Process / Service Inventory"

$knownProcesses = @("svchost","lsass","csrss","wininit","services","smss","winlogon",
                    "explorer","dwm","taskhostw","sihost","fontdrvhost","RuntimeBroker",
                    "SearchHost","StartMenuExperienceHost","ShellExperienceHost",
                    "System","Idle","Registry","conhost","dllhost",
                    "spoolsv","msdtc","VBoxService","vmtoolsd")

$processes = Get-Process | Where-Object { $knownProcesses -notcontains $_.Name }

Write-Host ""
Write-Host "  Non-standard running processes (investigate unknowns):" -ForegroundColor DarkGray
foreach ($p in $processes | Sort-Object Name) {
    $exe = try { $p.MainModule.FileName } catch { "Access Denied" }
    $sig = if ($exe -ne "Access Denied") {
        (Get-AuthenticodeSignature $exe -ErrorAction SilentlyContinue)?.Status
    } else { "Unknown" }
    $color = if ($sig -eq "Valid") { "DarkGray" } else { "Yellow" }
    Write-Host ("  {0,-25} PID:{1,-6} {2}" -f $p.Name, $p.Id, $exe) -ForegroundColor $color
}

Write-Host ""
Write-OK "Non-Windows service audit complete"
Write-INFO "Config file list: $configReport"
Write-Host ""
