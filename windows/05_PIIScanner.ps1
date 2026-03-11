<# 
Ridge Checked: Yes
Ran on a test box: NO 
Improvements: 
Order of Operations:  
1) Identify and list all potential PII data sources
2) Define specific patterns and keywords to search for
3) Implement file scanning logic
4) Generate report and output findings to "C:\CCDC_Logs"
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - PII Scanner
.DESCRIPTION
    Scans for files containing Personally Identifiable Information:
    - SSN patterns (XXX-XX-XXXX)
    - Credit card number patterns
    - CSV files (often contain bulk PII)
    - Common PII keywords in files
    Focuses on user directories, web roots, and shared folders.
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
$Report = "$LogDir\PII_Report_$Stamp.csv"

Write-Banner "PII SCANNER" "Magenta"
Write-WARN "This scan may take several minutes depending on disk size."
Write-Host ""

# ── Scan targets ─────────────────────────────────────────────────────────────
$scanRoots = @(
    "C:\Users",
    "C:\inetpub",
    "C:\Shares",
    "C:\Data",
    "C:\Databases",
    "D:\",
    "E:\"
)

# ── Patterns ──────────────────────────────────────────────────────────────────
$ssnPattern  = '\b\d{3}[-–]\d{2}[-–]\d{4}\b'
$ccPattern   = '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
$piiKeywords = @("SSN", "social.security", "password", "creditcard", "credit.card",
                 "passport", "dateofbirth", "date.of.birth", "dob", "drivers.license",
                 "bank.account", "routing.number", "employee.id", "salary", "medical")

# ── File types to scan content ────────────────────────────────────────────────
$contentExtensions = @("*.txt", "*.csv", "*.xml", "*.json", "*.sql", "*.log",
                        "*.conf", "*.config", "*.ini", "*.htm", "*.html",
                        "*.php", "*.asp", "*.aspx", "*.js")
$csvExtensions     = @("*.csv", "*.tsv", "*.xlsx", "*.xls")

$results = [System.Collections.ArrayList]@()
$scannedFiles = 0
$hitFiles = 0

# ── Phase 1: Find all CSVs ────────────────────────────────────────────────────
Write-STEP "Phase 1: Finding CSV / Spreadsheet Files"

foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($ext in $csvExtensions) {
        $files = Get-ChildItem -Path $root -Recurse -Filter $ext -ErrorAction SilentlyContinue -Force
        foreach ($f in $files) {
            Write-WARN "CSV/Spreadsheet found: $($f.FullName)  ($([Math]::Round($f.Length/1KB,1)) KB)"
            $null = $results.Add([PSCustomObject]@{
                File     = $f.FullName
                Type     = "CSV/Spreadsheet"
                Pattern  = "File type"
                Size_KB  = [Math]::Round($f.Length/1KB,1)
                Modified = $f.LastWriteTime
            })
            $hitFiles++
        }
    }
}

# ── Phase 2: Scan content for SSN / CC / Keywords ────────────────────────────
Write-STEP "Phase 2: Scanning File Contents for SSN, Credit Card, PII Keywords"
Write-INFO "Scanning text files — progress shown every 100 files..."

foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }

    foreach ($ext in $contentExtensions) {
        $files = Get-ChildItem -Path $root -Recurse -Filter $ext -ErrorAction SilentlyContinue -Force |
                 Where-Object { $_.Length -lt 10MB }  # Skip huge files

        foreach ($f in $files) {
            $scannedFiles++
            if ($scannedFiles % 100 -eq 0) {
                Write-Host "  Scanned $scannedFiles files, $hitFiles hits so far..." -ForegroundColor DarkGray
            }

            try {
                $content = Get-Content -Path $f.FullName -Raw -ErrorAction Stop -Encoding UTF8

                # SSN check
                if ($content -match $ssnPattern) {
                    Write-CRIT "SSN PATTERN found: $($f.FullName)"
                    $null = $results.Add([PSCustomObject]@{
                        File = $f.FullName; Type = "SSN Pattern"; Pattern = "SSN regex match"
                        Size_KB = [Math]::Round($f.Length/1KB,1); Modified = $f.LastWriteTime
                    })
                    $hitFiles++
                }

                # Credit card check
                if ($content -match $ccPattern) {
                    Write-CRIT "CREDIT CARD PATTERN found: $($f.FullName)"
                    $null = $results.Add([PSCustomObject]@{
                        File = $f.FullName; Type = "Credit Card Pattern"; Pattern = "CC regex match"
                        Size_KB = [Math]::Round($f.Length/1KB,1); Modified = $f.LastWriteTime
                    })
                    $hitFiles++
                }

                # Keyword checks
                foreach ($kw in $piiKeywords) {
                    if ($content -imatch $kw) {
                        Write-WARN "PII keyword '$kw' in: $($f.FullName)"
                        $null = $results.Add([PSCustomObject]@{
                            File = $f.FullName; Type = "PII Keyword"; Pattern = $kw
                            Size_KB = [Math]::Round($f.Length/1KB,1); Modified = $f.LastWriteTime
                        })
                        $hitFiles++
                        break  # Only report once per file for keywords
                    }
                }
            } catch {} # Skip unreadable files silently
        }
    }
}

# ── Phase 3: Database files ───────────────────────────────────────────────────
Write-STEP "Phase 3: Database File Hunt"

$dbExtensions = @("*.mdf", "*.ldf", "*.mdb", "*.sqlite", "*.db", "*.sqlite3", "*.accdb")
foreach ($root in $scanRoots) {
    if (-not (Test-Path $root)) { continue }
    foreach ($ext in $dbExtensions) {
        $files = Get-ChildItem -Path $root -Recurse -Filter $ext -ErrorAction SilentlyContinue -Force
        foreach ($f in $files) {
            Write-WARN "Database file: $($f.FullName) ($([Math]::Round($f.Length/1MB,1)) MB)"
            $null = $results.Add([PSCustomObject]@{
                File = $f.FullName; Type = "Database File"; Pattern = "DB extension"
                Size_KB = [Math]::Round($f.Length/1KB,1); Modified = $f.LastWriteTime
            })
        }
    }
}

# ── Phase 4: Credentials in config files ─────────────────────────────────────
Write-STEP "Phase 4: Credential / Password Leak Check in Config Files"

$credPatterns = @(
    @{ Name = "Plaintext password"; Pattern = 'password\s*[=:]\s*\S+' },
    @{ Name = "Connection string";  Pattern = 'Password=.{1,50};' },
    @{ Name = "AWS key";            Pattern = 'AKIA[0-9A-Z]{16}' },
    @{ Name = "API key";            Pattern = 'api[_-]?key\s*[=:]\s*\S{8,}' }
)

$configFiles = Get-ChildItem -Path "C:\" -Recurse -Include "*.config","*.conf","*.ini","*.env","web.config","appsettings*.json" `
               -ErrorAction SilentlyContinue -Force | Where-Object { $_.Length -lt 1MB }

foreach ($f in $configFiles) {
    try {
        $content = Get-Content $f.FullName -Raw -ErrorAction Stop
        foreach ($cp in $credPatterns) {
            if ($content -imatch $cp.Pattern) {
                Write-CRIT "$($cp.Name) found in: $($f.FullName)"
                $null = $results.Add([PSCustomObject]@{
                    File = $f.FullName; Type = "Credential Leak"; Pattern = $cp.Name
                    Size_KB = [Math]::Round($f.Length/1KB,1); Modified = $f.LastWriteTime
                })
            }
        }
    } catch {}
}

# ── Save Report ───────────────────────────────────────────────────────────────
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $Report -NoTypeInformation
    Write-Host ""
    Write-CRIT "$hitFiles PII-related files found! Report: $Report"
    Write-Host ""
    Write-Host "  NEXT STEPS for PII files:" -ForegroundColor Yellow
    Write-Host "  1. Restrict permissions: icacls <path> /inheritance:r /grant Administrators:F" -ForegroundColor White
    Write-Host "  2. Enable auditing on folders containing PII" -ForegroundColor White
    Write-Host "  3. Check who has accessed them: Event ID 4663 in Security log" -ForegroundColor White
    Write-Host "  4. Report to your team captain immediately" -ForegroundColor White
} else {
    Write-OK "No obvious PII patterns found in scanned locations"
}

Write-Host ""
Write-INFO "Total files scanned: $scannedFiles"
Write-OK "PII scan complete"
Write-Host ""
