#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Hidden File & Webshell Hunt
.DESCRIPTION
    - Find hidden files and folders
    - Detect webshells in IIS directories
    - Find recently modified files (red team drop indicators)
    - Filename pattern matching for suspicious names
    - NTFS ADS (Alternate Data Streams) detection
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
$Report = "$LogDir\HiddenFiles_$Stamp.csv"

Write-Banner "HIDDEN FILE & WEBSHELL HUNT" "Red"

$findings = [System.Collections.ArrayList]@()

# -- 1. Webshell Detection ----------------------------------------------------
Write-STEP "Webshell Detection (IIS / Web Directories)"

$webRoots = @("C:\inetpub", "C:\wwwroot", "C:\WebApps")
$webshellExtensions = @("*.asp", "*.aspx", "*.php", "*.php3", "*.php5",
                         "*.phtml", "*.shtml", "*.ashx", "*.asmx")

$shellPatterns = @(
    @{ Name = "cmd execution (eval)";   Pattern = 'eval\s*\(' },
    @{ Name = "exec() call";            Pattern = '(exec|shell_exec|passthru|system)\s*\(' },
    @{ Name = "cmd.exe spawn";          Pattern = 'cmd\.exe' },
    @{ Name = "powershell spawn";       Pattern = 'powershell|pwsh' },
    @{ Name = "base64 decode + exec";   Pattern = '(FromBase64String|base64_decode).{0,100}(invoke|eval|exec)' },
    @{ Name = "WScript.Shell";          Pattern = 'WScript\.Shell' },
    @{ Name = "ServerXMLHTTP (C2)";     Pattern = 'ServerXMLHTTP|MSXML2\.XMLHTTP' },
    @{ Name = "Upload handler";         Pattern = 'Request\.Files|move_uploaded_file|BinaryWrite' },
    @{ Name = "Byte array execution";   Pattern = '\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}' },
    @{ Name = "China Chopper pattern";  Pattern = 'z_execute|z_stream_copy|z_inflate' }
)

foreach ($root in $webRoots) {
    if (-not (Test-Path $root)) { continue }
    Write-INFO "Scanning: $root"

    foreach ($ext in $webshellExtensions) {
        $files = Get-ChildItem -Path $root -Recurse -Filter $ext -Force -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            try {
                $content = Get-Content $f.FullName -Raw -ErrorAction Stop
                $hits = @()
                foreach ($pat in $shellPatterns) {
                    if ($content -imatch $pat.Pattern) { $hits += $pat.Name }
                }
                if ($hits.Count -ge 2) {
                    Write-CRIT "LIKELY WEBSHELL: $($f.FullName)"
                    Write-Host "    Patterns: $($hits -join ', ')" -ForegroundColor Red
                    $null = $findings.Add([PSCustomObject]@{
                        File = $f.FullName; Type = "Likely Webshell"
                        Patterns = $hits -join "; "; Modified = $f.LastWriteTime
                    })
                } elseif ($hits.Count -eq 1) {
                    Write-WARN "Suspicious ($($hits[0])): $($f.FullName)"
                    $null = $findings.Add([PSCustomObject]@{
                        File = $f.FullName; Type = "Suspicious Web File"
                        Patterns = $hits -join "; "; Modified = $f.LastWriteTime
                    })
                }
            } catch {}
        }
    }
}

# -- 2. Recently Modified Web Files -------------------------------------------
Write-STEP "Recently Modified Web Files (last 48 hours)"

$cutoff = (Get-Date).AddHours(-48)
foreach ($root in $webRoots) {
    if (-not (Test-Path $root)) { continue }
    $recent = Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue |
              Where-Object { $_.LastWriteTime -gt $cutoff -and -not $_.PSIsContainer }
    foreach ($f in $recent) {
        Write-WARN "Recently modified: $($f.FullName)  ($($f.LastWriteTime))"
        $null = $findings.Add([PSCustomObject]@{
            File = $f.FullName; Type = "Recently Modified"
            Patterns = "Modified < 48h ago"; Modified = $f.LastWriteTime
        })
    }
}

# -- 3. Hidden Files in Key Locations -----------------------------------------
Write-STEP "Hidden Files in Key System Locations"

$hiddenSearchPaths = @(
    "C:\Users",
    "C:\ProgramData",
    "C:\Windows\Temp",
    "$env:TEMP"
)

$suspiciousHiddenNames = @(
    "*.exe", "*.dll", "*.bat", "*.ps1", "*.vbs", "*.js", "*.hta",
    "svchost*", "svch0st*", "lsass*", "csrss*", "winlogon*"
)

foreach ($path in $hiddenSearchPaths) {
    if (-not (Test-Path $path)) { continue }
    $hidden = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
              Where-Object { $_.Attributes -band [IO.FileAttributes]::Hidden }
    foreach ($f in $hidden) {
        $isSuspicious = $false
        foreach ($pat in $suspiciousHiddenNames) {
            if ($f.Name -like $pat) { $isSuspicious = $true; break }
        }
        if ($isSuspicious) {
            Write-CRIT "Hidden suspicious file: $($f.FullName)"
            $null = $findings.Add([PSCustomObject]@{
                File = $f.FullName; Type = "Hidden Suspicious File"
                Patterns = "Hidden attribute + suspicious extension/name"; Modified = $f.LastWriteTime
            })
        }
    }
}

# -- 4. Suspicious Filenames (Masquerading) -----------------------------------
Write-STEP "Process Masquerading / Suspicious Executables"

$writableLocations = @(
    "C:\Users\*\AppData\Local\Temp",
    "C:\Users\*\AppData\Roaming",
    "C:\Windows\Temp",
    "C:\ProgramData",
    "C:\Users\Public"
)

$exeExtensions = @("*.exe", "*.dll", "*.bat", "*.ps1", "*.vbs", "*.hta", "*.msi", "*.jar")

foreach ($pattern in $writableLocations) {
    foreach ($ext in $exeExtensions) {
        $files = Get-ChildItem -Path $pattern -Filter $ext -Recurse -Force -ErrorAction SilentlyContinue
        foreach ($f in $files) {
            $sig = Get-AuthenticodeSignature -FilePath $f.FullName -ErrorAction SilentlyContinue
            $sigStatus = if ($sig) { $sig.Status } else { "Unknown" }
            $color = if ($sigStatus -eq "Valid") { "DarkGray" } else { "Yellow" }
            $flag  = if ($sigStatus -ne "Valid") { " << UNSIGNED - investigate" } else { "" }

            Write-Host "  $($f.FullName)  [Sig: $sigStatus]$flag" -ForegroundColor $color

            if ($sigStatus -ne "Valid") {
                $null = $findings.Add([PSCustomObject]@{
                    File = $f.FullName; Type = "Unsigned Executable in Writable Location"
                    Patterns = "Sig: $sigStatus"; Modified = $f.LastWriteTime
                })
            }
        }
    }
}

# -- 5. NTFS Alternate Data Streams -------------------------------------------
Write-STEP "NTFS Alternate Data Streams (ADS) Detection"
Write-INFO "ADS can be used to hide malicious content in normal-looking files"

$adsPaths = @("C:\Users", "C:\inetpub", "C:\ProgramData")
foreach ($path in $adsPaths) {
    if (-not (Test-Path $path)) { continue }
    try {
        $adsFiles = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                    Get-Item -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne '' }
        foreach ($ads in $adsFiles) {
            Write-CRIT "ADS detected: $($ads.FileName) -> Stream: $($ads.Stream) ($($ads.Length) bytes)"
            $null = $findings.Add([PSCustomObject]@{
                File = $ads.FileName; Type = "NTFS Alternate Data Stream"
                Patterns = "Stream: $($ads.Stream)"; Modified = "N/A"
            })
        }
    } catch {}
}
if ($findings | Where-Object { $_.Type -eq "NTFS Alternate Data Stream" }) {
} else {
    Write-OK "No ADS found in scanned locations"
}

# -- Save Report --------------------------------------------------------------
if ($findings.Count -gt 0) {
    $findings | Export-Csv -Path $Report -NoTypeInformation
    Write-Host ""
    Write-CRIT "$($findings.Count) suspicious items found! Report: $Report"
    Write-Host ""
    Write-Host "  For each CRIT finding - check file contents, quarantine if needed:" -ForegroundColor Yellow
    Write-Host "  Quarantine:  Move-Item [file] C:\CCDC_Quarantine\" -ForegroundColor White
    Write-Host "  Delete:      Remove-Item [file] -Force" -ForegroundColor White
    Write-Host "  Contents:    Get-Content [file] | Select-Object -First 30" -ForegroundColor White
} else {
    Write-OK "No obvious malicious files found"
}

Write-Host ""
Write-OK "Hidden file hunt complete"
Write-Host ""
