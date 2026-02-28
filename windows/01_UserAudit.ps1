<# 
Ridge Checked: Yes
Ran on a test box: NO 
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - User & Admin Audit
.DESCRIPTION
    1. Snapshot all local users to a baseline file
    2. List domain users if on a DC
    3. Show who is in Administrators - prompt to remove unknowns
    4. Show last logon times
    5. Show logged-in sessions right now
    6. SSH authorized keys hunt
#>

# -- Colour helpers ----------------------------------------------------------
function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta    }

$LogDir = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Stamp  = Get-Date -Format "yyyyMMdd_HHmm"

Write-Banner "USER & ADMIN AUDIT" "Cyan"

# -- 1. Local Users Snapshot -------------------------------------------------
Write-STEP "Local User Snapshot"

$localUsers   = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordExpires, PasswordLastSet, Description
$snapshotPath = "$LogDir\UserSnapshot_$Stamp.csv"
$localUsers | Export-Csv -Path $snapshotPath -NoTypeInformation

Write-INFO "User snapshot saved -> $snapshotPath"
Write-Host ""
Write-Host "  Name                 Enabled   LastLogon" -ForegroundColor DarkGray
Write-Host "  -------------------  --------  --------------------" -ForegroundColor DarkGray

foreach ($u in $localUsers) {
    $enabledColor = if ($u.Enabled) { "White" } else { "DarkGray" }
    $nameStr      = $u.Name.PadRight(21)
    $enabStr      = ($u.Enabled.ToString()).PadRight(9)
    $lastStr      = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
    Write-Host "  $nameStr $enabStr $lastStr" -ForegroundColor $enabledColor
}

# -- 2. Administrators Group --------------------------------------------------
Write-STEP "Local Administrators Group"

$admins        = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$expectedAdmins = @("Administrator") # <-- ADD your expected admins here

Write-Host ""
Write-Host "  Current members of local Administrators:" -ForegroundColor DarkGray

$suspiciousAdmins = @()

foreach ($a in $admins) {
    $shortName = $a.Name -replace ".*\\"
    if ($expectedAdmins -contains $shortName -or $shortName -eq "Administrator") {
        Write-OK "$($a.Name)  [$($a.ObjectClass)]"
    } else {
        Write-CRIT "$($a.Name)  [$($a.ObjectClass)] - NOT EXPECTED"
        $suspiciousAdmins += $a
    }
}

if ($suspiciousAdmins.Count -gt 0) {
    Write-Host ""
    Write-Host "  [$($suspiciousAdmins.Count) unexpected admin(s) found]" -ForegroundColor Red

    foreach ($sa in $suspiciousAdmins) {
        $shortName = $sa.Name -replace ".*\\"
        $confirm   = Read-Host "  Remove '$($sa.Name)' from Administrators? (y/N)"

        if ($confirm -eq 'y') {
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $shortName -ErrorAction Stop
                Write-OK "Removed $($sa.Name) from Administrators"
            } catch {
                $result = Start-Process -FilePath "net" `
                    -ArgumentList "localgroup administrators `"$($sa.Name)`" /delete" `
                    -Wait -PassThru -NoNewWindow `
                    -RedirectStandardError "$LogDir\net_err_$Stamp.tmp"
                if ($result.ExitCode -eq 0) {
                    Write-OK "Removed $($sa.Name) via net command"
                } else {
                    Write-WARN "Could not remove $($sa.Name) - may be a domain account, handle manually"
                }
            }
        } else {
            Write-WARN "Skipped $($sa.Name) - remember to review manually"
        }
    }
} else {
    Write-OK "All Administrators look expected"
}

# -- 3. Active Directory Check (if DC) ---------------------------------------
Write-STEP "Active Directory Check"

$domainRole = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
$isDC       = $domainRole -ge 4

if ($isDC) {
    Write-INFO "This machine is a Domain Controller (DomainRole=$domainRole)"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        Write-Host ""
        Write-Host "  Domain Admins:" -ForegroundColor DarkGray
        $domainAdmins = Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop

        foreach ($da in $domainAdmins) {
            $user  = Get-ADUser $da.SamAccountName -Properties LastLogonDate, Enabled -ErrorAction SilentlyContinue
            $color = if ($user.Enabled) { "Yellow" } else { "DarkGray" }
            Write-Host "  $($da.SamAccountName.PadRight(25)) Enabled=$($user.Enabled)  LastLogon=$($user.LastLogonDate)" -ForegroundColor $color
        }

        $adUsersPath = "$LogDir\ADUsers_$Stamp.csv"
        Get-ADUser -Filter * -Properties LastLogonDate, Enabled, PasswordNeverExpires, PasswordLastSet |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordNeverExpires, PasswordLastSet |
            Export-Csv -Path $adUsersPath -NoTypeInformation
        Write-INFO "Full AD user list -> $adUsersPath"

        Write-Host ""
        Write-Host "  Accounts with PasswordNeverExpires = True:" -ForegroundColor DarkGray
        $noExpiry = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires
        if ($noExpiry) {
            foreach ($u in $noExpiry) { Write-WARN "$($u.SamAccountName)" }
        } else {
            Write-OK "None found"
        }

        Write-Host ""
        Write-Host "  Accounts inactive for 30+ days:" -ForegroundColor DarkGray
        $cutoff  = (Get-Date).AddDays(-30)
        $inactive = Get-ADUser -Filter { LastLogonDate -lt $cutoff -and Enabled -eq $true } -Properties LastLogonDate
        if ($inactive) {
            foreach ($u in $inactive) { Write-WARN "$($u.SamAccountName)  (LastLogon: $($u.LastLogonDate))" }
        } else {
            Write-OK "None found"
        }

    } catch {
        Write-WARN "ActiveDirectory module not available or failed: $_"
    }
} else {
    Write-INFO "Not a Domain Controller (DomainRole=$domainRole) - skipping AD checks"
}

# -- 4. Currently Logged-In Sessions -----------------------------------------
Write-STEP "Active Sessions Right Now"

$sessionOutput = & query session 2>&1
if ($sessionOutput) {
    Write-Host ($sessionOutput | Out-String) -ForegroundColor White
} else {
    Write-WARN "Could not query sessions - try running 'query session' manually"
}

# -- 5. SSH Authorized Keys Hunt ---------------------------------------------
Write-STEP "SSH Authorized Keys Hunt"

$keyPaths = @(
    "C:\ProgramData\ssh\administrators_authorized_keys",
    "C:\Users\*\.ssh\authorized_keys",
    "C:\Users\*\.ssh\known_hosts"
)

$sshFilesFound = 0

foreach ($pattern in $keyPaths) {
    $resolved = Get-Item -Path $pattern -ErrorAction SilentlyContinue
    foreach ($f in $resolved) {
        $sshFilesFound++
        Write-WARN "Found SSH key file: $($f.FullName)"
        Write-Host "    Contents:" -ForegroundColor DarkGray
        Get-Content $f.FullName -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "    $_" -ForegroundColor DarkYellow
        }
        Write-Host ""
    }
}

if ($sshFilesFound -eq 0) {
    Write-OK "No SSH key files found in standard locations"
} else {
    Write-WARN "$sshFilesFound SSH key file(s) found - review contents above and remove unknown keys!"
}

# -- Done --------------------------------------------------------------------
Write-Host ""
Write-OK "User audit complete. Logs saved to $LogDir"
Write-Host ""
