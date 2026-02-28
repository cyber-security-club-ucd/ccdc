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
    3. Show who is in Administrators — prompt to remove unknowns
    4. Show last logon times
    5. Show logged-in sessions right now
#>

# ── Colour helpers (inline so script works standalone) ──────────────────────
function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

$LogDir = "C:\CCDC_Logs"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$Stamp  = Get-Date -Format "yyyyMMdd_HHmm"

Write-Banner "USER & ADMIN AUDIT" "Cyan"

# ── 1. Local Users Snapshot ─────────────────────────────────────────────────
Write-STEP "Local User Snapshot" 

$localUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordExpires, PasswordLastSet, Description
$snapshotPath = "$LogDir\UserSnapshot_$Stamp.csv"
$localUsers | Export-Csv -Path $snapshotPath -NoTypeInformation

Write-INFO "User snapshot saved → $snapshotPath" # Save the user snapshot
Write-Host ""
Write-Host "  Name                 Enabled   LastLogon" -ForegroundColor DarkGray
Write-Host "  ───────────────────  ────────  ─────────────────────" -ForegroundColor DarkGray

foreach ($u in $localUsers) {
    $enabledColor = if ($u.Enabled) { "White" } else { "DarkGray" } # Gray out disabled accounts
    $nameStr  = $u.Name.PadRight(21) 
    $enabStr  = ($u.Enabled.ToString()).PadRight(9)
    $lastStr  = if ($u.LastLogon) { $u.LastLogon.ToString("yyyy-MM-dd HH:mm") } else { "Never" } # Format last logon time
    Write-Host "  $nameStr $enabStr $lastStr" -ForegroundColor $enabledColor
}
# All Local Users have been listed and saved to a CSV file for review. Disabled accounts are shown in gray, and last logon times are included for quick assessment of account activity.

# ── 2. Administrators Group ──────────────────────────────────────────────────
Write-STEP "Local Administrators Group"

$admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
$expectedAdmins = @("Administrator") # <-- ADD your expected admins herehere 

Write-Host ""
Write-Host "  Current members of local Administrators:" -ForegroundColor DarkGray

# Check each admin against the expected list and flag any unexpected ones
$suspiciousAdmins = @() # Collect unexxpected admins for review
foreach ($a in $admins) {
    $shortName = $a.Name -replace ".*\\"
    if ($expectedAdmins -contains $shortName -or $shortName -eq "Administrator") {
        Write-OK "$($a.Name)  [$($a.ObjectClass)]"
    } else {
        Write-CRIT "$($a.Name)  [$($a.ObjectClass)] — NOT EXPECTED"
        $suspiciousAdmins += $a
    }
}
# All current admin users have been listed. Any unexpected accounts are flagged in red for review. Reference back later if new admins are added during the competition.

if ($suspiciousAdmins.Count -gt 0) { # If there are unexpected admins, prompt to remove them
    Write-Host ""
    Write-Host "  [$($suspiciousAdmins.Count) unexpected admin(s) found]" -ForegroundColor Red
    foreach ($sa in $suspiciousAdmins) { # For each unexpected admin, prompt to remove
        $shortName = $sa.Name -replace ".*\\"
        $confirm = Read-Host "  Remove '$($sa.Name)' from Administrators? (y/N)" # Prompt to remove unexpected admins
        if ($confirm -eq 'y') { # If confirmed, attempt to remove the user from the Administrators group
            try {
                Remove-LocalGroupMember -Group "Administrators" -Member $shortName -ErrorAction Stop
                Write-OK "Removed $($sa.Name) from Administrators"
            } catch { # If short name fails, it may be a domain account or have a different format. Try with the full name.
                try {         # Try with full name if short fails
                    net localgroup administrators $sa.Name /delete 2>$null # find the full name and try to remove with net command as a fallback
                    Write-OK "Removed $($sa.Name) via net command" # If successful, confirm removal
                } catch {
                    Write-WARN "Could not remove $($sa.Name) — may be a domain account, handle manually"
                }
            }
        } else {
            Write-WARN "Skipped $($sa.Name) — remember to review manually"
        }
    }
} else {
    Write-OK "All Administrators look expected"
} 
 
# At this point, all unexpected admin accounts have been flagged and you have been prompted to remove them. If you chose not to remove any, make sure to review them as needed.

# ── 3. Active Directory Users (if DC) ───────────────────────────────────────
Write-STEP "Active Directory Check"


# Checks if the current machine is a Domain Controller and if not will skip the AD user checks. 
$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
if ($isDC) {
    Write-INFO "This machine is a Domain Controller"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        Write-Host ""
        Write-Host "  Domain Admins:" -ForegroundColor DarkGray
        $domainAdmins = Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop 
        
        # For each domain admin, get their last logon time and status.
        foreach ($da in $domainAdmins) {
            $user = Get-ADUser $da.SamAccountName -Properties LastLogonDate,Enabled -ErrorAction SilentlyContinue
            $color = if ($user.Enabled) { "Yellow" } else { "DarkGray" }
            Write-Host "  $($da.SamAccountName.PadRight(25)) Enabled=$($user.Enabled)  LastLogon=$($user.LastLogonDate)" -ForegroundColor $color
        }

        # Export full AD user list
        $adUsersPath = "$LogDir\ADUsers_$Stamp.csv"
        Get-ADUser -Filter * -Properties LastLogonDate, Enabled, PasswordNeverExpires, PasswordLastSet |
            Select-Object SamAccountName, Enabled, LastLogonDate, PasswordNeverExpires, PasswordLastSet |
            Export-Csv -Path $adUsersPath -NoTypeInformation
        Write-INFO "Full AD user list → $adUsersPath"

        # Flag accounts with password never expires
        Write-Host ""
        Write-Host "  Accounts with PasswordNeverExpires = True:" -ForegroundColor DarkGray
        $noExpiry = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties PasswordNeverExpires
        if ($noExpiry) {
            foreach ($u in $noExpiry) { Write-WARN "$($u.SamAccountName)" }
        } else {
            Write-OK "None found"
        }

        # Flag accounts inactive > 30 days
        Write-Host ""
        Write-Host "  Accounts inactive for 30+ days:" -ForegroundColor DarkGray
        $cutoff = (Get-Date).AddDays(-30)
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
    Write-INFO "Not a Domain Controller — skipping AD checks"
}

# ── 4. Currently Logged-In Sessions ─────────────────────────────────────────
Write-STEP "Active Sessions Right Now"

try { # Querey active sessions to see who is currently logged in.
    $sessions = query session 2>$null
    Write-Host ($sessions | Out-String) -ForegroundColor White
} catch {
    Write-WARN "Could not query sessions" 
}

# ── 5. SSH Authorized Keys Hunt ──────────────────────────────────────────────
Write-STEP "SSH Authorized Keys Hunt"

#Skim the common locations for SSH authorized keys and known hosts files. If you find any, check their contents to see if there are unexpected keys or hosts that could indicate a compromise.
$keyPaths = @(
    "C:\ProgramData\ssh\administrators_authorized_keys",
    "C:\Users\*\.ssh\authorized_keys",
    "C:\Users\*\.ssh\known_hosts"
)

foreach ($pattern in $keyPaths) {
    $found = Get-Item $pattern -ErrorAction SilentlyContinue
    foreach ($f in $found) {
        Write-WARN "Found SSH key file: $($f.FullName)"
        Write-Host "    Contents:" -ForegroundColor DarkGray
        Get-Content $f.FullName | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkYellow }
    }
}
if (-not $found) { Write-OK "No unexpected SSH key files found" }

# ── Done ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-OK "User audit complete. Logs saved to $LogDir"
Write-Host ""
