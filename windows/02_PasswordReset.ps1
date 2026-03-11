<# 
Ridge Checked: Yes
Ran on a test box: NO  
Needs modification?: YES  
- remove admin accounts maybe.... 
- lookinto password local policy settings (min length, complexity, history, etc) and set those too 
#>

#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Password Reset Script
.DESCRIPTION
    - Change local Administrator password
    - Optionally rotate all enabled local user passwords
    - Optionally change AD user passwords
    - Enforce password policy
    - Disable Guest and unnecessary accounts
    
    USAGE: Run interactively — it will prompt for the new password.
#>

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

Write-Banner "PASSWORD RESET" "Yellow"

Write-Host "  This script will change account passwords." -ForegroundColor White
Write-Host "  Make sure your TEAM knows the new password BEFORE you change it!" -ForegroundColor Yellow
Write-Host ""

# ── Get New Password ─────────────────────────────────────────────────────────
do {
    $pass1 = Read-Host "  Enter NEW password (min 14 chars, upper+lower+number+symbol)" -AsSecureString
    $pass2 = Read-Host "  Confirm new password" -AsSecureString

    $p1Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1))
    $p2Plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2))

    if ($p1Plain -ne $p2Plain) {
        Write-CRIT "Passwords do not match. Try again."
    } elseif ($p1Plain.Length -lt 14) {
        Write-CRIT "Password too short (minimum 14 characters)."
    } elseif ($p1Plain -notmatch '[A-Z]' -or $p1Plain -notmatch '[a-z]' -or
              $p1Plain -notmatch '[0-9]' -or $p1Plain -notmatch '[^a-zA-Z0-9]') {
        Write-CRIT "Password must contain uppercase, lowercase, number, and symbol."
    } else {
        break
    }
} while ($true)

Write-OK "Password accepted."
Write-Host ""

# ── Local Password Policy ────────────────────────────────────────────────────
Write-STEP "Setting Local Password Policy"

net accounts /minpwlen:14        2>$null | Out-Null # Set minimum password length to 14 characters
net accounts /maxpwage:90        2>$null | Out-Null # Set maximum password age to 90 days
net accounts /minpwage:1         2>$null | Out-Null # Set minimum password age to 1 day (prevents immediate reuse)
net accounts /uniquepw:10        2>$null | Out-Null # Remember last 10 passwords to prevent reuse

Write-OK "Password policy: min 14 chars, max age 90 days, min age 1 day, remember last 10 passwords"

# ── Administrator Account ────────────────────────────────────────────────────
Write-STEP "Resetting Local Administrator Password"

try {
    Set-LocalUser -Name "Administrator" -Password $pass1 -ErrorAction Stop
    Write-OK "Local Administrator password changed"
} catch {
    # Fallback to net user
    $result = net user Administrator $p1Plain 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-OK "Local Administrator password changed (via net user)"
    } else {
        Write-CRIT "Failed to change Administrator password: $result"
    }
}

# Enable Administrator account if it was disabled
Enable-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
Write-OK "Ensured Administrator account is enabled"

# ── Guest Account ────────────────────────────────────────────────────────────
Write-STEP "Disabling Guest Account"

try {
    Disable-LocalUser -Name "Guest" -ErrorAction Stop
    Write-OK "Guest account disabled"
} catch {
    net user Guest /active:no 2>$null | Out-Null
    Write-OK "Guest account disabled (via net user)"
}

# ── Other Local Users ────────────────────────────────────────────────────────
Write-STEP "Other Local User Accounts"

$skipAccounts = @("Administrator", "Guest", "DefaultAccount", "WDAGUtilityAccount",
                  "krbtgt", "SUPPORT_388945a0")

$otherUsers = Get-LocalUser | Where-Object {
    $_.Enabled -eq $true -and $_.Name -notin $skipAccounts
}

if ($otherUsers) {
    Write-Host ""
    Write-Host "  Enabled accounts found (besides Administrator):" -ForegroundColor White
    foreach ($u in $otherUsers) {
        Write-WARN "$($u.Name)  (LastLogon: $($u.LastLogon))"
    }
    Write-Host ""
    $resetAll = Read-Host "  Reset ALL of these accounts to the same password? (y/N)"
    if ($resetAll -eq 'y') {
        foreach ($u in $otherUsers) {
            try {
                Set-LocalUser -Name $u.Name -Password $pass1 -ErrorAction Stop
                Write-OK "Password changed: $($u.Name)"
            } catch {
                $r = net user $u.Name $p1Plain 2>&1
                if ($LASTEXITCODE -eq 0) { Write-OK "Password changed: $($u.Name)" }
                else { Write-CRIT "Failed for $($u.Name): $r" }
            }
        }
    } else {
        Write-INFO "Skipped. Change these manually if needed."
    }
} else {
    Write-OK "No other enabled local accounts found"
}

# ── Active Directory ─────────────────────────────────────────────────────────
Write-STEP "Active Directory Accounts"

$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
if ($isDC) {
    Write-INFO "Domain Controller detected"
    try {
        Import-Module ActiveDirectory -ErrorAction Stop

        # Reset krbtgt (important! Invalidates all Kerberos tickets)
        $resetKrb = Read-Host "  Reset krbtgt password? (Invalidates ALL Kerberos tickets - coordinate with team!) (y/N)"
        if ($resetKrb -eq 'y') {
            try {
                Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $pass1 -ErrorAction Stop
                Write-OK "krbtgt password reset — ALL existing Kerberos tickets are now invalid"
                Write-WARN "Users will need to re-authenticate. Services may hiccup briefly."
                # Reset TWICE to clear both old hashes
                Start-Sleep -Seconds 2
                Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword $pass1 -ErrorAction Stop
                Write-OK "krbtgt reset twice (best practice)"
            } catch {
                Write-CRIT "Failed to reset krbtgt: $_"
            }
        }

        # List and optionally reset Domain Admins
        $domainAdmins = Get-ADGroupMember "Domain Admins" -Recursive -ErrorAction Stop
        Write-Host ""
        Write-Host "  Domain Admin accounts:" -ForegroundColor White
        foreach ($da in $domainAdmins) {
            Write-WARN $da.SamAccountName
        }
        Write-Host ""
        $resetDA = Read-Host "  Reset all Domain Admin passwords? (y/N)"
        if ($resetDA -eq 'y') {
            foreach ($da in $domainAdmins) {
                try {
                    Set-ADAccountPassword -Identity $da.SamAccountName -Reset -NewPassword $pass1 -ErrorAction Stop
                    Set-ADUser -Identity $da.SamAccountName -ChangePasswordAtLogon $false -ErrorAction SilentlyContinue
                    Write-OK "Reset: $($da.SamAccountName)"
                } catch {
                    Write-CRIT "Failed: $($da.SamAccountName) — $_"
                }
            }
        }

    } catch {
        Write-WARN "AD module not available: $_"
    }
} else {
    Write-INFO "Not a DC — skipping AD password resets"
}

# ── Wipe plaintext password from memory ─────────────────────────────────────
$p1Plain = $null
$p2Plain = $null
[GC]::Collect()

Write-Host ""
Write-OK "Password reset complete!"
Write-WARN "Make sure your team has the new password!"
Write-Host ""
