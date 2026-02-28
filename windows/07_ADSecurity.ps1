#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Active Directory Security Hardening
.DESCRIPTION
    Patches and audits:
    - AS-REP Roasting (no pre-auth accounts)
    - Kerberoasting (weak SPN accounts)
    - AdminSDHolder / ACL abuse
    - Unconstrained / constrained delegation
    - NTDS dump detection guidance
    - Domain controller security
    
    References:
    - https://b2hu.me/posts/AS-REP-Roasting-Attack/
    - https://www.hackthebox.com/blog/ntds-dumping-attack-detection
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

Write-Banner "ACTIVE DIRECTORY SECURITY" "Yellow"

# ── Check if AD module is available ──────────────────────────────────────────
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-CRIT "ActiveDirectory module not found!"
    Write-INFO "Install with: Install-WindowsFeature RSAT-AD-PowerShell"
    Write-INFO "  Or: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    exit 1
}

$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
if (-not $isDC) {
    Write-WARN "This machine is NOT a domain controller."
    Write-INFO "Some checks require running on a DC. Others will still work if AD module is available."
}

try { $domain = Get-ADDomain } catch { Write-CRIT "Cannot reach domain. Exiting."; exit 1 }
Write-INFO "Domain: $($domain.DNSRoot)   DC: $($domain.PDCEmulator)"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. AS-REP ROASTING (DoesNotRequirePreAuth)
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "AS-REP Roasting Check (DoesNotRequirePreAuth)"
Write-INFO "Background: Accounts with 'Do not require Kerberos preauthentication' enabled"
Write-INFO "let attackers request an encrypted TGT without knowing the password first."
Write-INFO "The TGT can then be cracked offline. Fix: enable preauth, use strong passwords."
Write-Host ""

$asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
              -Properties DoesNotRequirePreAuth, PasswordLastSet, LastLogonDate, Enabled |
              Where-Object { $_.Enabled -eq $true }

$asrepLog = "$LogDir\ASREP_Vulnerable_$Stamp.csv"

if ($asrepUsers) {
    Write-CRIT "$($asrepUsers.Count) account(s) vulnerable to AS-REP Roasting!"
    Write-Host ""
    $asrepUsers | Select-Object SamAccountName, Enabled, PasswordLastSet, LastLogonDate |
        Format-Table | Out-String | Write-Host -ForegroundColor Red
    $asrepUsers | Export-Csv -Path $asrepLog -NoTypeInformation
    Write-INFO "Vulnerable accounts saved → $asrepLog"
    Write-Host ""

    foreach ($u in $asrepUsers) {
        Write-Host "  Account: $($u.SamAccountName)" -ForegroundColor White
        $fix = Read-Host "  Enable Kerberos preauth for '$($u.SamAccountName)'? (y/N)"
        if ($fix -eq 'y') {
            try {
                Set-ADUser -Identity $u.SamAccountName `
                    -KerberosEncryptionType @{Add="AES128,AES256"} `
                    -Replace @{userAccountControl = ($u.userAccountControl -band -bnot 4194304)} `
                    -ErrorAction Stop
                Write-OK "$($u.SamAccountName) — preauth enabled"
            } catch {
                # Fallback method
                $uac = (Get-ADUser $u.SamAccountName -Properties userAccountControl).userAccountControl
                $uac = $uac -band (-bnot 0x400000)  # Clear DONT_REQ_PREAUTH bit
                Set-ADUser -Identity $u.SamAccountName -Replace @{userAccountControl = $uac}
                Write-OK "$($u.SamAccountName) — preauth enabled (fallback method)"
            }
        } else {
            Write-WARN "Skipped $($u.SamAccountName) — ENSURE it has a 25+ char random password if it's a service account!"
        }
    }
} else {
    Write-OK "No AS-REP Roastable accounts found!"
}

# SIEM detection note
Write-Host ""
Write-INFO "SIEM: Watch for Event ID 4768 (Kerberos TGT request) with:"
Write-INFO "  - Pre-Authentication Type = 0 (means preauth was NOT required)"
Write-INFO "  - Multiple requests from the same source IP in a short time = red team AS-REP roasting"

# ─────────────────────────────────────────────────────────────────────────────
# 2. KERBEROASTING (SPNs)
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Kerberoasting Check (Service Principal Names)"
Write-INFO "Background: Accounts with SPNs set can have their service tickets requested"
Write-INFO "by any authenticated user. The ticket is encrypted with the account's password"
Write-INFO "hash, which can then be cracked offline. Fix: use strong (25+ char) passwords."
Write-Host ""

$kerberoastable = Get-ADUser -Filter { ServicePrincipalName -like "*" } `
    -Properties ServicePrincipalName, PasswordLastSet, LastLogonDate, Enabled, Description |
    Where-Object { $_.Enabled -eq $true -and $_.SamAccountName -ne "krbtgt" }

$kerbLog = "$LogDir\Kerberoastable_$Stamp.csv"

if ($kerberoastable) {
    Write-WARN "$($kerberoastable.Count) Kerberoastable account(s) found:"
    Write-Host ""
    foreach ($u in $kerberoastable) {
        $daysSincePwChange = if ($u.PasswordLastSet) {
            [int]((Get-Date) - $u.PasswordLastSet).TotalDays
        } else { 9999 }
        
        $color = if ($daysSincePwChange -gt 90) { "Red" } elseif ($daysSincePwChange -gt 30) { "Yellow" } else { "Green" }
        $flag  = if ($daysSincePwChange -gt 90) { " ◄ OLD PASSWORD — HIGH RISK" } elseif ($daysSincePwChange -gt 30) { " ◄ Password > 30 days old" } else { "" }

        Write-Host ("  {0,-25} PWAge: {1,4}d   SPN: {2}" -f $u.SamAccountName, $daysSincePwChange, ($u.ServicePrincipalName -join ", ")) -ForegroundColor $color
        Write-Host "  $flag" -ForegroundColor $color
    }
    Write-Host ""
    $kerberoastable | Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, Description |
        Export-Csv -Path $kerbLog -NoTypeInformation
    Write-INFO "Kerberoastable accounts saved → $kerbLog"
    Write-Host ""
    Write-WARN "ACTION REQUIRED: Ensure ALL SPN accounts have 25+ character random passwords!"
    Write-WARN "If an SPN is not needed, remove it: Set-ADUser <user> -ServicePrincipalNames @{Remove='<SPN>'}"
} else {
    Write-OK "No unexpected Kerberoastable accounts (besides krbtgt)"
}

# SIEM detection note
Write-INFO "SIEM: Watch for Event ID 4769 (Kerberos service ticket request) with:"
Write-INFO "  - Ticket Encryption Type = 0x17 (RC4 — weak, crackable)"
Write-INFO "  - Many 4769 events in quick succession from same IP = Kerberoasting in progress"

# ─────────────────────────────────────────────────────────────────────────────
# 3. RC4 DOWNGRADE CHECK
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Kerberos Encryption — RC4 Check"
Write-INFO "RC4 is weaker than AES and makes Kerberoasting easier to crack offline."

$usersWithRC4 = Get-ADUser -Filter * -Properties KerberosEncryptionType |
    Where-Object { $_.KerberosEncryptionType -band 4 } # 4 = RC4

if ($usersWithRC4) {
    Write-WARN "$($usersWithRC4.Count) accounts allow RC4 Kerberos encryption:"
    foreach ($u in $usersWithRC4) { Write-Host "  $($u.SamAccountName)" -ForegroundColor Yellow }
    Write-Host ""

    $disableRC4 = Read-Host "  Update all accounts to require AES128+AES256 only? (y/N)"
    if ($disableRC4 -eq 'y') {
        foreach ($u in $usersWithRC4) {
            try {
                Set-ADUser -Identity $u.SamAccountName `
                    -KerberosEncryptionType @{Replace=@("AES128","AES256")} -ErrorAction Stop
                Write-OK "$($u.SamAccountName) — updated to AES only"
            } catch {
                Write-WARN "Could not update $($u.SamAccountName): $_"
            }
        }
    } else {
        Write-INFO "Skipped — consider updating after verifying service compatibility"
    }
} else {
    Write-OK "No accounts explicitly configured for RC4-only encryption"
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. DOMAIN ADMIN & PRIVILEGED GROUP AUDIT
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Privileged Group Audit"

$privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins",
                "Administrators", "Group Policy Creator Owners", "Account Operators",
                "Backup Operators", "Server Operators")

$privLog = "$LogDir\PrivilegedGroups_$Stamp.csv"
$privData = @()

foreach ($grp in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction Stop
        foreach ($m in $members) {
            $privData += [PSCustomObject]@{ Group = $grp; Member = $m.SamAccountName; Type = $m.objectClass }
            $color = if ($grp -in @("Domain Admins","Enterprise Admins","Schema Admins")) { "Red" } else { "Yellow" }
            Write-Host ("  {0,-30} → {1} [{2}]" -f $grp, $m.SamAccountName, $m.objectClass) -ForegroundColor $color
        }
    } catch {
        Write-INFO "  $grp — could not enumerate (may not exist)"
    }
}

$privData | Export-Csv -Path $privLog -NoTypeInformation
Write-INFO "Privileged group members → $privLog"

# ─────────────────────────────────────────────────────────────────────────────
# 5. DELEGATION ABUSE CHECK
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Delegation Check (Unconstrained / Constrained)"
Write-INFO "Unconstrained delegation lets a machine/user impersonate ANY user — high risk!"

# Unconstrained delegation
$unconstrained = Get-ADComputer -Filter { TrustedForDelegation -eq $true } -Properties TrustedForDelegation |
    Where-Object { $_.Name -notlike "*DC*" }  # DCs legitimately have this

if ($unconstrained) {
    Write-CRIT "UNCONSTRAINED DELEGATION on non-DC machines:"
    foreach ($c in $unconstrained) { Write-CRIT "  $($c.Name)" }
    Write-WARN "If not required, disable: Set-ADComputer <name> -TrustedForDelegation \$false"
} else {
    Write-OK "No unexpected unconstrained delegation found"
}

# Constrained delegation (just inventory — may be legitimate)
$constrained = Get-ADObject -Filter { msDS-AllowedToDelegateTo -like "*" } `
    -Properties msDS-AllowedToDelegateTo, distinguishedName -ErrorAction SilentlyContinue
if ($constrained) {
    Write-WARN "Constrained delegation configured on:"
    foreach ($c in $constrained) {
        Write-Host "  $($c.distinguishedName)  → $($c.'msDS-AllowedToDelegateTo' -join ', ')" -ForegroundColor Yellow
    }
    Write-INFO "Verify these delegations are expected for your services"
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. NTDS DUMP DETECTION GUIDANCE
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "NTDS / Credential Dumping Detection"
Write-INFO "Reference: https://www.hackthebox.com/blog/ntds-dumping-attack-detection"
Write-Host ""
Write-Host "  Watch for these Event IDs indicating credential dumping attempts:" -ForegroundColor White
Write-Host ""

$dumpIndicators = @(
    @{ ID = "4662"; Desc = "Operation on AD object — watch for DCSync: requestedOperation includes '1131f6aa' (replication)" },
    @{ ID = "4624"; Desc = "Type 3 (network) logon from unexpected IP to DC = possible DCSync or lateral movement" },
    @{ ID = "4648"; Desc = "Explicit credentials logon — Pass-the-Hash indicator" },
    @{ ID = "7036"; Desc = "VSS (Volume Shadow Copy) service started — vssadmin used to copy NTDS.dit" },
    @{ ID = "4697"; Desc = "New service installed — Mimikatz / impacket may install as service" },
    @{ ID = "4698"; Desc = "Scheduled task created — persistence + execution vector" }
)

foreach ($d in $dumpIndicators) {
    Write-Host ("  EventID {0}  — {1}" -f $d.ID.PadRight(6), $d.Desc) -ForegroundColor Cyan
}

Write-Host ""
Write-Host "  Check for DCSync right now (suspicious 4662 events):" -ForegroundColor White
$dcSync = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "1131f6aa|1131f6ad|89e95b76" }

if ($dcSync) {
    Write-CRIT "$($dcSync.Count) potential DCSync events found in logs!"
    $dcSync | Select-Object TimeCreated, Message | Format-List | Out-String | Write-Host -ForegroundColor Red
} else {
    Write-OK "No recent DCSync indicators in event log"
}

# ─────────────────────────────────────────────────────────────────────────────
# 7. PASSWORD NEVER EXPIRES & STALE ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────
Write-STEP "Account Policy Issues"

$pwNeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true -and Enabled -eq $true } -Properties PasswordNeverExpires
if ($pwNeverExpires) {
    Write-WARN "$($pwNeverExpires.Count) enabled accounts with PasswordNeverExpires:"
    foreach ($u in $pwNeverExpires) { Write-Host "  $($u.SamAccountName)" -ForegroundColor Yellow }
    Write-INFO "Consider: Set-ADUser <user> -PasswordNeverExpires \$false (check if service accounts need this)"
} else {
    Write-OK "No accounts with PasswordNeverExpires (good!)"
}

# Blank passwords
$blankPw = Get-ADUser -Filter { PasswordNotRequired -eq $true -and Enabled -eq $true } -Properties PasswordNotRequired
if ($blankPw) {
    Write-CRIT "$($blankPw.Count) accounts allow BLANK PASSWORDS:"
    foreach ($u in $blankPw) { Write-CRIT "  $($u.SamAccountName) — fix immediately!" }
} else {
    Write-OK "No accounts allowing blank passwords"
}

# ─────────────────────────────────────────────────────────────────────────────
# Done
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""
Write-OK "Active Directory security audit complete"
Write-INFO "Logs saved to: $LogDir"
Write-Host ""
Write-Host "  Recommended next tools to run (if you have them):" -ForegroundColor DarkGray
Write-Host "  - PingCastle:     .\PingCastle.exe --healthcheck (AUDIT ONLY)" -ForegroundColor DarkGray
Write-Host "  - adPEAS:         Import-Module adPEAS; Invoke-adPEAS (AUDIT ONLY)" -ForegroundColor DarkGray
Write-Host "  - HardeningKitty: Invoke-HardeningKitty -Mode Audit (READ ONLY)" -ForegroundColor DarkGray
Write-Host ""
