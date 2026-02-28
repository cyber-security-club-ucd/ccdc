Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Host Start
Pause

# Check for and enter Administrator terminal
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
& {
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        Write-Host "Oppenheimer mode engage"
    }
    else {
        $Location2 = $PSCommandPath
        start-process powershell.exe $Location2 -verb runAs
        exit
    }
}

# Fix the SSL issue
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Stuff for general Windows hardening
function hardening {
    Write-Host "Doing General Hardening..."

    try {
        Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    }
    catch {
        Write-Error "Can't turn on Firewall"
    }

    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    }
    catch {
        Write-Error "Failed to disable SMB1"
    }

    $groups = @("Domain Admins", "Enterprise Admins", "Administrators", "DnsAdmins", "Group Policy Creator Owners", "Schema Admins", "Key Admins", "Enterprise Key Admins")

    foreach ($group in $groups) {
        $excludedSamAccountNames = @("Administrator", "Domain Admins", "Enterprise Admins")

        $members = Get-ADGroupMember -Identity $group | Where-Object {
            $excludedSamAccountNames -notcontains $_.SamAccountName
        }

        foreach ($member in $members) {
            try {
                Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
                Write-Host "Removed $($member.SamAccountName) from $group." -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to remove group member $($member.SamAccountName) from $group."
            }
        }
    }


    try {
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | Set-ADAccountControl -DoesNotRequirePreAuth $false
        Write-Host "Kerberos Pre-authentication enabled for applicable users." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to enable Kerberos Pre-authentication: $_" -ForegroundColor Red
    }

    try {
        $guestAccount = Get-ADUser -Identity "Guest" -ErrorAction Stop
        Disable-ADAccount -Identity $guestAccount.SamAccountName
        Write-Host "Guest account has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to disable Guest account."
    }

    try {
        Stop-Service -Name "Spooler" -ErrorAction Stop
        Set-Service -Name "Spooler" -StartupType Disabled
        Write-Host "Print Spooler service has been disabled." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to disable Print Spooler service: $_" -ForegroundColor Red
    }

    try {
        reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f | Out-Null
        Write-Host "FullSecureChannelProtection enabled." -ForegroundColor Green

        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
        $regName = "vulnerablechannelallowlist"
        if (Test-Path -Path "$regPath\$regName") {
            Remove-ItemProperty -Path $regPath -Name $regName -Force | Out-Null
            Write-Host "vulnerablechannelallowlist removed." -ForegroundColor Green
        } else {
            Write-Host "vulnerablechannelallowlist does not exist, no action needed." -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to apply Zerologon mitigation: $_" -ForegroundColor Red
    }

    try {
        Set-ADDomain -Identity $env:USERDNSDOMAIN -Replace @{"ms-DS-MachineAccountQuota" = "0" } | Out-Null
        Write-Host "ms-DS-MachineAccountQuota set to 0." -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to apply noPac mitigation: $_" -ForegroundColor Red
    }

    # Start compmgmt
    Start-Process compmgmt.msc
}

# Download, setup, and run needed security tools
function downloadTools {
    Write-Host "Downloading and running scanning tools..."
    # Turn off progress bar to speed up downloads
    $ProgressPreference = 'SilentlyContinue'

    #   curl nmap
    Invoke-WebRequest https://nmap.org/dist/nmap-7.98-setup.exe -OutFile "nmap-setup.exe"
    ./nmap-setup.exe

    #   curl everything and install silently
    Invoke-WebRequest https://ninite.com/everything/ -OutFile "everything-setup.exe"
    ./everything-setup.exe /S

    #   curl malwarebytes
    Invoke-WebRequest https://downloads.malwarebytes.com/file/mb-windows -OutFile "mbsetup.exe"
    ./mbsetup.exe

    #   curl ad-peas light
    Invoke-WebRequest https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1 -OutFile "adPEAS-Light.ps1"
    Start-Process powershell {
        . ./adPEAS-light.ps1
        Invoke-adPEAS -NoColor -OutputFile ".\adPEAS_output.txt"
    }

    #   curl sysinternals
    Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile "SysinternalsSuite.zip"
    Expand-Archive -Path SysinternalsSuite.zip -DestinationPath .\Sysinternals\ -Force

    #   setup sysmon
    Set-Location .\Sysinternals
    Invoke-WebRequest https://raw.githubusercontent.com/cyber-security-club-ucd/ccdc/refs/heads/main/windows/sysmonconfig.xml -OutFile config.xml
    .\sysmon.exe -accepteula -i config.xml

    #   curl pingcastle (USE AN OLDER VERSION ON SERVER 2016!!)
    Invoke-WebRequest https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip -OutFile "PingCastle_3.3.0.1.zip"
    Expand-Archive -Path PingCastle_3.3.0.1.zip -DestinationPath .\PingCastle\ -Force
    Start-Process powershell {
        .\PingCastle\PingCastle.exe --healthcheck
    }

}



function dns_backup {
    Write-Host "Backing up DNS..."
    # There is no reinventing the wheel with this one
    $secureBackupPath = "C:\Users\Administrator\Desktop\dns"

    if (!(Test-Path -Path $secureBackupPath)) {
        New-Item -Path $secureBackupPath -ItemType Directory -Force
    }

    # Get all DNS zones on the server
    $zones = Get-DnsServerZone
    
    foreach ($zone in $zones) {
        $zoneName = $zone.ZoneName
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFileName = "${zoneName}_backup_$timestamp.dns"
        $tempFilePath = "C:\Windows\System32\dns\$backupFileName"
        $finalFilePath = Join-Path $secureBackupPath $backupFileName

        Export-DnsServerZone -Name $zoneName -FileName $backupFileName

        Move-Item -Path $tempFilePath -Destination $finalFilePath -Force

        Write-Host "Backed up zone '$zoneName' to '$finalFilePath'"
    }

    Write-Host "All DNS zones backed up successfully."
}

# Run everything function
function all {
    hardening
    downloadTools
    dns_backup
}

# Menu to pick which hardening function you want to do
function mainMenu {
    Write-Host ""
    Write-Host ""

    Write-Host "Whaddya wanna do? Here's a directory"
    Write-Host "'hardening' to run hardening commands"
    Write-Host "'download' to download security tools"
    Write-Host "'dns' to backup dns"
    Write-Host "'all' to run all the above steps (first run)"

    $Choice = Read-Host -Prompt '>>'
    switch ($Choice) {
        'hardening' { hardening }
        'download' { downloadTools }
        'dns' { dns_backup }
        'all' { all }
    }
    Write-Host "Put in a valid word"
    mainMenu
    Write-Host ""
    Write-Host ""
} 
mainMenu