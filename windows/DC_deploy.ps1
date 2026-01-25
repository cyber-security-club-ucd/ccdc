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

# Function to rotate domain user passwords by calling the password generator API
function pwRotate {
    Set-PSReadlineOption -HistorySaveStyle SaveNothing
    Write-Host "Reset the password for Administrator so you don't get locked out"
    $p = Read-Host -AsSecureString
    Set-ADAccountPassword -identity Administrator -newpassword $p
} 

# Stuff for general Windows hardening
function hardening {
    Write-Host "Doing General Hardening..."

    # Enable firewall
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

    # Zerologon
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f

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

# Import the Security Compliance Toolkit GPOs
function GPOs {
    Write-Host "Importing GPOs..."

    # Get LGPO
    Invoke-WebRequest https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/LGPO.zip -OutFile "LGPO.zip"
    Expand-Archive -Path LGPO.zip -DestinationPath .\ -Force

    # Get the Windows version information
    $os = Get-CimInstance -ClassName Win32_OperatingSystem

    # Extract the version and build number
    $version = $os.Version
    $caption = $os.Caption

    # Check and print the server version
    if ($caption -like "*Server*") {
        switch -Wildcard ($version) {
            "10.0.14393*" { 
                Write-Host "Detected Version: Server 2016"
                Invoke-WebRequest https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip -OutFile "Baseline.zip" 
                Expand-Archive -Path Baseline.zip -DestinationPath .\ -Force
                Move-Item LGPO_30\LGPO.exe .\Windows-10-RS1-and-Server-2016-Security-Baseline\Local_Script\Tools\
                Set-Location .\Windows-10-RS1-and-Server-2016-Security-Baseline\Local_Script
                .\Domain_Controller_Install.cmd
                
            }
            "10.0.17763*" { 
                Write-Host "Detected Version: Server 2019"
                Invoke-WebRequest https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip -OutFile "Baseline.zip" 
                Expand-Archive -Path Baseline.zip -DestinationPath .\Baseline-2019\ -Force
                Move-Item LGPO_30\LGPO.exe .\Baseline-2019\Local_Script\Tools\
                Set-Location .\Baseline-2019\Local_Script\
                .\BaselineLocalInstall.ps1  -WS2019DomainControlle
            }
            "10.0.20348*" { 
                Write-Host "Detected Version: Server 2022"
                Invoke-WebRequest https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip -OutFile "Baseline.zip"
                Expand-Archive -Path Baseline.zip -DestinationPath .\ -Force
                Move-Item LGPO_30\LGPO.exe ".\Windows Server-2022-Security-Baseline-FINAL\Scripts\Tools\"
                Set-Location ".\Windows Server-2022-Security-Baseline-FINAL\Scripts\"
                .\Baseline-ADImport.ps1
            }
            "10.0.22000*" { 
                Write-Host "Detected Version: Server 2025"
                Invoke-WebRequest https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202025%20Security%20Baseline.zip -OutFile "Baseline.zip" 
                Expand-Archive -Path Baseline.zip -DestinationPath .\ -Force
                Move-Item LGPO_30\LGPO.exe "Windows Server 2025 Security Baseline - 2506\Scripts\Tools"
                Set-Location ".\Windows Server 2025 Security Baseline - 2506\Scripts"
                .\Baseline-ADImport.ps1
            }
            default { Write-Host "Unknown or unsupported server version" }
        }
    } else {
        Write-Host "Not a Windows Server OS."
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
    pwRotate
    hardening
    downloadTools
    GPOs
    dns_backup
}

# Menu to pick which hardening function you want to do
function mainMenu {
    Write-Host ""
    Write-Host ""

    Write-Host "Whaddya wanna do? Here's a directory"
    Write-Host "'pwrotate' to rotate passwords"
    Write-Host "'hardening' to run hardening commands"
    Write-Host "'download' to download security tools"
    Write-Host "'gpo' to import the STIG GPOs"
    Write-Host "'dns' to backup dns"
    Write-Host "'all' to run all the above steps (first run)"

    $Choice = Read-Host -Prompt '>>'
    switch ($Choice) {
        'pwrotate' { pwRotate }
        'hardening' { hardening }
        'download' { downloadTools }
        'gpo' { GPOs }
        'dns' { dns_backup }
        'all' { all }
    }
    Write-Host "Put in a valid word"
    mainMenu
    Write-Host ""
    Write-Host ""
} 
mainMenu