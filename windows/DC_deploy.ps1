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
    # Enable firewall
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    # Disable SMBv1
    Set-SmbServerConfiguration -EnableSMB1Protocol $false
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

    # Zerologon
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f
}

# Download, setup, and run needed security tools
function downloadTools {
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
    Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml -OutFile config.xml
    .\sysmon.exe -accepteula -i config.xml

    #   curl pingcastle (USE AN OLDER VERSION ON SERVER 2016!!)
    Invoke-WebRequest https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip -OutFile "PingCastle_3.3.0.1.zip"
    Expand-Archive -Path PingCastle_3.3.0.1.zip -DestinationPath .\PingCastle\ -Force
    Start-Process powershell {
        .\PingCastle\PingCastle.exe --healthcheck
    }

}

# Import the STIG GPOs
function GPOs {
    #   curl STIG GPOs
    Invoke-WebRequest dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_October_2025.zip -OutFile "C:\Temp\STIG_GPO.zip"
    Expand-Archive -Path "C:\Temp\STIG_GPO.zip" -DestinationPath "C:\Temp\STIG\" -Force

    # Update these everytime a new STIG drops!
    $inputFile = "DISA_AllGPO_Import_Oct2025.csv"
    $findString = "C:\Nov25 DISA STIG GPO Package 1111"

    # Import the GPOs
    Set-Location "C:\Temp\STIG\Support Files"
    
    # Modify the import CSV
    $data = Import-Csv -Path $inputFile

    foreach ($row in $data) {
        foreach ($property in $row.PSObject.Properties) {
            if ($property.Value -is [string]) {
                $property.Value = $property.Value -replace [regex]::Escape($findString), "C:\Temp\STIG"
            }
        }
    }

    $data | Export-Csv -Path $inputFile -NoTypeInformation

    # Edit the migtable manually even though it's XML but it's so painful to do with PowerShell
    Write-Host "The workgroup is $env:userdomain"
    .\importtable.migtable

    # Run the GPO import script
    .\DISA_GPO_Baseline_Import.ps1
}

function dns_backup {
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