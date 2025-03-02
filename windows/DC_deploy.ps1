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

    $userList = @()

    # API Call to get a secure password
((get-aduser -F *).sid.value).foreach{
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($psitem)
        $objUser = $objSID.Translate([System.Security.Principal.NTAccount])
        $username = ($objUser.Value -split "\\")[1] # Quotient only uses username with no domain
	
        Write-Host "Changing $username"
	
        $api = Invoke-RestMethod -Uri "https://api.genratr.com/?length=16&lowercase&uppercase&numbers" -Method Get
        $p = ConvertTo-SecureString -String $api.password -AsPlainText -Force
        Set-ADAccountPassword -identity $psitem -newpassword $p -Reset # Do we need reset?

    
        $userList += [PSCustomObject]@{username = $username; password = $api.password }
    }


    # Generate .csv for password changes
    $userList | ConvertTo-Csv -NoTypeInformation | ForEach-Object { $_ -replace '"', '' } | Out-File ".\balls.csv"

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
}

# Download, setup, and run needed security tools
function downloadTools {
    # Turn off progress bar to speed up downloads
    $ProgressPreference = 'SilentlyContinue'

    #   curl nmap
    Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -OutFile "nmap-setup.exe"
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
    Invoke-WebRequest https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_January_2025.zip -OutFile "C:\Temp\STIG_GPO.zip"
    Expand-Archive -Path "C:\Temp\STIG_GPO.zip" -DestinationPath "C:\Temp\STIG\" -Force

    # Update these everytime a new STIG drops!
    $inputFile = "DISA_AllGPO_Import_Jan2025.csv"
    $findString = "C:\Jan25 DISA STIG GPO Package 0117"

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

# Run everything function
function all {
    pwRotate
    hardening
    downloadTools
    GPOs
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
    Write-Host "'all' to run all the above steps (first run)"

    $Choice = Read-Host -Prompt '>>'
    switch($Choice){
        'pwrotate' {pwRotate}
        'hardening' {hardening}
        'download' {downloadTools}
        'gpo' {GPOs}
        'all' {all}
    }
    Write-Host "Put in a valid word"
    mainMenu
    Write-Host ""
    Write-Host ""
} 
mainMenu