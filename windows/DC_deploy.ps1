Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Output Start
Pause

# Check for and enter Administrator terminal
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
& {
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        Write-Host "Oppenheimer mode engage"
    }
    else {
        $Location2 = $PSCommandPath
        start-process powershell.exe $Location2 -verb runAs
	    exit
    }
}

# Change password for Domain users
Set-PSReadlineOption -HistorySaveStyle SaveNothing

$userList = @()

# API Call to get a secure password
((get-aduser -F *).sid.value).foreach{
	$objSID = New-Object System.Security.Principal.SecurityIdentifier($psitem)
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    $username = $objUser.Value
	
	Write-Host "Changing $username"
	
	$api = Invoke-RestMethod -Uri "https://api.genratr.com/?special&lowercase&uppercase&numbers" -Method Get
	$p = ConvertTo-SecureString -String $api.password -AsPlainText -Force
	Set-ADAccountPassword -identity $psitem -newpassword $p

    
    $userList += [PSCustomObject]@{username = $username; password = $api.password}
}


# Generate .csv for password changes
$userList | Export-Csv -Path ".\password.csv" -NoTypeInformation

Write-Host "Reset the password for Administrator so you don't get locked out"
$p = Read-Host -AsSecureString
Set-ADAccountPassword -identity Administrator -newpassword $p

# Enable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Download needed packages

# Fix the SSL issue
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#   curl nmap
Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -OutFile "nmap-setup.exe"
./nmap-setup.exe

#   curl malwarebytes
Invoke-WebRequest https://www.malwarebytes.com/api/downloads/mb-windows-mb4 -OutFile "mbsetup.exe"
./mbsetup.exe

#   curl ad-peas light
Invoke-WebRequest https://raw.githubusercontent.com/61106960/adPEAS/refs/heads/main/adPEAS-Light.ps1 -OutFile "adPEAS-Light.ps1"

#   curl sysinternals
Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile "SysinternalsSuite.zip"
Expand-Archive -Path SysinternalsSuite.zip -DestinationPath .\Sysinternals\ -Force

#   curl pingcastle
Invoke-WebRequest https://github.com/netwrix/pingcastle/releases/download/3.3.0.1/PingCastle_3.3.0.1.zip -OutFile "PingCastle_3.3.0.1.zip"
Expand-Archive -Path PingCastle_3.3.0.1.zip -DestinationPath .\PingCastle\ -Force
.\PingCastle\PingCastle.exe --healthcheck

#   curl STIG GPOs
Invoke-WebRequest https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_STIG_GPO_Package_October_2024.zip -OutFile "C:\Temp\STIG_GPO.zip"
Expand-Archive -Path "C:\Temp\STIG_GPO.zip" -DestinationPath "C:\Temp\STIG\" -Force