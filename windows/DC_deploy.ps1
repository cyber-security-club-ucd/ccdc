Set-ExecutionPolicy Bypass -Scope Process -Force

Write-Output Start
Pause

# Check for and enter Administrator terminal
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
& {
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        Write-Output "Oppenheimer mode engage"
    }
    else {
        $Location2 = $PSCommandPath
        start-process powershell.exe $Location2 -verb runAs
	    exit
    }
}

# Change password for Domain users
Set-PSReadlineOption -HistorySaveStyle SaveNothing
Write-Output "Enter the new password for all users"
$p = read-host -AsSecureString
((get-aduser -F *).sid.value).foreach{set-adaccountpassword -identity $psitem -newpassword $p}


# Generate .csv for password changes

#   Yeah you can't really print securestring b/c it would defeat the purpose...
#   Resolve this later
$p = read-host
$users = Get-ADUser -Filter * | Select-Object SAMAccountName


foreach ($user in $users){
    $export = [PsCustomObject]@{
        name = ($($user.SAMAccountName))
        password = $p
    }
    
    ConvertTo-Csv -InputObject $export -NoTypeInformation | Out-File .\password.csv -Append -Encoding Ascii
}

# Enable firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Download needed packages

#   curl nmap
Invoke-WebRequest https://nmap.org/dist/nmap-7.94-setup.exe -OutFile "nmap-setup.exe"
./nmap-setup.exe

#   curl malwarebytes
Invoke-WebRequest https://www.malwarebytes.com/api/downloads/mb-windows-mb4 -OutFile "mbsetup.exe"
./mbsetup.exe

#   curl sysinternals
Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile "SysinternalsSuite.zip"
Expand-Archive -Path SysinternalsSuite.zip -DestinationPath .\Sysinternals\ -Force

#   curl wazuh
Invoke-WebRequest https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.1-1.msi -OutFile "wazuh-agent-4.7.1-1.msi"
$ip = Read-Host "Enter the IP of the Wazuh server"
.\wazuh-agent-4.7.1-1.msi /q WAZUH_MANAGER=$ip