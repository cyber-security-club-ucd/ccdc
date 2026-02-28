# Back up C:\iis\

# List Shares

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

    #   curl winpeas

    #   curl everything
    Invoke-WebRequest https://ninite.com/everything/ -OutFile "everything-setup.exe"

    #   curl sysinternals
    Invoke-WebRequest https://download.sysinternals.com/files/SysinternalsSuite.zip -OutFile "SysinternalsSuite.zip"
    Expand-Archive -Path SysinternalsSuite.zip -DestinationPath .\Sysinternals\ -Force

    #   setup sysmon
    Set-Location .\Sysinternals
    Invoke-WebRequest https://raw.githubusercontent.com/cyber-security-club-ucd/ccdc/refs/heads/main/windows/sysmonconfig.xml -OutFile config.xml
    .\sysmon.exe -accepteula -i config.xml

}