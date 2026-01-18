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

