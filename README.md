Cutoff: 3/13/2019

### Useful Copy-Pastes:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

Invoke-WebRequest -Uri https://raw.githubusercontent.com/cyber-security-club-ucd/ccdc/refs/heads/main/windows/windows.zip -OutFile ~/Downloads/windows.zip
Expand-Archive -Path ~/Downloads/windows.zip -DestinationPath ~/Downloads/windows/ -Force
```