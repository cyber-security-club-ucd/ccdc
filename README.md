moo

***14 MARCH 2025 cutoff date***

## Windows Tools Usage
1) Run DC_deploy to set up neccesary tools and change passwords

```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/cyber-security-club-ucd/ccdc/refs/heads/main/windows/DC_deploy.ps1'))
```

2) Set up the network scanner, install the binaries from `/dist`
    * Usage: `nmap_tracker.exe / nmap_tracker (hosts_file)`
    * Hosts file is to be a sequential list of "known" IP addresses, separated with a newline.



## Changelog
Revision 3/29/2023
- Started development of GUI version of script, currently not usable (use the dist CLI tools)

Revision 3/27/2023
- Network scanner (basically a Python wrapper script for Nmap, visualize "up" and "down" hosts)

Revision 12/21/2023
- Domain Controller deploy script
