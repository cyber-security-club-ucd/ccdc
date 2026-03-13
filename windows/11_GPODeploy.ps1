#Requires -Modules GroupPolicy
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    CCDC - Deploy a Group Policy Object based on the detected Windows Server version
.DESCRIPTION
    Detects the current Windows Server version, locates the matching GPO backup
    folder, creates a new GPO in Active Directory, and imports the backup into it.
    Optionally links the GPO to a specified Organizational Unit (OU).
.PARAMETER GPOBackupRoot
    Path to the root folder containing per-version GPO backup subfolders.
    Defaults to ".\GPOBackups" relative to the script location.
.PARAMETER GPOName
    Name to assign to the newly created GPO.
    Defaults to "Server Baseline - <detected OS version>".
.PARAMETER TargetOU
    Distinguished Name of the OU to link the GPO to after import.
    If omitted, the GPO is created and imported but not linked.
.PARAMETER Domain
    Target AD domain. Defaults to the current computer's domain.
.EXAMPLE
    .\11_GPODeploy.ps1
.EXAMPLE
    .\11_GPODeploy.ps1 -GPOBackupRoot "C:\GPOBackups" -TargetOU "OU=Servers,DC=corp,DC=local"
.EXAMPLE
    .\11_GPODeploy.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$GPOBackupRoot = (Join-Path $PSScriptRoot "GPO"),

    [Parameter()]
    [string]$GPOName = "",

    [Parameter()]
    [string]$TargetOU = "",

    [Parameter()]
    [string]$Domain = $env:USERDNSDOMAIN
)

$ErrorActionPreference = "Stop"

function Write-Banner { param([string]$T,[string]$C="Cyan") $l="="*70; Write-Host "`n$l`n  $T`n$l`n" -ForegroundColor $C }
function Write-OK     { param([string]$m) Write-Host "  [OK]   $m" -ForegroundColor Green  }
function Write-WARN   { param([string]$m) Write-Host "  [WARN] $m" -ForegroundColor Yellow }
function Write-CRIT   { param([string]$m) Write-Host "  [CRIT] $m" -ForegroundColor Red    }
function Write-INFO   { param([string]$m) Write-Host "  [INFO] $m" -ForegroundColor Cyan   }
function Write-STEP   { param([string]$m) Write-Host "`n>> $m" -ForegroundColor Magenta   }

Write-Banner "GPO DEPLOYMENT" "Blue"

# -- 1. Detect Windows Server Version -----------------------------------------
function Get-WindowsServerVersion {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $caption = $os.Caption

    Write-INFO "Detected OS: $caption"

    $versionMap = [ordered]@{
        "2022" = "Windows Server 2022"
        "2019" = "Windows Server 2019"
        "2016" = "Windows Server 2016"
        "2012" = "Windows Server 2012"
        "2008" = "Windows Server 2008"
    }

    foreach ($key in $versionMap.Keys) {
        if ($caption -match $key) {
            return $versionMap[$key]
        }
    }

    throw "Unsupported or unrecognised Windows Server version: '$caption'. " +
          "Supported versions: $($versionMap.Values -join ', ')."
}

# -- 2. Locate GPO Backup Folder -----------------------------------------------
function Get-GPOBackupFolder {
    param (
        [string]$BackupRoot,
        [string]$ServerVersion
    )

    $versionFolder = Join-Path $BackupRoot $ServerVersion

    if (-not (Test-Path $versionFolder -PathType Container)) {
        throw "Version folder not found: '$versionFolder'. " +
              "Ensure a subfolder named '$ServerVersion' exists under '$BackupRoot'."
    }

    # The backup ID is a GUID-named subfolder inside the version folder
    $guidFolders = Get-ChildItem -Path $versionFolder -Directory |
                   Where-Object { $_.Name -match '^\{[0-9A-Fa-f\-]{36}\}$' }

    if ($guidFolders.Count -eq 0) {
        throw "No GUID-named backup subfolder found inside '$versionFolder'."
    }

    if ($guidFolders.Count -gt 1) {
        Write-WARN "Multiple GUID folders found; using the first: $($guidFolders[0].Name)"
    }

    $backupFolder = $guidFolders[0]

    # Validate expected backup artefacts
    $requiredFiles = @("Backup.xml", "bkupInfo.xml", "gpreport.xml")
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path (Join-Path $backupFolder.FullName $file))) {
            throw "Expected backup file '$file' is missing from '$($backupFolder.FullName)'."
        }
    }

    Write-INFO "GPO backup folder located: $($backupFolder.FullName)"
    return $backupFolder
}

# -- 3. Retrieve Backup ID from bkupInfo.xml -----------------------------------
function Get-BackupId {
    param ([System.IO.DirectoryInfo]$BackupFolder)

    $bkupInfoPath = Join-Path $BackupFolder.FullName "bkupInfo.xml"
    [xml]$bkupInfo = Get-Content $bkupInfoPath -Raw
    $backupId = $bkupInfo.BackupInst.ID

    if ([string]::IsNullOrWhiteSpace($backupId)) {
        # Fall back to the folder name itself (already a GUID)
        $backupId = $BackupFolder.Name
        Write-WARN "Could not parse BackupID from bkupInfo.xml; using folder name: $backupId"
    }

    Write-INFO "Backup ID: $backupId"
    return $backupId
}

# -- 4. Create New GPO --------------------------------------------------------
function New-BaselineGPO {
    param (
        [string]$Name,
        [string]$Domain
    )

    $existing = Get-GPO -Name $Name -Domain $Domain -ErrorAction SilentlyContinue

    if ($existing) {
        Write-WARN "GPO '$Name' already exists (ID: $($existing.Id)). Skipping creation."
        return $existing
    }

    Write-INFO "Creating new GPO: '$Name' in domain '$Domain'..."

    if ($PSCmdlet.ShouldProcess("Domain '$Domain'", "Create GPO '$Name'")) {
        $gpo = New-GPO -Name $Name -Domain $Domain -Comment "Deployed by 11_GPODeploy.ps1 on $(Get-Date -Format 'yyyy-MM-dd')"
        Write-OK "GPO created successfully. GUID: $($gpo.Id)"
        return $gpo
    }

    Write-WARN "[WhatIf] Would create GPO '$Name' in '$Domain'."
    return $null
}

# -- 5. Import GPO Backup -----------------------------------------------------
function Import-BaselineGPO {
    param (
        [string]$GPOName,
        [string]$BackupId,
        [string]$BackupPath,
        [string]$Domain
    )

    Write-INFO "Importing GPO backup (BackupId: $BackupId) into GPO '$GPOName'..."

    if ($PSCmdlet.ShouldProcess("GPO '$GPOName'", "Import backup '$BackupId' from '$BackupPath'")) {
        Import-GPO -BackupId $BackupId `
                   -TargetName $GPOName `
                   -Path $BackupPath `
                   -Domain $Domain | Out-Null

        Write-OK "GPO backup imported successfully into '$GPOName'."
    } else {
        Write-WARN "[WhatIf] Would import backup '$BackupId' from '$BackupPath' into GPO '$GPOName'."
    }
}

# -- 6. Link GPO to OU --------------------------------------------------------
function Set-GPOLink {
    param (
        [string]$GPOName,
        [string]$OU,
        [string]$Domain
    )

    Write-INFO "Linking GPO '$GPOName' to OU: $OU ..."

    if ($PSCmdlet.ShouldProcess("OU '$OU'", "Link GPO '$GPOName'")) {
        New-GPLink -Name $GPOName `
                   -Target $OU `
                   -Domain $Domain `
                   -LinkEnabled Yes `
                   -ErrorAction Stop | Out-Null

        Write-OK "GPO linked to '$OU' and enabled."
    } else {
        Write-WARN "[WhatIf] Would link GPO '$GPOName' to '$OU'."
    }
}

# -- Main Execution -----------------------------------------------------------
try {
    Write-INFO "Target domain    : $Domain"
    Write-INFO "GPO backup root  : $GPOBackupRoot"

    Write-STEP "Detecting Windows Server version"
    $serverVersion = Get-WindowsServerVersion

    if ([string]::IsNullOrWhiteSpace($GPOName)) {
        $GPOName = "Server Baseline - $serverVersion"
    }
    Write-INFO "Target GPO name  : $GPOName"

    Write-STEP "Locating GPO backup folder"
    $backupFolder = Get-GPOBackupFolder -BackupRoot $GPOBackupRoot -ServerVersion $serverVersion

    Write-STEP "Parsing backup ID"
    $backupId = Get-BackupId -BackupFolder $backupFolder
    # Import-GPO expects the *parent* of the GUID folder as -Path
    $importPath = $backupFolder.Parent.FullName

    Write-STEP "Creating GPO in Active Directory"
    $gpo = New-BaselineGPO -Name $GPOName -Domain $Domain

    Write-STEP "Importing GPO backup"
    Import-BaselineGPO -GPOName $GPOName `
                       -BackupId $backupId `
                       -BackupPath $importPath `
                       -Domain $Domain

    if (-not [string]::IsNullOrWhiteSpace($TargetOU)) {
        Write-STEP "Linking GPO to OU"
        Set-GPOLink -GPOName $GPOName -OU $TargetOU -Domain $Domain
    } else {
        Write-WARN "No TargetOU specified -- GPO created and imported but not linked."
    }

    Write-Host ""
    Write-OK "GPO deployment complete for '$serverVersion'."
    Write-Host ""

} catch {
    Write-CRIT "Deployment failed: $_"
    exit 1
}
