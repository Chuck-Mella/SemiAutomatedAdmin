# Get AD/Net Environment
    Switch ($env:OneDrive)
    {
        {$_ -eq $env:OneDriveCommercial}{$Global:envLoc = "WNet1"}
        {$_ -eq $env:OneDriveConsumer}{$Global:envLoc = "HNet1"}
    }

# Redirect Profile Folder to OneDrive (as needed)
    $tstDir = ($pDir = $Profile -replace '\\+[^\\]+$') -replace '\\','/'
    $tst1DrWork = ($1DriveWork = $env:OneDriveCommercial)  -replace '\\','/'
    $tst1DrHome = ($1DriveHome = $env:OneDriveConsumer)  -replace '\\','/'

    If (!([string]::IsNullOrEmpty($tst1DrHome)) -and ($tstDir -match $tst1DrHome))
    {
        $Profile = "$(($pDir -replace [regex]::escape($1DriveHome),$1DriveHome))"
    }
    If (!([string]::IsNullOrEmpty($tst1DrWork)) -and ($tstDir -match $tst1DrWork))
    {
        $Profile = "$(($pDir -replace [regex]::escape($1DriveWork),$1DriveWork))"
    }

    # If (($Profile) -notmatch 'OneDrive\\Documents'){
    #     $Profile = "$(($Profile -replace '\\Documents','\OneDrive\Documents'))"
    #     } #If Profile

# Set Base-Level Variables Marker (for env clean-ups)
    New-Variable -Force -Name StartupVariables -Value (Get-Variable | ForEach-Object{$_.Name})

# Start SMAISEAddOn snippet
    # If ((Get-Host).name -match 'ise'){ Import-Module SMAAuthoringToolkit }

# Set working root folder
    Switch ($envLoc)
    {
        "HNet1"  { $Global:wrkRoot = $env:OneDriveConsumer + '\Documents\GIT Repositories\Code - Personal' }
        "WNet1"  { $Global:wrkRoot = $env:OneDriveConsumer + '\Documents\GIT Repositories\Code - Work' }
    }
    $Global:codeLib = $env:OneDriveConsumer + '\Documents\GIT Repositories\Code - Personal\01 - MyPSRepos\INWORK\Repos.ps1xml'

# Launch Profile Script
    $Global:psRoot =ii "$($Profile -replace '\\+[^\\]+$')"
    & "$psRoot\CM.PowerShell_profile.ps1"
    

# Chocolatey profile
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
  Import-Module "$ChocolateyProfile"
}
