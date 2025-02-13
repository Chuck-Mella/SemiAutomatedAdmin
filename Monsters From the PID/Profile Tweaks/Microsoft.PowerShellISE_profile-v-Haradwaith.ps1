# Get AD/Net Environment
    Switch ($env:OneDrive)
    {
        {$_ -eq $env:OneDriveCommercial}{$Global:envLoc = "WNet1"}
        {$_ -eq $env:OneDriveConsumer}{$Global:envLoc = "HNet1"}
    }

# Redirect Profile Folder to Personal OneDrive (as needed)
    $tstProfile = ($Profile -replace '\\+[^\\]+$') -replace '\\','_'
    $filProfile = ($Profile -split '\\')[-1]
    $tstOneDrive = $env:OneDriveConsumer -replace '\\','_'
    If (!($tstProfile -match $tstOneDrive))
    {
        $Profile = "$env:OneDriveConsumer" + "\Documents\WindowsPowerShell\" + $filProfile
    } #If Profile

    <#
    If (($Profile) -notmatch "$env:OneDriveConsumer")
           {
               $Profile = "$(($Profile -replace '\\Documents','\OneDrive\Documents'))"
           } #If Profile
    #>

# Set Base-Level Variables Marker (for env clean-ups)
    New-Variable -Force -Name StartupVariables -Value (Get-Variable | ForEach-Object{$_.Name})

# Start SMAISEAddOn snippet
    If ((Get-Host).name -match 'ise'){ Import-Module SMAAuthoringToolkit }

# Launch Profile Script
    $Global:psRoot = "$($Profile -replace '\\+[^\\]+$')"
    & "$psRoot\CM.PowerShell_profile.ps1"
