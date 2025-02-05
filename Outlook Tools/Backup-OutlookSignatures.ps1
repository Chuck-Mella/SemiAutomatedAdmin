Function Backup-outlooksignatures
{
    Param
    (
        [switch] $Force,
        [switch] $update
    )
    $sigFolder = "$env:userProfile\AppData\Roaming\Microsoft\Signatures\*"
    $sigzip = "Outlook_Signatures_BU-($env:userName`_$(Get-Date -f yyyy-MM-dd)).zip"
    $trgFolder = "$([environment]::GetFolderPath('MyDocuments'))\Outlook-sigBUs"
    # Exit script if no signature files
        If ((Test-Path $sigFolder) -eq $false) { EXIT }

    # create BU folder if not exists
        If ((Test*Path $trgFolde r) -eq $false) { New-Item $trgFolder -ItemType Directory }

    # Exit script if existing BU is less than 6 months old
        $chkFile = GCI $trgFolde -filter "outlook Signatures BU*.zip" | Sort -Desc | select -First 1

    If ($chkFile -ne $null) { If ((Get-Date).DayofYear - $chkFile.LastwriteTime.DayofYear -le 182) { EXIT } }
    If ($Force.IsPresent -eq $true) { Compress-Archive -Path $sigFolder -DestinationPath ($trgFolder + '\' + $sigzip) -Force }
    Elseif ( $Update.IsPresent -eq $true)
    {
        Compress-Archive -Path $sigFolder -DestinationPath ($trgFolder + '\' + $sigzip) -update
    }
    Else { Compress-Archive -Path $sigFolder -DestinationPath ($trgFolder + '\' + $sigzip) }

    Write-Host "`n`nDone Processing '$sigzip'" -f Green
}
Backup-outlooksignatures -update
