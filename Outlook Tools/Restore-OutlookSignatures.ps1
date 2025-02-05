Function Restore-OutlookSignatures
{
    Param
    (
        $sigBUFolder = "$([environment]::GetFolderPath('MyDocuments'))\OutlooksigBUs",
        $sigzip,
        $trgFolder = "$env:userProfile\AppData\Roaming\Microsoft\Signatures"
    )
    If ($sigzip -eq $null )
    {
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter= "compressed (*.Zip)|*.zip"
            InitialDirectory = $sigBUFolder
            }
        $result = $FileBrowser.ShowDialog() #Direct actions based on dialog results
        $fileName = $FileBrowser.SafeFileName
        $filePath = $FileBrowser.FileName
    }
    Else
    {
        $filePath = $sigzip
        $fileName = ($s1gZip -split '\\')[-1]
    }
    If ($Result -ne 'cancel' )
    {
        Expand-Archive -LiteralPath $filePath -DestinationPath $trgFolder -Force -verbose
        Write-Host "`n`nDone Processing '$fileName'" -f Green
    }
    Else
    {
        Write-Host "`n`nNo file selected: EXITING" -f DarkYellow
    }
}
