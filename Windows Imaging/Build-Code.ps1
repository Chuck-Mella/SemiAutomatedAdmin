Function Global:Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
function New-ISOFilev2
{
    <#
    .SYNOPSIS
        Create an ISO file from a source folder.

    .DESCRIPTION
        Create an ISO file from a source folder.
        Optionally speicify a boot image and media type.

        Based on original function by Chris Wu.
        https://gallery.technet.microsoft.com/scriptcenter/New-ISOFile-function-a8deeffd (link appears to be no longer valid.)

        Changes:
            - Updated to work with PowerShell 7
            - Added a bit more error handling and verbose output.
            - Features removed to simplify code:
                * Clipboard support.
                * Pipeline input.

    .PARAMETER source
        The source folder to add to the ISO.

    .PARAMETER destinationIso
        The ISO file to create.

    .PARAMETER bootFile
        Optional. Boot file to add to the ISO.

    .PARAMETER media
        Optional. The media type of the resulting ISO (BDR, CDR etc). Defaults to DVDPLUSRW_DUALLAYER.

    .PARAMETER title
        Optional. Title of the ISO file. Defaults to "untitled".

    .PARAMETER force
        Optional. Force overwrite of an existing ISO file.

    .INPUTS
        None.

    .OUTPUTS
        None.

    .EXAMPLE
        New-ISOFile -source c:\forIso\ -destinationIso C:\ISOs\testiso.iso

        Simple example. Create testiso.iso with the contents from c:\forIso

    .EXAMPLE
        New-ISOFile -source f:\ -destinationIso C:\ISOs\windowsServer2019Custom.iso -bootFile F:\efi\microsoft\boot\efisys.bin -title "Windows2019"

        Example building Windows media. Add the contents of f:\ to windowsServer2019Custom.iso. Use efisys.bin to make the disc bootable.

    .LINK

    .NOTES
        01           Alistair McNair          Initial version.

    #>
    [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="Low")]
    Param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$false)]
        [string]$source,
        [parameter(Mandatory=$true,ValueFromPipeline=$false)]
        [string]$destinationIso,
        [parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [string]$bootFile = $null,
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [ValidateSet("CDR","CDRW","DVDRAM","DVDPLUSR","DVDPLUSRW","DVDPLUSR_DUALLAYER","DVDDASHR","DVDDASHRW","DVDDASHR_DUALLAYER","DISK","DVDPLUSRW_DUALLAYER","BDR","BDRE")]
        [string]$media = "DVDPLUSRW_DUALLAYER",
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [string]$title = "untitled",
        [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
        [switch]$force
        )
    Begin
    {
        Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
        Write-Verbose ("Function start.")
    }
    Process
    {

        Write-Verbose ("Processing nested system " + $vmName)

        ## Set type definition
        Write-Verbose ("Adding ISOFile type.")

        $typeDefinition = (Dec64 'CnB1YmxpYyBjbGFzcyBJU09GaWxlICB7DQogICAgcHVibGljIHVuc2FmZSBzdGF0aWMgdm9pZCBDcmVhdGUoc3RyaW5nIFBhdGgsIG9iamVjdCBTdHJlYW0sIGludCBCbG9ja1NpemUsIGludCBUb3RhbEJsb2Nrcykgew0KICAgICAgICBpbnQgYnl0ZXMgPSAwOw0KICAgICAgICBieXRlW10gYnVmID0gbmV3IGJ5dGVbQmxvY2tTaXplXTsNCiAgICAgICAgdmFyIHB0ciA9IChTeXN0ZW0uSW50UHRyKSgmYnl0ZXMpOw0KICAgICAgICB2YXIgbyA9IFN5c3RlbS5JTy5GaWxlLk9wZW5Xcml0ZShQYXRoKTsNCiAgICAgICAgdmFyIGkgPSBTdHJlYW0gYXMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLklTdHJlYW07DQoNCiAgICAgICAgaWYgKG8gIT0gbnVsbCkgew0KICAgICAgICAgICAgd2hpbGUgKFRvdGFsQmxvY2tzLS0gPiAwKSB7DQogICAgICAgICAgICAgICAgaS5SZWFkKGJ1ZiwgQmxvY2tTaXplLCBwdHIpOyBvLldyaXRlKGJ1ZiwgMCwgYnl0ZXMpOw0KICAgICAgICAgICAgfQ0KDQogICAgICAgICAgICBvLkZsdXNoKCk7IG8uQ2xvc2UoKTsNCiAgICAgICAgfQ0KICAgIH0NCn0K')

        ## Create type ISOFile, if not already created. Different actions depending on PowerShell version
        if (!('ISOFile' -as [type])) {

            ## Add-Type works a little differently depending on PowerShell version.
            ## https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type
            switch ($PSVersionTable.PSVersion.Major) {

                ## 7 and (hopefully) later versions
                {$_ -ge 7} {
                    Write-Verbose ("Adding type for PowerShell 7 or later.")
                    Add-Type -CompilerOptions "/unsafe" -TypeDefinition $typeDefinition
                } # PowerShell 7

                ## 5, and only 5. We aren't interested in previous versions.
                5 {
                    Write-Verbose ("Adding type for PowerShell 5.")
                    $compOpts = New-Object System.CodeDom.Compiler.CompilerParameters
                    $compOpts.CompilerOptions = "/unsafe"

                    Add-Type -CompilerParameters $compOpts -TypeDefinition $typeDefinition
                } # PowerShell 5

                default {
                    ## If it's not 7 or later, and it's not 5, then we aren't doing it.
                    throw ("Unsupported PowerShell version.")

                } # default

            } # switch

        } # if


        ## Add boot file to image
        if ($bootFile) {

            Write-Verbose ("Optional boot file " + $bootFile + " has been specified.")

            ## Display warning if Blu Ray media is used with a boot file.
            ## Not sure why this doesn't work.
            if(@('BDR','BDRE') -contains $media) {
                    Write-Warning ("Selected boot image may not work with BDR/BDRE media types.")
            } # if

            if (!(Test-Path -Path $bootFile)) {
                throw ($bootFile + " is not valid.")
            } # if

            ## Set stream type to binary and load in boot file
            Write-Verbose ("Loading boot file.")

            try {
                $stream = New-Object -ComObject ADODB.Stream -Property @{Type=1} -ErrorAction Stop
                $stream.Open()
                $stream.LoadFromFile((Get-Item -LiteralPath $bootFile).Fullname)

                Write-Verbose ("Boot file loaded.")
            } # try
            catch {
                throw ("Failed to open boot file. " + $_.exception.message)
            } # catch


            ## Apply the boot image
            Write-Verbose ("Applying boot image.")

            try {
                $boot = New-Object -ComObject IMAPI2FS.BootOptions -ErrorAction Stop
                $boot.AssignBootImage($stream)

                Write-Verbose ("Boot image applied.")
            } # try
            catch {
                throw ("Failed to apply boot file. " + $_.exception.message)
            } # catch


            Write-Verbose ("Boot file applied.")

        }  # if

        ## Build array of media types
        $mediaType = @(
            "UNKNOWN",
            "CDROM",
            "CDR",
            "CDRW",
            "DVDROM",
            "DVDRAM",
            "DVDPLUSR",
            "DVDPLUSRW",
            "DVDPLUSR_DUALLAYER",
            "DVDDASHR",
            "DVDDASHRW",
            "DVDDASHR_DUALLAYER",
            "DISK",
            "DVDPLUSRW_DUALLAYER",
            "HDDVDROM",
            "HDDVDR",
            "HDDVDRAM",
            "BDROM",
            "BDR",
            "BDRE"
        )

        Write-Verbose ("Selected media type is " + $media + " with value " + $mediaType.IndexOf($media))

        ## Initialise image
        Write-Verbose ("Initialising image object.")
        try {
            $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$title} -ErrorAction Stop
            $image.ChooseImageDefaultsForMediaType($mediaType.IndexOf($media))

            Write-Verbose ("initialised.")
        } # try
        catch {
            throw ("Failed to initialise image. " + $_.exception.Message)
        } # catch


        ## Create target ISO, throw if file exists and -force parameter is not used.
        if ($PSCmdlet.ShouldProcess($destinationIso)) {

            if (!($targetFile = New-Item -Path $destinationIso -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) {
                throw ("Cannot create file " + $destinationIso + ". Use -Force parameter to overwrite if the target file already exists.")
            } # if

        } # if


        ## Get source content from specified path
        Write-Verbose ("Fetching items from source directory.")
        try {
            $sourceItems = Get-ChildItem -LiteralPath $source -ErrorAction Stop
            Write-Verbose ("Got source items.")
        } # try
        catch {
            throw ("Failed to get source items. " + $_.exception.message)
        } # catch


        ## Add these to our image
        Write-Verbose ("Adding items to image.")

        foreach($sourceItem in $sourceItems) {

            try {
                $image.Root.AddTree($sourceItem.FullName, $true)
            } # try
            catch {
                throw ("Failed to add " + $sourceItem.fullname + ". " + $_.exception.message)
            } # catch

        } # foreach

        ## Add boot file, if specified
        if ($boot) {
            Write-Verbose ("Adding boot image.")
            $Image.BootImageOptions = $boot
        }

        ## Write out ISO file
        Write-Verbose ("Writing out ISO file to " + $targetFile)

        try {
            $result = $image.CreateResultImage()
            [ISOFile]::Create($targetFile.FullName,$result.ImageStream,$result.BlockSize,$result.TotalBlocks)
        } # try
        catch {
            throw ("Failed to write ISO file. " + $_.exception.Message)
        } # catch

        Write-Verbose ("File complete.")

        ## Return file details
        return $targetFile

    }
    End { Write-Verbose ("Function complete.") }

}
Function Get-Source
{
    Param ($initDir,[switch]$folder,$ext)
    $psPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    # Add-MpPreference -ControlledFolderAccessAllowedApplications $psPath
    # If ((Get-MpPreference).EnableControlledFolderAccess -ne 0 ){ $mp = $true; Set-MpPreference -EnableControlledFolderAccess Disabled }
    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

    If ($folder.IsPresent)
    {
        # (Dec64 'ICAgICAgICAgICAgICAgICMgKCR0cmdJdGVtID0gTmV3LU9iamVjdCBTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Gb2xkZXJCcm93c2VyRGlhbG9nKS5yb290Zm9sZGVyID0gIk15Q29tcHV0ZXIiCiAgICAgICAgICAgICAgICAkbW9kYWxmb3JtID0gTmV3LU9iamVjdCBTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Gb3JtDQogICAgICAgICAgICAgICAgJG1vZGFsZm9ybS5Ub3BNb3N0ID0gJHRydWUNCgogICAgICAgICAgICAgICAgJHRyZ0l0ZW0gPSBOZXctT2JqZWN0IFN5c3RlbS5XaW5kb3dzLkZvcm1zLkZvbGRlckJyb3dzZXJEaWFsb2cKICAgICAgICAgICAgICAgICR0cmdJdGVtLlJvb3RGb2xkZXIgPSBbU3lzdGVtLkVudmlyb25tZW50K1NwZWNpYWxGb2xkZXJdOjpNeUNvbXB1dGVyCiAgICAgICAgICAgICAgICAkdHJnSXRlbS5TZWxlY3RlZFBhdGggPSAkaW5pdERpciAKCiAgICAgICAgICAgICAgICBpZiAoJHRyZ0l0ZW0uU2hvd0RpYWxvZygkbW9kYWxmb3JtKSAtZXEgIk9LIikgeyAkZmxkZXIgKz0gW3N0cmluZ10kdHJnSXRlbS5TZWxlY3RlZFBhdGggfQo=')

        $trgItem = New-Object System.Windows.Forms.OpenFileDialog
        $trgItem.initialDirectory = $initDir
        $trgItem.DereferenceLinks = $true
        $trgItem.CheckPathExists = $true
        $trgItem.FileName = "[Select this folder]"
        $trgItem.Filter = "Folders|`n"
        $trgItem.AddExtension = $false
        $trgItem.ValidateNames = $false
        $trgItem.CheckFileExists = $false

        If ($trgItem.ShowDialog() -eq "OK") { Return $trgItem.FileName -replace "\\\[Select this folder\]" }
        Else { Write-Error "Operation cancelled by user." }
    }
    Else
    {
        Switch ($ext)
        {
            'iso'{ $fltr = 'ISO files (*.iso)| *.iso'}
            Default { $fltr = 'All files (*.*)| *.*'}
        }
        ($trgItem = New-Object System.Windows.Forms.OpenFileDialog).initialDirectory = $initDir
        $trgItem.filter = $fltr
        $null = $trgItem.ShowDialog()
        $trgItem.filename
    }
    # Remove-MpPreference -ControlledFolderAccessAllowedApplications $psPath 
    # If ($mp -eq $true){ Set-MpPreference -EnableControlledFolderAccess Enabled }
}
#region - Constants and Lab Config
    $isoDir = 'U:\VirtualMachines\ISOs'
    $wrkDir = 'U:\IsoBuild'
    $labRoot = 'U:\IsoLab'
    $rptForm = (Dec64 'PE1GUj46IDxNREw+IDxERVNDPiAoPE5PVEVTPik=')
    $systems = ('Mfgr,Model,Desc,Notes,Env
        Dell,3660,Precision Tower,Nipr|Sipr,NS
        Dell,7670,Precision Laptop,Misc IT,IT
        Dell,7920,Precision Tower,Fabcon,FC
        Panasonic,FZ-55,ToughBook,T&E,TB
        All,--,--,--,ALL') | ConvertFrom-Csv -delim ','

    # Create Build folders
        If ((Test-path $labRoot -PathType Container) -eq $false){ New-Item $labRoot -ItemType Directory }
        If ((Test-path $wrkDir -PathType Container) -eq $false){ New-Item $wrkDir -ItemType Directory }
        'Drivers','Mount' | %{ Try {New-Item "$labRoot\$_" -ItemType Directory -ea stop}Catch{} }
        New-Item "$wrkDir\Add-Ons" -ItemType Directory -ea Ignore

    # Select Model, BIOS type
        $trgSys = $systems | OGV -PassThru -Title 'Select Target System(s)'
        $fwType = (("1,BIOS`n2,UEFI" |
            ConvertFrom-Csv -delim ',' -Header Idx,Type) | OGV -PassThru -Title 'Select System Firmware BootLoader').Type

    # Add driver report file to ISO root folder
        If ($trgSys.Mfgr -eq 'All'){$trgSys = $systems | Where Mfgr -ne 'All'}
        ForEach ($itm in $trgSys)
        {
            $rpt += "$($rptForm -replace '<MFR>',$itm.Mfgr -replace '<MDL>',$itm.Model -replace '<DESC>',$itm.Desc -replace '<NOTES>',$itm.Notes)`n"
        }
        $rpt | Out-File "$wrkDir\Driver_Models.txt" -Encoding ascii -Force
        $rpt = $null

    # Build a configuration variable, select Source OS ISO, Source Drivers,
    # Target ISO filename & BIIOS loader for ISO to use
        $osBuild = @{} | Select OS,ISO,DrvrPath,ISOName,ISOVol,BIOS
        $osBuild.OS = 'Win11'
        $osBuild.ISO =  Get-Source -initDir $isoDir -ext 'ISO' # SOURCE ISO
        $osBuild.DrvrPath = Get-Source -folder -initDir "$wrkDir\Drivers"
        $osBuild.ISOName = "$($osBuild.OS)-$($trgSys.Env)-$fwType.ISO"  # TARGET ISO
        $osBuild.ISOVol = "$($osBuild.OS)-$($trgSys.Env)"
        $osBuild.BIOS = $(Switch ($fwType){ 'BIOS'{"$wrkDir\boot\etfsboot.com"};'UEFI'{"$wrkDir\efi\microsoft\boot\efisys.bin"} })
#endregion
#region - Mount source image and modify
    Mount-DiskImage -ImagePath $osBuild.ISO -PassThru
    $cd = (Get-DiskImage -ImagePath $osBuild.ISO | Get-Volume)

    Copy-Item "$($CD.DriveLetter):\*" -Destination "$wrkDir\" -Recurse
    Get-ChildItem $wrkDir -Recurse -File | % { $_.IsReadOnly=$false }
    Copy-Item "$labRoot\Add-Ons\*" -Destination "$wrkDir\Add-Ons" -Recurse
    # Copy any other needed files into the $wrkDir\Add-Ons Folder

    $filename = $(If ($osBuild.OS -eq '2019'){'install.wim'} Else {'boot.wim'})
    $idxPref = (Get-WindowsImage -ImagePath $wrkDir\sources\$filename | OGV -PassThru -Title 'Select Image to Insert Drivers').ImageIndex

    Mount-WindowsImage -Path $labRoot\Mount -ImagePath $wrkDir\sources\$filename -Index $idxPref #-ReadOnly
    $instDrvrs = Add-WindowsDriver -Path "$labRoot\Mount" -Driver $osBuild.DrvrPath -Recurse
    $instDrvrs | Export-Csv -Delim ',' -NoTypeInformation -LiteralPath "$wrkDir\Add-Ons\DriverImport_Results.csv" -Force -Append
    $instDrvrs | OGV
    # (Dec64 'JGRydnJEYXRhID0gKCRpbnN0RHJ2cnMpLlNwbGl0KFtDaGFyXVtJTlRdMTApDQogICAgJGRwMSA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Ecml2ZXIiDQogICAgJGRwMiA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5PcmlnaW5hbEZpbGVOYW1lIg0KICAgICRkcDMgPSAkZHJ2ckRhdGEgLW1hdGNoICJeSW5ib3giDQogICAgJGRwNCA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5DbGFzc05hbWUiDQogICAgJGRwNSA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Cb290Q3JpdGljYWwiDQogICAgJGRwNiA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Qcm92aWRlck5hbWUiDQogICAgJGRwNyA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5EYXRlIg0KICAgICRkcDggPSAkZHJ2ckRhdGEgLW1hdGNoICJeVmVyc2lvbiINCg0KICAgICRyZXN1bHRzID0gW0NvbGxlY3Rpb25zLkFycmF5TGlzdF1AKCkgCiAgICAwLi4kZHAxLkNvdW50IHwgJXsKICAgICAgICAgICAgICAgICRyc3QgPSBAe30gfCBTZWxlY3QtT2JqZWN0IERyaXZlcixPcmlnaW5hbEZpbGVOYW1lLEluYm94LENsYXNzTmFtZSxCb290Q3JpdGljYWwsUHJvdmlkZXJOYW1lLERhdGUsVmVyc2lvbgogICAgICAgICAgICAgICAgJHJzdC5Ecml2ZXIgICAgICAgICAgID0gKCgoJGRwMVskX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0Lk9yaWdpbmFsRmlsZU5hbWUgPSAoKCgkZHAyWyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRyc3QuSW5ib3ggICAgICAgICAgICA9ICgoKCRkcDNbJF9dICAtcmVwbGFjZSAnXHN7Mn0nKSAtc3BsaXQgJz0nKS50cmltKCkpWzFdDQogICAgICAgICAgICAgICAgJHJzdC5DbGFzc05hbWUgICAgICAgID0gKCgoJGRwNFskX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0LkJvb3RDcml0aWNhbCAgICAgPSAoKCgkZHA1WyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRyc3QuUHJvdmlkZXJOYW1lICAgICA9ICgoKCRkcDZbJF9dICAtcmVwbGFjZSAnXHN7Mn0nKSAtc3BsaXQgJz0nKS50cmltKCkpWzFdDQogICAgICAgICAgICAgICAgJHJzdC5EYXRlICAgICAgICAgICAgID0gKCgoJGRwN1skX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0LlZlcnNpb24gICAgICAgICAgPSAoKCgkZHA4WyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRudWxsID0gJHJlc3VsdHMuQWRkKCRyc3QpCiAgICAgICAgICAgICAgICB9CiAgICAkcmVzdWx0cyB8IE9HVgogICAgIyBTYXZlIHJlc3VsdHMKICAgICRyZXN1bHRzIHwgRXhwb3J0LUNzdiAtRGVsaW0gJywnIC1Ob1R5cGVJbmZvcm1hdGlvbiAtTGl0ZXJhbFBhdGggIiRsYWJSb290XElTT1xBZGQtT25zXERyaXZlckltcG9ydF9SZXN1bHRzLmNzdiIgLUZvcmNl')
#endregion
#region - Dismount all images and create ISO
    Dismount-WindowsImage -Path $labRoot\Mount -Save
    Dismount-DiskImage -ImagePath $osBuild.ISO

    $Params = @{
        Source = $wrkDir
        DestinationIso = "$labRoot\$($osBuild.ISOName)"
        Title = $osBuild.ISOVol
        BootFile = $osBuild.BIOS
        Force = $true
        }
    New-ISOFilev2 @Params
#endregion
#region - Clean-up
    # Clean ISO build folder
    GCI $wrkDir -Recurse | Remove-Item -Force -Recurse -Confirm:$false

    # Clear Lab MOUNT folder
    Remove-Item -Path $labRoot\Mount -Force -Recurse -Confirm:$false
#endregion
