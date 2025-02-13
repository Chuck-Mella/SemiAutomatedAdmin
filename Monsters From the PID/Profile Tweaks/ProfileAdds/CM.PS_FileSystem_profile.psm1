    function New-SymLink ($linkName, $target)
    {
        New-Item -Path $linkName -ItemType SymbolicLink -Value $target -ErrorAction SilentlyContinue -Verbose
    }
    
    function Get-ReparsePoint([string]$path)
    {
        $file = Get-Item $path -Force -ea SilentlyContinue
        If (([bool]($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) -eq 0){ Write-Warning "Not a SymLink!"}
        return $file.Target
    }

    function Test-ReparsePoint([string]$path)
    {
        $file = Get-Item $path -Force -ea SilentlyContinue
        return [bool]($file.Attributes -band [IO.FileAttributes]::ReparsePoint)
    }

    function New-CMDLineSymLink
    {
        Param ( $lnk, $trg )
        Return $(
            $cmd = "MKLINK /J `"$lnk`" `"$trg`"" | Clip 
            Start-Process CMD.exe -ArgumentList "/k `"TITLE PASTE Symbolic Link HERE! (Right-Click in the Window)`""
        )
    }
    Set-Alias -Name Paste-SymLink -Value 'New-CMDLineSymLink' -Scope Global -Force

    function Get-DriveLetter
    {
        Param
        (
        [parameter(Mandatory=$True)]$imgPath,
        [switch]$ISO
        )
        Switch ($ISO)
        {
            $True  { $rslt = (Get-diskimage $imgPath | Get-Volume).DriveLetter }
            $False { $rslt = ([String](Get-DiskImage -ImagePath $imgPath | 
                        Get-Disk | Get-Partition | 
                        Get-Volume ).DriveLetter).trim()
                    }
        }
        Return $rslt
    }

    function SearchLinks
    {
        [CmdletBinding()]
        Param (
            $srchPath='c:\',
            [ValidateSet('Directory','Archive','Read-only','Hidden','System','ReparsePoint','NotContentIndexe')]$type="ReparsePoint",
            [switch]$Hidden,    # -Force includes hidden and system files
            [switch]$Recurse,   # -Recurse gets all child items
            $prefEA             # -ErrorAction 'silentlycontinue' suppresses Access to the path XYZ is denied errors
            )
        # Explanation of Mode attributes�: d - Directory | a - Archive | r - Read-only | h - Hidden | s - System | l - Reparse point, symlink, etc.
            If (($Hidden.IsPresent) -eq $true){ $option = '-Force' }
            If (($Recurse.IsPresent) -eq $true){ $option = $option + ' -Recurse' }
            $cmd = "Dir $srchPath $option -ErrorAction $prefEA | Where { `$_.Attributes -match '$type' }"
            Return (Invoke-Expression $cmd)
    }

    Function Find-SymLinks
    {
        <#
            The function in this script was derived by from the answer given by Keith Hill at
            https://stackoverflow.com/questions/817794/find-out-whether-a-file-is-a-symbolic-link-in-powershell. 
            If you save the above script as ~/scripts/FindSymLinks.ps1, here is what a sample session looks like:
        #>
        param([string]$Path)
        if (-not (Test-Path $Path -PathType 'Container'))
        {
            throw "$($Path) is not a valid folder"
        }
        $Current=Get-Item .
        function Test-ReparsePoint($File)
        {
            if ([bool]($File.Attributes -band [IO.FileAttributes]::ReparsePoint))
            {
                $File
            }
            else
            {
                $FALSE
            }
            return
        }
        Set-Location $Path
        # Recurse through all files and folders, suppressing error messages.
        # Return any file/folder that is actually a symbolic link.
        Get-ChildItem -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { Test-ReparsePoint($_) }
        Set-Location $Current
    }

    function New-FileDownload
    {
        Param
        (
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No source file specified")] 
		    [string]$SourceFile,
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage="No destination folder specified")] 
            [string]$DestFolder,
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, HelpMessage="No destination file specified")] 
            [string]$DestFile
        )
	    $error.clear()
	    if (!($DestFolder))
        {
            $DestFolder = $TargetFolder
        }
	    Get-ModuleStatus -name BitsTransfer
	    if (!($DestFile))
        {
            [string] $DestFile = $SourceFile.Substring($SourceFile.LastIndexOf("/") + 1)
        }
	    if (Test-Path $DestFolder)
        {
            Write-Host "Folder: `"$DestFolder`" exists."
        }
        else
        {
            Write-Host "Folder: `"$DestFolder`" does not exist, creating..." -NoNewline
            New-Item $DestFolder -type Directory
            Write-Host "Done! " -ForegroundColor Green
        }
	    if (Test-Path "$DestFolder\$DestFile")
        {
		    Write-Host "File: $DestFile exists."
	    }
        else
        {
		    if ($HasInternetAccess)
            {
			    Write-Host "File: $DestFile does not exist, downloading..." -NoNewLine
			    Start-BitsTransfer -Source "$SourceFile" -Destination "$DestFolder\$DestFile"
			    Write-Host "Done! " -ForegroundColor Green
		    }
            else
            {
			    Write-Host "Internet access not detected. Please resolve and try again." -ForegroundColor red
		    }
	    }
    }

    function New-UnzippedFile
    {
        Param
        (
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No zip file specified")] 
            [string]$ZipFile,
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No file to unzip specified")] 
            [string]$UnzipFile,
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No location to unzip file specified")] 
            [string]$UnzipFileLocation
        )
        $error.clear()
        Write-Host "Zip File........................................................[" -NoNewLine
        Write-Host "Unzipping" -ForegroundColor yellow -NoNewLine
        Write-Host "]" -NoNewLine
        if (Get-Item $zipfile)
        {    
            $objShell = new-object -com shell.application
            # where the .zip is
            $FuncZipFolder = $objShell.namespace($ZipFile) 
            # the item in the zip
            $FuncFile = $FuncZipFolder.parsename($UnzipFile)      
            # where the item is to go
            $FuncTargetFolder = $objShell.namespace($UnzipFileLocation)       
            # do the copy of zipfile item to target folder
            $FuncTargetFolder.copyhere($FuncFile)
        }
        if ($error)
        {
            Write-Host "`b`b`b`b`b`b`b`b`b`bfailed!" -ForegroundColor red -NoNewLine
        }
        else
        {
            Write-Host "`b`b`b`b`b`b`b`b`b`bdone!" -ForegroundColor green -NoNewLine
        }		
        Write-Host "]    "
    }

    Function Test-Bitlocker
    {
        Param
        (
            [ValidateSet('Aes128','Aes256','XtsAes128','XtsAes256')]
            $blEnc = 'Aes256',
            $blPin = '1234',
            [ValidatePattern('[a-zA-Z]:')]$trgDrive,
            [switch]$Enable
        )

        $blStatus = Get-BitLockerVolume   #  was [manage-bde -status]
        If ($trgDrive -eq $null)
        {
            $trgDrv = $blStatus | Where-Object{ $_.VolumeType -eq 'OperatingSystem'}
        }
        Else
        { 
            $trgDrv = $blStatus | Where-Object{ $_.MountPoint -eq $trgDrive}
        }
        # $trgDrive | Select 'MountPoint','VolumeStatus','ProtectionStatus'
        If ($trgDrv.ProtectionStatus -ne 'off'){ $trgDrv | Format-List }
        Else
        { 
            Write-Warning "Bitlocker on [$($trgDrv.MountPoint)] is [$($trgDrv.ProtectionStatus)]."
            # Enable BitLocker
                if ($Enable.IsPresent -eq $true)
                {
                    Write-hOst -f gree "Enabling Bitlocker on [$($trgDrv.MountPoint)]."
                    $SecureString = ConvertTo-SecureString $blPin -AsPlainText -Force
                    Enable-BitLocker -MountPoint $trgDrv.MountPoint -EncryptionMethod $blEnc -UsedSpaceOnly -Pin $SecureString -TPMandPinProtector
                    Write-Output "Bitlocker on [$($trgDrv.MountPoint)] is Now [$($trgDrv.ProtectionStatus)]."
                }
        }
    } # Test-Bitlocker -trgDrive E:

    Function Mount-ImageQuietly
    {
        Param
        (
            $imagePath,
            [switch]$Dismount,
            [switch]$ISO
        )
        Switch ($Dismount)
        {
            $true  {
                If ($ISO) { DisMount-DiskImage -ImagePath $imagePath -Verbose }
                Else      { DisMount-VHD -Path $imagePath -Verbose }
                }
            $false {
                Stop-Service ShellHWDetection
                    Set-Location ($imagePath -replace "\\+[^\\]+$")
                    Mount-VHD -Path $imagePath -Verbose
                    Switch ($ISO)
                    {
                        $true  {
                            Mount-DiskImage -ImagePath $imagePath -Verbose
                            $drvLtr = Get-DriveLetter $imagePath -ISO
                            }
                        $false {
                            Mount-VHD -Path $imagePath -Verbose
                            $drvLtr = Get-DriveLetter $imagePath
                            }
                    }
                Start-Service ShellHWDetection
                Write-Output "[$imagePath] mounted as Drive [$drvLtr]"    
                }
        }
    }

    Function Get-SpecialFolders
    {
        [Enum]::GetNames([Environment+SpecialFolder]) |
        ForEach-Object {
        # ...for each, create a new object with the constant, the associated path
        # and the code required to get that path
        [PSCustomObject]@{
                Name = $_
                Path = [Environment]::GetFolderPath($_)
            }
          } 
    }

    Function Get-ProfilePaths
    {
        Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\profilelist\*' |
        Select-Object -Property ProfileImagePath, FullProfile  
    }
    
    Function Get-CommonPath
    {
        Param ( $Separator, $PathList )
        
        $SplitPaths = $PathList | ForEach-Object{ , $_.Split($Separator) }
        $MinDirectoryDepth = $SplitPaths | Measure-Object -Property Length -Minimum | Select-Object -EXP Minimum
        $CommonPath = foreach ($Index in 0..($MinDirectoryDepth - 1)) {
            $UniquePath = @($SplitPaths | ForEach-Object { $_[$Index] } | Sort-Object -Unique)
            if ($UniquePath.Length -gt 1) { break }
            $UniquePath
            }
        [String]::Join($Separator, $CommonPath)
    }

    Function Get-CommonPath2
    {
        <#
            .Synopsis
                Finds the deepest common directory path of files passed through the pipeline.
            .Parameter File
                PowerShell file object.
        #>
        param
        (
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [IO.FileInfo] $File
        )
        process
        {
            # Get the current file's path list
            $PathList =  $File.FullName -split "\$([IO.Path]::DirectorySeparatorChar)"
            # Get the most common path list
            if ($CommonPathList) {
                $CommonPathList = (Compare-Object -ReferenceObject $CommonPathList -DifferenceObject $PathList -IncludeEqual `
                    -ExcludeDifferent -SyncWindow 0).InputObject
            } else {
                $CommonPathList = $PathList
            }
        }
        end
        {
            $CommonPathList -join [IO.Path]::DirectorySeparatorChar
        }
    }

    Function Get-Drives
    {
        Param ([switch]$CD,[switch]$HD,[switch]$Empty)
        If ($CD.IsPresent-eq $true){ $drvType = 'DriveType=5' }
        ElseIf ($HD.IsPresent -eq $true){ $drvType = 'DriveType=3' }
        Else { Break }
        <#
            If you want to exclude CD-ROM drives with no media inserted, check the Access property. 
            It is 0 for no media, 1 for read access, 2 for write access and 3 for both
        #>
        if ($CD.IsPresent -AND $Empty.IsPresent){ $drvType = "$drvType and Access<1" }
        @(Get-WmiObject win32_logicaldisk -filter $drvType | ForEach-Object { $_.DeviceID })
    }

    Function New-ZipFile
    {
        Param
        (
            [String[]]$srcPath,
            [String]$trgPath,
            [Array]$excludes,  # exclusion rules. Can use wild cards (*)
            [ValidateSet('Fastest','NoCompression','Optimal')]$compLevel = 'Fastest'
        )
        $zipOptions = @{
            # get files to compress using exclusion filter
            Path = $(Get-ChildItem -Path $srcPath -Exclude $excludes)
            DestinationPath = $trgPath
            CompressionLevel = $compLevel
            }
        # Compress & Save
        Compress-Archive @zipOptions -Force
    }

    Function Remove-FilesInZip
    {
        Param
        (
            $zipfile,
            $files
        )

        [Reflection.Assembly]::LoadWithPartialName('System.IO.Compression')

        $stream = New-Object IO.FileStream($zipfile, [IO.FileMode]::Open)
        $mode   = [IO.Compression.ZipArchiveMode]::Update
        $zip    = New-Object IO.Compression.ZipArchive($stream, $mode)

        ForEach ($file in $files){($zip.Entries | Where-Object { [string]$_.FullName -match $file }) | ForEach-Object { $_.Delete() }}

        $zip.Dispose()
        $stream.Close()
        $stream.Dispose()
    }

    Function Get-MountPoints
    {
        $TotalGB = @{n="Capacity(GB)";e={[math]::round(($_.Capacity/ 1073741824),2)}}
        $FreeGB = @{n="FreeSpace(GB)";e={[math]::round(($_.FreeSpace / 1073741824),2)}}
        $FreePerc = @{n="Free(%)";e={[math]::round(((($_.FreeSpace / 1073741824)/($_.Capacity / 1073741824)) * 100),0)}}
        $volumes = Get-WmiObject win32_volume -Filter "DriveType='3'"
        $volumes | Select-Object Name, Label, DriveLetter, FileSystem, $TotalGB, $FreeGB, $FreePerc #| Format-Table -AutoSize
    }

#region symbolic links

# $trg = SearchLinks -srchPath 'C:\' -Hidden -type ReparsePoint -prefEA silentlycontinue
# $trg | select *Name,@{name='pspath';exp={($_.pspath).split(':{2}')[-2,-1]}},Target

# Paste-SymLink -lnk "C:\labSources" -trg "C:\Users\Chuck\OneDrive - Microsoft\RPS Srcs"

# Get-ChildItem C:\ | Where-Object { $_.Attributes -match "ReparsePoint" }

#MissionNet Redirects
# AutoLab Redirects

# Apple Data Redirect
$Redirects = @"
link,Path,Project,System
C:\lnkGITRepos,$env:USERPROFILE\OneDrive\Documents\GIT Repositories,MissionNet,
C:\LabSources,$env:USERPROFILE\OneDrive - Microsoft\RPS Srcs,MissionNet,
C:\ContentStore,C:\lnkGITRepos\MissionNet\VS Core 2.4\Release\ContentStore,MissionNet,
C:\lnkGITRepos\AutoLab\ISOs,E:\AutoLabISOs,AutoLab,
C:\lnkGITRepos\AutoLab\VMVirtualHardDisks,G:\SSDLabs1TB\AutoLab\VMVirtualHardDisks,AutoLab,
$env:USERPROFILE\AppData\Roaming\Apple Computer\MobileSync\Backup,G:\SSDLabs1TB\Phone Recovery\MobileSync\BackUp,AppleData,
"@ | ConvertFrom-CSV
$trg = ($Redirects | Where-Object{$_.project -eq 'MissionNet'})[0] #| fl
New-SymLink -link $trg.link -target $trg.Path # Test-ReparsePoint $trg.link

<# $trg = SearchLinks -srchPath 'C:\' -Recurse -Hidden -type ReparsePoint -prefEA silentlycontinue
# $trg | select *Name,@{name='pspath';exp={($_.pspath).split(':{2}')[-2,-1]}},Target

# Get-ChildItem C:\ | Where-Object { $_.Attributes -match "ReparsePoint" }

# $Link = @(,,,
#           "C:\RPS,C:\RPS","C:\ContentStore",
#           "","C:\LabSources",)
# $target = @(,,,
#             "G:\SSDLabs1TB\MissionNet\RPS","G:\PassportU4TB\Labs\MissionNet\RPS","G:\PassportU4TB\Labs\MissionNet\CurrentContentStore",
#             "G:\PassportU4TB\Labs\MissionNet\CurrentLabSource",,)

#>

    function ConvertFrom-ShortcutToXML{
    
        }

    Function Write-ZeroesToFreeSpace
    {
        <#
            .SYNOPSIS
                 Writes a large file full of zeroes to a volume in order to allow a storage
                 appliance to reclaim unused space.

            .DESCRIPTION
                 Creates a file called ThinSAN.tmp on the specified volume that fills the
                 volume up to leave only the percent free value (default is 5%) with zeroes.
                 This allows a storage appliance that is thin provisioned to mark that drive
                 space as unused and reclaim the space on the physical disks.
 
            .PARAMETER Root
                 The folder to create the zeroed out file in.  This can be a drive root (c:\)
                 or a mounted folder (m:\mounteddisk).  This must be the root of the mounted
                 volume, it cannot be an arbitrary folder within a volume.
 
            .PARAMETER PercentFree
                 A float representing the percentage of total volume space to leave free.  The
                 default is .05 (5%)

            .EXAMPLE
                 PS> Write-ZeroesToFreeSpace -Root "e:\"
 
                 This will create a file of all zeroes called c:\ThinSAN.tmp that will fill the
                 c drive up to 95% of its capacity.
 
            .EXAMPLE
                 PS> Write-ZeroesToFreeSpace -Root "c:\MountPoints\Volume1" -PercentFree .1
 
                 This will create a file of all zeroes called
                 c:\MountPoints\Volume1\ThinSAN.tmp that will fill up the volume that is
                 mounted to c:\MountPoints\Volume1 to 90% of its capacity.

            .EXAMPLE
                 PS> Get-WmiObject Win32_Volume -filter "drivetype=3" | Write-ZeroesToFreeSpace
 
                 This will get a list of all local disks (type=3) and fill each one up to 95%
                 of their capacity with zeroes.
 
            .NOTES
                 You must be running as a user that has permissions to write to the root of the
                 volume you are running this script against. This requires elevated privileges
                 using the default Windows permissions on the C drive.
        #>
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            [Alias("Name")]
            $Root,
            [ValidateRange(0,1)]
            $PercentFree =.05
        )
        process
        {
            #Convert the $Root value to a valid WMI filter string
            $FixedRoot = ($Root.Trim("\") -replace "\\","\\") + "\\"
            $FileName = "ThinSAN.tmp"
            $FilePath = Join-Path $Root $FileName
  
            #Check and make sure the file doesn't already exist so we don't clobber someone's data
            if( (Test-Path $FilePath) )
            {
                Write-Error -Message "The file $FilePath already exists, please delete the file and try again"
            }
            else
            {
            #Get a reference to the volume so we can calculate the desired file size later
            $Volume = Get-WmiObject win32_volume -filter "name='$FixedRoot'"
            if($Volume)
            {
                #I have not tested for the optimum IO size ($ArraySize), 64kb is what sdelete.exe uses
                $ArraySize = 64kb
                #Calculate the amount of space to leave on the disk
                $SpaceToLeave = $Volume.Capacity * $PercentFree
                #Calculate the file size needed to leave the desired amount of space
                $FileSize = $Volume.FreeSpace - $SpacetoLeave
                #Create an array of zeroes to write to disk
                $ZeroArray = new-object byte[]($ArraySize)
      
                #Open a file stream to our file 
                $Stream = [io.File]::OpenWrite($FilePath)
                #Start a try/finally block so we don't leak file handles if any exceptions occur
                try
                {
                    #Keep track of how much data we've written to the file
                    $CurFileSize = 0
                    while($CurFileSize -lt $FileSize)
                    {
                    #Write the entire zero array buffer out to the file stream
                    $Stream.Write($ZeroArray,0, $ZeroArray.Length)
                    #Increment our file size by the amount of data written to disk
                    $CurFileSize += $ZeroArray.Length
                }
              }
                finally
                {
                    #always close our file stream, even if an exception occurred
                    if($Stream) { $Stream.Close() }

                    #always delete the file if we created it, even if an exception occurred
                    if( (Test-Path $FilePath) ) { Remove-Item $FilePath }
                }
            }
            else { Write-Error "Unable to locate a volume mounted at $Root" }
        }
        }
    }

    Function Get-WWWebFile
    {
        Param ($WebFile,$lclFile)
        Invoke-WebRequest -Uri $WebFile -OutFile $lclFile
    }
    # Get-WWWebFile -WebFile "http://aka.ms/downloadazcopy" -lclFile "C:\temp\MicrosoftAzureStorageAzCopy_netcore_x64.msi"
