Function Get-ZipFileContent
{
    # https://techibee.com/powershell/reading-zip-file-contents-without-extraction-using-powershell/2152
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
            [string[]]$FileName,
        [String]$ExportCSVFileName
    )
    #Exit if the shell is using lower version of dotnet
        $dotnetversion = [Environment]::Version
        if(!($dotnetversion.Major -ge 4 -and $dotnetversion.Build -ge 30319))
        {
            write-error "You are not having Microsoft DotNet Framework 4.5 installed. Script exiting"
            exit(1)
        }
    # Import dotnet libraries
        [Void][Reflection.Assembly]::LoadWithPartialName('System.IO.Compression.FileSystem')
        $ObjArray = @()

        ForEach($zipfile in $FileName)
        {
            If (Test-Path $ZipFile)
            {
                $RawFiles = [IO.Compression.ZipFile]::OpenRead($zipFile).Entries
                ForEach($RawFile in $RawFiles)
                {
                    $object = New-Object -TypeName PSObject
                    $Object | Add-Member -MemberType NoteProperty -Name FileName -Value $RawFile.Name
                    $Object | Add-Member -MemberType NoteProperty -Name FullPath -Value $RawFile.FullName
                    $Object | Add-Member -MemberType NoteProperty -Name CompressedLengthInKB -Value ($RawFile.CompressedLength/1KB).Tostring("00")
                    $Object | Add-Member -MemberType NoteProperty -Name UnCompressedLengthInKB -Value ($RawFile.Length/1KB).Tostring("00")
                    $Object | Add-Member -MemberType NoteProperty -Name FileExtn -Value ([System.IO.Path]::GetExtension($RawFile.FullName))
                    $Object | Add-Member -MemberType NoteProperty -Name ZipFileName -Value $zipfile
                    $ObjArray += $Object
                    If (!$ExportCSVFileName) { $Object }
                }
            }
            Else { Write-Warning "$ZipFileInput File path not found" }
            If ($ExportCSVFileName)
            {
                Try { $ObjArray  | Export-CSV -Path $ExportCSVFileName -NotypeInformation }
                Catch { Write-Error "Failed to export the output to CSV. Details : $_" }
            }

        }
}

Function Create-7zip
{
    Param
    (
        [String] $aDirectory,
        [String] $aZipfile,
        [string]$pathToZipExe = "$($Env:ProgramFiles)\7-Zip\7z.exe"
    )
    [Array]$arguments = "a", "-tzip", "$aZipfile", "$aDirectory", "-r";
    & $pathToZipExe $arguments;
}
