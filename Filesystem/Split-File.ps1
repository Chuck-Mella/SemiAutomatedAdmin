#function Split-File {
  <#
      .SYNOPSIS
          Splits a file into multiple parts
 
      .DESCRIPTION
          Splits a file into smaller parts. The maximum size of the part files can be specified. The number of parts required is calculated.
 
      .EXAMPLE
          Split-File -Path 'c:\test.zip' -PartSizeBytes 2.5MB
          Splits the file c:\test.zip in as many parts as necessary. Each part file is no larger than 2.5MB
 
      .EXAMPLE
          Split-File -Path 'c:\test.zip' -PartSizeBytes 2.5MB -AddSelfExtractor
          Splits the file c:\test.zip in as many parts as necessary. Each part file is no larger than 2.5MB
          Adds a powershell script that joins the parts when run, and adds a shortcut file to
          run the PowerShell extractor script on double-click, essentially adding a self-extractor
  #>


    
    param
    (
        # Path to the file you want to split
        [Parameter(Mandatory,HelpMessage='Path to the file you want to split')]
        [String]$Path,

        # maximum size of file chunks (in bytes)
        [int]$PartSizeBytes = 1MB,

        # when specified, add a an extractor script and link file to easily convert
        # chunks back into the original file
        [Switch]$AddSelfExtractor
    )

    try
    {
        # get the path parts to construct the individual part file names:
            $fullBaseName = [IO.Path]::GetFileName($Path)
            $baseName = [IO.Path]::GetFileNameWithoutExtension($Path)
            $parentFolder = [IO.Path]::GetDirectoryName($Path)
            $extension = [IO.Path]::GetExtension($Path)

        # get the original file size and calculate the # of required parts:
            $originalFile = New-Object -TypeName System.IO.FileInfo -ArgumentList ($Path)
            $totalChunks = [int]($originalFile.Length / $PartSizeBytes) + 1
            $digitCount = [int][Math]::Log10($totalChunks) + 1

        # read the original file and split into chunks:
            $reader = [IO.File]::OpenRead($Path)
            $count = 0
            $buffer = New-Object -TypeName Byte[] -ArgumentList $PartSizeBytes
            $moreData = $true

        # read chunks until there is no more data
            while($moreData)
            {
                # read a chunk
                $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
                # create the filename for the chunk file
                $chunkFileName = "$parentFolder\$fullBaseName.{0:D$digitCount}.part" -f $count
                Write-Verbose -Message "saving to $chunkFileName..."
                $output = $buffer

                # did we read less than the expected bytes?
                if ($bytesRead -ne $buffer.Length)
                {
                    # yes, so there is no more data
                    $moreData = $false
                    # shrink the output array to the number of bytes
                    # actually read:
                    $output = New-Object -TypeName Byte[] -ArgumentList $bytesRead
                    [Array]::Copy($buffer, $output, $bytesRead)
                }
                # save the read bytes in a new part file
                [IO.File]::WriteAllBytes($chunkFileName, $output)
                # increment the part counter
                ++$count
            }
            # done, close reader
            $reader.Close()

        # add self-extractor
            if ($AddSelfExtractor)
            {
                Write-Verbose -Message "Adding extractor scripts..."
            
                # define the self-extractor powershell script:
                $extractorName = "${fullBaseName}.{0:D$digitCount}.part.ps1" -f $count
                $extractorPath = Join-Path -Path $parentFolder -ChildPath $extractorName
                $filePath = '$PSScriptRoot\' + "$baseName$extension"

                # define the self-extractor shortcut file that launches
                # the powershell script on double-click:
                $linkName = "Extract ${fullBaseName}.lnk"
                $linkPath = Join-Path -Path $parentFolder -ChildPath $linkName

                # this will be used inside the extractor script to find the
                # part files via relative path:
                $currentFile = '"$PSCommandPath"'
                $currentFolder = '"$PSScriptRoot"'
            
                # write the extractor script source code to file:
                "
                    # copy the join-file source code into the extractor script:
                        function Join-File {
                        ${function:Join-File}
                        }
                    # join the part files and delete the part files after joining:
                        Join-File -Path `"$filePath`" -Verbose -DeletePartFiles

                    # remove both extractor scripts:
                        (Join-Path -Path $currentFolder -ChildPath '$linkName') | Remove-Item
                        Remove-Item -Path $currentFile
 
                    # open the extracted file in windows explorer
                        explorer.exe /select,`"$filepath`"
                " | Set-Content -Path $extractorPath

                # create a shortcut file that launches the extractor script
                # when it is double-clicked:
                $shell = New-Object -ComObject WScript.Shell
                $scut = $shell.CreateShortcut($linkPath)
                $scut.TargetPath = "powershell.exe"
                $scut.Arguments = "-nop -executionpolicy bypass -file ""$extractorPath"""
                $scut.WorkingDirectory = ""
                $scut.IconLocation = "$env:windir\system32\shell32.dll,162"
                $scut.Save()
            }
    }
    catch { throw "Unable to split file ${Path}: $_" }
#}





# Install-Module -Name FileSplitter
# Install-Module -Name SysAdminsFriends

function Join-File
{
  <#
      .SYNOPSIS
      Joins the parts created by Split-File and re-creates the original file
 
      .DESCRIPTION
      Use Split-File first to split a file into multiple part files with extension .part
      To join (recreate) the original file, specify the original file name (less the part number and the extension .part)
 
      .EXAMPLE
      Join-File -Path "C:\test.zip"
      Looks for the file c:\testzip.00.part and starts creating c:\test.zip from it. Once c:\test.zip.00.part is processed, it looks for more parts until
      no more parts are found.
 
      .EXAMPLE
      Join-File -Path "C:\test.zip" -DeletePartFiles
      Looks for the file c:\testzip.00.part and starts creating c:\test.zip from it. Once c:\test.zip.00.part is processed, it looks for more parts until
      no more parts are found.
      Once the original file c:\test.zip is recreated, all c:\test.zip.XXX.part files are deleted.
  #>


    
    param
    (
        # specify the path name of the original file (less incrementing number and less extension .part)
        [Parameter(Mandatory,HelpMessage='Path of original file')]
        [String]
        $Path,

        # when specified, delete part files after file has been created
        [Switch]
        $DeletePartFiles
    )

    try
    {
        # get the file parts
        $files = Get-ChildItem -Path "$Path.*.part" | 
        # sort by part
        Sort-Object -Property {
            # get the part number which is the "extension" of the
            # file name without extension
            $baseName = [IO.Path]::GetFileNameWithoutExtension($_.Name)
            $part = [IO.Path]::GetExtension($baseName)
            if ($part -ne $null -and $part -ne '')
            {
                $part = $part.Substring(1)
            }
            [int]$part
        }
        # append part content to file
        $writer = [IO.File]::OpenWrite($Path)
        $files |
        ForEach-Object {
            Write-Verbose -Message "processing $_..."
            $bytes = [IO.File]::ReadAllBytes($_)
            $writer.Write($bytes, 0, $bytes.Length)
        }
        $writer.Close()

        if ($DeletePartFiles)
        {
            Write-Verbose -Message "Deleting part files..."
            $files | Remove-Item
        }
    }
    catch
    {
        throw "Unable to join part files: $_"
    }
}

function Split-File
{
  <#
      .SYNOPSIS
      Splits a file into multiple parts
 
      .DESCRIPTION
      Splits a file into smaller parts. The maximum size of the part files can be specified. The number of parts required is calculated.
 
      .EXAMPLE
      Split-File -Path 'c:\test.zip' -PartSizeBytes 2.5MB
      Splits the file c:\test.zip in as many parts as necessary. Each part file is no larger than 2.5MB
 
      .EXAMPLE
      Split-File -Path 'c:\test.zip' -PartSizeBytes 2.5MB -AddSelfExtractor
      Splits the file c:\test.zip in as many parts as necessary. Each part file is no larger than 2.5MB
      Adds a powershell script that joins the parts when run, and adds a shortcut file to
      run the PowerShell extractor script on double-click, essentially adding a self-extractor
  #>


    
    param
    (
        # Path to the file you want to split
        [Parameter(Mandatory,HelpMessage='Path to the file you want to split')]
        [String]
        $Path,

        # maximum size of file chunks (in bytes)
        [int]
        $PartSizeBytes = 1MB,

        # when specified, add a an extractor script and link file to easily convert
        # chunks back into the original file
        [Switch]
        $AddSelfExtractor
    )

    try
    {
        # get the path parts to construct the individual part
        # file names:
        $fullBaseName = [IO.Path]::GetFileName($Path)
        $baseName = [IO.Path]::GetFileNameWithoutExtension($Path)
        $parentFolder = [IO.Path]::GetDirectoryName($Path)
        $extension = [IO.Path]::GetExtension($Path)

        # get the original file size and calculate the
        # number of required parts:
        $originalFile = New-Object -TypeName System.IO.FileInfo -ArgumentList ($Path)
        $totalChunks = [int]($originalFile.Length / $PartSizeBytes) + 1
        $digitCount = [int][Math]::Log10($totalChunks) + 1

        # read the original file and split into chunks:
        $reader = [IO.File]::OpenRead($Path)
        $count = 0
        $buffer = New-Object -TypeName Byte[] -ArgumentList $PartSizeBytes
        $moreData = $true

        # read chunks until there is no more data
        while($moreData)
        {
            # read a chunk
            $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
            # create the filename for the chunk file
            $chunkFileName = "$parentFolder\$fullBaseName.{0:D$digitCount}.part" -f $count
            Write-Verbose -Message "saving to $chunkFileName..."
            $output = $buffer

            # did we read less than the expected bytes?
            if ($bytesRead -ne $buffer.Length)
            {
                # yes, so there is no more data
                $moreData = $false
                # shrink the output array to the number of bytes
                # actually read:
                $output = New-Object -TypeName Byte[] -ArgumentList $bytesRead
                [Array]::Copy($buffer, $output, $bytesRead)
            }
            # save the read bytes in a new part file
            [IO.File]::WriteAllBytes($chunkFileName, $output)
            # increment the part counter
            ++$count
        }
        # done, close reader
        $reader.Close()

        # add self-extractor
        if ($AddSelfExtractor)
        {
            Write-Verbose -Message "Adding extractor scripts..."
            
            # define the self-extractor powershell script:
            $extractorName = "${fullBaseName}.{0:D$digitCount}.part.ps1" -f $count
            $extractorPath = Join-Path -Path $parentFolder -ChildPath $extractorName
            $filePath = '$PSScriptRoot\' + "$baseName$extension"

            # define the self-extractor shortcut file that launches
            # the powershell script on double-click:
            $linkName = "Extract ${fullBaseName}.lnk"
            $linkPath = Join-Path -Path $parentFolder -ChildPath $linkName

            # this will be used inside the extractor script to find the
            # part files via relative path:
            $currentFile = '"$PSCommandPath"'
            $currentFolder = '"$PSScriptRoot"'
            
            # write the extractor script source code to file:
            "
                # copy the join-file source code into the extractor script:
                function Join-File {
                ${function:Join-File}
                }
                # join the part files and delete the part files after joining:
                Join-File -Path ""$filePath"" -Verbose -DeletePartFiles
 
                # remove both extractor scripts:
                (Join-Path -Path $currentFolder -ChildPath '$linkName') | Remove-Item
                Remove-Item -Path $currentFile
 
                # open the extracted file in windows explorer
                explorer.exe ""/select,""""$filepath""""""
            " | Set-Content -Path $extractorPath

            # create a shortcut file that launches the extractor script
            # when it is double-clicked:
            $shell = New-Object -ComObject WScript.Shell
            $scut = $shell.CreateShortcut($linkPath)
            $scut.TargetPath = "powershell.exe"
            $scut.Arguments = "-nop -executionpolicy bypass -file ""$extractorPath"""
            $scut.WorkingDirectory = ""
            $scut.IconLocation = "$env:windir\system32\shell32.dll,162"
            $scut.Save()
        }
    }
    catch
    {
        throw "Unable to split file ${Path}: $_"
    }
}

$filePath = "C:\Users\charles.a.mella.ctr\Downloads\Secure Host Baseline Framework v10.2004.0\SHB_Framework_v10.2004.0.exe"


Split-File -Path $filePath -PartSizeBytes 120.5MB -AddSelfExtractor 