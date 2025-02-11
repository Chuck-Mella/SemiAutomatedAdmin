#Function Join-File {
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
        [String]$Path,

        # when specified, delete part files after file has been created
        [Switch]$DeletePartFiles
    )

    try
    {
        # get the file parts
            $files = Get-ChildItem -Path "$Path.*.part" | 
            # sort by part
                Sort-Object -Property {
                    # get the part # which is the "extension" of the file name w/o extension
                    $baseName = [IO.Path]::GetFileNameWithoutExtension($_.Name)
                    $part = [IO.Path]::GetExtension($baseName)
                    if ($part -ne $null -and $part -ne '') { $part = $part.Substring(1) }
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
    catch { throw "Unable to join part files: $_" }
#}
