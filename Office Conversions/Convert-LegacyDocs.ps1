Param
(
    $netRoot = "\\Server\Share",
    [switch]$remove = $false
)

$rptDir = (Get-ChildItem -Path $netRoot -Directory -Include ' *').FullName
$lvl1Dirs = (Get-ChildItem -Path $netRoot -Directory -Exclude ' *').Name
$prblmDirs = @('pDir')

#region - Dump filtered GCIs to temp variables
    ForEach ($dir in $lvl1Dirs)
    {
        If ($prblmDirs -contains $dir){ CONTINUE }
        Else
        {
            subst B: "$netRoot\$dir"
            # New-PSDrive -Name B -Root "$netRoot\$dir" -PSProvider FileSystem
            Set-Variable -Name "Scan_$dir" -Value (Get-ChildItem -Path B: -File -Recurse -Force | Where-Object -FilterScript { $_.Extension -match '(\.doc$|\.xls$|\.ppt$|\.vsd$)' })
            subst B: /d
            # Remove-PSDrive B
        }
    }
#endregion

#region - Dump variables to XML files (null xmls saved as results csv)
    ForEach ($scan in Get-Variable Scan_*)
    {
        $sPath = "$rptDir\$($scan.Name -replace 'Scan_')"
        If ($scan.Value -ne $null){ $scan.Value | Export-Clixml -LiteralPath "$sPath`_Files.xml" -Force }
        Else { "$netRoot\$($scan.Name -replace 'Scan_'),No Targeted files located in folders" |
            ConvertFrom-Csv -Header Path,Result |
            Export-Csv -LiteralPath "$sPath`_Results.csv" -NoTypeInformation -Force }
        # Remove un-needed variables
        $tp1 = Test-Path -LiteralPath "$sPath`_Files.xml"
        $tp2 = Test-Path -LiteralPath "$sPath`_Results.csv"
        If ($tp1 -or $tp2 ){ Remove-Variable -Name $scan.Name -Force }
    }
#endregion

#region - Functions
    Function Get-LongestCommonPrefix
    {
        Param ( [Parameter(Mandatory=$true)][String[]]$Paths )
        $k = $Paths[0].Length

        for ($i = 1; $i -lt $Paths.Length; $i++)
        { 
            $k = [Math]::Min($k, $Paths[$i].Length)
            for ($j = 1; $j -lt $k; $j++)
             { 
                 If ( $Paths[$i][$j] -ne $Paths[0][$j]){ $k = $j; BREAK }
             }
        }
    
        Return $Paths[0].Substring(0,$k)
    }
    # Get-LongestCommonPrefix $x.FullName
    Function Convert-OfficeFilesV2
    {
        Param ( [Parameter(Mandatory=$true)][array]$files,[Parameter(Mandatory=$true)]$compartment )

        #region - Functions (Conversion)
            Function Convert-OldOffice 
            {
                [CmdletBinding()]
                Param ( [Parameter(Mandatory=$true)]$officeFile )

                $rslt = @{} | Select-Object File,Result,ErrMsg
                Switch ($officeFile.Extension)
                {
                    '.doc'
                    {
                    $Word = New-Object -ComObject Word.Application
                    $Word.Visible = 0
                    $Word.DisplayAlerts = 0
                    $wdFixedFormat = [Microsoft.Office.Interop.Word.wdSaveFormat]::wdFormatDocumentDefault
                    $path = $officeFile.DirectoryName + '\' + $officeFile.BaseName + '.docx'

                    Try
                    {
                        Try
                        {
                        $Document = $Word.Documents.Open($officeFile.FullName,$null,$null,$null,"123$%^789")
                        If ($Document.HasVBProject)
                        {
                            $wdFixedFormat = [Microsoft.Office.Interop.Word.wdSaveFormat]::xlOpenXMLWorkbookMacroEnabled
                            $path = $path -replace '.docx','.docm'
                        }
                        $Document.SaveAs([ref]$path, [ref]$wdFixedFormat)
                        $Document.Close()
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERTED SUCCESSFULLY'
                        $rslt.ErrMsg = $null
                        }
                        Catch
                        {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'PASSWORD PROTECTED'
                        $rslt.ErrMsg = $null
                        }
                    }
                    Catch [Runtime.InteropServices.COMException]
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'FILE NOT FOUND'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    Catch
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERSION FAILED'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    $Word.Quit()
                    $Word = $Null
                    }
                    '.xls'
                    {
                    $Excel = New-Object -ComObject Excel.Application
                    $Excel.Visible = 0
                    $Excel.DisplayAlerts = 0
                    $xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlOpenXMLWorkbook
                    $path = $officeFile.DirectoryName + '\' + $officeFile.BaseName + '.xlsx'

                    Try
                    {
                        Try
                        {
                        $WorkBook = $Excel.Workbooks.Open($officeFile.FullName, 0, $true,$null,"123$%^789")
                        If ($WorkBook.HasVBProject)
                        {
                            $xlFixedFormat = [Microsoft.Office.Interop.Excel.XlFileFormat]::xlOpenXMLWorkbookMacroEnabled
                            $path = $path -replace '.xlsx','.xlsm'
                        }
                        $WorkBook.SaveAs($path, $xlFixedFormat)
                        $WorkBook.Close()
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERTED SUCCESSFULLY'
                        $rslt.ErrMsg = $null
                        }
                        Catch
                        {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'PASSWORD PROTECTED'
                        $rslt.ErrMsg = $null
                        }
                    }
                    Catch
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERSION FAILED'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    $Excel.Quit()
                    $Excel = $Null
                    }
                    '.ppt'
                    {
                    $PowerPoint = New-Object -ComObject PowerPoint.Application
                    $PowerPoint.DisplayAlerts = 1
                    $pptFixedFormat = [Microsoft.Office.Interop.PowerPoint.PpSaveAsFileType]::ppSaveAsOpenXMLPresentation
                    $path = $officeFile.DirectoryName + '\' + $officeFile.BaseName + '.pptx'

                    Try
                    {
                        $Presentation = $PowerPoint.Presentations.Open($officeFile.FullName, `
                        [Microsoft.Office.Core.MsoTriState]::msoTrue, `
                        [Microsoft.Office.Core.MsoTriState]::msoFalse, `
                        [Microsoft.Office.Core.MsoTriState]::msoFalse)
                        If ($Presentation.HasVBProject)
                        {
                            $pptFixedFormat = [Microsoft.Office.Interop.PowerPoint.PpSaveAsFileType]::ppSaveAsOpenXMLPresentationMacroEnabled
                            $path = $path -replace '.pptx','.pptm'
                        }
                        $Presentation.SaveAs($path, $pptFixedFormat)
                        $Presentation.Close()
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERTED SUCCESSFULLY'
                        $rslt.ErrMsg = $null
                    }
                    Catch [Runtime.InteropServices.COMException]
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'ORIGINAL FILE CORRUPTED'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    Catch
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERSION FAILED'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    $Powerpoint.Quit()
                    $PowerPoint = $Null
                    }
                    '.vsd'
                    {
                    $Visio = New-Object -ComObject Visio.Application # | Wait-Process -Timeout $maximumRuntimeSeconds -ErrorAction Stop
                    $Visio.Visible = 0
                    $Visio.AlertResponse = 1
                    $path = $officeFile.DirectoryName + '\' + $officeFile.BaseName + '.vsdx'

                    Try
                    {
                        $VisioDiagram = $Visio.Documents.Open($officeFile.FullName)
                        If ($VisioDiagram.HasVBProject)
                        {
                            $rslt.File = $officeFile.FullName
                            $rslt.Result = 'MACRO-ENABLED DOCUMENT'
                            $rslt.ErrMsg = 'File has macros enabled (VBA code), skipping.'
                        }
                        Else
                        {
                            $VisioDiagram.SaveAs($path)
                            $VisioDiagram.Close()
                            $rslt.File = $officeFile.FullName
                            $rslt.Result = 'CONVERTED SUCCESSFULLY'
                            $rslt.ErrMsg = $null
                        }
                    }
                    Catch
                    {
                        $rslt.File = $officeFile.FullName
                        $rslt.Result = 'CONVERSION FAILED'
                        $rslt.ErrMsg = $Error[0].Exception.Message
                    }
                    $Visio.Quit()
                    $Visio = $Null
                    }
                }
                [gc]::Collect()
                [gc]::WaitForPendingFinalizers()

                Return $rslt
            }
        #endregion

        # Convert the files
            $results = [Collections.ArrayList]@()
            $countdown = $files.Count
            ForEach ($file in $files) #{}
            {
                $countdown - $countdown - 1
                Write-Host "Processing $file"

                If ($file -is [string]){ $itm = Try { Get-ChildItem -LiteralPath $file -EA Stop } Catch { 'NOT FOUND'} }
                Else { $itm = $file }

                If ($itm -eq 'NOT FOUND')
                { # File deleted after scan but before conversion
                    $rst = @{} | Select-Object File,Result,ErrMsg
                    $rst.File = $file
                    $rst.Result = 'MISSING DOCUMENT'
                    $rst.ErrMsg = "Unable to locate, file may have been deleted prior to conversion attempt."
                }
                ElseIf ((Test-Path -LiteralPath "$($itm.FullName)") -AND (Test-Path -LiteralPath "$($itm.FullName)x"))
                { # Test if file has already been converted
                    $rst = @{} | Select-Object File,Result,ErrMsg
                    $rst.File = $itm.FullName
                    $rst.Result = 'PREVIOUSLY CONVERTED'
                    $rst.ErrMsg = "An updated file already exists, file may have been previously converted or a new document was created. Skipping."
                }
                Else
                {
                    If ($itm.Length -eq 0){ # Test if file has content (Delete & skip if 0)
                        $rst = @{} | Select-Object File,Result,ErrMsg
                        $rst.File = $itm.FullName
                        $rst.Result = 'EMPTY DOCUMENT'
                        $rst.ErrMsg = "File Size: $($itm.Length), Deleted."
                        Remove-Item -LiteralPath ("{0}" -f $itm.FullName) -Verbose -Force -Confirm:$false
                    }
                    ElseIf ($itm.BaseName -match '^~' -AND $itm.Length -eq 162){ # Test if orphaned temp file (Delete & skip if true)
                        $rst = @{} | Select-Object File,Result,ErrMsg
                        $rst.File = $itm.FullName
                        $rst.Result = 'ORPHANED TEMP DOCUMENT'
                        $rst.ErrMsg = "File Size: $($itm.Length), Deleted."
                        Remove-Item -LiteralPath ("{0}" -f $itm.FullName) -Verbose -Force -Confirm:$false
                    }
                    Else
                    {
                        # Test if file is MS Office document
                        $typeTest = [IO.File]::ReadAllBytes($itm.FullName)
                        $test = ((0..3 | ForEach-Object{ '{0:x2}' -f $typeTest[$_] }) -join '')
                        If ($test -ne 'd0cf11e0'){
                            $rst = @{} | Select-Object File,Result,ErrMsg
                            $rst.File = $itm.FullName
                            $rst.Result = 'NOT MS OFFICE DOCUMENT'
                            $rst.ErrMsg = "ByteCheck: $test"
                        }
                        Else
                        {
                            $rst = Convert-OldOffice($itm)
                        }
                    }

                }
                $null = $results.Add($rst)
                Write-Host -f Cyan "Files Remaining($($files.Count)): $countdown"
            }
        # Save results
            $results | Export-Csv -Delim ',' -NoTypeInformation -LiteralPath "$rptDir\$($compartment)_Results.csv" -Force

    }
#endregion

#region - V2 Conversion Code
    $dataFile = Get-ChildItem $rptDir -Filter *.xml |
        Where-Object { $_.Name -notmatch '_done.' } |
            Out-GridView -PassThru -Title 'Select DataSet'

    If ($dataFile -ne $null)
    {
        #region - Collect files to be converted
            ($dataSet = Import-Clixml $dataFile.FullName).Count

            # Empty Files
                ($mtSet = $dataSet | Where-Object Length -eq 0).Count
            # orphaned Temp Files
                ($openSet = $dataSet | Where-Object Name -match '^~').Count
                # Files to be processed
                ($modSet = $dataSet).Count
        #endregion

        #region - Convert ModSet files
            subst B: "$netRoot\$($dataFile.BaseName -replace '_Files')"
            Convert-OfficeFilesV2 -files $modSet.FullName -compartment ($dataFile.BaseName -replace '_Files')
            subst B: /d
            Rename-Item $dataFile.FullName "$($dataFile.BaseName)_DONE.xml"
        #endregion

        #region - Remove converted files
            # Collect conversion results and select successful items only
                $rsltCSV = Import-Csv -Path ($dataFile.Fullname -replace 'Files','Results' -replace 'xml','csv')
                $delFiles = $rsltCSV | Where-Object Result -eq 'CONVERTED SUCCESSFULLY'
                $rsltCSV.Count
                $delFiles.Count

            # Delete converted originals (Only if new format file exists)
                subst B: "$netRoot\$($dataFile.BaseName -replace '_Files')"
                ForEach ($fyl in $delFiles)
                {
                    If ((Test-Path "$($fyl.File)x") -OR (Test-Path "$($fyl.File)m"))
                    {
                        If (Test-Path "$($fyl.File)"){ Remove-Item -Path $fyl.File -Force -Verbose } # -WhatIf 
                    }
                }

                # Delete Empty Files & Orphaned Temp Files
                    # $mtSet.FullName | %{ Remove-Item -Path ("{0}" -f $_) -Force -Verbose } # -WhatIf 
                    # $openSet.FullName | %{ Remove-Item -Path ("{0}" -f $_) -Force -Verbose } # -WhatIf 
                & "$env:windir\system32\subst.exe" B: /d
        #endregion
    }
#endregion

#region - Metrics Code
    $metrics = @{} | Select Success,Fail,Corrupted,Missing,Temp,Macro,PWD,Converted,Empty,Non-MSO,ByteCheck
    $rsltRoot = '<PATH>\ Legacy Office File Conversions'
    '1st Run','2nd Run','~_3rd Run' | ForEach
    {
        $files = GCI -L $rsltRoot\$_ -Recurse -Filter *.csv
        ForEach ($files in $files)
        {
            $metrics.Success    += ($met | Where Result -eq 'CONVERTED SUCCESSFULLY').Count
            $metrics.Fail       += ($met | Where Result -eq 'CONVERSION FAILED').Count
            $metrics.Corrupted  += ($met | Where Result -eq 'ORIGINAL FILE CORRUPTED').Count
            $metrics.Missing    += ($met | Where Result -eq 'MISSING DOCUMENT').Count
            $metrics.Temp       += ($met | Where Result -eq 'ORPHANED TEMP DOCUMENT').Count
            $metrics.Macro      += ($met | Where Result -eq 'MACRO-ENABLED DOCUMENT').Count
            $metrics.Empty      += ($met | Where Result -eq 'EMPTY DOCUMENT').Count
            $metrics.PWD        += ($met | Where Result -eq 'PASSWORD PROTECTED').Count
            $metrics.'Non-MSO'  += ($met | Where Result -eq 'NOT MS OFFICE DOC').Count
            $metrics.Converted  += ($met | Where Result -eq 'PREVIOUSLY CONVERTED').Count
            $metrics.ByteCheck  += ($met | Where Result -eq 'NOT MS OFFICE DOC' | Select -Exp ErrMsg) -replace 'ByteCheck: '
        }
    }

    # Get-Process *Word*,*Excel*,*Point*,*Visio* | Stop-Process -Force
#endregion
