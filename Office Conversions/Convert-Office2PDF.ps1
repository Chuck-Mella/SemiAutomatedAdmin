<#
    Shoulders of Giants nod to:
      https://www.erickscottjohnson.com/blog--examples/how-to-convert-any-office-document-to-pdf-with-powershell 
      https://github.com/escottj/Doc2PDF/blob/master/Doc2PDF.ps1

    Doc2PDF
    Created: April 30, 2016
    Last Modified: June 16, 2016
    Version: 1.0
    Supported Office: 2010*, 2013, 2016
    Supported PowerShell: 4, 5
    Copyright © 2016 Erick Scott Johnson
    All rights reserved.
#>
Param ( $Input = $args[0 )
#region - Define Office Formats
    $Wrd_Array = '*.docx', '*.doc', '*.odt', '*.rtf', '*.txt', '*.wpd'
    $Exl_Array = '*.xlsx', '*.xls', '*.ods', '*.csv'
    $Pow_Array = '*.pptx', '*.ppt', '*.odp'
    $Pub_Array = '*.pub'
    $Vis_Array = '*.vsdx', '*.vsd', '*.vssx', '*.vss'
    $Off_Array = $Wrd_Array + $Exl_Array + $Pow_Array + $Pub_Array + $Vis_Array
    $ExtChk    = [System.IO.Path]::GetExtension($Input)
#endregion
#region - Functions
    # Word to PDF
        Function Wrd-PDF($f, $p)
        {
            $Wrd     = New-Object -ComObject Word.Application
            $Version = $Wrd.Version
            $Doc     = $Wrd.Documents.Open($f)

            #Check Version of Office Installed
            If ($Version -eq '16.0' -Or $Version -eq '15.0') {
                $Doc.SaveAs($p, 17) 
                $Doc.Close($False)
            }
            ElseIf ($Version -eq '14.0') {
                $Doc.SaveAs([ref] $p,[ref] 17)
                $Doc.Close([ref]$False)
            }
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $Wrd.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Wrd)
            Remove-Variable Wrd
        }

    # Excel to PDF
        Function Exl-PDF($f, $p)
        {
            $Exl = New-Object -ComObject Excel.Application
            $Doc = $Exl.Workbooks.Open($f)
            $Doc.ExportAsFixedFormat([Microsoft.Office.Interop.Excel.XlFixedFormatType]::xlTypePDF, $p)
            $Doc.Close($False)
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $Exl.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Exl)
            Remove-Variable Exl
        }

    # PowerPoint to PDF
        Function Pow-PDF($f, $p)
        {
            $Pow = New-Object -ComObject PowerPoint.Application
            $Doc = $Pow.Presentations.Open($f, $True, $True, $False)
            $Doc.SaveAs($p, 32)
            $Doc.Close()
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $Pow.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Pow)
            Remove-Variable Pow
        }

    # Publisher to PDF
        Function Pub-PDF($f, $p)
        {
            $Pub = New-Object -ComObject Publisher.Application
            $Doc = $Pub.Open($f)
            $Doc.ExportAsFixedFormat([Microsoft.Office.Interop.Publisher.PbFixedFormatType]::pbFixedFormatTypePDF, $p)
            $Doc.Close()
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $Pub.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Pub)
            Remove-Variable Pub
        }

    # Visio to PDF
        Function Vis-PDF($f, $p)
        {
            $Vis = New-Object -ComObject Visio.Application
            $Doc = $Vis.Documents.Open($f)
            $Doc.ExportAsFixedFormat([Microsoft.Office.Interop.Visio.VisFixedFormatType]::xlTypePDF, $p)
            $Doc.Close()
            [gc]::Collect()
            [gc]::WaitForPendingFinalizers()
            $Vis.Quit()
            [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Vis)
            Remove-Variable Vis
        }

    # Check for Formats
        Function Fmt-Chk($f, $e, $p, $fmt)
        {
            $f = [string]$f
            For ($i = 0; $i -le $Wrd_Array.Length; $i++)
            {
                $Temp = [string]$Wrd_Array[$i]
                $Temp = $Temp.TrimStart('*')
                If ($e -eq $Temp)
                {
                    Switch ($Fmt)
                    {
                        'Wrd' { Wrd-PDF $f $p }
                        'Exl' { Exl-PDF $f $p }
                        'Pow' { Pow-PDF $f $p }
                        'Pub' { Pub-PDF $f $p }
                        'Vis' { Vis-PDF $f $p }
                    }
                }
            }
        }
#endregion

# Check if input is file or directory
    If ($ExtChk -eq '')
    {
        $Files = Get-ChildItem -path $Input -include $Off_Array -recurse
        ForEach ($File in $Files) {
            $Path     = [System.IO.Path]::GetDirectoryName($File)
            $Filename = [System.IO.Path]::GetFileNameWithoutExtension($File)
            $Ext      = [System.IO.Path]::GetExtension($File)
            $PDF      = $Path + '\' + $Filename + '.pdf'
            'Wrd','Exl','Pow','Pub','Vis'  | %{ Fmt-Chk $File $Ext $PDF $_ } 
            }
    }
    Else
    {
        $File     = $Input
        $Path     = [System.IO.Path]::GetDirectoryName($File)
        $Filename = [System.IO.Path]::GetFileNameWithoutExtension($File)
        $Ext      = [System.IO.Path]::GetExtension($File)
        $PDF      = $Path + '\' + $Filename + '.pdf'
        'Wrd','Exl','Pow','Pub','Vis'  | %{ Fmt-Chk $File $Ext $PDF $_ } 
    }
# Cleanup
    'Wrd','Exl','Pow','Pub','Vis'  | %{ Remove-Item Function:$_-PDF, Function:$_-Chk }
