Function Remove-InSeries
{
    Param ($String, $Delim = '\', [switch]$First, [switch]$Last)
    If ($First.IsPresent){ Return ($String -replace "^\w+[^\$Delim]+\$Delim") }
    If ($Last.IsPresent){ Return ($String -replace "\$Delim+[^\$Delim]+$") }
}

Remove-InSeries -String "C:\dir1\dir2\dir3\file.1" -Delim '\' -First
Remove-InSeries -String "C:\dir1\dir2\dir3\file.1" -Delim '\' -Last

