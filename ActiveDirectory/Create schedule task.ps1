Function Get-Key
{
    Param ( [switch]$pt,$it )
    $curDomain = ([Directoryservices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
    $keyFile = "\\$curDomain\SYSVOL\$curDomain\scripts\PSScripts_GPO\key$it.bin"
    $aesKey = (GC $keyFile)[0..31]
    $encText = (GC $keyFile)[-1] | convertTo-securestring -Key $aesKey
    $rslt = ($obj = New-object system.Management.Automation.Pscredential ('',$encText)).Password
    if ( $pt.IsPresent -eq $true )
    {
        $blue = [System.Runtime.Interopservices.Marshal]::securestringToCoTaskMemunicode($rslt)
        $red = [System.Runtime.Interopservices.Marshal]::PtrToStringuni($blue)
        [System.Runtime.Interopservices.Marshal]::zeroFreeCoTaskMemunicode($blue)
    }
    $rslt = $obj.GetNetworkcredential().Password
    Return $rslt
}
$curDomain = ([Directoryservices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
$Params = [Ordered]@{
    TaskName = "server Event Capture"
    Description = 'Daily Eventlog Backup'
    Trigger = New-scheduledTaskTrigger -At 23:00 -Daily
    Action = New-scheduledTaskAction -Execute 'Powershell.exe' -Argument "-NoLogo -NoProfile -ExecutionPolicy ByPass -file `"\\$curDomain\SYSVOL\$curDomain\scripts\PSScripts_GPO\Backup*EventLogs.psl`""
    settings = New-ScheduledTaskSettingsSet -compatibility win8
    user = "$((Get-ADDomain).NetBIOSName)\svc_PoshscriptAdm"
    Password = "(Get-Key -pt -it $null )"
    TaskPath = '\ScriptedTasks'
    RunLevel = 'Highest'
    }
Register-ScheduledTask @Params
