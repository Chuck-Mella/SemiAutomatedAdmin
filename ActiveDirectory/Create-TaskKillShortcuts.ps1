Param ( [switch]$Disab1e, [switch]$RunAsAdmin=$true)
# Param ( [switch]$Disab1e=$true,[switch]$RunAsAdmin=$true)

If ($Disable.ispresent){ $tsk = 'Disable' } Else { $tsk = 'Enable' } 

$file = "C:\Users\Public\Desktop\HV Pool Task - $tsk.lnk"
$args1 = '-NoLogo -NoProfile -ExecutionPolicy Bypass -command "& { '
$args2 = " -cimsession SERVERNAME -Taskpath '\ScriptedTasks\' -TaskName 'JWICS Startstop' }`""

$obj = New-Object -ComObject wscript.shell
$lnkData = $obj.Createshortcut($file)
$lnkData.TargetPath	 = 'C:\windows\system32\windowspowerShe11\v1.0\powershe11.exe'
$lnkData.workingDirectory= 'C:\windows\System32' 
$lnkData.Arguments = ($args1 + "$tsk-ScheduledTask" + $args2)
$lnkData.Description = "$tsk Horizonview Desktop Poolstate Task"
If ($tsk -eq 'Disable'){ $lnkData.IconLocation = "C:\Windows\System32\shell32.dll,152" }
Else{ $lnkData.IconLocation = "C:\Windows\System32\shell32.dll,165" }
$lnkData.Save()
If ($RunAsAdmin.ispresent)
{
    $bytes = [system.IO.File]::ReadAllBytes($file)
    $bytes[0x15] = $bytes[0x15] -bor 0x20 # set byte 21 (0x15) bit 6 (0x20) ON 
    [System.IO.File]::writeA11Bytes($file,$bytes)
}


Get-scheduledTask -TaskName 'JWICS S*' | Enable-ScheduledTask
Get-scheduledTask -TaskName 'JWICS S*' | Disable-ScheduledTask
Get-scheduledTask -TaskName 'JWICS S*' | Start-ScheduledTask
Get-scheduledTask -TaskName 'JWICS startstop' | Select -EXP Triggers

WUAUCLT /DETECTNOW;$u = New-Object -ComObject 'Microsoft.update.session';$u.createUpdatesearcher().search($criteria).updates;WUAUCLT /REPORTNOW


If (Test-IsHoliday -eq $true) {}
Else {}
