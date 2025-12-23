# Verify Admin Rights
Function Test-IsAdmin
{
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    Switch ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
    {
        $true  { Return $true }
        $false { Return $false }
    }
}
If ((Test-IsAdmin) -eq $false){ Write-Host -f Magenta 'The current user context requires adminitrative rights.  EXITING  '}

# Collect Cleared Event Logs
$clrEvents = Get-WinEvent -FilterHashTable @{
                                LogName = "system";
                                # StartTime = $(Get-Date 4/3/2022)
                                ID = 104
                                } | Where Message -like "*file was cleared*"

$lstClrEvents = ForEach ($clr in $clrEvents) { $clr | Select ID,TimeCreated,@{n='Logname';e={$_.Message.split(' ')[1]}} } 

# Clear Event Logs
Clear-EventLog -LogName 'Application' -WhatIf


$test = $lstClrEvents[-1]

$el = get-eventlog -log $test.Logname -After $test.TimeCreated -EntryType Error, Warning


$el | Export-Clixml "$(& Hostname)_$($test.Logname)_evtlog_$((get-date $test.TimeCreated -f yyyyMMdd))-$((get-date -f yyyyMMdd)).xml"