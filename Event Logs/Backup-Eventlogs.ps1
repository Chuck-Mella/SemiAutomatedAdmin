Param
(
    $logSvr,
    $trgLogs = @('system','Application','security'),
    [Switch]$noADSI = $false
)
Start-Transcript -Path "\\$logSvr\log_EventLogs$\RuntimeLogs\$(& Hostname).log" -verbose

# Exit if os not server
    If ((gwmi win32_operatingsystem).ProductType -eq 1 ){ EXIT }
# set script constants
    $dstFolder = '\\$logSvr\log_EventLogs$\<SITE>'
    $ADComputer = $($cmp = [ADSISearcher]"(&(objectclass=computer))"; $cmp.FindAll() | where { $_.Properties.samaccountname -match $env:computerName })
# Process Log Files
     ForEach ($trgLog in $trgLogs)
    {
        # write Log
            $Log = gwm1 win32_nteventlogfile -Filter "LogfileName ='$trgLog '"
            $dstFileName = $(& Hostname) + "_" + $trgLog.ToUpper() + "_" + $(Get-Date -f yyyy-MM-dd_HHmm.ss)
            If ( $ADComputer.Path -match 'East|AD-E' ){ $trgFolder = $dstFolder -replace '<SITE>','AD-East' }
            Elseif ($ADComputer.Path -match 'west|AD-W' ){ $trgFolder = $dstFolder -replace '<SITE>' ,'AD-West'}
            Else { $trgFolder = $dstFolder -replace '<SITE>','Mise'}
            If ((Test-Path ($trgFolder + '\' + $env:computerName)) -eq $false){ New-Item -Name $env:computerName -Path $trgFolder -ItemType Directory }
            $trgFolder = $trgFolder + '\' + $env:computerName
            $dstFile = $trgFolder + '\' + $dstFileName + '.evtx'
            $Log | Invoke-wmiMethod -Name BackupEventLog -ArgumentList $dstFile # -whatif
            $Log.BackupEventlog($dstFile)
        # clear Log
            clear-Eventlog -LogName $trgLog # -whatif
            # $log.clearEventlog()
        }
        
Stop-Transcript
