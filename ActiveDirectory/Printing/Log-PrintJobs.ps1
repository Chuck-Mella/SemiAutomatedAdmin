
# On Print Server, enable the following in local policy:
# Computer Configuration / Adminstrative Templates / Printers / Allow Job Name in Eventlog
Param
(
    $prntServer = 'VANPS010900-130',
    $trgLog = 'Microsoft-Windows-PrintService/Operational',
    $trgEvent = 307,
    $logFile = "\\vanfs030900-130\AD-IT\__LogCaptures\PrintJobs\PrintJobMonitor.csv",
    [Switch]$fixLogs
)
# Start-Transcript -Path "C:\automation\PrintJobs\ts_$(Get-Date -f yyyy-MM-dd_HHmm).log"

# Open Monitor Log and collect most recent Event
    $lastEvt = Import-Csv $logFile | %{ Get-Date $_.timecreated } | Sort -Desc | Select -First 1
    $startEvt = $lastEvt.AddSeconds(1)

# Collect Print Logs from Server
    Try
    {
        $prntLog = Get-winEvent -FilterHashtable @{LogName = $trgLog;ID = $trgEvent;StartTime = $startEvt} -ComputerName $prntServer -ea Stop
        $fmtLog = $prntLog | Select-Object -Property TimeCreated,
            @{n='UserName';e={$_.Properties[2].Value}},
            @{n='ComputerName';e={$_.Properties[3].Value}},
            @{n='PrinterName';e={$_.Properties[4].Value}},
            @{n='PrinterIP';e={$_.Properties[5].Value}},
            @{n='PrinterSize';e={$_.Properties[6].Value}},
            @{n='DocName';e={$_.Properties[1].Value}},
            @{n='Pages';e={$_.Properties[7].Value}}

        # Format Date/Time to correct sort
            ForEach ($item in $fmtLog)
            {
                $item.TimeCreated = ("{0:MM/dd/yyyy HH:mm:ss}" -f $item.TimeCreated)
            }

        # Appent new collection to existing log file
            $fmtLog | Export-Csv -Path $logFile -NoTypeInformation -Append
    }
    Catch
    {
        Write-Warning "No Events Found"; Break
    }

# Clean and trim log files
    If ($fixLogs.IsPresent -eq $true)
    {
        $log = Import-Csv -Path $logFile
        $scrub = ((Get-Date -f yyyy) - 1)
        $log | Where TimeCreated -Match $scrub | Export-Csv -Path ($logFile -replace "\.csv","_$scrub.csv") -NoTypeInformation -Append
        Sleep -Seconds 2
        $log | Where TimeCreated -NotMatch $scrub | Export-Csv -Path $logFile -NoTypeInformation

    }

# Stop-Transcript
