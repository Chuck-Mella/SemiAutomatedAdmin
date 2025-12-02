    Function Test-VMState($trgVM)
    {
        $cntOS,$cntNet = 1,1
        do
        {
            $rslt = Get-VMIntegrationService -VMName $trgVM |
                Where-Object Name -eq "Heartbeat" |
                    Select -ExpandProperty PrimaryStatusDescription
            Sleep -Seconds 2
            Write-Host -F Yellow "Testing OS - Attempt: $cntOS - Retry in 2 Seconds"
            $cntOS ++
        }until($rslt -eq 'OK')
        Write-Host -F Green "OS-OK"
        do
        {
            $IPs = Get-VMNetworkAdapter -VMName $trgVM | Select IPAddresses
            Sleep -Seconds 2
            Write-Host -F Yellow "Testing NIC - Attempt: $cntNet - Retry in 2 Seconds"
            $cntNet ++
        }while($null -eq $IPs)
        Write-Host -F Green "online"
        Return "Ready"
    }
