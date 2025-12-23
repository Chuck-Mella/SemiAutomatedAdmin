#Requires -RunAsAdministrator
[DateTime]$starttime = Get-Date
$trgVol = 'Jenny'
# Connect and Verify Removable Device
    $drvWSUS = 'U:\WSUS'
    $drvRem = gwmi Win32_LogicalDisk | Where VolumeName -eq $trgVol | Select -Exp DeviceID
    If ($drvRem -eq $null) { Write-Warning "$trgVol Device not connected; EXITING"; Break }
    Else { Write-Host -f Green "$trgVol device located as [$drvRem]" }


# Remove unrequired and irrelevant updates
    # Load WSUS
        [reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
        $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
        $ListOfUpdates = $wsus.getupdates() 

    # Decline N/A WSUS Updates
        # Decline Lang Packs
            $subSet = $ListOfUpdates | where {$_.title -like "*Lang*" `
                                         -and $_.title -notlike "*en-us*"}
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }
    
        # Decline Chinese versions
            $subSet = $ListOfUpdates | where {$_.title -like  "*Pro N*" `
					                      -or $_.title -like  "*Education N*" `
				                          -or $_.title -like  "*Enterprise N*" }
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }

        # Decline Non-Intel
            $subSet = $ListOfUpdates | where {$_.title -like "*Arm64*" `
 					                      -or $_.title -like  "*AMD64*"}
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }

        # Decline 32Bit
            $subSet = $ListOfUpdates | where {$_.title -like "*x86*"}
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }

        # Decline Previews
            $subSet = $ListOfUpdates | where {$_.title -like "*Preview*"}
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }
       
        # Decline Obsolete Windows
            $subSet = $ListOfUpdates | where {$_.title -like "*business editions*" `
						                  -or $_.title -like  "*Microsoft Office IME*" `
						                  -or $_.title -like  "* 1507*" `
						                  -or $_.title -like  "* 1511*" `
						                  -or $_.title -like  "* 1703*" `
						                  -or $_.title -like  "* 1709*"}
            $subSet | Select Title
            $subSet | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }

        # Decline Superseded Updates
            $subSet = $wsus.getupdates() | where {$_.Issuperseded -eq $true}
            $subSet | Select Title | measure | select count
            foreach ($Update in $subSet)
            { $Update.Decline(); Write-Host $Update.Title Declined }


    # Delete Declined Updates
        # Delete Declined
            $resultantUpdates = $wsus.getupdates() 
            $StaleSet = $resultantUpdates | where {$_.isdeclined -eq $TRUE}
            $StaleSet | measure | select count
            foreach ($Update in $StaleSet)
            {
	            $wsus.DeleteUpdate($Update.Id.UpdateId.ToString()); 
                Write-Host -f Yellow $Update.Title removed
            }
            $wsus.getupdates() | where {$_.isdeclined -eq $TRUE} | measure | select count

        # Invoke Server Cleanup
            Get-WsusServer | 
                Invoke-WsusServerCleanup -CleanupObsoleteComputers `
                                         -CleanupObsoleteUpdates `
                                         -CleanupUnneededContentFiles `
                                         -CompressUpdates


# PAUSE SCRIPT 1 MINUTE TO ALLOW SERVER PROCESSES TO COMPLETE
    Write-Host -f Cyan 'Pausing script for Server Cleanup to Complete (1 Min)'
    sleep -Seconds 60
    Write-Host -f Green "Beginning Transfer to $trgVol ($drvRem)"


# Export WSUS Data
    Write-Host -f Cyan "Exporting WSUS Data Locally to $drvWSUS (2-5 Min)"
    SL "$env:ProgramFiles\Update Services\Tools"
    $fileName = [string](Get-Date -f 'yyyy-MM-dd') + '.export'
    .\WsusUtil.exe export $drvWSUS\$fileName.xml.gz $drvWSUS\$fileName.log

# Copy WSUS Data to Removable Device
    Write-Host -f Cyan "Copying WSUS Data from $drvWSUS to $drvRem\WSUS (10-20 Min)"
    # Remomve residual xfer data from Removable Device PRIOR to copying current
        If ((Test-Path $drvRem\WSUS) -eq $true)
        { Remove-Item -Path $drvRem\WSUS -Recurse -Force -Verbose }
    # Measure-Command {
        Robocopy $drvWSUS $drvRem\WSUS /XO /E
    # } -Verbose

    Write-Host -f Cyan "`n`n`n`n`nScript Complete - Secure $trgVol at this time."
    [System.Console]::Beep(6000,500)

# Close out script
    [DateTime]$endtime = Get-Date
    $duration = ($endtime - $starttime)
    "`n`nScript Runtime - {0:dd}.{0:hh}:{0:mm}:{0:ss}" -f $duration
    Pause
