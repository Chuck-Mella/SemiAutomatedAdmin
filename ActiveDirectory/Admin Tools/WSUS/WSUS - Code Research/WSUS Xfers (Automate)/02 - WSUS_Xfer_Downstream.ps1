#Requires -RunAsAdministrator
[DateTime]$starttime = Get-Date
$trgVol = 'Jenny'
$envTags = "
        Internal,olad,`"DC=olad,DC=mil`",vanws010900-130
        Fabcon,fab,`"DC=fab,DC=net`",fabconwsus01
        <Environment>,<DomainNetbiosName>,<`"root fqdn`">,<ServerName>
        MSTest,Contoso,`"DC=Contoso,DC=Com`",WSUS01
    " | Convertfrom-CSV -Header env,netbios,fqdn,WsusServer

# Connect and Verify Removable Device
    $drvRem = Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -eq $trgVol | Select-Object -Exp DeviceID
    If ($drvRem -eq $null) { Write-Warning "$trgVol Device not connected; EXITING"; Break }
    Else { Write-Host -f Green "$trgVol device located as [$drvRem]" }

# Determine Network Environment
    $domain = @{
        netbios = [adsi]'' | Select-Object -exp name
        fqdn    = [adsi]'' | Select-Object -exp distinguishedname
    }

# Copy WSUS Data from Removable Device
    # Set Job Parameters
        $trgEnv = $envTags | Where-Object netbios -eq $domain.netbios
        $trgServer = $trgEnv.WsusServer
        if ([String]::IsNullOrEmpty($trgServer)){ Write-Warning 'Unknown Environment; EXITING'; BREAK }
        else { Write-Host -f c "`n`n[$($trgEnv.env)] Environment Detected....`n`n" }
        if ((& Hostname) -eq $trgServer){ $drvWSUS = 'U:\' }
        else { $drvWSUS = "\\$trgServer\U$\" }
        $drvWSUS

    # Stop WSUS Services on Target Server
        if ((& Hostname) -eq $trgServer){ Get-Service  WsusService,W3SVC | Stop-Service -Verbose }
        else { Get-Service  WsusService,W3SVC -ComputerName $trgServer | Stop-Service -Verbose }
        Start-Sleep -Seconds 5
     
    # Rename existing WSUS Folder (temp BU)
        if ((& Hostname) -eq $trgServer){ Set-Location $drvWSUS }
        else { Push-Location $drvWSUS }
        
        Rename-Item -Path WSUS -NewName "WSUS_Old_$(Get-Date -f yyyy-MM-dd)"
        # Rename-Item -Path "WSUS_Old_$(Get-Date -f yyyy-MM-dd)" -NewName WSUS
        Pop-Location
     
    # Copy files from Removable Device to WSUS Folder		
        Write-Host -f Cyan "Copying WSUS Data from $drvRem\WSUS to $drvWSUS`WSUS (Up to 1-2+ hours)"
        # Measure-Command {
            Robocopy "$drvRem\WSUS" ($drvWSUS + 'WSUS') /XO /E
        # } -Verbose

# Import WSUS Data
    $trgBU = gci u:\wsus -filter *.gz |
        Sort LastWriteTime -Descending |
        Out-Gridview -Title 'Select Dataset to Import (Cancel defaults to most recent Export)' -PassThru
    If ($trgBU -eq $null){ $trgBU = gci u:\wsus -filter *.gz | Sort LastWriteTime -Descending | Select -First 1 }
    Write-Host -f Cyan "`n`nRecovering WSUS Data from [$($trgBU.BaseName)] (2-5 Min)`n`n"
    SL "$env:ProgramFiles\Update Services\Tools"
    $fileName = ($trgBU.FullName -split '.xml')[0]
    .\WsusUtil.exe import ($fileName + '.xml.gz') ($fileName + '.log')

# Restart WSUS Services on Target Server
    if ((& Hostname) -eq $trgServer){ Get-Service  WsusService,W3SVC | Start-Service -Verbose }
    else { Get-Service  WsusService,W3SVC -ComputerName $trgServer | Start-Service -Verbose }



# Close out script
    Write-Host -f Cyan "`n`n`n`n`nScript Complete - Secure $trgVol at this time."
    [System.Console]::Beep(6000,500)

    [DateTime]$endtime = Get-Date
    $duration = ($endtime - $starttime)
    "`n`nScript Runtime - {0:dd}.{0:hh}:{0:mm}:{0:ss}" -f $duration
    Pause

# Post-script
    if ((& Hostname) -eq $trgServer){ Invoke-Item "$env:ProgramFiles\Update Services\AdministrationSnapin\wsus.msc" }
