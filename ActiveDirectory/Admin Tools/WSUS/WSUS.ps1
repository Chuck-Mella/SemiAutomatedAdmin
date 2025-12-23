#region - WSUS
    #region - 00 - WSUS Xfers (Upstream & Downstream) 
        #Requires -RunAsAdministrator
        Param
        (
            [ValidateSet('Upstream','Downstream')]$trgWSUS = 'Upstream',
            [ValidateSet('Jenny','Enterprise')]$extDrvVol = 'Jenny',
            [DateTime]$starttime = (Get-Date)
        )
        #region - Functions
            Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
            Function Get-NextAvailDrvLetter
            {
                $asgnDrives = (Get-WmiObject win32_LogicalDisk | Where-Object DriveType -match '^(3|4)$' | Select-Object -Exp DeviceID) -join ','
                67..90 | ForEach-Object { "$([char]$_):" } | 
                    Where-Object { $asgnDrives -notcontains $_  } | 
                        Where-Object { 
                            (new-object System.IO.DriveInfo $_).DriveType -eq 'noRootdirectory' 
                        } | Select-Object -First 1
            }
            Function Get-XferDrive
            {
                Param
                (
                    [Parameter(Mandatory=$true)]$extDrvVol,
                    $trgServer,
                    [Switch]$mapLocal
                )
                # Locate and Verify Removable Device
                    # Is drive local?
                        $islocal = [bool](Get-WmiObject -Class Win32_LogicalDisk | Where-Object VolumeName -eq $extDrvVol)
                        If ($islocal) { $drvExtrnlovable = (Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -eq $extDrvVol).DeviceID }

                    # Is drive remotely attached?
                        If ($islocal -eq $false)
                        {
                            if ([String]::IsNullOrEmpty($trgServer)) { $trgServer = Read-Host -Prompt "Enter Server Name Where-Object removable volume '$extDrvVol' is attached:" }
                            If ([String]::IsNullOrEmpty($trgServer)) { Write-Warning "No Server Name provided for volume '$extDrvVol':: EXITING"; EXIT }
                            # IF (Test-Connection -BufferSize 32 -Count 1 -ComputerName $trgServer -Quiet) { Write-Warning "Server [$trgServer] offline:: EXITING"; EXIT }
                            $isRemote = [bool](Get-WmiObject Win32_LogicalDisk -ComputerName $trgServer -ea SilentlyContinue | Where-Object VolumeName -eq $extDrvVol)
                            If ($isRemote -eq $true)
                            {
                                $drvTemp = (Get-WmiObject Win32_LogicalDisk -ComputerName $trgServer -ea SilentlyContinue | Where-Object VolumeName -eq $extDrvVol).DeviceID
                                $drvUNC = "\\$trgServer\$($drvTemp -replace '\:','$')"
                                $drvExtrnlovable = $drvUNC
                            }
                        }
                    # Connect Removable Device (Remote)
                        if ($mapLocal.IsPresent -eq $true -and $null -ne $drvTemp)
                        {
                            $drvlist = (Get-PSDrive -PSProvider filesystem).Name
                            Foreach ($drvletter in "EFGHIJKLMNOPQRSTUVWXYZ".ToCharArray())
                            {
                                If ($drvlist -notcontains $drvletter)
                                {
                                    $drv = New-PSDrive -PSProvider filesystem -Name $drvletter -Root $drvUNC -Scope Global
                                    EXIT
                                }
                            }
                            Write-Host -f Green "$extDrvVol device located at [$drvUNC], mapping as [$($drv.Name):]"
                            $drvExtrnlovable = "$($drv.Name):"
                        }
                        Else
                        {
                            If ($isRemote -eq $true -and [String]::IsNullOrEmpty($drvUNC) -eq $false)
                            { Write-Host -f Green "$extDrvVol device located at [$drvUNC]" }
                        }

                    # Is not found, notify and quit
                        If ($null -eq $drvExtrnlovable)
                        {
                            Write-Warning "'$extDrvVol' volume not found locally nor on [$trgServer]:: EXITING"
                            Return $null
                            EXIT
                        }
                    # Return Removable Volume Device
                        Else
                        {
                            Return $drvExtrnlovable
                            EXIT
                        }
            }
        #endregion
        #region - Environment
            # Set Script Start Time
                [DateTime]$starttime = Get-Date
            # Network Environment
                $domJoined = (Get-WmiObject win32_ComputerSystem).PartOfDomain
                $domain = [Ordered]@{} | Select-Object netbios,fqdn
                switch ($domJoined)
                {
                    $false
                    {
                        $domain.netbios = (Get-WmiObject win32_ComputerSystem) | Select-Object -Exp Domain
                        $domain.fqdn    = (Get-WmiObject win32_ComputerSystem) | Select-Object -Exp WorkGroup
                    }
                    $true
                    {
                        $domain.netbios = [adsi]'' | Select-Object -exp name
                        $domain.fqdn    = [adsi]'' | Select-Object -exp distinguishedname
                    }
                } 
                $envTags = "
                        Yellow,$(Dec64 YXhhZA==),$(Dec64 IkRDPWF4YWQsREM9aWMsREM9Z292Ig==),$(Dec64 andpY3N3c3VzMDE=)
                        Internal,$(Dec64 b2xhZA==),$(Dec64 IkRDPW9sYWQsREM9bWlsIg==),$(Dec64 dmFud3MwMjA5MDAtMTMw)
                        Fabcon,$(Dec64 ZmFi),$(Dec64 IkRDPWZhYixEQz1uZXQi),$(Dec64 ZmFiY29ud3N1czAxLTEzMA==)
                        WORKGROUP,`"$($domain.netbios)`",`"$($domain.fqdn)`",$(& HostName)
                        <Environment>,<DomainNetbiosName>,<`"root fqdn`">,<ServerName>
                    " | Convertfrom-CSV -Header env,netbios,fqdn,WsusServer
                $trgEnv = $envTags | Where-Object netbios -eq $domain.netbios
            # Locate & Connect to External Drive
                $Params = @{
                    extDrvVol = $extDrvVol
                    trgServer = $trgEnv.WsusServer
                    mapLocal = $false
                    }
                # Connect and Verify Removable Device
                    $drvExtrnl = Get-XferDrive @Params
                    # $drvExtrnl = Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -eq $extDrvVol | Select-Object -Exp DeviceID
                    If ($null -eq $drvExtrnl) { Write-Warning "External Device [$extDrvVol] not connected; EXITING"; EXIT }
                    Else { Write-Host -f Green "External Device [$extDrvVol] located as [$drvExtrnl]" }
            # Set Content Location
                # Set Job Parameters
                $fldrWSUS = 'WSUS'
                $trgServer = $trgEnv.WsusServer
                If ([String]::IsNullOrEmpty($trgServer)){ Write-Warning 'Unknown Environment; EXITING'; EXIT }
                Else { Write-Host -f c "`n`n[$($trgEnv.env)] Environment Detected....`n`n" }
                If ((& Hostname) -eq $trgServer){ $drvWSUS = 'U:' }
                Else { $drvWSUS = "\\$trgServer\U$" }
                "$drvWSUS\$fldrWSUS"
        #endregion
        Switch ($trgWSUS)
        {
            'Upstream'
            {
                # Export WSUS Data
                    Write-Host -f Cyan "Exporting WSUS Data Locally to $drvWSUS\$fldrWSUS (2-5 Min)"
                    Set-Location "$env:ProgramFiles\Update Services\Tools"
                    $fileName = [string](Get-Date -f 'yyyy-MM-dd') + '.export'
                    .\WsusUtil.exe export $drvWSUS\$fldrWSUS\$fileName.xml.gz $drvWSUS\$fldrWSUS\$fileName.log

                # Copy WSUS Data to Removable Device
                    Write-Host -f Cyan "Copying WSUS Data from $drvWSUS\$fldrWSUS to $drvExtrnl\$fldrWSUS (10-20 Min)"
                    # Remomve residual xfer data from Removable Device PRIOR to copying current
                        If ((Test-Path "$drvExtrnl\WSUS") -eq $true)
                        { Remove-Item -Path $drvExtrnl\WSUS -Recurse -Force -Verbose }
                    # Measure-Command {
                        Robocopy $drvWSUS\$fldrWSUS $drvExtrnl\$fldrWSUS /XO /E
                    # } -Verbose

                    Write-Host -f Cyan "`n`n`n`n`nScript Complete - Secure $extDrvVol at this time."
                    [System.Console]::Beep(6000,500)

                # Close out script
                    [DateTime]$endtime = Get-Date
                    $duration = ($endtime - $starttime)
                    "`n`nScript Runtime - {0:dd}.{0:hh}:{0:mm}:{0:ss}" -f $duration
                    Start-Sleep  -Seconds 120
            }
            'Downstream'
            {
                # Copy WSUS Data from Removable Device
                    # Stop WSUS Services on Target Server
                        If ((& Hostname) -eq $trgServer){ Get-Service  WsusService,W3SVC | Stop-Service -Verbose }
                        Else { Get-Service  WsusService,W3SVC -ComputerName $trgServer | Stop-Service -Verbose }
                        Start-Start-Sleep  -Seconds 5
     
                    # Rename existing WSUS Folder (temp BU) '\\+[^\\]+$'
                        If ((& Hostname) -eq $trgServer){ Set-Location $drvWSUS\ }
                        Else { Push-Location $drvWSUS\ }
        
                        Rename-Item -Path WSUS -NewName "WSUS_Old_$(Get-Date -f yyyy-MM-dd)"
                        # Rename-Item -Path "WSUS_Old_$(Get-Date -f yyyy-MM-dd)" -NewName WSUS
                        Pop-Location
     
                # Copy files from Removable Device to WSUS Folder		
                    Write-Host -f Cyan "Copying WSUS Data from $drvExtrnl\WSUS to $drvWSUS`WSUS (Up to 1-2+ hours)"
                    # Measure-Command {
                        Robocopy "$drvExtrnl\WSUS" "$drvWSUS\$fldrWSUS" /XO /E
                    # } -Verbose

                # Import WSUS Data
                    $trgBU = Get-ChildItem  "$drvWSUS\$fldrWSUS" -filter *.gz |
                        Sort-Object LastWriteTime -Descending |
                        Out-Gridview -Title 'Select-Object Dataset to Import (Cancel defaults to most recent Export)' -PassThru
                    If ($null -eq $trgBU){ $trgBU = Get-ChildItem  "$drvWSUS\$fldrWSUS" -filter *.gz | Sort-Object LastWriteTime -Descending | Select-Object -First 1 }
                    Write-Host -f Cyan "`n`nRecovering WSUS Data from [$($trgBU.BaseName)] (2-5 Min)`n`n"
                    Set-Location "$env:ProgramFiles\Update Services\Tools"
                    $fileName = ($trgBU.FullName -split '.xml')[0]
                    .\WsusUtil.exe import ($fileName + '.xml.gz') ($fileName + '.log')

                # Restart WSUS Services on Target Server
                    If ((& Hostname) -eq $trgServer){ Get-Service  WsusService,W3SVC | Start-Service -Verbose }
                    Else { Get-Service  WsusService,W3SVC -ComputerName $trgServer | Start-Service -Verbose }

                # Close out script
                    Write-Host -f Cyan "`n`n`n`n`nScript Complete - Secure $extDrvVol at this time."
                    [System.Console]::Beep(6000,500)

                    [DateTime]$endtime = Get-Date
                    $duration = ($endtime - $starttime)
                    "`n`nScript Runtime - {0:dd}.{0:hh}:{0:mm}:{0:ss}" -f $duration
                    Start-Sleep  -Seconds 120

                # Post-script
                    if ((& Hostname) -eq $trgServer){ Invoke-Item "$env:ProgramFiles\Update Services\AdministrationSnapin\wsus.msc" }
            }
            default { EXIT }
        }
        #region - Decline N/A WSUS Updates
            #region - Load WSUS
                [reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
                $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer();
                $ListOfUpdates = $wsus.getupdates() 
                  $prod = $ListOfUpdates | Select-Object -Exp ProductTitles -Unique | Sort-Object
                  $family = $ListOfUpdates | Select-Object -Exp ProductFamilyTitles -Unique | Sort-Object
                  $type = $ListOfUpdates | Select-Object -Exp UpdateClassificationTitle -Unique | Sort-Object
            #endregion
            $declinedUpdts = "
                Y;Y;Title;;Language;Lang
                Y;Y;Title;;Chinese;(Pro N|Education N|Enterprise N)
                Y;Y;Title;Windows;Non-Intel;(Arm64|AMD64)
                Y;Y;Title;;Previews;Preview
                Y;Y;Title;SQL Server;GDR;GDR
                Y;Y;Title;Windows;GDR;GDR
                Y;Y;Title;Windows;32Bit;x86
                N;N;Title;Windows;64Bit;x64
                Y;Y;Title;Windows;Dynamic;Dynamic
                Y;Y;Title;Windows;Insider;(Version|Server) Next
                Y;Y;Title;Windows;OldOS;server 2012 R2|business editions|\s(1507|1511|1607|170(3|9)|180(3|9)|190(3|9)|2004|2(0|1)H(1|2))
                Y;N;Title;Windows;NewOS;^Windows (10|11), Version\s\d{2}H(1|2)
                Y;Y;Title;Windows;Defender;Defender
                Y;Y;Title;Windows;Edge;Edge.(beta|dev|exten|WebView|for windows 10)
                Y;Y;Title;Office;Office;(Microsoft 365 Apps Update|Office (365|LTSC|2))
                Y;Y;Issuperseded;;Superceded,$true
                " | ConvertFrom-Csv -Delimiter ';' -Header Decline,Delete,SrchField,UpdtFam,UpdateType,SrchText
            [System.Collections.ArrayList]$rslts = @()
            $wrkList = $ListOfUpdates | Where-Object {$_.isdeclined -eq $false} 
            ForEach ($decline in ($declinedUpdts | Where-Object  Decline -eq 'Y'))
            {
                # Remove unrequired and irrelevant updates
                    # If SrchField is logical (True/False) use -eq  Else if SrchField is text, use  -match with regex
                    If (($decline.SrchText -eq $true) -or ($decline.SrchText -eq $false))
                    { $subSet = $wrkList | Where-Object {$_.($decline.SrchField) -eq $decline.SrchText} }
                    Else { $subSet = $wrkList | Where-Object {$_.($decline.SrchField) -match $decline.SrchText -and $_.ProductFamilyTitles -eq $decline.UpdtFam } }

                    ForEach ($Update in $subSet)
                    { $Update.Decline(); Write-Host $Update.Title Declined }

                # Log Newly Declined Counts
                    $rslt = @{} | Select-Object UpdtType,Count
                        $rslt.UpdtType = $decline.UpdateType
                        $rslt.Count = $subSet.Count
                    [Void]$rslts.Add($rslt)

                # Remove Newly Declined From WorkList
                    ForEach ($itm in $subSet)
                    { $wrkList = $wrkList | Where-Object {$_.id.UpdateId.Guid -ne $itm.Guid } }

                # Decline Lang Packs
                #($ListOfUpdates | Where-Object { $_.title -like "*Lang*" -and $_.title -notlike "*en-us*"}).Count
            }
            $rslts | Format-Table
        #endregion
        #region - Delete Declined Updates
            $nonDels = $declinedUpdts | Where-Object Decline -eq 'Y' | Where-Object Delete -eq 'N' | Select-Object -Exp SrchText
            $resultantUpdates = $wsus.getupdates() 
            # Remove non-delete updates from list
                $nonDels | ForEach-Object{$x=$_; $resultantUpdates = $resultantUpdates | Where-Object { $_.Title -NotMatch $x } }
            # Create list of deletable updates and delete them
                ($StaleSet = $resultantUpdates | Where-Object {$_.isdeclined -eq $TRUE}).Count
                ForEach ($Update in $StaleSet)
                {
                  $wsus.DeleteUpdate($Update.Id.UpdateId.ToString()); 
                    Write-Host -f Yellow $Update.Title removed
                }
                ($wsus.getupdates() | Where-Object {$_.isdeclined -eq $TRUE}).Count

            # Invoke Server Cleanup
                $params = @{
                    CleanupObsoleteComputers = $true
                    CleanupObsoleteUpdates = $true
                    CleanupUnneededContentFiles = $true
                    CompressUpdates = $true
                    }
                Get-WsusServer | Invoke-WsusServerCleanup @params

            # PAUSE SCRIPT 1 MINUTE TO ALLOW SERVER PROCESSES TO COMPLETE
                Write-Host -f Cyan 'Pausing script for Server Cleanup to Complete (1 Min)'
                Start-Sleep  -Seconds 60
                Write-Host -f Green "Beginning Transfer to $extDrvVol ($drvExtrnl)"
        #endregion
    #endregion
    #region - Import-WsusCatelogUpdates.ps1
        $msCat = 'https://catalog.update.microsoft.com/'
        <#
        .SYNOPSIS
        Powershell script to import an update, or multiple updates into WSUS based on the UpdateID from the catalog.

        .DESCRIPTION
        This script takes user input and attempts to connect to the WSUS server.
        Then it tries to import the update using the provided UpdateID from the catalog.

        .INPUTS
        The script takes WSUS server Name/IP, WSUS server port, SSL configuration option and UpdateID as input. UpdateID can be viewed and copied from the update details page for any update in the catalog, https://catalog.update.microsoft.com. 

        .OUTPUTS
        Writes logging information to standard output.

        .EXAMPLE
        # Use with remote server IP, port and SSL
        .\ImportUpdateToWSUS.ps1 -WsusServer 127.0.0.1 -PortNumber 8531 -UseSsl -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
        # Use with remote server Name, port and SSL
        .\ImportUpdateToWSUS.ps1 -WsusServer WSUSServer1.us.contoso.com -PortNumber 8531 -UseSsl -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
        # Use with remote server IP, defaultport and no SSL
        .\ImportUpdateToWSUS.ps1 -WsusServer 127.0.0.1  -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
        # Use with localhost default port
        .\ImportUpdateToWSUS.ps1 -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
        # Use with localhost default port, file with updateID's
        .\ImportUpdateToWSUS.ps1 -UpdateIdFilePath .\file.txt


        Import-UpdateToWSUS -wsusserver $env:computerName `
                            -PortNumber 8530 `
                            -usessl:$false `
                            -UpdateId '12345678-90ab-cdef-1234-567890abcdef' `
                            -UpdateIdFilePath '.\file.txt' `
                            -verbose



        .NOTES  
        # On error, try enabling TLS: https://learn.microsoft.com/mem/configmgr/core/plan-design/security/enable-tls-1-2-client

        # Sample registry add for the WSUS server from command line. Restarts the WSUSService and IIS after adding:
        reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1

        ## Sample registry add for the WSUS server from PowerShell. Restarts WSUSService and IIS after adding:
        $registryPath = "HKLM:\Software\Microsoft\.NETFramework\v4.0.30319"
        $Name = "SchUseStrongCrypto"
        $value = "1" 
        if (!(Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
        New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
        Restart-Service WsusService, w3svc

        # Update import logs/errors are under %ProgramFiles%\Update Services\LogFiles\SoftwareDistribution.log

        #>
        Function Import-UpdateToWSUS
        {
        param(
            [Parameter(Mandatory = $false, HelpMessage = "Specifies the name of a WSUS server, if not specified connects to localhost")]
            # Specifies the name of a WSUS server, if not specified connects to localhost.
            [string]$WsusServer,

            [Parameter(Mandatory = $false, HelpMessage = "Specifies the port number to use to communicate with the upstream WSUS server, default is 8530")]
            # Specifies the port number to use to communicate with the upstream WSUS server, default is 8530.
            [ValidateSet("80", "443", "8530", "8531")]
            [int32]$PortNumber = 8530,

            [Parameter(Mandatory = $false, HelpMessage = "Specifies that the WSUS server should use Secure Sockets Layer (SSL) via HTTPS to communicate with an upstream server")]
            # Specifies that the WSUS server should use Secure Sockets Layer (SSL) via HTTPS to communicate with an upstream server.  
            [Switch]$UseSsl,

            [Parameter(Mandatory = $true, HelpMessage = "Specifies the update Id we should import to WSUS", ParameterSetName = "Single")]
            # Specifies the update Id we should import to WSUS
            [ValidateNotNullOrEmpty()]
            [String]$UpdateId,

            [Parameter(Mandatory = $true, HelpMessage = "Specifies path to a text file containing a list of update ID's on each line", ParameterSetName = "Multiple")]
            # Specifies path to a text file containing a list of update ID's on each line.
            [ValidateNotNullOrEmpty()]
            [String]$UpdateIdFilePath
        )

        # Set-StrictMode -Version Latest

        # set server options
        $serverOptions = "Get-WsusServer"
        if ($psBoundParameters.containsKey('WsusServer')) { $serverOptions += " -Name $WsusServer -PortNumber $PortNumber" }
        if ($UseSsl) { $serverOptions += " -UseSsl" }

        # empty updateID list
        $updateList = @()

        # get update id's
        if ($UpdateIdFilePath) {
            if (Test-Path $UpdateIdFilePath) {
                foreach ($id in (Get-Content $UpdateIdFilePath)) {
                    $updateList += $id.Trim()
                }
            }
            else {
                Write-Error "[$UpdateIdFilePath]: File not found"
            return
            }
        }
        else {
            $updateList = @($UpdateId)
        }

        # get WSUS server
        Try {
            Write-Host "Attempting WSUS Connection using $serverOptions... " -NoNewline
            $server = invoke-expression $serverOptions
            Write-Host "Connection Successful"
        }
        Catch {
            Write-Error $_
            return
        }

        # empty file list
        $FileList = @()

        # call ImportUpdateFromCatalogSite on WSUS
        foreach ($uid in $updateList) {
            Try {
                Write-Host "Attempting WSUS update import for Update ID: $uid... " -NoNewline
                $server.ImportUpdateFromCatalogSite($uid, $FileList)
                Write-Host "Import Successful"
            }
            Catch {
                Write-Error "Failed. $_"
            }
        }
        }

        $Params = @{
            WsusServer = $env:COMPUTERNAME
            PortNumber = 8530
            }
        Import-UpdateToWSUS @Params -UpdateId fcce0a2d-b402-4ae1-b091-83b826bcff24

    #endregion
    #region - PSWindowsUpdate Module Cmds
        Import-Module PSWindowsupdate
        Get-Command -Module PSWindowsupdate
        $UPD = 'KB890830'
        $UPD = 'KB5030179'
        Install-windowsupdate -KBArticleiD KB890830
        Get-windowsupdate -KBArticleiD KB890830
        Get-windowsupdate -KBArticleiD KB890830 -Download
        oownload -windowsupdate -KBArticleiD KB890830
        $updates = Get-WindowsUpdate
        ($updates | Where-Object Title -Match 'EDGE' ) | Install-WindowsUpdate

        Install-Module PSWindowsupdate
        Import-Module PSWindowsupdate -
        Get-Package -Name PSWindowsupdate
        Get-command -Module PSWindowsupate
        Get-WUList -computerName $env:computerName

    #endregion
    #region - WSUS Clients
        #region - Client-Side Force Updates
            ($Searcher = New-Object DirectoryServices.DirectorySearcher).Filter = '(objectCategory=computer)'
            $aDCs = $($Searcher.SearchRoot = "LDAP://ou=domain controllers,$(([ADSI]'').distinguishedname)"
                    $Searcher.FindAll() | Select-Object @{n='DC';e={$_.Properties.cn}} | Select-Object -exp DC
                    ) -notmatch '^W'
            $MBRs = $($Searcher.SearchRoot = "LDAP://ou=SvrContainer,ou=Member Servers,$(([ADSI]'').distinguishedname)"
                    $Searcher.FindAll() | Select-Object @{n='DC';e={$_.Properties.cn}} | Select-Object -exp DC
                    )
            $aDCs = $($Searcher.SearchRoot = "LDAP://ou=domain controllers,$(([ADSI]'').distinguishedname)"
                    $Searcher.FindAll() | Select-Object @{n='DC';e={$_.Properties.cn}} | Select-Object -exp DC
                    ) -notmatch '^W'
            Invoke-Command -ComputerName ($tmp = $mbrs|Sort-Object|Out-GridView -P) -ScriptBlock { wuauclt /detectnow; $upt = New-Object -ComObject 'Microsoft.Update.session'; $upt.CreateUpdatesearcher().search($Criteria).updates; wuauclt /reportnow }
            $MBRs = ($Mbrs -ne $tmp|Sort-Object)
      # Strip domain from UserName
      $UserName = $UserName -replace '^\w+[^\\]+\\' -replace '\@+[^\@]+$'
            
        #endregion
        #region - Force updates Manually
            #region - wsus Get-UpdateFile
                Function Get-UpdateFile
                {
                    Param ( $kb = '5032337' )
                    $sqlconn = 'server=\\.\pipe\MICROSOFT##WID\tsql\query;database=susdb;trusted_connection=true;'
                    $sqlDB = New-Object System.Data.SqlClient.SqlConnection($sqlconn)
                    $sqlDB.Open()
                    $sqlcmd = $sqlDB.createcommand()
                    # Find KB
                        $sqlcmd.commandText = "SELECT [updateid],[RevisionNumber],[DefaultTitle],[DefaultDescription] FROM [SUSDB].[PUBLic_VIEWS].[vupdate] Where-Object [DefaultTitle] like '%$kb%'"
                        $dbReader = $sqlcmd.ExecuteReader()
                        $dataTbl = New-object system.Data.DataTable
                        $dataTbl.Load($dbReader)
                        $kbPatches = $dataTbl
                    # Find KB Files
                        $kbPatches.DefaultTitle
                        $sglcmd.commandText = "SELECT [FileDigest],[FileName] FROM [SUSDB].[dbo].tbFile] Where-Object FileName like `'%$kb%`'"
                        $dbReader = $sqlcmd.ExecuteReader()
                        $dataTbl = New-object System.Data.DataTable
                        $dataTbl.Load($dbReader)
                        $kbFiles = $dataTbl[0] | Select-Object -Exp FileDigest
                        # $sqlcmd.commandText 'SELECT * FROM sessiontable'
                        # $sqlcmd.CommandText = "SELECT * FROM [SUSDB].[dbo].[tbFile] Where-Object FileName like `%$kb%`'"

                    $sqlDB.Close()
                    Return $dataTbl
                }
                $db = ($WSUS.GetDatabaseconfiguration()).DatabaseName
                $upd = @{} | Select-Object Kb,TitleText,Declined
                $upd.Kb = '5032337'
                $upd.TitleText = 'windows 10'
                $upd.Declined = $false
                ($trgupdate = $wsus.searchupdates($upd.Kb)).count
                $trg = ($trgupdate | Where-Object { $_. IsDeclined -eq $false -AND $_.Title -notmatch $upd.TitleText })
                # $trg = ($trgupdate | Where-Object { $_.Title -notmatch '(arm64lx86I23H2)' })
                $updiD = $trg.id.updateid.Guid
                Get-updateFile $upd.Kb
            #endregion
            #region - Dir DB Search for Update Files
                [reflection.assembly]::LoadwithPartialName("Microsoft.UpdateServices.Administration")
                $wsus1 = [Microsoft.updateservices.Administration.AdminProxy]::Getupdateserver();

                $kb = '5034123' # 5036892-Win11Update
                $relupdts = $wsus1.searchupdates($kb) | Where-Object IsDeclined -eq $false | Where-Object IsSuperseded -eq $false; $relupdts.count
                $relupdts = $relupdts | Where-Object LegacyName -notmatch '(ARM|x86)'; $relupdts.count
                # $relupdts = $relupdts | Where-Object Title -match '23h2'; $relupdts.count
                # Srelupdts = $relupdts | Where-Object Title -notmatch 'server'; $relupdts.count
                # $relupdts.title

                $updinfo = $relupdts.Getinstallableitems().Files.FileURI.absoluteuri
                # $trgUpdt = $wsus1.Getupdate((guid]$relupdts.id.updaterd.Guid)
                $regWSUS = (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate | Select-Object -Exp wuserver) -replace ".$env:UserDnsDomain"
                If ($regWSUS -match $env:computername)
                { $updInfo = $updInfo -replace "$regWSUS`/",'U:\WSUS\Wsus' -replace 'http://','\\' -replace '/','\'}
                Else
                { $updInfo = $updInfo -replace ':8530/','\u$\wsus\wsus' -replace 'http://','\\' -replace '/','\' }
    
                $updts = ( $updInfo | ForEach-Object{ "/PackagePath:`"$_`"" }) -join ''

                "DISM /Online /Add-Package $updts" | clip
                "DISM /Online /Add-Package /PackagePath:`" $updInfo`"" | clip
            #endregion
            #region - Force WSUS Check-ins
                Function Force-WSUScheckIn($Computer)
                {
                    Invoke-command -computername $computer -scriptblock { Start-Service wuauserv -verbose }
                    # Have to use psexec with the -s parameter as otherwise we receive an "Access denied" message loading the comobject
                    # $cmd = '$updatesession = new-object -com "Microsoft.Update.session";$updates=$updatesession.createupdatesearcher().search($criteria).Updates'
                    # & c:\bin\psexec.exe -s \\$Computer powershell.exe -command $cmd
                    # write*host "waiting 10 seconds for syncupdates webservice to complete to add to the wuauserv queue so that it can be reported on"
                    # start-sleep -seconds 10
                    Invoke-command -computername $computer -scriptblock `
                    {
                        # Now that the system is told it CAN report in, run every permutation of commands to actually trigger the report in operation
                        wuauclt /detectnow
                        (New-Object -ComObject Microsoft.update.Autoupdate).DetectNow()
                        wuauclt /reportnow
                        c:\windows\ system32\Usoclient.exe startscan
                    }
                }
                Force-WSUScheckIn vandhcp01
                Enter-PSSession -computerName vandhcp01
                    wuauclt /detectnow
                    $upt = New-Object -comobject Microsoft.Update.session
                    $upt.CreateUpdateSearcher().search($criteria).updates
                    wuauclt /reportnow
                Exit-PSSession
            #endregion
            #region - Client Machines Not Reporting
                # https://www.ajtek.ca/wsus/client-machines-not-reporting-to-wsus-properly/
                Stop-Service -Name BITS, wuauserv -Force
                  Remove-ItemProperty -Name AccountDomainSid, PingID, SusClientId, SusClientIDValidation -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\ -ErrorAction SilentlyContinue
                  Remove-Item "$env:SystemRoot\SoftwareDistribution\" -Recurse -Force -ErrorAction SilentlyContinue
                Start-Service -Name BITS, wuauserv

                wuauclt /resetauthorization /detectnow
                (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
            #endregion
        #endregion
        #region - Install wsus
            # Install
                # Intall wsus Console only
                Get-WindowsFeature -Name updateservices-ui -verbose
                Install-WindowsFeature -Name updateservices-ui -verbose
                Remove-WlndowsFeature -Name Updateservices* -verbose -IncludeManagementTools
            # Intall wsus All
                Install-WindowsFeature -Name Updateservices,updateservices-widDB,
                    Updateserv1ces-serv1ces,Updateservlces-RSAT,updateservices-API updateservices-UI -verbose
                #Install-windowsFeature -Name Updateservices -Verbose -IncludeManagementTools
                Remove-windowsFeature -Name updateservices* -verbose -IncludeManagementTools

            # Post Install config
                Start-Process -FilePath 'C:\Program Files\Update services\Tools\wsusutil.exe' -ArgumentList 'postinstall content_dir=u:\WSUS' -wait -verbose
                $wsus = Get-Wsusserver
                $wsusconfig = $wsus.Getconfiguration()
            # Set Upstream server
                Set-WsusServerSynchronization -UssServerName 'UPSTRMSVR' -PortNumber 8530 -Replica:$false -usessl:$false
            # Set Lang to English
                $wsusconfig.AllupdateLanguagesEnabled = $false
                $wsusconfig.SetEnabledupdateLanguages("en")
                $wsusconfig.save()
            # Kill config Nag
                $wsusconfig.oobernitialized = $true
                $wsusconfig.save()

            Start-Process -FilePath "C:\Program Files\Update services\Administrationsnapin\wsus.msc"

            (Get-ItemProperty hklm:\SOFTWARE\Policies\Microsoft\Windows\Windowsupdate).wuserver
        #endregion
        #region - wsus-Troubleshooting
            Get-service | Where-Object Name -match '(wuauserv|cryptsvc|bits|msiserver)'| Stop-Service -Force -verbose
            Rename-Item C:\Windows\System32\CatRoot2 CatRoot2.old -verbose
            Rename-Item C:\Windows\SoftwareDistribution softwareDistribution.old -verbose
            Get-Service | Where-Object Name -match '(wuauserv|cryptsvc|bits|msiserver)' | Start-Service -verbose
        #endregion
        #region - WSUS Client fixes
            Function Invoke-WSUSClientFix
            {
                <#  
                .SYNOPSIS  
                    Performs a WSUS client reset on local or remote system.
        
                .DESCRIPTION
                    Performs a WSUS client reset on local or remote system.
        
                .PARAMETER Computername
                    Name of the remote or local system.
                   
                .NOTES  
                    Name: Invoke-WSUSClientFix
                    Author: Boe Prox
                    DateCreated: 18JAN2012
                    DateModified: 28Mar2014  
              
                .EXAMPLE  
                    Invoke-WSUSClientFix -Computername 'Server' -Verbose
        
                    VERBOSE: Server: Testing network connection
                    VERBOSE: Server: Stopping wuauserv service
                    VERBOSE: Server: Making remote registry connection to LocalMachine hive
                    VERBOSE: Server: Connection to WSUS Client registry keys
                    VERBOSE: Server: Removing Software Distribution folder and subfolders
                    VERBOSE: Server: Starting wuauserv service
                    VERBOSE: Server: Sending wuauclt /resetauthorization /detectnow command
    
                    Description
                    -----------
                    This command resets the WSUS client information on Server.
                #> 
                [cmdletbinding(SupportsShouldProcess=$True)]
                Param
                (
                    [parameter(ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True)]
                    [Alias('__Server','Server','CN')]
                    [string[]]$Computername = $Env:Computername
                )
                Begin
                {
                    $reghive = [microsoft.win32.registryhive]::LocalMachine
                }
                Process
                {
                    ForEach ($Computer in $Computername) {
                        Write-Verbose ("{0}: Testing network connection" -f $Computer)
                        If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                            Write-Verbose ("{0}: Stopping wuauserv service" -f $Computer)
                            $wuauserv = Get-Service -ComputerName $Computer -Name wuauserv 
                            Stop-Service -InputObject $wuauserv
                
                            Write-Verbose ("{0}: Making remote registry connection to {1} hive" -f $Computer, $reghive)
                            $remotereg = [microsoft.win32.registrykey]::OpenRemoteBaseKey($reghive,$Computer)
                            Write-Verbose ("{0}: Connection to WSUS Client registry keys" -f $Computer)
                            $wsusreg1 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate',$True)
                            $wsusreg2 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',$True)
                
                            #Begin deletion of registry values for WSUS Client
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientId'))) {
                                If ($PScmdlet.ShouldProcess("SusClientId","Delete Registry Value")) {
                                    $wsusreg1.DeleteValue('SusClientId')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientIdValidation'))) {
                                If ($PScmdlet.ShouldProcess("SusClientIdValidation","Delete Registry Value")) {
                                    $wsusreg1.DeleteValue('SusClientIdValidation')
                                }
                            }                
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('PingID'))) {
                                If ($PScmdlet.ShouldProcess("PingID","Delete Registry Value")) {
                                    $wsusreg1.DeleteValue('PingID')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('AccountDomainSid'))) {
                                If ($PScmdlet.ShouldProcess("AccountDomainSid","Delete Registry Value")) {
                                    $wsusreg1.DeleteValue('AccountDomainSid')
                                }
                            }   
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('LastWaitTimeout'))) {
                                If ($PScmdlet.ShouldProcess("LastWaitTimeout","Delete Registry Value")) {
                                    $wsusreg2.DeleteValue('LastWaitTimeout')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('DetectionStartTimeout'))) {
                                If ($PScmdlet.ShouldProcess("DetectionStartTimeout","Delete Registry Value")) {
                                    $wsusreg2.DeleteValue('DetectionStartTimeout')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('NextDetectionTime'))) {
                                If ($PScmdlet.ShouldProcess("NextDetectionTime","Delete Registry Value")) {
                                    $wsusreg2.DeleteValue('NextDetectionTime')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('AUState'))) {
                                If ($PScmdlet.ShouldProcess("AUState","Delete Registry Value")) {
                                    $wsusreg2.DeleteValue('AUState')
                                }
                            }
                
                            Write-Verbose ("{0}: Removing Software Distribution folder and subfolders" -f $Computer)
                            Try {
                                Remove-Item "\\$Computer\c$\Windows\SoftwareDistribution" -Recurse -Force -Confirm:$False -ErrorAction Stop                                                                                         
                            } Catch {
                                Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                            }
                
                            Write-Verbose ("{0}: Starting wuauserv service" -f $Computer)
                            Start-Service -InputObject $wuauserv
                
                            Write-Verbose ("{0}: Sending wuauclt /resetauthorization /detectnow command" -f $Computer)
                            Try {
                                $null = Invoke-WmiMethod -Path Win32_Process -ComputerName $Computer -Name Create `
                                -ArgumentList "wuauclt /resetauthorization /detectnow" -ErrorAction Stop
                            } Catch {
                                Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                            }
                        }
                    }
                }
            }



            <#
                1. Create a batch file named ResetSUSClientID.bat using the text below:

                Rem - Batch script to delete duplicate SusClientIDs
                Rem - Implement this script as a "Startup" or "Logon"  script
                Rem - Script creates an output file called %Systemdrive%\SUSClientID.log
                Rem - If the %Systemdrive%\SUSClientID.log is already present, then the script simply exits

                @Echo off
            #>
            <#
                # if exist %systemdrive%\SUSClientID.log goto end
                If ((Test-Path "$env:systemdrive\SUSClientID.log" -PathType Leaf) -eq $true) { Break }
                # net stop bits
                Get-Service wuauserv | Stop-Service
                # net stop bits
                Get-Service bits | Stop-Service
                # reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f  > %systemdrive%\SUSClientID.log 2>&1
                reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f  > $env:systemdrive\SUSClientID.log 2>&1
                reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f  >> %systemdrive%\SUSClientID.log 2>&1
                reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f  >> %systemdrive%\SUSClientID.log 2>&1
                # net start wuauserv
                Get-Service wuauserv | Start-Service
                wuauclt.exe /resetauthorization /detectnow         
                # :end
                # exit
            #>
        #endregion
        #region - WSUS Trace Logging
            Function Toggle-WSUSClientTraceLogging
            {
                <#
                    .SYNOPSIS
                        Enable or Disable WSUS client (Windows Update Agent) trace logging.

                    .DESCRIPTION
                        This function can be used to enable or disable WSUS client (Windows Update Agent)
                        trace logging. This is useful when you need to debug a problem with the WSUS client.

                    .PARAMETER TraceLogging
                        This parameter sets the trace logging state. It can be either Enabled or Disabled.

                    .EXAMPLE
                        Toggle-WSUSClientTraceLogging -TraceLogging Enabled
                            Enables WSUS trace logging.

                    .EXAMPLE
                        Toggle-WSUSClientTraceLogging -TraceLogging Disabled
                            Disables WSUS trace logging. 

                    .NOTES
                        This script makes modifications to the registry. Modifying REGISTRY settings incorrectly can 
                        cause serious problems that may prevent your computer from booting properly. 
                #>
                [CmdletBinding()]
                param (
                    [Parameter(Mandatory = $false)]
                    [ValidateSet('Enabled', 'Disabled')]
                    [string]$TraceLogging = 'Enabled'
                )
                begin {
                    $rootWUPath = 'registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
                    $tracePath = "$rootWUPath\Trace"
                    $restartService = $true
                }
                process {
                    switch ($TraceLogging) {
                        Enabled {
                            if (-not (Test-Path $tracePath)) {
                                $null = New-Item -Path $rootWUPath -Name Trace -ItemType Directory
                            }
                            Set-ItemProperty -Path $tracePath -Name Flags -Value 7 -Force
                            Set-ItemProperty -Path $tracePath -Name Level -Value 4 -Force
                        }
                        Disabled {
                            if (Test-Path $tracePath) {
                                Remove-Item -Path $tracePath -Recurse -Force
                            }
                            else {
                                Write-Warning 'Trace logging is already disabled'
                                $restartService = $false
                            }
                        }
                    }
                }
                end {
                    if ($restartService) {
                        Restart-Service -Name wuauserv
                        Write-Host "Trace logging is now $TraceLogging"
                    }
                }
            }
        #endregion
    #endregion
    #region - PatchTues.ps1
        Function Get-PatchTuesday
        {
            # Alternatively, Calculate from the 12th (the only day of the month 
            # always in the same calendar week as Patch Tuesday).
            ($a=(Get-Date -Day 12 ).Date).AddHours(15).AddDays( 2 - [int]$a.DayOfWeek )
        }
        Function Get-PatchTuesdayv2
        { 
            [CmdletBinding()]
            param
            (
            [Parameter(HelpMessage = 'Enter a numeric month (1-Jan, 12-Dec, etc.)')]
            [ValidateSet(1,2,3,4,5,6,7,8,9,10,11,12)] [string]$Month=$(Get-Date).Month,
         
            [Parameter(HelpMessage = 'Enter a 4-digit year')]
            [ValidatePattern('\d{4}')] [string]$Year=$(Get-Date).Year,
    
            [ValidateSet("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")]
            [String]$weekDay = 'Tuesday',
    
            [ValidateRange(0, 5)] [int]$findNthDay = 2,
        
            [Switch]$objSchedule,
            [Switch]$csvSchedule
            )
            # Get selected Month parameters
            [datetime]$BoM = (Get-Date -Day 1 -Hour 0 -Minute 0 -Second 0 -Month $Month -Year $Year)
            [datetime]$EoM = (($BoM).AddMonths(1).AddSeconds(-1))
            [System.Object]$monthLength = 0..[datetime]::DaysInMonth($Year, $Month)
            [System.Collections.ArrayList]$arrDoW = @()
 
            foreach ($day in $monthLength)
            {
            [datetime]$loopDay = $BoM.AddDays($day)
            if ($loopDay.DayOfWeek -eq $weekDay) { $null = $arrDoW.Add($loopDay) }
            }
 
            $rslt = (Get-Date ($arrDoW | Select-Object -Index ($findNthDay - 1))).AddHours(15)
            If ($objSchedule.IsPresent -eq $true -AND $csvSchedule.IsPresent -eq $true){ $rslt }
            ElseIf ($objSchedule.IsPresent -eq $true)
            {
            [Ordered]@{
                ('Patch{0}' -f $rslt.DayOfWeek)                 = ('{0:dd MMMM yyyy}' -f $rslt)
                ('PrePatch{0}' -f $rslt.AddDays(2).DayOfWeek)   = ('{0:dd MMMM yyyy}' -f $rslt.AddDays(2)) 
                ('prodPatch{0}' -f $rslt.AddDays(10).DayOfWeek) = ('{0:dd MMMM yyyy}' -f $rslt.AddDays(10)) 
                ('prodPatch{0}' -f $rslt.AddDays(11).DayOfWeek) = ('{0:dd MMMM yyyy}' -f $rslt.AddDays(11)) 
            ('prodPatch{0}' -f $rslt.AddDays(12).DayOfWeek) = ('{0:dd MMMM yyyy}' -f $rslt.AddDays(12)) }     
            }
            ElseIf ($csvSchedule.IsPresent -eq $true)
            {
            $rslt | ForEach-Object{ ('
                    Patch{0},{1}
                    PrePatch{2},{3} 
                    prodPatch{4},{5} 
                    prodPatch{6},{7} 
                prodPatch{8},{9}' -f $_.DayOfWeek, 
                ('{0:dd MMMM yyyy}' -f $_), $_.AddDays(2).DayOfWeek, 
                ('{0:dd MMMM yyyy}' -f $_.AddDays(2)), $_.AddDays(10).DayOfWeek, 
                ('{0:dd MMMM yyyy}' -f $_.AddDays(10)), $_.AddDays(11).DayOfWeek, 
                ('{0:dd MMMM yyyy}' -f $_.AddDays(11)), $_.AddDays(12).DayOfWeek, 
            ('{0:dd MMMM yyyy}' -f $_.AddDays(12))) }| ConvertFrom-Csv -Header Event,Date
            }
            Else { $rslt }
   
        }

        Get-PatchTuesdayv2
        Get-PatchTuesdayv2 -objSchedule
        Get-PatchTuesdayv2 -csvSchedule
        Get-PatchTuesdayv2 -csvSchedule -objSchedule

        Get-PatchTuesdayv2 -Month 2 -Year 2024 -findNthDay 3 -weekDay Monday
        Get-PatchTuesdayv2 -Month 1 -Year 2024 -findNthDay 3 -weekDay Wednesday -objSchedule
        Get-PatchTuesdayv2 -Month 1 -Year 2024 -findNthDay 3 -weekDay Wednesday -csvSchedule
        Get-PatchTuesdayv2 -Month 1 -Year 2024 -findNthDay 3 -weekDay Wednesday -objSchedule -csvSchedule
    #endregion
    #region - Start-WSUSSync
        $PatchTuesday = ($a=( Get-Date -Day 12 ).Date).AddDays( 2 - [int]$a.DayOfWeek )
        $lastSync = ((Get-WsusServer).GetSubscription().GetLastSynchronizationInfo()).EndTime

        If
        (
            (Get-Date) -ge $PatchTuesday -AND
            (New-TimeSpan $lastSync (Get-Date)).Days -ge 14
        )
        { (Get-WsusServer).GetSubscription().StartSynchronization() }
        $encodedCommand = "KABHAGUAdAAtAFcAcwB1AHMAUwBlAHIAdgBlAHIAKQAuAEcAZQB0AFMAdQBiAHMAYwByAGkAcAB0AGkAbwBuACgAKQAuAFMAdABhAHIAdABTAHkAbgBjAGgAcgBvAG4AaQB6AGEAdABpAG8AbgAoACkA"
        $Command = Dec64v2 $encodedCommand

    #endregion
    #region - WSUS_Tranfer_Snippets.ps1
        #region - Functions
            Function Get-ClientWSUSSetting
            {
                <#  
                    .SYNOPSIS  
                    Retrieves the wsus client settings on a local or remove system.
                    .DESCRIPTION
                    Retrieves the wsus client settings on a local or remove system.
         
                    .PARAMETER Computername
                    Name of computer to connect to. Can be a collection of computers.
                    .PARAMETER ShowEnvironment
                    Display only the Environment settings.
                    .PARAMETER ShowConfiguration
                    Display only the Configuration settings.
                    .NOTES  
                    Name: Get-WSUSClient
                    Author: Boe Prox
                    DateCreated: 02DEC2011 
               
                    .LINK  
                    https://learn-powershell.net
        
                    .EXAMPLE
                    Get-ClientWSUSSetting -Computername TestServer
    
                    RescheduleWaitTime            : NA
                    AutoInstallMinorUpdates       : NA
                    TargetGroupEnabled            : NA
                    ScheduledInstallDay           : NA
                    DetectionFrequencyEnabled     : 1
                    WUServer                      : http://wsus.com
                    Computername                  : TestServer
                    RebootWarningTimeoutEnabled   : NA
                    ElevateNonAdmins              : NA
                    ScheduledInstallTime          : NA
                    RebootRelaunchTimeout         : 10
                    ScheduleInstallDay            : NA
                    RescheduleWaitTimeEnabled     : NA
                    DisableWindowsUpdateAccess    : NA
                    AUOptions                     : 3
                    DetectionFrequency            : 4
                    RebootWarningTimeout          : NA
                    ScheduleInstallTime           : NA
                    WUStatusServer                : http://wsus.com
                    TargetGroup                   : NA
                    RebootRelaunchTimeoutEnabled  : 1
                    UseWUServer                   : 1
                    NoAutoRebootWithLoggedOnUsers : 1
                    Description
                    -----------
                    Displays both Environment and Configuration settings for TestServer
    
                    .EXAMPLE
                    Get-ClientWSUSSetting -Computername Server1 -ShowEnvironment
    
                    Computername               : Server1
                    TargetGroupEnabled         : NA
                    TargetGroup                : NA
                    WUStatusServer             : http://wsus.com
                    WUServer                   : http://wsus.com
                    DisableWindowsUpdateAccess : 1
                    ElevateNonAdmins           : 0
    
                    Description
                    -----------
                    Displays the Environment settings for Server1
    
                    .Example
                    Get-ClientWSUSSetting -Computername Server1 -ShowConfiguration
    
                    ScheduledInstallTime          : NA
                    AutoInstallMinorUpdates       : 0
                    ScheduledInstallDay           : NA
                    Computername                  : Server1
                    RebootWarningTimeoutEnabled   : NA
                    RebootWarningTimeout          : NA
                    NoAUAsDefaultShutdownOption   : NA
                    RebootRelaunchTimeout         : NA
                    DetectionFrequency            : 4
                    ScheduleInstallDay            : NA
                    RescheduleWaitTime            : NA
                    RescheduleWaitTimeEnabled     : 0
                    AUOptions                     : 3
                    NoAutoRebootWithLoggedOnUsers : 1
                    DetectionFrequencyEnabled     : 1
                    ScheduleInstallTime           : NA
                    NoAUShutdownOption            : NA
                    RebootRelaunchTimeoutEnabled  : NA
                    UseWUServer                   : 1
                    IncludeRecommendedUpdates     : NA  
    
                    Description
                    -----------
                    Displays the Configuration settings for Server1
                #>
                [cmdletbinding()]
                Param
                (
                    [parameter(ValueFromPipeLine = $True)]
                    [string[]]$Computername = $Env:Computername,
                    [parameter()]
                    [switch]$ShowEnvironment,
                    [parameter()]
                    [switch]$ShowConfiguration        
                )
                Begin
                {
                    $EnvKeys = "WUServer","WUStatusServer","ElevateNonAdmins","TargetGroupEnabled","TargetGroup","DisableWindowsUpdateAccess"
                    $ConfigKeys = "AUOptions","AutoInstallMinorUpdates","DetectionFrequency","DetectionFrequencyEnabled","NoAutoRebootWithLoggedOnUsers",
                        "NoAutoUpdate","RebootRelaunchTimeout","RebootRelaunchTimeoutEnabled","RebootWarningTimeout","RebootWarningTimeoutEnabled",
                        "RescheduleWaitTime","RescheduleWaitTimeEnabled","ScheduleInstallDay","ScheduleInstallTime","UseWUServer"
                }
                Process
                {
                    $PSBoundParameters.GetEnumerator() | ForEach-Object {  Write-Verbose ("{0}" -f $_) }
                    ForEach ($Computer in $Computername)
                    {
                        If (Test-Connection -ComputerName $Computer -Count 1 -Quiet)
                        {
                            $WSUSEnvhash = @{}
                            $WSUSConfigHash = @{}
                            $ServerReg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$Computer)
                            #Get WSUS Client Environment Options
                            $WSUSEnv = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate')
                            $subkeys = @($WSUSEnv.GetValueNames())
                            $NoData = @(Compare-Object -ReferenceObject $EnvKeys -DifferenceObject $subkeys | Select-Object -ExpandProperty InputObject)
                            ForEach ($item in $NoData)
                            {
                                $WSUSEnvhash[$item] = 'NA'
                            }
                            $Data = @(Compare-Object -ReferenceObject $EnvKeys -DifferenceObject $subkeys -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject)
                            ForEach ($key in $Data) {
                                If ($key -eq 'WUServer')
                                {
                                    $WSUSEnvhash['WUServer'] = $WSUSEnv.GetValue('WUServer')
                                }
                                If ($key -eq 'WUStatusServer')
                                {
                                    $WSUSEnvhash['WUStatusServer'] = $WSUSEnv.GetValue('WUStatusServer')
                                }
                                If ($key -eq 'ElevateNonAdmins')
                                {
                                    $WSUSEnvhash['ElevateNonAdmins'] = $WSUSEnv.GetValue('ElevateNonAdmins')
                                }
                                If ($key -eq 'TargetGroupEnabled')
                                {
                                    $WSUSEnvhash['TargetGroupEnabled'] = $WSUSEnv.GetValue('TargetGroupEnabled')
                                }
                                If ($key -eq 'TargetGroup')
                                {
                                    $WSUSEnvhash['TargetGroup'] = $WSUSEnv.GetValue('TargetGroup')
                                }  
                                If ($key -eq 'DisableWindowsUpdateAccess')
                                {
                                    $WSUSEnvhash['DisableWindowsUpdateAccess'] = $WSUSEnv.GetValue('DisableWindowsUpdateAccess')
                                }              
                            }
                            #Get WSUS Client Configuration Options
                            $WSUSConfig = $ServerReg.OpenSubKey('Software\Policies\Microsoft\Windows\WindowsUpdate\AU')
                            $subkeys = @($WSUSConfig.GetValueNames())
                            $NoData = @(Compare-Object -ReferenceObject $ConfigKeys -DifferenceObject $subkeys | Select-Object -ExpandProperty InputObject)
                            ForEach ($item in $NoData)
                            {
                                $WSUSConfighash[$item] = 'NA'
                            }            
                            $Data = @(Compare-Object -ReferenceObject $ConfigKeys -DifferenceObject $subkeys -IncludeEqual -ExcludeDifferent | Select-Object -ExpandProperty InputObject)
                            ForEach ($key in $Data)
                            {
                                If ($key -eq 'AUOptions')
                                {
                                    $WSUSConfighash['AUOptions'] = $WSUSConfig.GetValue('AUOptions')
                                }
                                If ($key -eq 'AutoInstallMinorUpdates')
                                {
                                    $WSUSConfighash['AutoInstallMinorUpdates'] = $WSUSConfig.GetValue('AutoInstallMinorUpdates')
                                }
                                If ($key -eq 'DetectionFrequency')
                                {
                                    $WSUSConfighash['DetectionFrequency'] = $WSUSConfig.GetValue('DetectionFrequency')
                                }
                                If ($key -eq 'DetectionFrequencyEnabled')
                                {
                                    $WSUSConfighash['DetectionFrequencyEnabled'] = $WSUSConfig.GetValue('DetectionFrequencyEnabled')
                                }
                                If ($key -eq 'NoAutoRebootWithLoggedOnUsers')
                                {
                                    $WSUSConfighash['NoAutoRebootWithLoggedOnUsers'] = $WSUSConfig.GetValue('NoAutoRebootWithLoggedOnUsers')
                                }
                                If ($key -eq 'RebootRelaunchTimeout')
                                {
                                    $WSUSConfighash['RebootRelaunchTimeout'] = $WSUSConfig.GetValue('RebootRelaunchTimeout')
                                }
                                If ($key -eq 'RebootRelaunchTimeoutEnabled')
                                {
                                    $WSUSConfighash['RebootRelaunchTimeoutEnabled'] = $WSUSConfig.GetValue('RebootRelaunchTimeoutEnabled')
                                }
                                If ($key -eq 'RebootWarningTimeout')
                                {
                                    $WSUSConfighash['RebootWarningTimeout'] = $WSUSConfig.GetValue('RebootWarningTimeout')
                                }
                                If ($key -eq 'RebootWarningTimeoutEnabled')
                                {
                                    $WSUSConfighash['RebootWarningTimeoutEnabled'] = $WSUSConfig.GetValue('RebootWarningTimeoutEnabled')
                                }
                                If ($key -eq 'RescheduleWaitTime')
                                {
                                    $WSUSConfighash['RescheduleWaitTime'] = $WSUSConfig.GetValue('RescheduleWaitTime')
                                }                                                                                                            
                                If ($key -eq 'RescheduleWaitTimeEnabled')
                                {
                                    $WSUSConfighash['RescheduleWaitTimeEnabled'] = $WSUSConfig.GetValue('RescheduleWaitTimeEnabled')
                                }  
                                If ($key -eq 'ScheduleInstallDay')
                                {
                                    $WSUSConfighash['ScheduleInstallDay'] = $WSUSConfig.GetValue('ScheduleInstallDay')
                                }  
                                If ($key -eq 'ScheduleInstallTime')
                                {
                                    $WSUSConfighash['ScheduleInstallTime'] = $WSUSConfig.GetValue('ScheduleInstallTime')
                                }  
                                If ($key -eq 'UseWUServer')
                                {
                                    $WSUSConfighash['UseWUServer'] = $WSUSConfig.GetValue('UseWUServer')
                                }                                          
                            }
                
                            #Display Output
                            If ((-Not ($PSBoundParameters['ShowEnvironment'] -OR $PSBoundParameters['ShowConfiguration'])) -OR `
                            ($PSBoundParameters['ShowEnvironment'] -AND $PSBoundParameters['ShowConfiguration']))
                            {
                                Write-Verbose "Displaying everything"
                                $WSUSHash = ($WSUSEnvHash + $WSUSConfigHash)
                                $WSUSHash['Computername'] = $Computer
                                New-Object PSObject -Property $WSUSHash
                            }
                            Else
                            {
                                If ($PSBoundParameters['ShowEnvironment'])
                                {
                                    Write-Verbose "Displaying environment settings"
                                    $WSUSEnvHash['Computername'] = $Computer
                                    New-Object PSObject -Property $WSUSEnvhash
                                }
                                If ($PSBoundParameters['ShowConfiguration'])
                                {
                                    Write-Verbose "Displaying Configuration settings"
                                    $WSUSConfigHash['Computername'] = $Computer
                                    New-Object PSObject -Property $WSUSConfigHash
                                }
                            }
                        }
                        Else
                        {
                            Write-Warning ("{0}: Unable to connect!" -f $Computer)
                        }
                    }
                }
            }

            Function Install-WSUSServer
            {
                <#  
                    .SYNOPSIS  
                    Downloads (if needed) and performs an unattended installation of WSUS Server with SP2 on a local or remote system. Requires psexec.exe to be in the same
                    location as the script in order to run properly.
                    .DESCRIPTION
                    Downloads (if needed) and performs an unattended installation of WSUS Server with SP2 on a local or remote system. Requires psexec.exe to be in the same
                    location as the script in order to run properly. Also optional to have the installation files in the same location as the script, otherwise the files will
                    be downloaded from the internet.
     
                    .PARAMETER Computername
                    Name of computer to install WSUS server on.
                    .PARAMETER ConsoleOnlyServer
                    Switch used to only install the console without installing the server application.
                    .PARAMETER StoreUpdatesLocally
                    Switch used to determine if updates will be downloaded and saved to system locally.
                    .PARAMETER ContentDirectory
                    Path to the local content folder holding update files. Default location is: %rootdrive%\WSUS\WSUSContent Where-Object the root drive is the largest local drive on the system.
                    .PARAMETER InternalDatabasePath
                    Path to install the internal database
    
                    .PARAMETER CreateDatabase
                    Create a database on the SQL server. Will not create database and attempt to use existing database if switch not used.
                    .PARAMETER WebsitePort
                    Determine the port of the WSUS Site. Accepted Values are "80" and "8530". 
                    .PARAMETER SQLInstance
                    Name of the SQL Instance to connect to for database
    
                    .PARAMETER IsFrontEndServer
                    This server will be a front end server in an NLB
                    .NOTES  
                    Name: Install-WSUSServer
                    Author: Boe Prox
                    DateCreated: 29NOV2011 
           
                    .LINK  
                    https://learn-powershell.net
    
                    .EXAMPLE
                    Install-WSUSServer.ps1 -ConsoleOnly
                    Description
                    -----------
                    Installs the WSUS Console on the local system
                    .EXAMPLE
                    Install-WSUSServer.ps1 -ConsoleOnly -Computername Server1
                    Description
                    -----------
                    Installs the WSUS Console on the remote system Server1
                    .EXAMPLE
                    Install-WSUSServer.ps1 -Computername TestServer -StoreUpdatesLocally -ContentDirectory "D:\WSUS" -InternalDatabasePath "D:\" -CreateDatabase
                    Description
                    -----------
                    Installs WSUS server on TestServer and stores content locally on D:\WSUS and installs an internal database on D:\
                    .EXAMPLE
                    Install-WSUSServer.ps1 -Computername A24 -StoreUpdatesLocally -ContentDirectory "D:\WSUS" -SQLInstance "Server1\Server1" -CreateDatabase
                    Description
                    -----------
                    Installs WSUS server on TestServer and stores content locally on D:\WSUS and creates a database on Server1\Server1 SQL instance
                    .EXAMPLE
                    Install-WSUSServer.ps1 -Computername A24 -StoreUpdatesLocally -ContentDirectory "D:\WSUS" -SQLInstance "Server1\Server1"
                    Description
                    -----------
                    Installs WSUS server on TestServer and stores content locally on D:\WSUS and uses an existing WSUS database on Server1\Server1 SQL instance
                #> 
                [cmdletbinding(
                    DefaultParameterSetName = 'Console',
                    SupportsShouldProcess = $True
                )]
                Param
                (
                    [parameter(ValueFromPipeLine = $True)]
                    [string]$Computername = $Env:Computername,
                    [parameter(ParameterSetName = 'Console')]
                    [switch]$ConsoleOnly,
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [switch]$StoreUpdatesLocally,
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [string]$ContentDirectory,
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [string]$InternalDatabasePath, 
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [ValidateSet("80","8530")]
                    [string]$WebsitePort,
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [switch]$CreateDatabase,
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [string]$SQLInstance,
                    [parameter(ParameterSetName = 'SQLInstanceDatabase')]
                    [parameter(ParameterSetName = 'InternalDatabase')]
                    [switch]$IsFrontEndServer    
    
                )
                Begin
                {
                    If (-NOT (Test-Path psexec.exe))
                    {
                        Write-Warning ("Psexec.exe is not in the current directory! Please copy psexec to this location: {0} or change location to Where-Object psexec.exe is currently at.`nPsexec can be downloaded from the following site:`
                        http://download.sysinternals.com/Files/SysinternalsSuite.zip" -f $pwd)
                        Break
                    }
    
                    #Source Files for X86 and X64
                    Write-Verbose "Setting source files"
                    $x86 = Join-Path $pwd "WSUS30-KB972455-x86.exe"
                    $x64 = Join-Path $pwd "WSUS30-KB972455-x64.exe"
        
                    #Menu items for later use if required
                    Write-Verbose "Building scriptblock for later use"
                    $sb = {$title = "WSUS File Required"
                    $message = "The executable you specified needs to be downloaded from the internet. Do you wish to allow this?"
                    $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                    "Download the file."
                    $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                    "Do not download the file. | will download it myself."    
                    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
                    Write-Verbose "Launching menu for file download"
                    $Host.ui.PromptForChoice($title, $message, $options, 0)}             
    
                    Write-Verbose "Adding URIs for installation files"
                    #URI of specified files if needed to download        
                    $WSUS_X86 = "http://download.microsoft.com/download/B/0/6/B06A69C3-CF97-42CF-86BF-3C59D762E0B2/WSUS30-KB972455-x86.exe"
                    $WSUS_X64 = "http://download.microsoft.com/download/B/0/6/B06A69C3-CF97-42CF-86BF-3C59D762E0B2/WSUS30-KB972455-x64.exe"
    
                    #Define Quiet switch first
                    $arg = "/q "
    
                    #Process parameters
                    If ($PSBoundParameters['ConsoleOnly'])
                    {
                        Write-Verbose "Setting argument to Console Install Only"
                        $arg += "CONSOLE_INSTALL=1 "
                    }
                    If ($PSBoundParameters['StoreUpdatesLocally'])
                    {
                        $arg += "CONTENT_LOCAL=1 "
                        If ($PSBoundParameters['ContentDirectory'])
                        {
                            $arg += "CONTENT_DIR=$ContentDirectory "
                        }
                    }
                    If ($PSBoundParameters['WebsitePort'])
                    {
                        Switch ($WebsitePort)
                        {
                            "80" { $arg += "DEFAULT_WEBSITE=1 " }
                            "8530" { $arg += "DEFAULT_WEBSITE=0 " }
                            Default { $arg += "DEFAULT_WEBSITE=1 " }
                        }
                    }
                    If ($PSBoundParameters['InternalDatabasePath'])
                    {
                        $arg += "WYUKON_DATA_DIR=$InternalDatabasePath "
                    }
                    If ($PSBoundParameters['CreateDatabase'])
                    {
                        $arg += "CREATE_DATABASE=1 "
                    }
                    ElseIf ($PSCmdlet.ParameterSetName -ne 'Console')
                    {
                        #Use default database
                        $arg += "CREATE_DATABASE=0 "
                    }
                    If ($PSBoundParameters['SQLInstance'])
                    {
                        $arg += "SQLINSTANCE_NAME=$SQLInstance "
                    }
                    If ($PSBoundParameters['IsFrontEndServer'])
                    {
                        $arg += "FRONTEND_SETUP=1 "
                    }
                }
                Process
                {
                    Try
                    {
                        $OSArchitecture = Get-WmiObject Win32_OperatingSystem -ComputerName $Computername | 
                            Select-Object -Expand OSArchitecture -EA Stop
                    }
                    Catch
                    {
                        Write-Warning ("{0}: Unable to perform lookup of operating system!`n{1}" -f $Computername,$_.Exception.Message)
                    }  
                    If ($OSArchitecture -eq "64-bit")
                    {
                        Write-Verbose ("{0} using 64-bit" -f $Computername)
                        If (-NOT (Test-Path $x64))
                        {
                            Write-Verbose ("{0} not found, download from internet" -f $x64)
                            switch (&$sb)
                            {
                                0 {
                                    If ($pscmdlet.ShouldProcess($WSUS_X64,"Download File"))
                                    {
                                        Write-Verbose "Configuring webclient to download file"
                                        $wc = New-Object Net.WebClient
                                        $wc.UseDefaultCredentials = $True              
                                        Write-Host -ForegroundColor Green -BackgroundColor Black ("Downloading from {0} to {1} prior to installation. This may take a few minutes" -f $WSUS_X64,$x64)
                                        Try {
                                            $wc.DownloadFile($WSUS_X64,$x64)                                                                                    
                                        }
                                        Catch
                                        {
                                            Write-Warning ("Unable to download file!`nReason: {0}" -f $_.Exception.Message)
                                            Break
                                        } 
                                    }                   
                                    }
                                1 {
                                    #Cancel action
                                    Break
                                    }                
                            }
                        } 
                        #Copy file to root drive
                        If (-NOT (Test-Path ("\\$Computername\c$\{0}" -f (Split-Path $x64 -Leaf))))
                        {
                            Write-Verbose ("Copying {0} to {1}" -f $x64,$Computername)
                            If ($pscmdlet.ShouldProcess($Computername,"Copy File"))
                            {                                
                                Try
                                {
                                    Copy-Item -Path $x64 -Destination "\\$Computername\c$" -EA Stop
                                }
                                Catch
                                {
                                    Write-Warning ("Unable to copy {0} to {1}`nReason: {2}" -f $x64,$Computername,$_.Exception.Message)
                                }
                            }
                        }
                        Else
                        {
                            Write-Verbose ("{0} already exists on {1}" -f (Split-Path $x64 -Leaf),$Computername)
                        }
                        #Perform the installation
                        Write-Verbose ("Begin installation on {0} using specified options" -f $Computername)
                        If ($pscmdlet.ShouldProcess($Computername,"Install WSUS"))
                        {
                            .\psexec.exe -accepteula -i -s \\$Computername cmd /c ("C:\{0} $arg" -f (Split-Path $x64 -Leaf))                                
                        }
                    }
                    Else
                    {
                        Write-Verbose ("{0} using 32-bit" -f $Computername)
                        If (-NOT (Test-Path $x86))
                        {
                        Write-Verbose ("{0} not found, download from internet" -f $x86)
                        switch (&$sb)
                        {
                            0   {
                                If ($pscmdlet.ShouldProcess($WSUS_X86,"Download File"))
                                {
                                    Write-Verbose "Configuring webclient to download file"
                                    $wc = New-Object Net.WebClient
                                    $wc.UseDefaultCredentials = $True              
                                    Write-Host -ForegroundColor Green -BackgroundColor Black ("Downloading from {0} to {1} prior to installation. This may take a few minutes" -f $WSUS_X86,$x86)
                                    Try
                                    {
                                        $wc.DownloadFile($WSUS_X86,$x86)                                                                                          
                                    }
                                    Catch
                                    {
                                        Write-Warning ("Unable to download file!`nReason: {0}" -f $_.Exception.Message)
                                        Break
                                    }
                                }                    
                                }
                            1   {
                                #Cancel action
                                Break
                                }                                
                        }
                    }
                    #Copy file to root drive
                    If (-NOT (Test-Path ("\\$Computername\c$\{0}" -f (Split-Path $x86 -Leaf)))) {
                        Write-Verbose ("Copying {0} to {1}" -f $x86,$Computername) 
                        If ($pscmdlet.ShouldProcess($Computername,"Copy File")) {
                        Try {
                            Copy-Item -Path $x86 -Destination "\\$Computername\c$" -EA Stop
                        } Catch {
                            Write-Warning ("Unable to copy {0} to {1}`nReason: {2}" -f $x86,$Computername,$_.Exception.Message)
                        }
                        }
                    } Else {Write-Verbose ("{0} already exists on {1}" -f $x86,$Computername)}
                    #Perform the installation
                    Write-Verbose ("Begin installation on {0} using specified options" -f $Computername)
                    If ($pscmdlet.ShouldProcess($Computername,"Install WSUS")) {
                        .\psexec.exe -accepteula -i -s \\$Computername cmd /c ("C:\{0} $arg" -f (Split-Path $x86 -Leaf))
                    }
                    }   
                }
            }

            Function Invoke-WSUSDBMaintenance
            {
                <#
                    .SYSNOPSIS
                    Performs maintenance tasks on the SUSDB database using the WSUS API and T-SQL code.
                    .DESCRIPTION
                    Performs maintenance tasks on the SUSDB database using the WSUS API.
            
                    1. Identifies indexes that are fragmented and defragments them. For certain 
                    tables, a fill-factor is set in order to improve insert performance. 
                    Based on MSDN sample at http://msdn2.microsoft.com/en-us/library/ms188917.aspx 
                    and tailored for SUSDB requirements 
                    2. Updates potentially out-of-date table statistics. 
                    .PARAMETER UpdateServer
                    Update server to connect to
                    .PARAMETER Port
                    Port to connect to the Update Server. Default port is 80.
                    .PARAMETER Secure
                    Use a secure connection
                    .NOTES
                    Name: Invoke-WSUSDBMaintenance
                    Author: Boe Prox
                    DateCreated: 03 Jul 2013
                    T-SQL Code used from http://gallery.technet.microsoft.com/scriptcenter/6f8cde49-5c52-4abd-9820-f1d270ddea61
                    .EXAMPLE
                    Invoke-WSUSDBMaintenance -UpdateServer DC1 -Port 80 -Verbose
            
                    VERBOSE: Connecting to DC1
                    VERBOSE: Connecting to SUSDB on DC1
                    VERBOSE: Performing operation "Database Maintenance" on Target "SUSDB".
                    VERBOSE: Completed.
                    Description
                    -----------
                    Performs database maintenance on the database for Update Server DC1 on DC1
                #>
                [cmdletbinding(
                    SupportsShouldProcess = $True
                )]
                Param
                (
                    [parameter(Mandatory=$True)]
                    [ValidateScript({
                        If (-Not (Get-Module -List -Name UpdateServices))
                        {
                            Try
                            {
                                Add-Type -Path "$Env:ProgramFiles\Update Services\Api\Microsoft.UpdateServices.Administration.dll"            
                                $True
                            }
                            Catch
                            {
                                Throw ("Missing the required assemblies to use the WSUS API from {0}" -f "$Env:ProgramFiles\Update Services\Api")
                            }
                        }
                        Else {$True}
                    })]
                    [string]$UpdateServer,
                    [parameter()]
                    [ValidateSet('80','443','8530','8531')]
                    [int]$Port = 8530,
                    [parameter()]
                    [switch]$Secure
                )
                $tSQL = (Dec64v2 'IAAgACAAIABTAEUAVAAgAE4ATwBDAE8AVQBOAFQAIABPAE4AOwAgAA0ACgAgAA0ACgAgACAAIAAgAC0ALQAgAFIAZQBiAHUAaQBsAGQAIABvAHIAIAByAGUAbwByAGcAYQBuAGkAegBlACAAaQBuAGQAZQB4AGUAcwAgAGIAYQBzAGUAZAAgAG8AbgAgAHQAaABlAGkAcgAgAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4AIABsAGUAdgBlAGwAcwAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAHcAbwByAGsAXwB0AG8AXwBkAG8AIABUAEEAQgBMAEUAIAAoACAADQAKACAAIAAgACAAIAAgACAAIABvAGIAagBlAGMAdABpAGQAIABpAG4AdAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAGkAbgBkAGUAeABpAGQAIABpAG4AdAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAHAAYQBnAGUAZABlAG4AcwBpAHQAeQAgAGYAbABvAGEAdAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4AIABmAGwAbwBhAHQAIAANAAoAIAAgACAAIAAgACAAIAAgACwAIABuAHUAbQByAG8AdwBzACAAaQBuAHQAIAANAAoAIAAgACAAIAApACAADQAKACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAbwBiAGoAZQBjAHQAaQBkACAAaQBuAHQAOwAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAGkAbgBkAGUAeABpAGQAIABpAG4AdAA7ACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAcwBjAGgAZQBtAGEAbgBhAG0AZQAgAG4AdgBhAHIAYwBoAGEAcgAoADEAMwAwACkAOwAgACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAbwBiAGoAZQBjAHQAbgBhAG0AZQAgAG4AdgBhAHIAYwBoAGEAcgAoADEAMwAwACkAOwAgACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAaQBuAGQAZQB4AG4AYQBtAGUAIABuAHYAYQByAGMAaABhAHIAKAAxADMAMAApADsAIAAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAG4AdQBtAHIAbwB3AHMAIABpAG4AdAAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAGQAZQBuAHMAaQB0AHkAIABmAGwAbwBhAHQAOwAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4AIABmAGwAbwBhAHQAOwAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABAAGMAbwBtAG0AYQBuAGQAIABuAHYAYQByAGMAaABhAHIAKAA0ADAAMAAwACkAOwAgACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAZgBpAGwAbABmAGEAYwB0AG8AcgBzAGUAdAAgAGIAaQB0ACAADQAKACAAIAAgACAARABFAEMATABBAFIARQAgAEAAbgB1AG0AcABhAGcAZQBzACAAaQBuAHQAIAANAAoAIAANAAoAIAAgACAAIAAtAC0AIABTAGUAbABlAGMAdAAgAGkAbgBkAGUAeABlAHMAIAB0AGgAYQB0ACAAbgBlAGUAZAAgAHQAbwAgAGIAZQAgAGQAZQBmAHIAYQBnAG0AZQBuAHQAZQBkACAAYgBhAHMAZQBkACAAbwBuACAAdABoAGUAIABmAG8AbABsAG8AdwBpAG4AZwAgAA0ACgAgACAAIAAgAC0ALQAgACoAIABQAGEAZwBlACAAZABlAG4AcwBpAHQAeQAgAGkAcwAgAGwAbwB3ACAADQAKACAAIAAgACAALQAtACAAKgAgAEUAeAB0AGUAcgBuAGEAbAAgAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4AIABpAHMAIABoAGkAZwBoACAAaQBuACAAcgBlAGwAYQB0AGkAbwBuACAAdABvACAAaQBuAGQAZQB4ACAAcwBpAHoAZQAgAA0ACgAgACAAIAAgAEkATgBTAEUAUgBUACAAQAB3AG8AcgBrAF8AdABvAF8AZABvACAADQAKACAAIAAgACAAUwBFAEwARQBDAFQAIAANAAoAIAAgACAAIAAgACAAIAAgAGYALgBvAGIAagBlAGMAdABfAGkAZAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAGkAbgBkAGUAeABfAGkAZAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAGEAdgBnAF8AcABhAGcAZQBfAHMAcABhAGMAZQBfAHUAcwBlAGQAXwBpAG4AXwBwAGUAcgBjAGUAbgB0ACAADQAKACAAIAAgACAAIAAgACAAIAAsACAAYQB2AGcAXwBmAHIAYQBnAG0AZQBuAHQAYQB0AGkAbwBuAF8AaQBuAF8AcABlAHIAYwBlAG4AdAAgAA0ACgAgACAAIAAgACAAIAAgACAALAAgAHIAZQBjAG8AcgBkAF8AYwBvAHUAbgB0ACAADQAKACAAIAAgACAARgBSAE8ATQAgACAADQAKACAAIAAgACAAIAAgACAAIABzAHkAcwAuAGQAbQBfAGQAYgBfAGkAbgBkAGUAeABfAHAAaAB5AHMAaQBjAGEAbABfAHMAdABhAHQAcwAgACgARABCAF8ASQBEACgAKQAsACAATgBVAEwATAAsACAATgBVAEwATAAgACwAIABOAFUATABMACwAIAAnAFMAQQBNAFAATABFAEQAJwApACAAQQBTACAAZgAgAA0ACgAgACAAIAAgAFcASABFAFIARQAgAA0ACgAgACAAIAAgACAAIAAgACAAKABmAC4AYQB2AGcAXwBwAGEAZwBlAF8AcwBwAGEAYwBlAF8AdQBzAGUAZABfAGkAbgBfAHAAZQByAGMAZQBuAHQAIAA8ACAAOAA1AC4AMAAgAGEAbgBkACAAZgAuAGEAdgBnAF8AcABhAGcAZQBfAHMAcABhAGMAZQBfAHUAcwBlAGQAXwBpAG4AXwBwAGUAcgBjAGUAbgB0AC8AMQAwADAALgAwACAAKgAgAHAAYQBnAGUAXwBjAG8AdQBuAHQAIAA8ACAAcABhAGcAZQBfAGMAbwB1AG4AdAAgAC0AIAAxACkAIAANAAoAIAAgACAAIAAgACAAIAAgAG8AcgAgACgAZgAuAHAAYQBnAGUAXwBjAG8AdQBuAHQAIAA+ACAANQAwACAAYQBuAGQAIABmAC4AYQB2AGcAXwBmAHIAYQBnAG0AZQBuAHQAYQB0AGkAbwBuAF8AaQBuAF8AcABlAHIAYwBlAG4AdAAgAD4AIAAxADUALgAwACkAIAANAAoAIAAgACAAIAAgACAAIAAgAG8AcgAgACgAZgAuAHAAYQBnAGUAXwBjAG8AdQBuAHQAIAA+ACAAMQAwACAAYQBuAGQAIABmAC4AYQB2AGcAXwBmAHIAYQBnAG0AZQBuAHQAYQB0AGkAbwBuAF8AaQBuAF8AcABlAHIAYwBlAG4AdAAgAD4AIAA4ADAALgAwACkAIAANAAoAIAANAAoAIAANAAoAIAAgACAAIABTAEUATABFAEMAVAAgAEAAbgB1AG0AcABhAGcAZQBzACAAPQAgAHMAdQBtACgAcABzAC4AdQBzAGUAZABfAHAAYQBnAGUAXwBjAG8AdQBuAHQAKQAgAA0ACgAgACAAIAAgAEYAUgBPAE0AIAANAAoAIAAgACAAIAAgACAAIAAgAEAAdwBvAHIAawBfAHQAbwBfAGQAbwAgAEEAUwAgAGYAaQAgAA0ACgAgACAAIAAgACAAIAAgACAASQBOAE4ARQBSACAASgBPAEkATgAgAHMAeQBzAC4AaQBuAGQAZQB4AGUAcwAgAEEAUwAgAGkAIABPAE4AIABmAGkALgBvAGIAagBlAGMAdABpAGQAIAA9ACAAaQAuAG8AYgBqAGUAYwB0AF8AaQBkACAAYQBuAGQAIABmAGkALgBpAG4AZABlAHgAaQBkACAAPQAgAGkALgBpAG4AZABlAHgAXwBpAGQAIAANAAoAIAAgACAAIAAgACAAIAAgAEkATgBOAEUAUgAgAEoATwBJAE4AIABzAHkAcwAuAGQAbQBfAGQAYgBfAHAAYQByAHQAaQB0AGkAbwBuAF8AcwB0AGEAdABzACAAQQBTACAAcABzACAAbwBuACAAaQAuAG8AYgBqAGUAYwB0AF8AaQBkACAAPQAgAHAAcwAuAG8AYgBqAGUAYwB0AF8AaQBkACAAYQBuAGQAIABpAC4AaQBuAGQAZQB4AF8AaQBkACAAPQAgAHAAcwAuAGkAbgBkAGUAeABfAGkAZAAgAA0ACgAgAA0ACgAgACAAIAAgAC0ALQAgAEQAZQBjAGwAYQByAGUAIAB0AGgAZQAgAGMAdQByAHMAbwByACAAZgBvAHIAIAB0AGgAZQAgAGwAaQBzAHQAIABvAGYAIABpAG4AZABlAHgAZQBzACAAdABvACAAYgBlACAAcAByAG8AYwBlAHMAcwBlAGQALgAgAA0ACgAgACAAIAAgAEQARQBDAEwAQQBSAEUAIABjAHUAcgBJAG4AZABlAHgAZQBzACAAQwBVAFIAUwBPAFIAIABGAE8AUgAgAFMARQBMAEUAQwBUACAAKgAgAEYAUgBPAE0AIABAAHcAbwByAGsAXwB0AG8AXwBkAG8AIAANAAoAIAANAAoAIAAgACAAIAAtAC0AIABPAHAAZQBuACAAdABoAGUAIABjAHUAcgBzAG8AcgAuACAADQAKACAAIAAgACAATwBQAEUATgAgAGMAdQByAEkAbgBkAGUAeABlAHMAIAANAAoAIAANAAoAIAAgACAAIAAtAC0AIABMAG8AbwBwACAAdABoAHIAbwB1AGcAaAAgAHQAaABlACAAaQBuAGQAZQB4AGUAcwAgAA0ACgAgACAAIAAgAFcASABJAEwARQAgACgAMQA9ADEAKQAgAA0ACgAgACAAIAAgAEIARQBHAEkATgAgAA0ACgAgACAAIAAgACAAIAAgACAARgBFAFQAQwBIACAATgBFAFgAVAAgAEYAUgBPAE0AIABjAHUAcgBJAG4AZABlAHgAZQBzACAADQAKACAAIAAgACAAIAAgACAAIABJAE4AVABPACAAQABvAGIAagBlAGMAdABpAGQALAAgAEAAaQBuAGQAZQB4AGkAZAAsACAAQABkAGUAbgBzAGkAdAB5ACwAIABAAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4ALAAgAEAAbgB1AG0AcgBvAHcAcwA7ACAADQAKACAAIAAgACAAIAAgACAAIABJAEYAIABAAEAARgBFAFQAQwBIAF8AUwBUAEEAVABVAFMAIAA8ACAAMAAgAEIAUgBFAEEASwA7ACAADQAKACAADQAKACAAIAAgACAAIAAgACAAIABTAEUATABFAEMAVAAgACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEAAbwBiAGoAZQBjAHQAbgBhAG0AZQAgAD0AIABRAFUATwBUAEUATgBBAE0ARQAoAG8ALgBuAGEAbQBlACkAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAALAAgAEAAcwBjAGgAZQBtAGEAbgBhAG0AZQAgAD0AIABRAFUATwBUAEUATgBBAE0ARQAoAHMALgBuAGEAbQBlACkAIAANAAoAIAAgACAAIAAgACAAIAAgAEYAUgBPAE0AIAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABzAHkAcwAuAG8AYgBqAGUAYwB0AHMAIABBAFMAIABvACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAEkATgBOAEUAUgAgAEoATwBJAE4AIABzAHkAcwAuAHMAYwBoAGUAbQBhAHMAIABhAHMAIABzACAATwBOACAAcwAuAHMAYwBoAGUAbQBhAF8AaQBkACAAPQAgAG8ALgBzAGMAaABlAG0AYQBfAGkAZAAgAA0ACgAgACAAIAAgACAAIAAgACAAVwBIAEUAUgBFACAAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAbwAuAG8AYgBqAGUAYwB0AF8AaQBkACAAPQAgAEAAbwBiAGoAZQBjAHQAaQBkADsAIAANAAoAIAANAAoAIAAgACAAIAAgACAAIAAgAFMARQBMAEUAQwBUACAAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAAQABpAG4AZABlAHgAbgBhAG0AZQAgAD0AIABRAFUATwBUAEUATgBBAE0ARQAoAG4AYQBtAGUAKQAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIAAsACAAQABmAGkAbABsAGYAYQBjAHQAbwByAHMAZQB0ACAAPQAgAEMAQQBTAEUAIABmAGkAbABsAF8AZgBhAGMAdABvAHIAIABXAEgARQBOACAAMAAgAFQASABFAE4AIAAwACAARQBMAFMARQAgADEAIABFAE4ARAAgAA0ACgAgACAAIAAgACAAIAAgACAARgBSAE8ATQAgACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAHMAeQBzAC4AaQBuAGQAZQB4AGUAcwAgAA0ACgAgACAAIAAgACAAIAAgACAAVwBIAEUAUgBFACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAG8AYgBqAGUAYwB0AF8AaQBkACAAPQAgAEAAbwBiAGoAZQBjAHQAaQBkACAAQQBOAEQAIABpAG4AZABlAHgAXwBpAGQAIAA9ACAAQABpAG4AZABlAHgAaQBkADsAIAANAAoAIAANAAoAIAAgACAAIAAgACAAIAAgAEkARgAgACgAKABAAGQAZQBuAHMAaQB0AHkAIABCAEUAVABXAEUARQBOACAANwA1AC4AMAAgAEEATgBEACAAOAA1AC4AMAApACAAQQBOAEQAIABAAGYAaQBsAGwAZgBhAGMAdABvAHIAcwBlAHQAIAA9ACAAMQApACAATwBSACAAKABAAGYAcgBhAGcAbQBlAG4AdABhAHQAaQBvAG4AIAA8ACAAMwAwAC4AMAApACAADQAKACAAIAAgACAAIAAgACAAIAAgACAAIAAgAFMARQBUACAAQABjAG8AbQBtAGEAbgBkACAAPQAgAE4AJwBBAEwAVABFAFIAIABJAE4ARABFAFgAIAAnACAAKwAgAEAAaQBuAGQAZQB4AG4AYQBtAGUAIAArACAATgAnACAATwBOACAAJwAgACsAIABAAHMAYwBoAGUAbQBhAG4AYQBtAGUAIAArACAATgAnAC4AJwAgACsAIABAAG8AYgBqAGUAYwB0AG4AYQBtAGUAIAArACAATgAnACAAUgBFAE8AUgBHAEEATgBJAFoARQAnADsAIAANAAoAIAAgACAAIAAgACAAIAAgAEUATABTAEUAIABJAEYAIABAAG4AdQBtAHIAbwB3AHMAIAA+AD0AIAA1ADAAMAAwACAAQQBOAEQAIABAAGYAaQBsAGwAZgBhAGMAdABvAHIAcwBlAHQAIAA9ACAAMAAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABTAEUAVAAgAEAAYwBvAG0AbQBhAG4AZAAgAD0AIABOACcAQQBMAFQARQBSACAASQBOAEQARQBYACAAJwAgACsAIABAAGkAbgBkAGUAeABuAGEAbQBlACAAKwAgAE4AJwAgAE8ATgAgACcAIAArACAAQABzAGMAaABlAG0AYQBuAGEAbQBlACAAKwAgAE4AJwAuACcAIAArACAAQABvAGIAagBlAGMAdABuAGEAbQBlACAAKwAgAE4AJwAgAFIARQBCAFUASQBMAEQAIABXAEkAVABIACAAKABGAEkATABMAEYAQQBDAFQATwBSACAAPQAgADkAMAApACcAOwAgAA0ACgAgACAAIAAgACAAIAAgACAARQBMAFMARQAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABTAEUAVAAgAEAAYwBvAG0AbQBhAG4AZAAgAD0AIABOACcAQQBMAFQARQBSACAASQBOAEQARQBYACAAJwAgACsAIABAAGkAbgBkAGUAeABuAGEAbQBlACAAKwAgAE4AJwAgAE8ATgAgACcAIAArACAAQABzAGMAaABlAG0AYQBuAGEAbQBlACAAKwAgAE4AJwAuACcAIAArACAAQABvAGIAagBlAGMAdABuAGEAbQBlACAAKwAgAE4AJwAgAFIARQBCAFUASQBMAEQAJwA7ACAADQAKACAAIAAgACAAIAAgACAAIABFAFgARQBDACAAKABAAGMAbwBtAG0AYQBuAGQAKQA7ACAAIAANAAoAIAAgACAAIABFAE4ARAAgAA0ACgAgAA0ACgAgACAAIAAgAC0ALQAgAEMAbABvAHMAZQAgAGEAbgBkACAAZABlAGEAbABsAG8AYwBhAHQAZQAgAHQAaABlACAAYwB1AHIAcwBvAHIALgAgAA0ACgAgACAAIAAgAEMATABPAFMARQAgAGMAdQByAEkAbgBkAGUAeABlAHMAOwAgAA0ACgAgACAAIAAgAEQARQBBAEwATABPAEMAQQBUAEUAIABjAHUAcgBJAG4AZABlAHgAZQBzADsAIAANAAoAIAANAAoAIAAgACAAIABJAEYAIABFAFgASQBTAFQAUwAgACgAUwBFAEwARQBDAFQAIAAqACAARgBSAE8ATQAgAEAAdwBvAHIAawBfAHQAbwBfAGQAbwApACAADQAKACAAIAAgACAAQgBFAEcASQBOACAADQAKACAAIAAgACAAIAAgACAAIABTAEUATABFAEMAVAAgAEAAbgB1AG0AcABhAGcAZQBzACAAPQAgAEAAbgB1AG0AcABhAGcAZQBzACAALQAgAHMAdQBtACgAcABzAC4AdQBzAGUAZABfAHAAYQBnAGUAXwBjAG8AdQBuAHQAKQAgAA0ACgAgACAAIAAgACAAIAAgACAARgBSAE8ATQAgAA0ACgAgACAAIAAgACAAIAAgACAAIAAgACAAIABAAHcAbwByAGsAXwB0AG8AXwBkAG8AIABBAFMAIABmAGkAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAASQBOAE4ARQBSACAASgBPAEkATgAgAHMAeQBzAC4AaQBuAGQAZQB4AGUAcwAgAEEAUwAgAGkAIABPAE4AIABmAGkALgBvAGIAagBlAGMAdABpAGQAIAA9ACAAaQAuAG8AYgBqAGUAYwB0AF8AaQBkACAAYQBuAGQAIABmAGkALgBpAG4AZABlAHgAaQBkACAAPQAgAGkALgBpAG4AZABlAHgAXwBpAGQAIAANAAoAIAAgACAAIAAgACAAIAAgACAAIAAgACAASQBOAE4ARQBSACAASgBPAEkATgAgAHMAeQBzAC4AZABtAF8AZABiAF8AcABhAHIAdABpAHQAaQBvAG4AXwBzAHQAYQB0AHMAIABBAFMAIABwAHMAIABvAG4AIABpAC4AbwBiAGoAZQBjAHQAXwBpAGQAIAA9ACAAcABzAC4AbwBiAGoAZQBjAHQAXwBpAGQAIABhAG4AZAAgAGkALgBpAG4AZABlAHgAXwBpAGQAIAA9ACAAcABzAC4AaQBuAGQAZQB4AF8AaQBkACAADQAKACAAIAAgACAARQBOAEQAIAAgAA0ACgAgAA0ACgAgACAAIAAgAC0ALQBVAHAAZABhAHQAZQAgAGEAbABsACAAcwB0AGEAdABpAHMAdABpAGMAcwAgACAADQAKACAAIAAgACAARQBYAEUAQwAgAHMAcABfAHUAcABkAGEAdABlAHMAdABhAHQAcwAgACAA')
                Write-Verbose ("Connecting to {0}" -f $UpdateServer)
                Try
                {
                    If (Get-Module -List -Name UpdateServices)
                    {
                        $Wsus = Get-WSUSServer -Name $UpdateServer -PortNumber $Port
                    }
                    Else
                    {
                        $Wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($UpdateServer,$Secure,$Port)
                    }
                    $db = $wsus.GetDatabaseConfiguration().CreateConnection()
                    Write-Verbose ("Connecting to {0} on {1}" -f $db.databasename,$db.servername)
                    $db.Connect()
                    If ($PSCmdlet.ShouldProcess($db.Databasename,'Database Maintenance'))
                    {
                        $db.ExecuteCommandNoResult($tSQL,[System.Data.CommandType]::Text)
                        $db.CloseCommand()
                        $db.Close()
                    }   
                }
                Catch
                {
                    Write-Warning ("{0}" -f $_.Exception.Message)
                }
                Write-Verbose "Completed"
            }

            Function Invoke-WSUSClientFix
            {
                <#  
                    .SYNOPSIS  
                    Performs a WSUS client reset on local or remote system.
        
                    .DESCRIPTION
                    Performs a WSUS client reset on local or remote system.
        
                    .PARAMETER Computername
                    Name of the remote or local system.
                   
                    .NOTES  
                    Name: Invoke-WSUSClientFix
                    Author: Boe Prox
                    DateCreated: 18JAN2012
                    DateModified: 28Mar2014  
              
                    .EXAMPLE  
                    Invoke-WSUSClientFix -Computername 'Server' -Verbose
        
                    VERBOSE: Server: Testing network connection
                    VERBOSE: Server: Stopping wuauserv service
                    VERBOSE: Server: Making remote registry connection to LocalMachine hive
                    VERBOSE: Server: Connection to WSUS Client registry keys
                    VERBOSE: Server: Removing Software Distribution folder and subfolders
                    VERBOSE: Server: Starting wuauserv service
                    VERBOSE: Server: Sending wuauclt /resetauthorization /detectnow command
    
                    Description
                    -----------
                    This command resets the WSUS client information on Server.
                #> 
                [cmdletbinding(SupportsShouldProcess=$True)]
                Param
                (
                    [parameter(ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True)]
                    [Alias('__Server','Server','CN')]
                    [string[]]$Computername = $Env:Computername
                )
                Begin
                {
                    $reghive = [microsoft.win32.registryhive]::LocalMachine
                }
                Process
                {
                    ForEach ($Computer in $Computername)
                    {
                        Write-Verbose ("{0}: Testing network connection" -f $Computer)
                        If (Test-Connection -ComputerName $Computer -Count 1 -Quiet)
                        {
                            Write-Verbose ("{0}: Stopping wuauserv service" -f $Computer)
                            $wuauserv = Get-Service -ComputerName $Computer -Name wuauserv 
                            Stop-Service -InputObject $wuauserv
                
                            Write-Verbose ("{0}: Making remote registry connection to {1} hive" -f $Computer, $reghive)
                            $remotereg = [microsoft.win32.registrykey]::OpenRemoteBaseKey($reghive,$Computer)
                            Write-Verbose ("{0}: Connection to WSUS Client registry keys" -f $Computer)
                            $wsusreg1 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate',$True)
                            $wsusreg2 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',$True)

                            #Begin deletion of registry values for WSUS Client
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientId')))
                            {
                                If ($PScmdlet.ShouldProcess("SusClientId","Delete Registry Value"))
                                {
                                    $wsusreg1.DeleteValue('SusClientId')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientIdValidation')))
                            {
                                If ($PScmdlet.ShouldProcess("SusClientIdValidation","Delete Registry Value"))
                                {
                                    $wsusreg1.DeleteValue('SusClientIdValidation')
                                }
                            }                
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('PingID')))
                            {
                                If ($PScmdlet.ShouldProcess("PingID","Delete Registry Value"))
                                {
                                    $wsusreg1.DeleteValue('PingID')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('AccountDomainSid')))
                            {
                                If ($PScmdlet.ShouldProcess("AccountDomainSid","Delete Registry Value"))
                                {
                                    $wsusreg1.DeleteValue('AccountDomainSid')
                                }
                            }   
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('LastWaitTimeout')))
                            {
                                If ($PScmdlet.ShouldProcess("LastWaitTimeout","Delete Registry Value"))
                                {
                                    $wsusreg2.DeleteValue('LastWaitTimeout')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('DetectionStartTimeout')))
                            {
                                If ($PScmdlet.ShouldProcess("DetectionStartTimeout","Delete Registry Value"))
                                {
                                    $wsusreg2.DeleteValue('DetectionStartTimeout')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('NextDetectionTime')))
                            {
                                If ($PScmdlet.ShouldProcess("NextDetectionTime","Delete Registry Value"))
                                {
                                    $wsusreg2.DeleteValue('NextDetectionTime')
                                }
                            }
                            If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('AUState')))
                            {
                                If ($PScmdlet.ShouldProcess("AUState","Delete Registry Value"))
                                {
                                    $wsusreg2.DeleteValue('AUState')
                                }
                            }
               
                
                            Write-Verbose ("{0}: Removing Software Distribution folder and subfolders" -f $Computer)
                            Try
                            {
                                Remove-Item "\\$Computer\c$\Windows\SoftwareDistribution" -Recurse -Force -Confirm:$False -ErrorAction Stop                                                                                         
                            }
                            Catch
                            {
                                Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                            }
                
                            Write-Verbose ("{0}: Starting wuauserv service" -f $Computer)
                            Start-Service -InputObject $wuauserv
                
                            Write-Verbose ("{0}: Sending wuauclt /resetauthorization /detectnow command" -f $Computer)
                            Try
                            {
                                $null = Invoke-WmiMethod -Path Win32_Process -ComputerName $Computer -Name Create `
                                    -ArgumentList "wuauclt /resetauthorization /detectnow" -ErrorAction Stop
                            }
                            Catch
                            {
                                Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                            }
                        }
                    }
                }
            }

            Function Invoke-WSUSConnection
            {
                $nonLocal = !((Get-WindowsFeature -Name UpdateServices).InstallState -eq 'Installed')
 
                If ($nonLocal -eq $true){ $wSrvr = Read-Host -Prompt 'Enter WSUS Netbios Name' }
                Else { $wSrvr = $Env:computername }
        
                If ($nonLocal -eq $false)
                {
                    Add-Type -Path "$Env:ProgramFiles\Update Services\Api\Microsoft.UpdateServices.Administration.dll"
                    $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
                }
                Else
                {
                    Try
                    {
                        If ($null -eq $wsus){ [void]($wsus = Get-WSUSServer -Name $wSrvr -Port 8530) }
                    } Catch {}
                    Try
                    {
                        If ($null -eq $wsus){ $wsus = Connect-PSWSUSServer -WsusServer $wSrvr -Port 8530 }
                    } Catch {}
                    Try
                    {
                        If ($null -eq $wsus)
                        {
                            # Add-Type -Path "\\$wSrvr`\c$\Program Files\Update Services\Api\Microsoft.UpdateServices.Administration.dll"  "$Env:ProgramFiles\"
                            $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer($wSrvr,$False,8530)
                        }
                    } Catch {}
                    Try
                    {
                        If ($null -eq $wsus)
                        {
                            New-PSSession -ComputerName $wSrvr -Name WSUS
                            Enter-PSSession -Name WSUS
                            Start-Sleep  -sec 2
                            [reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
                            Start-Sleep  -sec 2
                            $wsus = [Microsoft.UpdateServices.Administration.AdminProxy]::GetUpdateServer()
                            # Exit-PSSession
                        }
                                     
                    } Catch {}
           
           
                } 
                If ($null -eq $wsus){ Write-Warning "Unable to connect to $wSrvr; Exiting" }
                Else { Return $wsus }
            }

            Function Get-XferDrive
            {
                Param
                (
                    [Parameter(Mandatory=$true)]$trgVol,
                    $trgServer,
                    [Switch]$mapLocal
                )
                function Get-NextFreeDrive
                {
                    $asgnDrives = (Get-WmiObject win32_LogicalDisk | Where-Object DriveType -match '^(3|4)$' | Select-Object -Exp DeviceID) -join ','
                    67..90 | ForEach-Object { "$([char]$_):" } | 
                        Where-Object { $asgnDrives -notcontains $_  } | 
                            Where-Object { 
                                (new-object System.IO.DriveInfo $_).DriveType -eq 'noRootdirectory' 
                            } | Select-Object -First 1
                }

                # Locate and Verify Removable Device
                    # Is drive local?
                        $islocal = [bool](Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -eq $trgVol)
                        If ($islocal) { $drvRemovable = (Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -eq $trgVol).DeviceID }

                    # Is drive remotely attached?
                        If ($islocal -eq $false)
                        {
                            if ([String]::IsNullOrEmpty($trgServer)) { $trgServer = Read-Host -Prompt "Enter Server Name Where-Object removable volume '$trgVol' is attached:" }
                            If ([String]::IsNullOrEmpty($trgServer)) { Write-Warning "No Server Name provided for volume '$trgVol':: EXITING"; BREAK }
                            # IF (Test-Connection -BufferSize 32 -Count 1 -ComputerName $trgServer -Quiet) { Write-Warning "Server [$trgServer] offline:: EXITING"; BREAK }
                            $isRemote = [bool](Get-WmiObject Win32_LogicalDisk -ComputerName $trgServer -ea SilentlyContinue | Where-Object VolumeName -eq $trgVol)
                            If ($isRemote -eq $true)
                            {
                                $drvTemp = (Get-WmiObject Win32_LogicalDisk -ComputerName $trgServer -ea SilentlyContinue | Where-Object VolumeName -eq $trgVol).DeviceID
                                $drvUNC = "\\$trgServer\$($drvTemp -replace '\:','$')"
                                $drvRemovable = $drvUNC
                            }
                        }
                    # Connect Removable Device (Remote)
                        if ($mapLocal.IsPresent -eq $true -and $null -ne $drvTemp)
                        {
                            $drvlist = (Get-PSDrive -PSProvider filesystem).Name
                            Foreach ($drvletter in "EFGHIJKLMNOPQRSTUVWXYZ".ToCharArray())
                            {
                                If ($drvlist -notcontains $drvletter)
                                {
                                    $drv = New-PSDrive -PSProvider filesystem -Name $drvletter -Root $drvUNC -Scope Global
                                    Break
                                }
                            }
                            Write-Host -f Green "$trgVol device located at [$drvUNC], mapping as [$($drv.Name):]"
                            $drvRemovable = "$($drv.Name):"
                        }
                        Else
                        {
                            If ($isRemote -eq $true -and [String]::IsNullOrEmpty($drvUNC) -eq $false)
                            { Write-Host -f Green "$trgVol device located at [$drvUNC]" }
                        }

                    # Is not found, notify and quit
                        If ($null -eq $drvRemovable)
                        {
                            Write-Warning "'$trgVol' volume not found locally nor on [$trgServer]:: EXITING"
                            Return $null
                            BREAK
                        }
                    # Return Removable Volume Device
                        Else
                        {
                            Return $drvRemovable
                            Break
                        }
            }
        #endregion

        $remDrv = Get-XferDrive -trgVol 'Jenny' -mapLocal -trgServer 'fabconhv01' # 'vanws010900-130'
        Get-ChildItem $remDrv

        
        # Intall WSUS Console Only
            Install-WindowsFeature -Name UpdateServices-Ui -Verbose

        $wsus = Invoke-WSUSConnection
        $computerscope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
        $updatescope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
  
        # Get WSUS update History
            $updateHistory = $wsus.GetUpdateEventHistory("$((Get-Date).AddDays(-40))","$(Get-Date)")
            $updateHistory[0] | Select-Object ComputerId,HasAssociatedUpdate,HasAssociatedComputer,ID,Status,WsusEventSource,WsusEventId,
                                        Message,IsError,ErrorCode,@{n='UpdateServer';e={$_.UpdateServer.Name}},
                                        @{n='UpdateId';e={$_.UpdateId.UpdateId.Guid}},@{n='UpdateRevId';e={$_.UpdateId.RevisionNumber}},
                                        CreationDate,@{n='RowInfo';e={$_.Row | ConvertTo-Csv -NoTypeInformation}}
            $updateHistory[0].UpdateServer | Select-Object *
            $updateHistory[0].UpdateId | Get-Member
            $updateHistory[0].Row | Get-Member

        # Get WSUS Approval Rules
            $approvalrules = $wsus.GetInstallApprovalRules()
            $approvalrules[0]

        # Get WSUS Computers
            $wsus.GetComputerTargets($computerscope)
    
        # Get WSUS Computer Status
            $wsus.GetComputerStatus($computerscope,$updatescope.UpdateSources)
  
        #region Get Selected Products and Categories
            # https://4sysops.com/archives/configure-wsus-products-and-classifications-with-powershell/
            # https://community.spiceworks.com/topic/2289475-how-do-the-classifications-and-categories-in-powershell-relate-to-the-gui
            $selectedProducts = $WSUS.GetSubscription().GetUpdateCategories() # PRODUCTS
            $selectedCategories = $WSUS.GetSubscription().GetUpdateClassifications() # CLASSIFICATIONS

            $selectedProducts | Select-Object -ExpandProperty title
            $selectedCategories | Select-Object -ExpandProperty title

            # Save to XML
                $wSrvr = $wsus.ServerName
                Invoke-Item ($dstPath = [Environment]::GetFolderPath('Desktop'))
                $selectedProducts | Export-Clixml -Path ($dstPath + "\$wSrvr`_Prodlist.xml") -Force -Verbose
                $selectedCategories | Export-Clixml -Path ($dstPath + "\$wSrvr`_Catlist.xml") -Force -Verbose

            # Load from XML
                $remDrive = Get-XferDrive -trgVol Jenny
                $ustrmSrvr = 'WSUS01'
                If ($null -eq $remDrive){ Break }
                Else
                {
                    $xmlPath = $remDrive + '\WSUS Transfer Scripts'
                    $upstreamCat = Import-Clixml -Path ($xmlPath + "\$ustrmSrvr`_Catlist.xml")
                    $upstreamProd = Import-Clixml -Path ($xmlPath + "\$ustrmSrvr`_Prodlist.xml")

                    $upstreamCat | Select-Object -ExpandProperty title
                    $upstreamProd | Select-Object -ExpandProperty title
                }

                $compCat = Compare-Object ($upstreamCat | Select-Object -ExpandProperty title) ($selectedCategories | Select-Object -ExpandProperty title) -IncludeEqual
                $compProd = Compare-Object ($upstreamProd | Select-Object -ExpandProperty title) ($selectedProducts | Select-Object -ExpandProperty title) -IncludeEqual

                #  Modify Categories to match Upstream Server
                    $missingCats = $compCat | Where-Object SideIndicator -eq '<=' | Select-Object -Exp InputObject
                    $xtraCats = $compCat | Where-Object SideIndicator -eq '=>' | Select-Object -Exp InputObject
                    # $missingCats | ForEach-Object{ Get-WsusClassification | Where-Object { $_.Classification.Title -eq $_ } | Set-WsusClassification }
                    $missingCats | ForEach-Object{ Get-PSWsusClassification | Where-Object Title -eq $_  | Set-poshWsusClassification }
                    # $xtraCats    | ForEach-Object{ Get-WsusClassification | gmWhere-Object { $_.Classification.Title -eq $_ } | Set-WsusClassification -Disable }
                    $xtraCats    | ForEach-Object{ Get-PSWsusClassification | gmWhere-Object { $_.Title -eq $_ } | Set-poshWsusClassification -Disable }

                #  Modify Products to match Upstream Server
                    $missingProds = $compProd | Where-Object SideIndicator -eq '<=' | Select-Object -Exp InputObject
                    $xtraProds = $compProd | Where-Object SideIndicator -eq '=>' | Select-Object -Exp InputObject
                    $missingProds | ForEach-Object{ Get-WsusProduct | Where-Object{ $_.Product.Title -eq $_ } | Set-WsusProduct }
                    $xtraProds    | ForEach-Object{ Get-WsusProduct | Where-Object{ $_.Product.Title -eq $_ } | Set-WsusProduct -Disable }

                    # $missingProds | ForEach-Object{ Get-WsusClassification | Where-Object { $_.Classification.Title -eq $_ } | Set-WsusClassification }
                    $missingProds | ForEach-Object{ Get-PSWsusClassification | Where-Object Title -eq $_  | Set-poshWsusClassification }
                    # $xtraProds    | ForEach-Object{ Get-WsusClassification | gmWhere-Object { $_.Classification.Title -eq $_ } | Set-WsusClassification -Disable }
                    $xtraProds    | ForEach-Object{ Get-PSWsusClassification | gmWhere-Object { $_.Title -eq $_ } | Set-poshWsusClassification -Disable }
            #endregion
            'PoshWSUS','PSWindowsUpdate' | ForEach-Object { Install-Module -Name $_ <#-RequiredVersion 2.1.0.1#> }
            'PoshWSUS','PSWindowsUpdate' | ForEach-Object { Import-Module -Name $_ }
            'PoshWSUS','PSWindowsUpdate' | ForEach-Object { Get-Command -Module $_ }

        #region wsus db connect
            $wsusConfig = $wsus.GetConfiguration() | Sort-Object
            $wsusdbCfg = $wsus.GetDatabaseConfiguration()
            $wsusdbConn = $wsusdbCfg.CreateConnection()
            $wsusdbConn.ConnectionString
            $db = $wsusdbConn.CreateConnection()
            $db.connect()
            $db
            $db.GetDataSet
            $result = $db.GetDataSet('Select-Object * from INFORMATION_SCHEMA.TABLES',[System.Data.CommandType]::Text)
            $result.tables.rows

            $sqlConn = 'server=\\.\pipe\MICROSOFT##WID\tsql\query;database=susdb;trusted_connection=true;'
            $conn = New-Object System.Data.SQLClient.SQLConnection($sqlConn)
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = 'SELECT * FROM sessiontable'
            $rdr = $cmd.ExecuteReader()
            $dt = New-Object System.Data.DataTable
            $dt.Load($rdr)
            $conn.Close()
            $dt
        #endregion


            #region Selected Products and Categories
            # https://4sysops.com/archives/configure-wsus-products-and-classifications-with-powershell/
    
            $WSUS.GetSubscription() | Get-Member

            $selectedProducts = $WSUS.GetSubscription().GetUpdateCategories()
            $selectedProducts | Select-Object title
            $selectedCategories = $WSUS.GetSubscription().GetUpdateClassifications()
            $selectedCategories | Select-Object title

            Invoke-Item ($dstPath = [Environment]::GetFolderPath('Desktop'))
            $selectedProducts | Export-Clixml -Path ($dstPath + "\$Env:computername`_Prodlist.xml") -Force -Verbose
            $tstSelProd = Import-Clixml -Path ($dstPath + "\$Env:computername`_Prodlist.xml")
            $tstSelProd | Select-Object title

            $selectedCategories | Export-Clixml -Path ($dstPath + "\$Env:computername`_Catlist.xml") -Force -Verbose
            $tstSelCat = Import-Clixml -Path ($dstPath + "\$Env:computername`_Catlist.xml")
            $tstSelCat | Select-Object title



            Get-WsusProduct |
                Where-Object{ $_.Product.Title -eq "Windows 11"} |
                    Set-WsusProduct -Disable -WhatIf
            Get-WsusClassification | 
                Where-Object {$_.Classification.Title -eq "Drivers"} |
                    Set-WsusClassification -Disable -WhatIf
        #endregion
            <#
            #region wsus Product & Categories
                # SO This is the Products Tab:
                $str = $($wsus.GetUpdateCategories())
                $str | ForEach-Object { $_.Type } | Sort-Object | unique
                < #
                    Company # <*2nd level in the tree
                    Product # <*3rd level in the tree
                        ProductFamily # <*4th level in the tree
                    ----
                # >
                #region Constants
                    $tmpltCategories = "Applications,Disabled
                        Critical Updates,Enabled
                        Definition Updates,Enabled
                        Driver Sets,Disabled
                        Drivers,Disabled
                        Feature Packs,Enabled
                        Security Updates,Enabled
                        Service Packs,Enabled
                        Tools,Enabled
                        Update Rollups,Disabled
                        Updates,Enabled
                        Upgrades,Enabled" | 
                            ConvertFrom-Csv -Header Category,Status

                    $objtmpltCategories = @{
                        Applications = 0
                        'Critical Updates' = 1
                        'Definition Updates' = 1
                        'Driver Sets' = 0
                        Drivers = 0
                        'Feature Packs' = 1
                        'Security Updates' = 1
                        'Service Packs' = 1
                        Tools = 1
                        'Update Rollups' = 0
                        Updates = 1
                        Upgrades = 1
                    }
                #endregion
                #region SQL
                    ### Connects to the SQL DB name of the sql server and the default db instance must be changed
                    Set-Location SQLSERVER:\sql\WSUSSERVERNAME\SQLEXPRESS\databases\SUSDB

                    ### Creates the SQL Query that will be used to get the patches and the Patch ID
                    $sqlQuery = "SELECT [UpdateId],[RevisionNumber],[DefaultTitle],[DefaultDescription] FROM [SUSDB].[PUBLIC_VIEWS].[vUpdate] Where-Object [DefaultTitle] like '%Preview%'"

                    ### Run the Query and saves it back to a Varible
                    $patchesWithUpdateID = Invoke-Sqlcmd -query $sqlQuery

                    ### Loops through all the patches and Denies them

                    foreach($patchWithUpdateID in $patchesWithUpdateID.UpdateId)
                    {

                    Get-WsusServer | Get-WsusUpdate -UpdateId $patchWithUpdateID.Guid | Deny-WsusUpdate
                    }



                    $sqlWSUS = (get-item 'HKLM:\Software\Microsoft\Update Services\Server\Setup').GetValue('SQLServerName')

                    $update = $wsus.SearchUpdates('powershell')
                    $update.count
                    $update | Select-Object Title,UpdateSource
                #endregion
            #endregion
        #>
        $wsus.GetUpdateClassifications()

        $wsusUpdtFolderSize = [Math]::Round((Get-ChildItem U:\WSUS\*.* -Recurse | Measure-Object -Sum Length).sum / 1GB,2)

        #region updates
            # Get Update list
            $updtCount = ($Updates = $WSUS.GetUpdates()).count
            # Get Update list in Window
            $Updates | Select-Object Title,
                @{n='Product Family';e={$_.ProductFamilyTitles}},
                @{n='Product';e={$_.ProductTitles}},
                @{n='KB Article';e={$_.KnowledgebaseArticles}} |
                    Sort-Object ProductTitles |
                    Out-GridView -Title "Current Update List ($updtCount)"

            # Get Updates by Selected Catagory list
                $Updates | Select-Object -ExpandProperty UpdateClassificationTitle -Unique | ForEach-Object{
                    $cnt = ($updt = $Updates | Where-Object UpdateClassificationTitle -match $_).count
                    $updt | Out-GridView -Title "$_ ($cnt)"
                    }
            # Get Updates by Product Titles list
                $Updates | Select-Object -ExpandProperty ProductTitles -Unique | ForEach-Object{
                    $cnt = ($updt = $Updates | Where-Object ProductTitles -match $_).count
                    $updt | Out-GridView -Title "$_ ($cnt)"
                    }

            # Get Updates by Product Family Titles list
                $Updates | Select-Object -ExpandProperty ProductFamilyTitles -Unique | ForEach-Object{
                    $cnt = ($updt = $Updates | Where-Object ProductFamilyTitles -match $_).count
                    $updt | Out-GridView -Title "$_ ($cnt)"
                    }

            # Get Summary by Update
            $updtSet = $wsus.SearchUpdates('Windows 10')
            $update = $updtSet[0]
            $update.GetSummary($computerscope)

            $update.GetUpdateInstallationInfoPerComputerTarget($ComputerScope)[0]
            $update.GetUpdateInstallationInfoPerComputerTarget($ComputerScope)[0] |
            Select-Object @{L='Client';E={$wsus.GetComputerTarget(([guid]$_.ComputerTargetId)).FulldomainName}},
            @{L='TargetGroup';E={$wsus.GetComputerTargetGroup(([guid]$_.UpdateApprovalTargetGroupId)).Name}},
            @{L='Update';E={$wsus.GetUpdate(([guid]$_.UpdateId)).Title}},
            UpdateInstallationState,UpdateApprovalAction
                      
            # Get Summary by computer
            $wsus.GetSummariesPerComputerTarget($updatescope,$computerscope) |
            Format-Table @{L='ComputerTarget';E={($wsus.GetComputerTarget([guid]$_.ComputerTargetId)).FullDomainName}},
            @{L='NeededCount';E={($_.DownloadedCount + $_.NotInstalledCount)}},
            DownloadedCount,NotApplicableCount,NotInstalledCount,InstalledCount,FailedCount

            $updatescope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
            $updatescope.IncludedInstallationStates = [Microsoft.UpdateServices.Administration.UpdateInstallationStates]::NotInstalled
            $updatescope.FromArrivalDate = [datetime]"12/13/2021"   

            # NotApplicable
            $wsusComps = Get-WsusComputer -All
            $wsusComps = $wsus.GetComputerTargets()
            $wsusComps = Get-PSWSUSClient
            $notNeeded = $wsus.GetSummariesPerUpdate($updatescope,$computerscope) | Where-Object NotApplicableCount -eq $wsusComps.Count
            "$($updtCount - ($notNeeded.Count)) Applicable Updates ($($notNeeded.Count) N/A)"

            $wsus.GetSummariesPerUpdate($updatescope,$computerscope) |
            Format-List @{L='UpdateTitle';E={($wsus.GetUpdate([guid]$_.UpdateId)).Title}},
            @{L='NeededCount';E={($_.DownloadedCount + $_.NotInstalledCount)}},
            DownloadedCount,NotApplicableCount,NotInstalledCount,InstalledCount,FailedCount

            #endregion


            $AuthoringUpdates = "
                Creating Update Binaries,https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902476(v=vs.85)
                Installing 3rd Party Uppdates,https://social.technet.microsoft.com/forums/windowsserver/en-US/8d5ece85-460f-4336-b90f-f880a75c4172/can-i-install-third-party-software-updates-through-wsus#:~:text=Provided%20you%20are%20running%20WSUS%203%20with%20service,that%20utilize%20WSUS%20to%20distribute%20third%20party%20updates.
                Local Publishing,https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bb902470(v=vs.85)?redirectedfrom=MSDN
                Local Update Publisher,http://www.localupdatepublisher.com/" | ConvertFrom-Csv -Header Topic,Link -Delimiter ','
            $AuthoringUpdates


        $tmpltCategories = "Applications,Disabled
            Critical Updates,Enabled
            Definition Updates,Enabled
            Driver Sets,Disabled
            Drivers,Disabled
            Feature Packs,Enabled
            Security Updates,Enabled
            Service Packs,Enabled
            Tools,Enabled
            Update Rollups,Disabled
            Updates,Enabled
            Upgrades,Enabled" | 
            ConvertFrom-Csv -Header Category,Status


        $tmpltCategories = @{
            Applications = 0
            'Critical Updates' = 1
            'Definition Updates' = 1
            'Driver Sets' = 0
            Drivers = 0
            'Feature Packs' = 1
            'Security Updates' = 1
            'Service Packs' = 1
            Tools = 1
            'Update Rollups' = 0
            Updates = 1
            Upgrades = 1
            }



    #endregion
    #region - WSUS Automation
        ### Configure post-deplpyment settings
        Start-Process -FilePath "C:\Program Files\Update Services\Tools\WsusUtil.exe" -ArgumentList "postinstall CONTENT_DIR=C:\WSUS" -Wait -Verbose

        ### Get WSUS Server Object
        $wsus = Get-WSUSServer

        ### Connect to WSUS server configuration
        $wsusConfig = $wsus.GetConfiguration()
        Set-WsusServerSynchronization -UssServerName 'UStremSrvr' -PortNumber 8530 -Replica:$false -UseSsl:$false #-SyncFromMU # Set to download updates from Microsoft Updates

        ### Set Update Languages to English and save configuration settings
        $wsusConfig.AllUpdateLanguagesEnabled = $false           
        $wsusConfig.SetEnabledUpdateLanguages("en")           
        $wsusConfig.Save()

        ### Start the WSUS synchronization
        $wsus.GetSubscription().StartSynchronizationForCategoryOnly()
        start-sleep 15

        ### Starting while loop, which ensures that the synchronization finishes before continuing
        while ($wsus.GetSubscription().GetSynchronizationStatus() -ne "NotProcessing") {
        $time = get-date -UFormat "%H:%M:%S"
        $total = $wsus.GetSubscription().getsynchronizationprogress().totalitems
        $processed = $wsus.GetSubscription().getsynchronizationprogress().processeditems
        $process = $processed/$total
        $progress = "{0:P0}" -f $process
        Write-Host ""
        Write-Host "The first synchronization isn't completed yet $time"
        Write-Host "Kindly have patience, the progress is $progress"
        Start-Start-Sleep  10
        }
        Write-Host "The synchronization has completed at $time" -ForegroundColor Green
        Write-Host "The WSUS Configuration will now continue"  -ForegroundColor Green

        ### Configure the Products
        write-host 'Setting WSUS Products'
        Get-WsusProduct | where-Object {
            $_.Product.Title -in (
            'Windows 10')
        } | Set-WsusProduct

        ### Configure classifications
        write-host 'Setting WSUS Classifications'
        Get-WsusClassification | Where-Object {
            $_.Classification.Title -in (
            'Critical Updates',
            'Security Updates')
        } | Set-WsusClassification

        ### Configure Synchronizations
        write-host 'Enabling WSUS Automatic Synchronisation'
        $subscription = $wsus.GetSubscription()
        $subscription.SynchronizeAutomatically=$true

        ### Set synchronization scheduled for midnight each night
        $subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
        $subscription.NumberOfSynchronizationsPerDay=1
        $subscription.Save()

        ### Create computer target group
        $wsus.CreateComputerTargetGroup("Updates")

        ### Configure Default Approval
        write-host 'Configuring default automatic approval rule'
        [void][reflection.assembly]::LoadWithPartialName("Microsoft.UpdateServices.Administration")
        $rule = $wsus.GetInstallApprovalRules() | Where-Object {
            $_.Name -eq "Default Automatic Approval Rule"}
        $class = $wsus.GetUpdateClassifications() | Where-Object  {$_.Title -In (
            'Critical Updates',
            'Security Updates')}
        $class_coll = New-Object Microsoft.UpdateServices.Administration.UpdateClassificationCollection
        $class_coll.AddRange($class)
        $rule.SetUpdateClassifications($class_coll)
        $rule.Enabled = $True
        $rule.Save()

        ### Configure that computers are assigned to correct group


        ### Remove WSUS configuration pop-up when opening WSUS Management Console
        $wsusConfig.OobeInitialized = $true
        $wsusConfig.Save()

        ### Start Synchronization
        $wsus.GetSubscription().StartSynchronization()
    #endregion
    #region - WSUS Client Control
        #Last Update Check
        $(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate
        $(New-Object -ComObject Microsoft.Update.AutoUpdate).Results

        # Fix client connection issues
            $susServer = 'http://SERVERNAME HERE:8530'
            $regPath1 = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
            $regPath2 = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'

            'SusClientId','SusClientIdValidation' | ForEach-Object{ Remove-ItemProperty -Path $regPath1 -Name $_ -Force -Confirm:$false }

            'WUServer','WUStatusServer' | ForEach-Object{ New-ItemProperty -Path $regPath2 -Name $_ -Value $susServer -PropertyType String -Force -Confirm:$false }

                # String - Equivalent to REG_SZ.
                # ExpandString - Equivalent to REG_EXPAND_SZ.
                # Binary - Equivalent to REG_BINARY.
                # DWord - Equivalent to REG_DWORD.
                # MultiString - Equivalent to REG_MULTI_SZ.
                # Qword - Equivalent to REG_QWORD. - 
                # Unknown. Indicates an unsupported registry data type, such as REG_RESOURCE_LIST.

            gpupdate
  
            Get-Service | Where-Object Name -Match '(wuauserv|BITS)' | Stop-Service -Verbose -Force -Confirm:$false
            Remove-Item -Path 'C:\WINDOWS\SoftwareDistribution' -Recurse -Force -Confirm:$false
            Remove-Item -Path 'c:\windows\windowsupdate.log' -Force -Confirm:$false

            'WUAPI.DLL','WUAUENG.DLL','WUAUENG1.DLL','ATL.DLL','WUCLTUI.DLL','WUPS.DLL','WUPS2.DLL','WUWEB.DLL','msxml3.dll' | ForEach-Object{ regsvr32 $_ /s }

            Get-Service | Where-Object Name -Match '(wuauserv|BITS)' | Start-Service -Verbose -Force -Confirm:$false
            wuauclt.exe /resetauthorization /detectnow

        # WU History
            # Check last few patches
            #
            # Get list of computers (one per line)
            $Comps = Get-Content .\complist.txt
            #
            # Package Alberto's script all together for remote execution
            #
            $ARscript = {
                $Session = New-Object -ComObject "Microsoft.Update.Session";
                $Searcher = $Session.CreateUpdateSearcher();
                $ct = $Searcher.GetTotalHistoryCount();
                $Searcher.QueryHistory(0, $ct) | 
                    Sort-Object date | 
                        Select-Object Date,
                            @{name="Operation";expression={switch($_.operation){1 {"Installation"}; 2 {"Uninstallation"};3 {"Other"}}}}, 
                            @{name="Status"; expression={switch($_.resultcode){1 {"In Progress"};2 {"Succeeded"}; 3 {"Succeeded With Errors"};4 {"Failed"}; 5 {"Aborted"} }}},
                            Title,Description -last 10
                }
            & $ARscript
            # Initialize array
            $Outfinal = @()

            # Loop over the computers in the list
            foreach ($c in $Comps)
            {
                # Test if the computer's alive, then run the script
                if (Test-Connection -ComputerName $c -count 1 -quiet)
                {
                    Write-output "Working on $c"
                    $outtemp = Invoke-Command -ComputerName $c -Command $ARscript | Select-Object PSComputername, Date, Status, Title
                    # Collect everything for final output
                    $Outfinal += $outtemp
                }
                else { Write-Output 'Computer $c not responding' }
            }
            $Outfinal | export-csv .\LastPatches.csv
        <#

            $updateInfoMsg = "Windows Update Status: `n";

            $UpdateSession = New-Object -ComObject Microsoft.Update.Session;
            $UpdateSearcher = $UpdateSession.CreateupdateSearcher();
            $Updates = @($UpdateSearcher.Search("Type='Software'").Updates);
            $Updates = @($UpdateSearcher.Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0 and Type='Software'").Updates);
            $Found = ($Updates | Select-Object -Expand Title);

            If ($Found -eq $Null) {
                $updateInfoMsg += "Up to date";
            } Else {
                $Found = ($Updates | Select-Object -Expand Title) -Join "`n";
                $updateInfoMsg += "Updates available:`n";
                $updateInfoMsg += $Found;
            }

            $updateInfoMsg;



            since Windows 10 the command wuauclt /detectnow does not work anymore.

            You can simply use the Comject Object Microsoft.Update.AutoUpdate within powershell (in evelated/administrator mode) to trigger Windows Update for detecting new updates.

            1
            (new-object -Comobject Microsoft.Update.AutoUpdate).detectnow()
            To Install all downloaded Updates and restart the computer if requiered:


                $oInstaller=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateInstaller()
                $aUpdates=New-Object -ComObject Microsoft.Update.UpdateColl((New-Object -ComObject Microsoft.Update.Session).CreateupdateSearcher().Search("IsAssigned=1 and IsHidden=0 and IsInstalled=0 and Type='Software'")).Updates|ForEach-Object{
                    if(!$_.EulaAccepted){$_.EulaAccepted=$true}
                    [void]$aUpdates.Add($_)
                }
                $oInstaller.ForceQuiet=$true
                $oInstaller.Updates=$aUpdates
                if($oInstaller.Updates.count -ge 1){
                  write-host "Installing " $oInstaller.Updates.count "Updates"
                  if($oInstaller.Install().RebootRequired){Restart-Computer}
                } else {
                  write-host "No updates detected"
                }
                Or use the Windows Update Powershell Module which provides a set of command-lets for handling windows updates.

                Newer Version of Windows 10 uses the usoclient command line utility. There are 4 options

                usoclient StartScan
                usoclient StartDownload
                usoclient StartInstall
                usoclient RestartDevice
        #>
    #endregion
    #region - Parse SUS logs
        $tempLog = ([Environment]::GetFolderPath('Desktop') + "\SUSLogs__$($env:COMPUTERNAME)__$(Get-Date -f yyyy-MM-dd_HHmm).log")
        Get-WindowsUpdateLog -LogPath $tempLog

        $tmp = Get-Content $tempLog
        $tmp = ($tmp -replace '(?<=(\d{4}\/\d{2}\/\d{2}))\s',',' -replace '(?<=(\d{2}\:\d{2}\:\d{2})\.\d{7})\s{1}',',' `
                    -replace '(?<=(\,\d+))\s+',',' -replace '(?<=(\,\d+))\s+',',' -replace '(?<=(\,\w+))\s+',',' |
                    ConvertFrom-Csv -Delim ',' -Header Date,Time,ProcessID,ThreadID,EventName,UserData) 
        $tmp = $tmp | Select-Object @{N='Date';E={Get-Date $_.Date -f yyyy-MM-dd}},@{N='Time';E={Get-Date $_.Time -f HH:mm:ss}},ProcessID,ThreadID,EventName,UserData
        $tmp | Export-Csv -NoTypeInformation -Path ($tempLog -replace '.log$','.csv')
        Remove-Item $tempLog -Force -Confirm:$false

        $tmp | Out-GridView -Title "Windows Update Logs - $env:COMPUTERNAME"
    #endregion
    #region - Other Updates
        #region - Installer Shortcuts
            $LocalTempDir = $env:TEMP
            $ChromeInstaller = "ChromeInstaller.exe"
            (new-object System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller")
            & "$LocalTempDir\$ChromeInstaller" /silent /install
            $Process2Monitor = "ChromeInstaller"
            Do {
                $ProcessesFound = Get-Process | Where-Object {$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name
                If ($ProcessesFound) { "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Start-Sleep  -Seconds 2 }
                else { Remove-Item "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue -Verbose }
                }
            Until (!$ProcessesFound)

            $updts = 'Adobe,acro*.exe,/qPB
            Chrome,chrome*.exe,/silent /install
            Edge,*edge*.msi,/passive
            FFox,firefox*.exe,-ms' | ConvertFrom-Csv -Delim ',' -Header Installer,Pattern,Switch
            $updPath = 'C:\Temp'

            ForEach ($updt in $updts)
            {
                $TargetFile = (Get-ChildItem $updPath -Filter $updt.Pattern)
                $ShortcutFile = ($updPath + '\ ' + $updt.Installer + "-Update[RunMe].lnk")
                $WScriptShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
                $Shortcut.TargetPath = $TargetFile.FullName
                $Shortcut.Arguments = $updt.Pattern
                $Shortcut.Save()
        }
        #endregion
        #region - MonthlyUPDTs.ps1
            # Updates
            If ($null -eq (Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -match "(Jenny|Fortress)").DeviceID){ $xferDrive = 'C:\TEMP' }
            Else { $xferDrive = (Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -match "(Jenny|Fortress)").DeviceID }
            If ($null -eq $xferDrive){ BREAK }
            $updPath = Join-Path $xferDrive "_Monthly_Updates\$(Get-Date -f yyyy-MM)"
            If (!(Test-Path $updPath)){ New-Item $updPath -ItemType Directory }
            #region - DL Latest  Edge
                # [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
                $lclPath = $updPath 
                $dlUri= "http://go.microsoft.com/fwlink/?LinkID=2093437"
                $Installer = "MicrosoftEdgeEnterpriseX64_$(Get-Date -f yyyy-MM-dd).msi";
                Invoke-WebRequest -Uri $dlUri -OutFile ($lclPath + '\' + $Installer)
                    # Start-Process "$Download" -ArgumentList "/quiet"
            #endregion
            #region - DL Latest chrome
                # 'https://chromeenterprise.google/browser/download/#windows-tab'
                $lclPath = $updPath 
                $dlUri= "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B0022FD8E-83B2-A4FB-5279-5DF9E9769D28%7D%26lang%3Den%26browser%3D3%26usagestats%3D0%26appname%3DGoogle%2520Chrome%26needsadmin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/chrome/install/ChromeStandaloneSetup64.exe"
                # $dlUri= "https://dl.google.com/chrome/install/latest/chrome_installer.exe"
                $Installer = "chrome_installer_$(Get-Date -f yyyy-MM-dd).exe";
                Invoke-WebRequest -Uri $dlUri -OutFile ($lclPath + '\' + $Installer)
                    # Start-Process -FilePath $Path$Installer -Args "/silent /install" -Verb RunAs -Wait
                    # Remove-Item $Path$Installer

                    # $path /install
            #endregion
            #region - DL Latest FireFox
                #iex ('wget -O c:\temp\FirefoxSetup_' + (Get-Date -f yyyy-MM-dd) + '.exe "https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US"')
                $lclPath = $updPath 
                $dlUri= "https://download.mozilla.org/?product=firefox-latest&os=win&lang=en-US"
                $Installer = "FirefoxSetup_$(Get-Date -f yyyy-MM-dd).exe";
                Invoke-WebRequest -Uri $dlUri -OutFile ($lclPath + '\' + $Installer)
            #endregion
            #region - DL Latest Adobe Reader FIX FIX FIX file dl
                
                
                
                'https://adminconsole.adobe.com'
                'Timothy.j.schmidt18.ctr@mail.mil'
                "A...a...1...!..."

                $newAdobe = 'https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/' #index.html
                (Invoke-WebRequest -uri $newAdobe).Links
            
                # rv ftp*
                $lclPath = $updPath 
                $ftpFolderUrl = 'ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/'

                #connect to ftp, and get directory listing
                    $ftpRequest = [System.Net.FtpWebRequest]::Create("$ftpFolderUrl") 
                    $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
                    $ftpResponse = $ftpRequest.GetResponse()
                    $ResponseStream = $ftpResponse.GetResponseStream()
                    $ftpReader = New-Object System.IO.Streamreader -ArgumentList $ResponseStream
                    $DirList = $ftpReader.ReadToEnd()

                # from Directory Listing get last entry in list of any numeric version
                    $LatestUpdate = $DirList -split '[\n]' | Where-Object {$_ -match '^\d'} | Sort-Object | Select-Object -Last 1

                # build file name & download url for latest file
                    $LatestFile = "AcroRdrDCUpd" + $LatestUpdate + "_MUI.msp"
                    $DownloadURL = "$ftpFolderUrl$LatestUpdate/$LatestFile" # | Clip

                # download the file
                    ftp get $DownloadURL $updPath
                    (New-Object System.Net.WebClient).DownloadFile($DownloadURL, $LatestFile)
                    (New-Object System.Net.WebClient).DownloadFile($DownloadURL, ($lclPath + '\' + $LatestFile))
                    $FZ = "C:\Users\adminCM\Downloads\FileZilla-3.65.0\filezilla.exe"

                    {Write-Host "Downloading $DownloadURL to $updPath"

                    $downloadRequest = [Net.WebRequest]::Create($DownloadURL)
                    $downloadRequest.Method =
                        [System.Net.WebRequestMethods+Ftp]::DownloadFile
                    $downloadRequest.Credentials = New-Object System.Net.NetworkCredential("anonymous", "mypassword")

                    $downloadResponse = $downloadRequest.GetResponse()
                    $sourceStream = $downloadResponse.GetResponseStream()
                    $targetStream = [System.IO.File]::Create($localFilePath)
                    $buffer = New-Object byte[] 10240
                    while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0)
                    {
                        $targetStream.Write($buffer, 0, $read);
                    }
                    $targetStream.Dispose()
                    $sourceStream.Dispose()
                    $downloadResponse.Dispose()}

                    try
                    {
                        # Load WinSCP .NET assembly
                        Add-Type -Path "C:\Users\adminCM\AppData\Local\Programs\WinSCP\WinSCPnet.dll"
 
                        # Setup session options
                        $sessionOptions = New-Object WinSCP.SessionOptions -Property @{
                            Protocol = [WinSCP.Protocol]::Sftp
                            HostName = $DownloadURL
                            UserName = "user"
                            Password = "mypassword"
                            }
                            #SshHostKeyFingerprint = "ssh-rsa 2048 xxxxxxxxxxx..."

                        $session = New-Object WinSCP.Session
 
                        try
                        {
                            # Connect
                            $session.Open($sessionOptions)
 
                            # Upload files
                            $transferOptions = New-Object WinSCP.TransferOptions
                            $transferOptions.TransferMode = [WinSCP.TransferMode]::Binary
 
                            $transferResult =
                                $session.PutFiles("d:\toupload\*", "/home/user/", $False, $transferOptions)
 
                            # Throw on any error
                            $transferResult.Check()
 
                            # Print results
                            foreach ($transfer in $transferResult.Transfers)
                            {
                                Write-Host "Upload of $($transfer.FileName) succeeded"
                            }
                        }
                        finally
                        {
                            # Disconnect, clean up
                            $session.Dispose()
                        }
 
                        exit 0
                    }
                    catch
                    {
                        Write-Host "Error: $($_.Exception.Message)"
                        exit 1
                    }
                    $hmmm = {
                        function DownloadFtpDirectory($url, $credentials, $localPath)
                        {
                            $listRequest = [Net.WebRequest]::Create($downloadurl)
                            $listRequest.Method =
                                [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails
                            $listRequest.Credentials = $credentials
    
                            $lines = New-Object System.Collections.ArrayList

                            $listResponse = $listRequest.GetResponse()
                            $listStream = $listResponse.GetResponseStream()
                            $listReader = New-Object System.IO.StreamReader($listStream)
                            while (!$listReader.EndOfStream)
                            {
                                $line = $listReader.ReadLine()
                                $lines.Add($line) | Out-Null
                            }
                            $listReader.Dispose()
                            $listStream.Dispose()
                            $listResponse.Dispose()

                            foreach ($line in $lines)
                            {
                                $tokens = $line.Split(" ", 9, [StringSplitOptions]::RemoveEmptyEntries)
                                $name = $tokens[8]
                                $permissions = $tokens[0]

                                $localFilePath = Join-Path $localPath $name
                                $fileUrl = ($url + $name)

                                if ($permissions[0] -eq 'd')
                                {
                                    if (($name -ne ".") -and ($name -ne ".."))
                                    {
                                        if (!(Test-Path $localFilePath -PathType container))
                                        {
                                            Write-Host "Creating directory $localFilePath"
                                            New-Item $localFilePath -Type directory | Out-Null
                                        }

                                        DownloadFtpDirectory ($fileUrl + "/") $credentials $localFilePath
                                    }
                                }
                                else
                                {
                                    Write-Host "Downloading $fileUrl to $localFilePath"

                                    $downloadRequest = [Net.WebRequest]::Create($fileUrl)
                                    $downloadRequest.Method =
                                        [System.Net.WebRequestMethods+Ftp]::DownloadFile
                                    $downloadRequest.Credentials = $credentials

                                    $downloadResponse = $downloadRequest.GetResponse()
                                    $sourceStream = $downloadResponse.GetResponseStream()
                                    $targetStream = [System.IO.File]::Create($localFilePath)
                                    $buffer = New-Object byte[] 10240
                                    while (($read = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0)
                                    {
                                        $targetStream.Write($buffer, 0, $read);
                                    }
                                    $targetStream.Dispose()
                                    $sourceStream.Dispose()
                                    $downloadResponse.Dispose()
                                }
                            }
                        }
                        $credentials = New-Object System.Net.NetworkCredential("user", "mypassword") 
                        $url = "ftp://ftp.example.com/directory/to/download/"
                        DownloadFtpDirectory $url $credentials "C:\target\directory"
                    }
            #endregion
            #region - WSUS
                [DateTime]$starttime = Get-Date
                # Connect and Verify Removable Device
                    $drvWSUS = 'U:\WSUS'
                    $drvRem = Get-WmiObject Win32_LogicalDisk | Where-Object VolumeName -match "(Jenny|Fortress)" | Select-Object -Exp DeviceID
                    If ($null -eq $drvRem) { Write-Warning "$trgVol Device not connected; EXITING"; Break }
                    Else { Write-Host -f Green "Jenny/Fortress device located as [$drvRem]" }


                # Export WSUS Data
                    # Run AFTER unneeded updates removed
                    Write-Host -f Cyan "Exporting WSUS Data Locally to $drvWSUS (2-5 Min)"
                    Set-Location "$env:ProgramFiles\Update Services\Tools"
                    $fileName = [string](Get-Date -f 'yyyy-MM-dd') + '.export'
                    .\WsusUtil.exe export $drvWSUS\$fileName.xml.gz $drvWSUS\$fileName.log

                # Copy WSUS Data to Removable Device
                    Write-Host -f Cyan "Copying WSUS Data from $drvWSUS to $drvRem\WSUS (120-240 Min)"
                    # Remomve residual xfer data from Removable Device PRIOR to copying current
                        If ((Test-Path $drvRem\WSUS) -eq $true)
                        { Remove-Item -Path $drvRem\WSUS -Recurse -Force -Verbose }
                    # Measure-Command {
                        Robocopy $drvWSUS $drvRem\WSUS /XO /E
                    # } -Verbose

            #endregion

            #region - VMWare - Scott/vic/tim
            '	Agent - VMs
              Composer - VSphere
              HView - Horizon
              VMWareTools'
            #endregion
            #region - Office (Currently: Office Pro 2019 Plus)
                $jPath = "e:\_Monthly_Updates\Office Deployment Tools"
                $cPath = "C:\Temp\_Monthly_Updates\Office Deployment Tools"
                $Path = $jPath
                # Office Deployment Tools folder is prereq
                
                Function Install-Office
                { 
                    Param
                    (
                        [ValidatePattern('(DLoad|Config|Install)')]$mode = 'DLoad',
                        [ValidatePattern('(32|64)')][string]$bits = 32,
                        $instPath = "C:\Temp\_Monthly_Updates\Office Deployment Tools"
                    )
                    Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
                    $id = "32,64`na4afe507-39a8-4183-a503-d7ad8c604aac,dbe6b7f7-2424-40cd-af6a-8d34c46c71e3" | ConvertFrom-CSV
                    $ofcXml = (Dec64 'DQo8Q29uZmlndXJhdGlvbiBJRD0iPElEPiI+DQogIDxBZGQgT2ZmaWNlQ2xpZW50RWRpdGlvbj0iPEJJVD4iIENoYW5uZWw9IlBlcnBldHVhbFZMMjAxOSI+DQogICAgPFByb2R1Y3QgSUQ9IlByb1BsdXMyMDE5Vm9sdW1lIiBQSURLRVk9Ik5NTUtKLTZSSzRGLUtNSlZYLThEOU1KLTZNV0tQIj4NCiAgICAgIDxMYW5ndWFnZSBJRD0iZW4tdXMiIC8+DQogICAgICA8RXhjbHVkZUFwcCBJRD0iR3Jvb3ZlIiAvPg0KICAgICAgPEV4Y2x1ZGVBcHAgSUQ9Ikx5bmMiIC8+DQogICAgICA8RXhjbHVkZUFwcCBJRD0iT25lRHJpdmUiIC8+DQogICAgPC9Qcm9kdWN0Pg0KICAgIDxQcm9kdWN0IElEPSJWaXNpb1BybzIwMTlWb2x1bWUiIFBJREtFWT0iOUJHTlEtSzM3WVItUlFIRjItMzhSUTMtN1ZDQkIiPg0KICAgICAgPExhbmd1YWdlIElEPSJlbi11cyIgLz4NCiAgICAgIDxFeGNsdWRlQXBwIElEPSJHcm9vdmUiIC8+DQogICAgICA8RXhjbHVkZUFwcCBJRD0iTHluYyIgLz4NCiAgICAgIDxFeGNsdWRlQXBwIElEPSJPbmVEcml2ZSIgLz4NCiAgICA8L1Byb2R1Y3Q+DQogICAgPFByb2R1Y3QgSUQ9IlByb2plY3RQcm8yMDE5Vm9sdW1lIiBQSURLRVk9IkI0TlBSLTNGS0s3LVQyTUJWLUZSUTRXLVBLRDJCIj4NCiAgICAgIDxMYW5ndWFnZSBJRD0iZW4tdXMiIC8+DQogICAgICA8RXhjbHVkZUFwcCBJRD0iR3Jvb3ZlIiAvPg0KICAgICAgPEV4Y2x1ZGVBcHAgSUQ9Ikx5bmMiIC8+DQogICAgICA8RXhjbHVkZUFwcCBJRD0iT25lRHJpdmUiIC8+DQogICAgPC9Qcm9kdWN0Pg0KICA8L0FkZD4NCiAgPFByb3BlcnR5IE5hbWU9IlNoYXJlZENvbXB1dGVyTGljZW5zaW5nIiBWYWx1ZT0iMCIgLz4NCiAgPFByb3BlcnR5IE5hbWU9IkZPUkNFQVBQU0hVVERPV04iIFZhbHVlPSJGQUxTRSIgLz4NCiAgPFByb3BlcnR5IE5hbWU9IkRldmljZUJhc2VkTGljZW5zaW5nIiBWYWx1ZT0iMCIgLz4NCiAgPFByb3BlcnR5IE5hbWU9IlNDTENhY2hlT3ZlcnJpZGUiIFZhbHVlPSIwIiAvPg0KICA8UHJvcGVydHkgTmFtZT0iQVVUT0FDVElWQVRFIiBWYWx1ZT0iMSIgLz4NCiAgPFVwZGF0ZXMgRW5hYmxlZD0iVFJVRSIgLz4NCiAgPFJlbW92ZU1TSSAvPg0KPC9Db25maWd1cmF0aW9uPg0K')
                    $ofcInst = $ofcXml -Replace '<BIT>',$bits -Replace '<ID>',($id.$bits)
                    $xmlfile = "$instPath\Office2019_$bits`_$(Get-Date -f yyyy-MM-dd).xml"
                
                    $urlODT = 'https://www.microsoft.com/en-us/download/details.aspx?id=49117'
                    $urlDeploy = ((Invoke-WebRequest -uri $urlODT).Links | Where-Object InnerText -eq 'Download').href
                    $urlConfig = 'https://config.office.com/deploymentsettings'
                    $dst = [string](Get-Date -f yyyy-MM-dd)
                    If ((Test-path -Path $xmlfile -PathType Leaf) -eq $false){ Set-Content -Path $xmlfile -Value $ofcInst -Encoding ASCII }
                    Switch ($mode)
                    {
                        'DLoad'
                        {
                            # Check for Insaller file and DL if needed
                                If ($null -eq (Get-ChildItem $instPath -Filter *.exe | Where-Object Name -match 'Ofc_Deploy'))
                                { Invoke-WebRequest -uri $urlDeploy -OutFile ($oFile = "$instPath\Ofc_Deploy_$(Get-Date -f yyyy-MM-dd).exe") -Verbose }
                                Else { $oFile = (Get-ChildItem $instPath -Filter *.exe | Where-Object Name -match 'Ofc_Deploy').FullName }
                
                            # Extract Office Intaller files
                                Start-Process -FilePath $oFile -ArgumentList "/extract:`"$instPath\$dst`" /Quiet" -Wait
                
                            # Clean up installer files 
                                If (!(Test-Path $instPath\$dst\setup.exe))
                                { Throw "Installer File unavailable"}
                                Else
                                {
                                    Remove-Item -path $instPath\$dst\co*.xml -Force -Confirm:$false
                                    Write-Host -f c "`nInstaller File ready`n".
                                }
                        }
                        'Config'
                        {
                            # Create installer folder
                                $cfgTool = "Setup.exe"
                                $cfgConfig = (Get-ChildItem $instPath -Filter *.xml | Where-Object {$_.Name -match ("_"+$bits+"_")})
                                Set-Location "$instPath\$dst"
                                Copy-Item $cfgConfig.FullName
                                Start-Process -FilePath $cfgTool -ArgumentList "/download $($cfgConfig.Name)" -Wait
                        }
                        'Install'
                        {
                            # load install and install Office
                                $dplyTool = "Setup.exe"
                                $cfgConfig = (Get-ChildItem $instPath -Filter *.xml | Where-Object {$_.Name -match ("_"+$bits+"_")})
                                Set-Location $instPath\$dst
                                Start-Process -FilePath $dplyTool -ArgumentList "/configure ..\$($cfgConfig.Name)" -Wait
                        }
                    }
                }
                Install-Office -mode DLoad -bits 32 -instPath $Path
                Install-Office -mode Config -bits 32 -instPath $Path
                Install-Office -mode Install -bits 32 -instPath $Path
            #endregion
            #region - Titus?
            #endregion
            #region - Trellix? Jeron
                'TrellixAgent_v5.8.0_2023-09_Win'
                'http://patches.csd.disa.mil/'
                'https://patches.csd.disa.mil/Metadata.aspx?id=165203'
                Invoke-WebRequest -Uri 'https://patches.csd.disa.mil/SecureDownload.aspx?sfs=asset&fGuid=260926'  -OutFile test.zip -Credential 
            #endregion
            #region - OS Base Image
                $mctDir = 'C:\temp\_Monthly_Updates\Base OS Tools\Media Creation Tools'
                $urlMCT = 'https://support.microsoft.com/en-us/windows/create-installation-media-for-windows-99a58364-8c02-206f-aa6f-40c3b507420d'
                $mct10 = 'https://go.microsoft.com/fwlink/?LinkId=691209'
                $mct11 = 'https://go.microsoft.com/fwlink/?linkid=2156295'
                $entKey = 'NPPR9-FWDCX-D2C8J-H872K-2YT43'
                Set-Location $mctDir
                $cfg = '/Eula Accept /Retail /MediaLangCode en-us /MediaArch x64 /MediaEdition Enterprise'
                Invoke-WebRequest -Uri $mct10  -OutFile Win10-22H2.exe
                Invoke-WebRequest -Uri $mct11  -OutFile Win11-23H2.exe
                Start-Process -FilePath 'Win10-22H2.exe' -ArgumentList $cfg
                Start-Process -FilePath 'Win11-23H2.exe' -ArgumentList $cfg
               # https://www.microsoft.com/en-US/software-download/


                'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019'

            #endregion
        #endregion
    #endregion
#endregion
