        Function Toggle-NetworkState_ps1
        {
            #Requires -RunAsAdministrator
            #region - Script Constants
                $currDomain = ([DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                $svcAcct = 'svc_PoshScriptAdm'
                $admScriptPath = "\\MACHINENAME\c$\Users\Public\Desktop\ Dusk & Dawn Scripts"
                $scriptPath = "\\$currDomain\SYSVOL\$currDomain\Scripts\PSScripts"
                # Copy "$admScriptPath\Toggle-NetworkState.ps1" "$scriptPath\Toggle-NetworkState.ps1" -Verbose
                $trgMod = 'VMWare.PowerCLI'
                $noCyber = $false
                $accts = "
                    admin@vshpere.local,VCenter
                    domain\$svcAcct,Domain" | ConvertFrom-Csv -Delimiter ',' -Header Acct,trgDomain
                #region - Populate Server List
                    Function Get-IP($a){ Return [Net.DNS]::GetHostByName($a).AddressList.IPAddressToString }
                    $srvrList = @{} | Select DCs,MSvrs
                      ($Searcher = New-Object DirectoryServices.DirectorySearcher).Filter = '(objectCategory=computer)'
                      $srvrList.DCs = $($Searcher.SearchRoot = "LDAP://ou=domain controllers,$(([ADSI]'').distinguishedname)"
                        $Searcher.FindAll() | Select-Object @{n='DC';e={$_.Properties.cn}} | Select-Object -exp DC
                        ) -notmatch '^W'
                      $srvrList.MSvrs = $($Searcher.SearchRoot = "LDAP://ou=SvrContainer,ou=Member Servers,$(([ADSI]'').distinguishedname)"
                        $Searcher.FindAll() | Select-Object @{n='DC';e={$_.Properties.cn}} | Select-Object -exp DC
                        ) | Sort

                    $aSrvrs = $srvrList.DCs + $srvrList.MSvrs
                    $ipL = [Collections.ArrayList]@()
                    ForEach ($itm in $item) #{}
                    {
                        $rst = @{} | Select-Object Name,IP,Type,Role
                            $rst.Name = $itm
                            $rst.IP = (Get-IP $itm)
                            $rst.Type = 'VM'
                            $rst.Role = '--'
                        $null = $ipL.Add($rst)
                    }
                    $IPs = ($ipL | ConvertTo-Csv -Del ',' -NoTypeInformation) | ConvertFrom-Csv
                    $IPs | %{
                        If ($_.Name -Match '(dc07|be0)'){ $_.Type = 'Phys' }
                        If ($_.Name -Match 'DC'){ $_.Role = 'DC' }
                        If ($_.Name -Match 'BE'){ $_.Role = 'BE' }
                        If ($_.Name -Match 'VCen'){ $_.Role = 'VCenter' }
                        If ($_.Name -Match 'HV'){ $_.Role = 'HView' }
                        If ($_.Name -Match '(file|av0)'){ $_.Role = 'FS' }
                        If ($_.Name -Match 'ws'){ $_.Role = 'WSUS' }
                        If ($_.Name -Match '(mail|titus)'){ $_.Role = 'Email' }
                        If ($_.Name -Match '(epo|va01)'){ $_.Role = 'Cyber' }
                        If ($_.Name -Match '(dhcp|kms|wms)'){ $_.Role = 'Utility' }
                        }
                #endregion
                $vctrServer = ($IPs | Where Role -eq 'VCenter').Name
                $hvServer = ($IPs | Where Role -eq 'HView').Name
                $physicals = ($IPs | Where Type -match 'Phys').Name
            #endregion
            #region - VCenter Pause
                # (Test-NetConnection -ComputerName ($IPs | Where Role -eq 'VCenter').Name).PingSucceeded -eq $true
                # (Test-Connection -ComputerName ($IPs | Where Role -eq 'VCenter').Name -count 1) | Select *
                # (Test-NetConnection -ComputerName ($IPs | Where Role -eq 'VCenter').Name).isp
            #endregion
            #region - Script Functions
                Function Get-Key
                {
                    Param = ([switch]$pt,$it)
                    $currDomain = ([DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()).Name
                    $keyFile = "\\$currDomain\SYSVOL\$currDomain\Scripts\PSScripts\key$it.bin"
                    If ((Test-Path $keyFile) -ne $true)
                    {
                        [void][reflection.assembly]::LoadWithPartialName('System.Windows.Forms')
                        $d = New-Object Windows.Forms.OpenFileDialog
                        $d.ShowHelp = $true
                        $d.Title = 'Select Key File to use with Script'
                        $d.InitialDirectory = "$($env:SystemDrive)\Users\Public\Desktop"
                        $d.Filter = 'Key Files (*.bin)|*.bin'
                        $rslt = $d.ShowDialog((New-Object Windows.Forms.Form -Property @{TopMost = $true}))
                        If ($rslt -eq [Windows.Forms.DialogResult]::OK){$keyFile = $d.FileName}
                        Else { Write-Warning "No KeyFile!": BREAK }
                    }
                    $aesKey = (gc $keyFile)[0..31]
                    $encText = (gc $keyFile)[-1]
                    $rslt = ($obj = New-Object System.Management.Automation.PSCredential('',$encText)).Password
                    If ($pt.IsPresent -eq $true)
                    {
                        $blue = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($rslt)
                        $red = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($blue)
                        [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($blue)
                        $rslt = $obj.GetNetworkCredential().Password
                    }
                    Return $rslt
                }
                Function Install-VMWareCmdlets
                {
                    Param
                    (
                        $trgModPath = ($env:PSModulePath -split ';' | Where { $_ -match 'Program Files'}), # System32
                        $zipPath = "\\$(($IPs | Where ROle -eq 'FS').Name)\FilePath\VMWare PowerCLI v13",
                        $cliZip = "VMWare-PowerCLI-13.1.0-12624340.Zip",
                        $hzvwZip = 'PowerCLI-Example-Scripts-master.zip'
                    )
                    # Install PowerCLI Commands
                        $testModPath = GCI $trgModPath -Directory | Where { $_ -Match 'PowerCLI' }
                        If ($testModPath -eq $null)
                        {
                            Try
                            {
                                New-Item -Name $trgMod -Path $trgModPath -ItemType Directory -ea Stop
                                $srcZipFile = "$zipPath\$cliZip"
                                Expand-Archive -Path $srcZipFile -DestinationPath $trgModPath -Verbose -ea Stop
                            }
                            Catch
                            {
                                Write-Error 'Module not Installed'
                                EXIT
                            }
                        }
                    # Install HorizonView Commands
                        $testHVPath = GCI $trgModPath -Directory | Where { $_ -Match '^VMWare.HV' }
                        If ($testHVPath -eq $null)
                        {
                            Try
                            {
                                New-Item -Name $trgMod -Path $trgModPath -ItemType Directory -ea Stop
                                $srcZipFile = "$zipPath\$hzvwZip"
                                Expand-Archive -Path $srcZipFile -DestinationPath $trgModPath -Verbose -ea Stop
                            }
                            Catch
                            {
                                Write-Error 'Sub-Module not Installed'
                                EXIT
                            }
                        }
                    # Unlock Newly Added Files
                        $cleanPath = GCI $trgModPath -Directory | Where { $_ -Match '^VMWare' }
                        GCI $trgModPath.FullName -Recurse | Unblock-File -Verbose
                }
                Function Configure-PowerCLI
                {
                    Param
                    (
                        [ValidateSet('AllSigned','Bypass','Default','RemoteSigned','Restricted','Unrestricted','Undefined')]$execPolicy = 'RemoteSigned'
                    ) 
                    If ((Get-ExecutionPolicy) -ne $execPolicy){ Set-ExecutionPolicy $execPolicy }
                    Import-Module VMWare.PowerCLI -Verbose
                    # Kill nag for allowinf feedback to VMWare
                    If ((Get-PowerCLIConfiguration -Scope User).ParticipateInCEIP -ne $false)
                    {
                        Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false
                    }
                    # Verify the current settings of the InvalidCertificateAction parameter
                    If ((Get-PowerCLIConfiguration).InvalidCertificateAction -isnot [array])
                    {
                        $vals = "Unset,
                                 Fail,
                                 Ignore,
                                 Warn,
                                 Prompt,
                                 " | ConvertFrom-Csv -Delimiter ',' -Header Value,Description
                            $promptChoices = "
                                     Deny,
                                     Accept Once,
                                     Accept Permanently,
                                     Accept For All Users,
                                     " | ConvertFrom-Csv -Delimiter ',' -Header Option,Action
                        Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction $vals[2].Value -Confirm:$false
                    }
                }
                Function Get-LastFridayOfMonth([datetime]$d = (get-date))
                {
                    $lastday = New-Object DateTime($d.Year, $d.Month, [DateTime]::DaysInMonth($d.Year, $d.Month))
                    $diff = ([int][DayOfWeek]::Friday) - ([int]$lastday.DayOfWeek)
                    If ($diff -ge 0){ Return $lastday.AddDays(-(7-$diff)) }
                    Else { Return $lastday.AddDays($diff) }
                }
            #endregion
            #region - Start and Connect to VMWare Environment
                # Install VMWare PowerCLI mmodule (If needed)
                    If ((Get-Module -ListAvailable VMWare.PowerCLI*) -isnot [array]){ Install-VMWareCmdlets }
                # Config PowerCLI (If needed)
                    If ((Get-ExecutionPolicy) -ne 'RemoteSigned'){ Configure-PowerCLI -execPolicy RemoteSigned }
    
                Import-Module VMWare.PowerCLI -Verbose -Force

                #region - Connect to VCenter, HorizonView and ESXi Hosts
                    # Populate Credentials
                        Write-Host -f Green "`n`nVerifying required credentials`n`n"
                        $Creds1 = New-Object System.Management.Automation.PSCredential(($accts | ? trgDomain -eq 'VCenter').acct,(Get-Key -it 7))
                        $Creds2 = New-Object System.Management.Automation.PSCredential(($accts | ? trgDomain -eq 'Domain').acct,(Get-Key -it 23))
                        # $Creds2 = Get-Credential -UserName "$($env:UserDomain)\$($env:UserName)" -Message "Enter HorizonView Password"
        
                    # Connect to VCenter
                        Write-Host -f Green "`n`nConnecting to VCenter server $vctrServer and the ESXi hosts`n`n"
                        ### FIX-FIX-FIX ###        
                        $srvrVCtr = Connect-VIServer -Server $vctrServer -Credential $Creds1
                        $esxiHosts = Get-VMHost
                #endregion
            #endregion
            #region - Set Script Action Path
                # $action = 'Shutdown','Startup' | OGV -Title 'Select Action' -PassThru
                $action = 'Cancel'
                If ([int](Get-Date -f HHmm) -le 0900){ $action = 'Startup' }
                If ([int](Get-Date -f HHmm) -ge 1500){ $action = 'Shutdown' }
                $action
            #endregion
            Switch ($action)
            {
                'Startup'
                {
                    Write-Host -f Green "Startup action selected"
                    #region - 1-4
                        # Remove keys and drive(s) from safe
                        # Insert drive into admin WKS
                        # Insert drives into Servers
                        # Insert Run keys
                    #endregion
                    #region - 5-10
                        # Poweron Phys DC
                        # Poweron Node 1
                        # PowerOn BE (Last Friday as needed)
                        # Poweron Nodes 2 & 3
                        # Poweron WSUS
                        # Poweron admin WKS
                        # logon to admin WKS
                    #endregion
                    #region - 11 Ping until reachable (Phys DC, vm DC's, VCenter
                        Write-Host -f Green "`n`nVerifying DC's and VCenter are Pingable`n`n"
                        $chkServers = $IPs | Where Role -match '(DC|VCenter)' | Where Type -eq 'VM' # Type added to remove Phys boxes from ping test
                        ForEach ($svr in $chkServers)
                        {
                            Do
                            {
                                Write-Host "Pinging $(((nslookup $svr | Select-String -Pattern 'name') -split ' ')[-1])"
                                $test = [bool](Test-Connection $svr -Count 2)
                            }
                            Until ($test -eq $true)
                        }
                    #endregion
                    #region - 12 Node 2 - Verify on and remove from MM
                        Write-Host -f Green "`n`nVerifying Node 2 PowerOn and remove from MM`n`n"
                        If ($esxiHosts -eq $null) { $esxiHosts = Get-VMHost }
                        $esx2 = $esxiHosts | Where Name -Match '\-02'
                        If ($esx2.PowerState -ne 'PoweredOn'){  }
                        If ($esx2.ConnectionState -eq 'Maintenance')
                        {
                            $null = Set-VMHost -VMHost $esx2 -State Connected -Confirm:$false -RunAsync
                            While ((Get-VMHost -Name $esx2).ConnectionState -eq 'Maintenance'){ Sleep 5;"$((Get-VMHost -Name $esx2).Name) is $((Get-VMHost -Name $esx2).ConnectionState)" }
                        }
                    #endregion
                    #region - 13 Node 3 - Verify on and remove from MM
                        Write-Host -f Green "`n`nVerifying Node 3 PowerOn and remove from MM`n`n"
                        If ($esxiHosts -eq $null) { $esxiHosts = Get-VMHost }
                        $esx3 = $esxiHosts | Where Name -Match '\-03'
                        If ($esx2.PowerState -ne 'PoweredOn'){  }
                        If ($esx2.ConnectionState -eq 'Maintenance')
                        {
                            $null = Set-VMHost -VMHost $esx3 -State Connected -Confirm:$false -RunAsync
                            While ((Get-VMHost -Name $esx3).ConnectionState -eq 'Maintenance'){ Sleep 5;"$((Get-VMHost -Name $esx3).Name) is $((Get-VMHost -Name $esx3).ConnectionState)" }
                        }
                    #endregion
                    #region - 14 Power On all other VMs
                        Write-Host -f Green "`n`nInitiating VM Power-On`n`n"
                        $VMs = Get-VM | Where Name -Match '(^jwic|^ess)' | Sort Name
                        $VMs = $VMs | Where PowerState -ne 'PoweredOn'
                        If ($noCyber -eq $true){ $VMs = $VMs | Where Name -NotMatch '(acas|^ess)' }
                        $VMs | %{ Start-VM -RunAsync -VM $_.Name }
                    #endregion
                    #region - 15 Apply DRS Recommends
                        Sleep 30
                        Write-Host -f Green "`n`nApplying DRS Recommendations`n`n"
                        $drs = Get-DrsRecommendation
                        $drs | Apply-DrsRecommendation -Verbose
                    #endregion
                    #region - 15a Restart DHCP Services (If needed)
                        $dhcpServer = ($IPs | Where Role -Match 'dhcp')
                        Get-Service -ComputerName $dhcpServer -Name dhcps*
                        Get-Service -ComputerName $dhcpServer -Name dhcps* | Restart-Service
                        Get-Service -ComputerName $dhcpServer -Name dhcps*
                    #endregion
                    #region - 16 Logon to HorizonView and enable Desktops
                        #region Connect to HV server (Script continues once connected)
                            IPMO VMWARE.VIMAutomation.HorizonView
                            Sleep 10
                            $global:count = 0
                            $strtTimer = (Get-Date)
                            Write-Host -f Green "`n`nConnecting to HorizonView Server $hvServer`n`n"
                            Do
                            {
                                Try
                                {
                                    $count ++
                                    $srvrHV = Connect-HVServer -Server $hvServer -Credential $Creds2
                                }
                                Catch
                                {
                                    Write-Warning "Error connecting [attempt $count] - Retrying"
                                }
                                sleep 2
                            }
                            Until ($srvrHV.IsConnected -eq $true)
                            $endTimer = (Get-Date)
                            $tspanConnect = New-TimeSpan -Start $strtTimer -End $endTimer
                            Write-Host ("Total runtime for connect - {0:mm:ss}" -f ($tspanConnect | Select Minutes,Seconds)) -f Cyan
                        #endregion
                        #region - Connect to HV Pool (monitor until online then continue)
                            $global:count = 0
                            $strtTimer = (Get-Date)
                            Write-Host -f Green "`n`nEnabling HorizonView Desktop Pool & Verifying VMs online`n`n"
                            $HVServices = $global:DefaultHVServers.ExtensionData
                            $trgPool = (Get-HVPoolSummary | Select -Exp DesktopSummaryData).Name
                            Set-HVPool -PoolName $trgPool -Enable -Verbose
                            Sleep 15
                            Do
                            {
                                $vms = (Get-HVMachineSummary).Base
                                $trgr = $vms | Where BasicState -Match '(Available|Connected)'
                                $vms | Select Name,BasicState | FT
                                If ($trgr.Count -lt 15){ "`n`nRefreshing`n`n" }
                                Sleep 3
                            }
                            Until ($trgr.count -eq 15)
                            #(Get-HVMachineSummary).Base.BasicState
                            $endTimer = (Get-Date)
                            $tspanPools = New-TimeSpan -Start $strtTimer -End $endTimer
                            Write-Host ("Total runtime for Pools Online - {0:mm:ss}" -f ($tspanPools | Select Minutes,Seconds)) -f Cyan
                        #endregion
                    #endregion
                }
                'Shutdown'
                {
                    Write-Host -f yellow "Shutdown action selected"
                    #region 1 Logon to HV, disable pools, log off all open sessions, shutdown vms & delete
                        Write-Host -f Green "`n`nConnecting to HorizonView server $hvServer`n`n"
                        $srvrHV = Connect-HVServer -Server $hvServer -Credential $Creds2
                        $HVServices = $global:DefaultHVServers.ExtensionData

                        # Disable Pool
                            $trgPool = (Get-HVPoolSummary | Select -Exp DesktopSummaryData).Name
                            Write-Host -f Green "`nDisabling Desktop pool $trgPool`n"
                            Set-HVPool -PoolName $trgPool -Disable -Verbose

                        # Logogff Users
                            Write-Host -f Green "`nForcing logoffs from $hvServer`n"
                            $HVServices.Session.Session_LogoffSessionForced((Get-HVLocalSession).ID)
                            Do { $a = (Get-HVLocalSession).ID.Count; $a} Until ($a -eq 0) #add progress bar?

                        # Delete VMs
                            (Get-HVMachine | Select -Exp Base).Name | %{ Remove-Machine -MachineNames $_ -HVServer $hvServer -Force -Confirm:$false }

                    #endregion
                    #region 2 Migrate all VMs (Compute & Storage) to Node 1
                        Write-Host -f Green "`n`nMigrating VMs from Nodes 2 & 3to Node 1`n"
                        $node3VMs = Get-VM | Where VMHost -match '\-03'
                        $node2VMs = Get-VM | Where VMHost -match '\-02'
                        $node1VMs = Get-VM | Where VMHost -match '\-01'
                        Write-Host -f Green "`nFrom Node 3`n"
                        ForEach ($vm in $node3VMs)
                        {
                            $vm | Move-VM -Destination ($esxiHosts | Where Name -match '\-01').Name -Verbose -VMotionPriority High -Confirm:$false -RunAsync
                        }
                        Do
                        {
                             Sleep 5
                             Write-Host -f Cyan "Migrating VMs from $($esxiHosts | Where Name -Match '\-03')"
                             $a = (Get-VM | Where VMHost -match '\-03').Count
                        }
                        until ($a -eq 0)
                        Write-Host -f Green "`nFrom Node 2`n"
                        ForEach ($vm in $node2VMs)
                        {
                            $vm | Move-VM -Destination ($esxiHosts | Where Name -match '\-01').Name -Verbose -VMotionPriority High -Confirm:$false -RunAsync
                        }
                        Do
                        {
                             Sleep 5
                             Write-Host -f Cyan "Migrating VMs from $($esxiHosts | Where Name -Match '\-02')"
                             $a = (Get-VM | Where VMHost -match '\-02').Count
                        }
                        until ($a -eq 0)
                    #endregion
                    #region 3-4 Place Nodes 2 & 3 into Maintenance Mode
                        Write-Host -f Green "`n`nPlacing Nodes 2 & 3 into Maintenance Mode`n"
                        Write-Host -f Green "`n`nPlacing Node 3 into Maintenance Mode`n"
                        $esx3 = Get-VMHost| Where Name -match '\-03'
                        If ($esx3.ConnectionState -ne 'Maintenance')
                        {
                            $null = Set-VMHost -VMHost $esx3 -State Maintenance -Confirm:$false -RunAsync -VsanDataMigrationMode EnsureAccessibilty
                            While ((Get-VMHost -Name $esx3).ConnectionState -ne 'Maintenance'){
                                Sleep 5
                                Write-Host -f yellow "$((Get-VMHost -Name $esx3).Name) is $((Get-VMHost -Name $esx3).ConnectionState)"
                                }
                        }
                        Write-Host -f Green "`n`nPlacing Node 2 into Maintenance Mode`n"
                        $esx2 = Get-VMHost| Where Name -match '\-02'
                        If ($esx2.ConnectionState -ne 'Maintenance')
                        {
                            $null = Set-VMHost -VMHost $esx2 -State Maintenance -Confirm:$false -RunAsync -VsanDataMigrationMode EnsureAccessibilty
                            While ((Get-VMHost -Name $esx2).ConnectionState -ne 'Maintenance'){
                                Sleep 5
                                Write-Host -f yellow "$((Get-VMHost -Name $esx2).Name) is $((Get-VMHost -Name $esx2).ConnectionState)"
                                }
                        }
                    #endregion
                    #region 4 Power-Off Nodes 2 & 3
                        Write-Host -f Green "`n`nPowering Off Nodes 2 & 3`n"
                        Write-Host -f yellow "`n`nPowering Off Node 3`n"
                        If ((Get-VMHost -Name $esx3).PowerState -eq 'PoweredOn'){ Stop-VMHost -VMHost $esx3 -Confirm:$false -Reason 'Secure Storage' }
                        Write-Host -f yellow "`n`nPowering Off Node 2`n"
                        If ((Get-VMHost -Name $esx2).PowerState -eq 'PoweredOn'){ Stop-VMHost -VMHost $esx2 -Confirm:$false -Reason 'Secure Storage' }
                    #endregion
                    #region 5 Shutdown all VMs in proper order (except VCenter)
                        Write-Host -f Green "`n`nPowering Off Server VMs`n"
                        $VMs = Get-VM | Where Name -Match '(^jwic|^ess)' | Where PowerState -eq 'PoweredOn' | Sort Name
                            $grp1 = $VMs | Where Name -NotMatch '(vcenter|dc|file)'
                            $grp2 = $VMs | Where Name -Match '(dc06|file)'
                            $grp3 = $VMs | Where Name -Match '(dc05)'
                            Write-Host -f Yellow "`n`nPowering Off Group 1`n"
                            ForEach ($itm in $grp1)
                            {
                                If ($itm.Name -match 'acas'){ Stop-VM -RunAsync -VM $itm.Name -Confirm:$false }
                                Else { Stop-VMGuest -Guest $itm.Name -Confirm:$false }
                            }
                            ForEach ($itm in $grp1)
                            {
                                DO {"Powering Off $($itm.Name)";Sleep 5} Until ((Get-VM $itm).PowerState -eq 'PoweredOff')
                            }
                            Write-Host -f Yellow "`n`nPowering Off Group 2`n"
                            ForEach ($itm in $grp2) { Stop-VMGuest -Guest $itm.guest -Confirm:$false }
                            ForEach ($itm in $grp2) { DO {"Powering Off $($itm.Name)";Sleep 5} Until ((Get-VM $itm).PowerState -eq 'PoweredOff') }
                            Write-Host -f Yellow "`n`nPowering Off Group 3`n"
                            ForEach ($itm in $grp3) { Stop-VMGuest -Guest $itm.guest -Confirm:$false }
                            ForEach ($itm in $grp3) { DO {"Powering Off $($itm.Name)";Sleep 5} Until ((Get-VM $itm).PowerState -eq 'PoweredOff') }
                    #endregion
                    #region 6 Poweroff Node 1 (No Maint Mode)
                        Write-Host -f Green "`n`nPowering Off Node 1`n"
                        $esx1 = $esxiHosts | Where Name -match '\-01'
                        If ((Get-VMHost -Name $esx1).PowerState -eq 'PoweredOn'){ Stop-VMHost -VMHost $esx1 -Confirm:$false -Reason 'Secure Storage' -Force }
                    #endregion
                    #region 7-10 adm wks poweroff, wsus poweroff, backups poweroff (last Friday of month), dc poweroff
                        Write-Host -f Green "`n`nPowering Off Physical Systems`n`n"
                        $lastFriday = Get-LastFridayOfMonth (Get-Date)
                        If ((Get-Date $lastFriday -f MM-dd-yyyy) -ne (Get-Date -f MM-dd-yyyy)){ $physicals = $physicals -notmatch 'be01' }
                        ForEach ($itm in $physicals)
                        {
                            Start-Process cmd.exe -ArgumentList '/c','title',"Pinging $itm",'&&','Ping',$itm,'/t' -Wait:$false
                            Stop-Computer -ComputerName $itm `
                                          -Credential $cred2 `
                                          -Force `
                                          -Confirm:$false # `
                                          #-WhatIf
                        }
                    #endregion
                    #region 11-14 Pull run keys, server drives, adm wks drive, Secure Drives & keys in Server Room Safe
                    #endregion
                }
                'Cancel'{ Write-Warning "No Action Selected" }
            }
            <#
                Get-Service -ComputerName HV01 | Export-CSV C:\Temp\HV01_svc.csv -Append -NoTypeInformation
                Get-Process -ComputerName HV01 | Export-CSV C:\Temp\HV01_proc.csv -Append -NoTypeInformation
                (Get-VMHost | Where Name -Match '\-03').PowerState
            #>
        }
