        Function  Toggle-PoolState_ps1 
        {
            # & taskschd.msc
            #Requires -RunAsAdministrator
            Param
            (
                $sTime = (Get-Date),
                $script = $MyInvocation.MyCommand.Source,
                $hvServer = 'HVServer',
                $hvIP = [Net.Dns]::GetHostbyName($hvServer).AddressList.IPAddressToString,
                $svcAcct = 'svc_PoshScriptAdm',
                $exmptPools = 'N/A',
                $nonDelPools = @('Pool1'), #,'Pool2'
                [switch]$TS = $true
            )
            
            # Troublshooting Logs - If Needed
                If ($TS.IsPresent){ Start-Transcript -Path "PATHTOLOGS\FILENAME_TS_$(Get-Date -f yyyy-MM-dd_HHmm).log" }

            #region Create Event Log connector to log script actions
                $evtLog,$evtSrc,$evtLvl,$evtCmd = 'Application','psScripting',('Information','Warning','Error'),[System.Diagnostics.EventLog]
            #endregion
            
            #region - Script Functions
                Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
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
                Function Connect-HVServer2
                {
                    $retries = 25
                    Sleep 2
                    $global:count = 0
                    $strtTimer = (Get-Date)

                    $msg = "Connecting to HorizonView Server $hvServer`nScript: $script`nUser: $env:UserName"
                    $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                    Do
                    {
                            $count ++
                            $srvrHV = Connect-HVServer -Server $hvIP -Credential $crdHV -Verbose
                            Sleep 2
                    }
                    Until ($srvrHV.IsConnected -eq $true -or $count -gt $retries)
                    If ($count -gt $retries)
                    {
                        $msg = "Unable to connect to HorizonView Server $hvServer after $count attempts`nEXITING SCRIPT`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[2],7773)
                        EXIT
                    }
                    Else
                    {
                        $endTimer = (Get-Date)
                        $tspanConnect = New-TimeSpan -Start $strtTimer -End $endTimer
                        $msg = "Connection Info:`nTotal runtime for connect - {0:mm:ss}`nScript: $script`nUser: $env:UserName" -f ($tspanConnect | Select Minutes,Seconds)
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                        Return $srvrHV
                    }

                }
                function Test-IsHoliday([datetime] $DateToCheck = (Get-Date))
                {
                    # Powershell Holiday Checks
                    [int]$year = $DateToCheck.Year
                    If ($DateToCheck.Day -eq 31 -and $DateToCheck.Month -eq 12 -and $DateToCheck.DayOfWeek -eq 'Friday'){$year = $year + 1}
                    $HolidaysInYear = (@(
                        [datetime]"1/1/$year", #New Year's Day on Saturday will be observed on 12/31 of prior year
                        $((0..29 | %{([datetime]"1/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]),# Martin Luther King Day - 3rd Monnday in Jan
                        $((0..29 | %{([datetime]"2/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[2]),#Presidents Day - 3rd Monday in Feb
                        (23..30 | %{([datetime]"5/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[-1], #Memorial Day
                        $([datetime]"6/19/$year" | Where Year -ge 2021), #Juneteenth is a federal holiday since 2021
                        [datetime]"7/4/$year",#Independence Day
                        (0..6 | %{([datetime]"9/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[0], #Labor Day - first Mon in Sept.
                        $((0..29 | %{([datetime]"10/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Monday'})[1]), #Columbus Day - 2nd Monday in Oct
                        $([datetime]"11/11/$year"), #Veterans Day Nov 11th,Y
                        (0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3],#Thanksgiving - last Thu in Nov.
                        $(((0..29 | %{([datetime]"11/1/$year").AddDays($_)}|?{$_.DayOfWeek -eq 'Thursday'})[3]).AddDays(1)), # Black Friday - Day after Thanksgiving
                        $([datetime]"12/24/$year" | Where DayofWeek -NotMatch '(Sat|Sun)'), # Christmas Eve Dec 24th on a weekday,N
                        [datetime]"12/25/$year"#Christmas
                        ) | %{$_.AddDays($(If($_.DayOfWeek -eq 'Saturday'){-1}) + $(If($_.DayOfWeek -eq 'Sunday'){+1})) })
                    Return $HolidaysInYear.Contains($DateToCheck.Date)
                }
            #endregion
            #region - Script Constants
                $accts = "
                    $(Dec64 'YWRtaW5pc3RyYXRvckB2c2hwZXJlLmxvY2Fs'),VCenter
                    $env:USERDOMAIN\$svcAcct,Domain" | ConvertFrom-Csv -Delimiter ',' -Header Acct,trgDomain
                IPMO VMWARE.VIMAutomation.HorizonView
            #endregion
            #region - Eventlog actions
                # Verify event logging source
                    If (!($evtCmd::SourceExists($evtSrc))){ $evtCmd::CreateEventSource($evtSrc,$evtLog) }
                # Review scripting events
                    # Get-EventLog -LogName $evtLog -Source $evtSrc
                # Delete event source
                    # $evtCmd::DeleteEventSource($evtSrc)
                    If ($sTime.DayOfWeek -match '(Saturday|Sunday)' )
                    {
                        $msg = "Aborting automated script (Not Run on Weekends):`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[1],7772)
                        EXIT
                    }
                    ElseIf (Test-IsHoliday -eq $true)
                    {
                        $msg = "Aborting automated script (Not Run on Federal Holidays):`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[1],7772)
                        EXIT
                    }
                    Else
                    {
                        $msg = "Beginning automated script:`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                    }
            #endregion
            #region - Populate Credentials
                $crdHV = New-Object System.Management.Automation.PSCredential(($accts | ? trgDomain -eq $env:UserDomain).Acct,(Get-Key -it 23))
                ### FIX ### FIX ### FIX ### Automate Key Selection
                $crdVC = New-Object System.Management.Automation.PSCredential(($accts | ? trgDomain -eq 'VCenter').Acct,(Get-Key -it 7))
            #endregion
            #region - Set Script Action Path
                # $action = 'Shutdown','Startup' | OGV -Title 'Select Action' -PassThru
                $action = 'Cancel'
                If ((Get-Date -f HHmm) -le '0900'){ $action = 'Startup' }
                If ((Get-Date -f HHmm) -ge '1500'){ $action = 'Shutdown' }
                
                $msg = "Setting script action to '$action'`nScript: $script`nUser: $env:UserName" -f ($tspanConnect | Select Minutes,Seconds)
                $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
            #endregion
            #region - Execute desired action path
                If ($action -ne 'Cancel')
                {
                    $strtTimer = (Get-Date)
                    $srvrHV = Connect-HVServer2
                    $endTimer = (Get-Date)
                    $tspanPools = New-TimeSpan -Start $strtTimer -End $endTimer
                    If ($srvrHV.IsConnected)
                    {
                        $msg = "Total runtime for connecting to HorizonView Server [$($srvrHV.Name)]`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)

                    }
                    Else
                    {
                        $msg = "Unable to connect to HorizonView Server [EXITING Script]`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[2],7773)
                        EXIT
                    }
                }
                Switch ($action)
                {
                    'Startup'
                    {
                        #region - Connect to HV Pool (Monitor unil online then continue)
                            $global:count = 0
                            $msg = "Enabling HV Desktop Pool & Verfying online`nScript: $script`nUser: $env:UserName"
                            $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                            $HVServices = $global:DefaultHVServers.ExtensionData
                            #region Enable Required Pools
                                [array]$trgPools = (Get-HVPoolSummary | Select -Exp DesktopSummaryData | Where Name -NotContains $exmptPools).Name
                                ForEach ($trgPool in $trgPools)
                                {
                                    $pool = (Get-HVPoolSummary -PoolName $trgPool).DesktopSummaryData
                                    $pool | %{ Set-HVPool -PoolName $_ -Enable -Verbose }

                                    If ($pool.Type -ne 'MANUAL')
                                    {
                                        Sleep 5

                                        $strtTimer = (Get-Date)
                                        DO
                                        {
                                            $vms = (Get-HVMachineSummary | Where {$_.NamesData.DesktopName -eq $pool.Name}).Base.Name
                                            $trgr = $vms | Where BasicState -Match '(Available|Connected)'
                                            $vms | Select Name,BasicState | FT
                                            If ($trgr.Count -lt $pool.NumMachines){ "`n`nRefreshing`n`n" }
                                            Sleep 3
                                        }
                                        UNTIL($trgr.count -eq $pool.NumMachines)
                                        $msgData = ($vms | Select Name,BasicState | FT) | Out-String
                                        $endTimer = (Get-Date)
                                        $tspanPools = New-TimeSpan -Start $strtTimer -End $endTimer
                                        $msg = "Current Pool Info:`n$msgData`n`nExecution Info:`nTotal runtime for pool online - {0:mm:ss}`nScript: $script`nUser: $env:UserName" -f ($tspanConnect | Select Minutes,Seconds)
                                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                                    }
                                }
                            #endregion
                        #endregion
                    }
                    'Shutdown'
                    {
                        #region - Disable Desktop Pools, logoff all users and shutdown then delete VMs
                            #region Logoff all connected Users
                                $msg = "Forcing Logoffs from $hvServer"
                                $trgUsers = (Get-HVLocalSession).ID
                                $HVServices.Session.Session_LogoffSessionsForced($trgUsers)

                                Do { $a = (Get-HVLocalSession).ID.Count; $a } Until ($a -eq 0)

                                $msg = $msg + "`nScript: $script`nUser: $env:UserName"
                                $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                            #endregion
                            $srvrHV = Connect-HVServer2
                            $HVServices = $global:DefaultHVServers.ExtentionData
                            $nonDelPools = @('Pool1')

                            # Disable Required Pool(s)
                                [array]$trgPools = (Get-HVPoolSummary | Select -Exp DesktopSummaryData | Where Name -NotContains $exmptPools).Name
                                ForEach ($trgPool in $trgPools)
                                {
                                    $pool = (Get-HVPoolSummary -PoolName $trgPool).DesktopSummaryData

                                    #Disable Pool
                                        $msg = "Disabling Desktop Pool [$($pool.Name)]`n"
                                        $msg = $msg + (Set-HVPool -PoolName $pool.Name -Disable -Verbose | Out-String)
                                        $trgPool = (Get-HVPoolSummary | Select -Exp DesktopSummaryData).Name
                                        $msg = $msg + "`nScript: $script`nUser: $env:UserName"
                                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)

                                    # Delete VMs
                                        If ($pool.Type -ne 'MANUAL')
                                        {
                                            $msg = "Deleting VMs from [$($pool.Name)] pool"
                                            $poolVMs = (Get-HVMachine | Where { $_.Base.DesktopName -eq $pool.Name })
                                            $poolVMs = $poolVMs | Where { $nonDelPools -notcontains $_.Base.DesktopName } # Explicit VM Protects
                                            ($poolVMs | Select -Exp Base).Name | Sort | %{ Remove-HVMachine -MachineNames $_ -HVServer $srvrHV -DeleteFromDisk:$true -Confirm:$false }
                                        }
                                        Else
                                        {
                                            $msg = "VMs from [$($pool.Name)] pool do not require deletion"
                                        }
                                        $msg = $msg + "`nScript: $script`nUser: $env:UserName"
                                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                                }
                        #endregion
                        #region Logoff HorizonView
                                $msg = "Disconnecting from HorizonView server $hvServer`n`n"
                                Disconnect-HVServer -Server $srvrHV -Force -Confirm:$false
                                $msg = $msg + "`nScript: $script`nUser: $env:UserName"
                                $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
                        #endregion

                    }
                    'Cancel'
                    {
                        Write-Warning "No Action Selected"
                        $msg = "No Script Action was selected, EXITING`nScript: $script`nUser: $env:UserName"
                        $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[1],7772)
                    }
                }
                $lstTimer = (Get-Date)
                $tspanPools = New-TimeSpan -Start $sTime -End $lstTimer
                $msg = $msg + "EXITING SCRIPT - Total Runime: {0:mm:ss}`nScript: $script`nUser: $env:UserName" -f ($tspanPools | Select Minutes,Seconds)
                $evtCmd::WriteEntry($evtSrc,$msg,$evtLvl[0],7771)
            #endregion

                If ($TS.IsPresent){ Stop-Transcript }

            #region - New Event View for Scripting
                # $dirViews = "$env:ProgramData\Microsoft\Event Viewer\Views"
                # $xmlData = (Dec64 'Cjw/eG1sIHZlcnNpb249IjEuMCI/Pg0KPFZpZXdlckNvbmZpZz4NCiAgPFF1ZXJ5Q29uZmlnPg0KICAgIDxRdWVyeVBhcmFtcz4NCiAgICAgIDxTaW1wbGU+DQogICAgICAgIDxDaGFubmVsPkFwcGxpY2F0aW9uPC9DaGFubmVsPg0KICAgICAgICA8UmVsYXRpdmVUaW1lSW5mbz4wPC9SZWxhdGl2ZVRpbWVJbmZvPg0KICAgICAgICA8U291cmNlPnBzU2NyaXB0aW5nPC9Tb3VyY2U+DQogICAgICAgIDxCeVNvdXJjZT5UcnVlPC9CeVNvdXJjZT4NCiAgICAgIDwvU2ltcGxlPg0KICAgIDwvUXVlcnlQYXJhbXM+DQogICAgPFF1ZXJ5Tm9kZT4NCiAgICAgIDxOYW1lPkF1dG9tYXRpb24gU2NyaXB0aW5nPC9OYW1lPg0KICAgICAgPERlc2NyaXB0aW9uPkF1dG9tYXRlZCBTY3JpcHRpbmcgRXZlbnRzPC9EZXNjcmlwdGlvbj4NCiAgICAgIDxRdWVyeUxpc3Q+DQogICAgICAgIDxRdWVyeSBJZD0iMCI+DQogICAgICAgICAgPFNlbGVjdCBQYXRoPSJBcHBsaWNhdGlvbiI+KltTeXN0ZW1bUHJvdmlkZXJbQE5hbWU9J3BzU2NyaXB0aW5nJ11dXTwvU2VsZWN0Pg0KICAgICAgICA8L1F1ZXJ5Pg0KICAgICAgPC9RdWVyeUxpc3Q+DQogICAgPC9RdWVyeU5vZGU+DQogPC9RdWVyeUNvbmZpZz4NCjwvVmlld2VyQ29uZmlnPgo=')
                # $latestView = GCI $dirViews -Filter "*View_*.xml" | Sort LastWriteTime -Descending | Select -First 1
                # If ($latestView -eq $null){ $newView = $dirViews + "\" + "View_0.xml" }
                # Else { $newView = $dirViews + "\" + "View_" + ([int]($latestView.Name -replace 'View_' -replace '.xml') + 1) + ".xml" }
                # $xmlData | SC $newView

                # GCI $dirViews -Filter "*View_*.xml" 
            #endregion
        }