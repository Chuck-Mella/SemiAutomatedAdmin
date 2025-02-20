#region - Windows Deployment          
    #region - volume License prep
        $trgVer = 'Standard' #'DataCenter'
        $volSvr2019 = 'Product,Edition,GVLK
        2019 Datacenter,ServerDataCenter,WMDGN-G9PQG-XVVXX-R3X43-63DFG
        2019 Standard,ServerStandard,N69G4-B89J2-4G8F4-WWYCC-J464C' | ConvertFrom-Csv -delim ','
        $trgGVLK = ($volSvr2019 | Where Product -Match $trgVer).GVLK
        $trgEdtn = ($volSvr2019 | Where Product -Match $trgVer).Edition
        # Open an elevated command prompt
        "DISM.exe /Online /Get-TargetEditions" | Clip
        "DISM /online /Set-Edition:Enterprise /ProductKey:NPPR9-FWDCX-D2C8J-H872K-2YT43 /AcceptEula" | Clip
    #endregion

    #region - MDK_ADK_SHB
        #region - Downloads
            $dlDir = "$env:USERPROFILE\Downloads\"
            # SCCM Toolkit
                $sccmTools = 'https://download.microsoft.com/download/0/0/1/001d97e2-c427-4d4b-ad30-1556ee0ff1b0/MCM_Configmgr_2303.exe?culture=en-us&country=us'
                (new-object System.Net.WebClient).DownloadFile($sccmTools,"$dlDir\MCM_Configmgr_2303.exe")

            # MS Deployment Toolkit
                $imdt = $dlDir + ($mdt = 'https://download.microsoft.com/download/3/3/9/339BE62D-B4B8-4956-B58D-73C4685FC492/MicrosoftDeploymentToolkit_x64.msi').Split('/')[-1]
                # $imdtx86 = ($dlDir + ($mdtx86 = $mdt -replace '_x64','_x86').Split('/')[-1])
                    (new-object System.Net.WebClient).DownloadFile($mdt,$imdt)
                    # (new-object System.Net.WebClient).DownloadFile($mdtx86,$imdtx86)

            # Windows ADK w/PE add-on https://go.microsoft.com/fwlink/?linkid=2271337
                $iadk = $dlDir + ($adk = 'https://download.microsoft.com/download/5/8/6/5866fc30-973c-40c6-ab3f-2edb2fc3f727/ADK/adksetup.exe').Split('/')[-1]
                $iadkPE = $dlDir + ($adkPE = 'https://download.microsoft.com/download/d/f/0/df0273fb-4587-4cc5-a98c-7d2359b4a387/ADKWinPEAddons/adkwinpesetup.exe').Split('/')[-1]
                    (new-object System.Net.WebClient).DownloadFile($adk,$iadk)
                    (new-object System.Net.WebClient).DownloadFile($adkPE,$iadkPE)
            
            #region - Fix|Verify x86 path below
                $pex86 = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment"
                If ((Test-path ($pex86+'\x86\WinPE_OCs')) -eq $false){ xcopy "$($pex86)\amd64" "$pex86\x86" /E /H /C /I }
            #endregion
        #endregion
        #region - Build MDT VM
            $vmRoot = "C:\VirtualMachines"
            $isoRoot = "$($vmRoot -replace '^C','U')\ISOs"
            $vhdRoot = "$($vmRoot -replace '^C','U')\VDH-Shares"
            $admCreds = $($aesKey = (137,51,63,190,205,150,20,73,189,108,202,22,97,208,88,80,93,170,21,52,98,105,188,51,73,111,119,92,72,154,19,81)
                      $encText = '76492d1116743f0423413b16050a5345MgB8AHUAdgBBAHIAYgBvAFUANABTAG4AWAA3AGIAeQBQAGkAMABRAHEARwArAFEAPQA9AHwAOAA3AGEANQA4ADYAZAAzADUAOQA1ADMAMgBmADUAMwBlADIANwBmAGQAMgBhAGQAZQAwAGIAYgAzADkAZQAzADAAYQAxAGYAMABiADUANQAzADEAOAAwAGEAZAA2ADUANwAzADAAMAAxADAAYwA3AGMAOQBkADQANwBiADQAYQA0AGEAYgAyAGQAMwA4AGEAMgAyAGUANwA3ADYAYQA3AGUAYgAzADcAYgA5ADAAZABmADMANABkADMAYgA3ADMA' | convertTo-securestring -Key $aesKey
                      New-object system.Management.Automation.Pscredential ('~\Dod_Admin',$encText)
                      )
                      # [System.Runtime.Interopservices.Marshal]::PtrToStringuni([System.Runtime.Interopservices.Marshal]::securestringToCoTaskMemunicode($admCreds.Password))
            $vmData = "Set	Name	Gen	Path	Proc	Ram	hdd1	sz1	hdd2	sz2	iso1	iso2	net1	mac	net2	snet	role	OS	Ver	notes
                CFG	MECM-DC1	2		2	8GB		64GB	n/a		$isoRoot\2019_DC_x64.iso		MDT-External	mac	MDTPriv	10	Server	2019	ServerDatacenter	U2VydmVyIDIwMTlgbkgyUlBNLU5ENDRQLVhDR0ZXLTZNNDdCLTNHUkJE
                CFG	MECM-CS1	2		2	16GB		64GB		128GB	$isoRoot\2019_DC_x64.iso		MDT-External	mac	MDTPriv	10	Server	2019	ServerDatacenter	U2VydmVyIDIwMTlgbkgyUlBNLU5ENDRQLVhDR0ZXLTZNNDdCLTNHUkJE
                SUS	SUS-US1	2		2	16GB		64GB		2TB	$isoRoot\2016_x64.iso		MDT-External	mac	MDTPriv	10	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                SDC	DEP-US1	1		2	4GB		64GB	n/a	n/a	$isoRoot\LiteTouchPE_x64.iso	n/a	MDTPriv	aa:bb:cc:30:40:50	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                SDC	MDT-SDC	2		2	16GB		128GB		128GB	$isoRoot\2016_x64.iso	$isoRoot\MDT_PSD_Tools.iso	MDT-External	mac	MDTPriv	11	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                SDC	DEP-SDC	1		2	4GB		64GB	n/a	n/a	$isoRoot\LiteTouchPE_x64.iso	n/a	MDTPriv	aa:bb:cc:30:40:50	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                SHB	MDT-SHB	2		2	16GB		128GB		128GB	$isoRoot\2016_x64.iso	$isoRoot\MDT_PSD_Tools.iso	MDT-External	mac	MDTPriv	12	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                SHB	DEP-SHB	1		2	4GB		64GB	n/a	n/a	$isoRoot\LiteTouchPE_x64.iso	n/a	MDTPriv	00:11:22:33:44:55	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                SHB2	MDT-SHB2	2		2	16GB		128GB		128GB	$isoRoot\2016_x64.iso	$isoRoot\MDT_PSD_Tools.iso	MDT-External	mac	MDTPriv	12	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                SHB2	DEP-SHB2	1		2	4GB		64GB	n/a	n/a	$isoRoot\LiteTouchPE_x64.iso	n/a	MDTPriv	00:11:22:33:44:55	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                SHBS	MDT-SHBS	2		2	16GB		128GB		128GB	$isoRoot\2016_x64.iso	$isoRoot\MDT_PSD_Tools.iso	MDT-External	mac	MDTPriv	13	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                SHBS	DEP-SHBS	1		2	8GB		64GB	n/a	n/a	$isoRoot\SHBS_LiteTouchPE_x64.iso	n/a	MDTPriv	00:11:22:33:44:55	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                PSD	MDT-PSD	2		2	16GB		128GB		128GB	$isoRoot\2016_x64.iso	$isoRoot\MDT_PSD_Tools.iso	MDT-External	mac	MDTPriv	14	Server	2016	ServerStandard	U2VydmVyIDIwMTZgblRGTUtOLVZSUDJYLTNDRzg3LVBWSzJWLTRDM0RG
                PSD	DEP-PSD	1		2	4GB		64GB	n/a	n/a	$isoRoot\PSD_LiteTouchPE_x64.iso	n/a	MDTPriv	00:11:22:dd:ee:ff	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                DEV	DEP-Win11	1		2	4GB		64GB	n/a	n/a	$isoRoot\Windows_11_ENT_x64_en-us.iso	n/a	MDT-External	aa:bb:cc:30:40:50	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==
                PAW	DEP-SDC	1		2	8GB		128GB	n/a	n/a	$isoRoot\Windows_11_ENT_x64_en-us.iso	n/a	MDT-External	aa:bb:cc:30:40:50	n/a	11	Client	Win11	Ver	V2luZG93cyAxMSAoMjNIMilgbkRlcGxveW1lbnQgVGVzdGluZyBXb3Jrc3RhdGlvbg==" | 
                ConvertFrom-Csv -Delimiter "`t"
            ForEach ($vDat in $vmData)
            {
                 $vDat.Path = "$vmRoot\$($vDat.Name)"
                 If ($vDat.role -eq 'Server'){ $vDat.hdd1 = "$vmRoot\$($vDat.Name)\$($vDat.Set)-C-Drive.vhdx" }
                 Else { $vDat.hdd1 = "$vmRoot\$($vDat.Name)\DEP-C-Drive.vhdx" }

                 Switch ($vDat.hdd2)
                 {
                     {$_ -ne 'n/a'}
                     {
                        If ($vDat.Set -ne 'SUS'){ $vDat.hdd2 = "$vmRoot\$($vDat.Name)\$($vDat.Set)-E-Drive.vhdx" }
                        ElseIf ($vDat.Set -eq 'SUS'){ $vDat.hdd2 = "$vhdRoot\$($vDat.Set)-U-Drive.vhdx" }
                     }
                 }

                 If (($vDat.role -eq 'Client') -and ($vDat.iso1 -notmatch 'LiteTouch')){ $vDat.iso1 = "$isoRoot\$($_.Set)_LiteTouchPE_x64.iso" }
                 }

            $newVM = $vmData | OGV -Passthru #| Where Name -eq "MDT-SDC" # "MDT-SHB" "MDT-SHBS" "MDT-SDC" "MDT-PSD"
            $newVMC = $vmData | Where Name -eq ($newVM.Name -replace '^(MDT|SUS)','DEP') #$vmData | OGV -Passthru
            $newVMC = $vmData | Where Name -ne "DEP-SHB2"

            #region - Server
                #region - Build VM
                    New-VM -Name $newVM.Name -NewVHDPath $newVM.hdd1 -NewVHDSizeBytes ($newVM.sz1 /1) -Generation $newVM.Gen -Path $newVM.Path

                    Set-VM -Name $newVM.Name `
                           -ProcessorCount $newVM.Proc `
                           -StaticMemory -MemoryStartupBytes ($newVM.ram /1) -Notes ((Dec64 $newVM.notes) -replace '`n',[environment]::NewLine)

                    Get-VM $newVM.Name | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $newVM.net1
                    Add-VMDvdDrive -VMName $newVM.Name -Path $newVM.iso1

                    If ($newVM.hdd2 -ne 'n/a')
                    {
                        New-VHD -Path $newVM.hdd2 -BlockSizeBytes 128MB -LogicalSectorSize 4KB -SizeBytes ($newVM.sz2 /1)
                        Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 2 -Path $newVM.hdd2
                        # You can validate the in-use bus locations in advance:
                                            # Get-VMIdeController -VMName $newVM.Name
                                            Get-VMScsiController -VMName $newVM.Name | Select -Exp Drives
                    }
                    Set-VMFirmware $newVM.Name -FirstBootDevice (Get-VMDvdDrive -VMName $newVM.Name)
        
                    # Run SERVER INSTALL (2016), Login as admin
                        Start-VM -Name $newVM.Name
                #endregion
                #region - Initial Server Config
                    $pk = (dec64 $newVM.notes) -replace 'Server 201(6|9)`n' 
                    $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds
                       Invoke-Command -Session $ts -ScriptBlock { DISM /online /Get-CurrentEdition }
                       Invoke-Command -Session $ts -ScriptBlock { DISM /online /Set-Edition:ServerStandard /ProductKey:$using:pk /AcceptEula }
                       Invoke-Command -Session $ts -ScriptBlock { DISM /online /Set-Edition:ServerDataCenterCor /ProductKey:$using:pk /AcceptEula }

                       Invoke-Command -Session $ts -ScriptBlock { Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose }
                       Invoke-Command -Session $ts -ScriptBlock { Rename-Computer -NewName $($using:newVM.Name) -Force -Restart }
                    $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds
                       Invoke-Command -Session $ts -ScriptBlock { DISM /online /Get-CurrentEdition }


                    Checkpoint-VM -Name $newVM.Name -SnapshotName 'OS Installed, Renamed'


                    # Config 2nd adapter
                        $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds #'eastlab\eadmincm'
                        # Rename existing adapter (Internally)
                            Invoke-Command -Session $ts -ScriptBlock { Rename-NetAdapter -Name "E*t" -NewName $using:newVM.net1 }
                        # Add 2nd adapter & rename (Internally)
                            Add-VMNetworkAdapter -VMName $newVM.Name -SwitchName $newVM.net2
                            Invoke-Command -Session $ts -ScriptBlock { Rename-NetAdapter -Name "E*t" -NewName $using:newVM.net2 }
                    
                        $id = $newVM.snet
                        Invoke-Command -Session $ts -ScriptBlock { netsh interface ipv4 set address name="$($using:newVM.net2)" static 172.16.$using:id.1 255.255.255.0 }
                        # Invoke-Command -Session $ts -ScriptBlock { New-NetIPAddress -IPAddress 172.16.$using:id.1 -PrefixLength 24 -InterfaceIndex (Get-NetAdapter -Name Eth*2).ifIndex }
                        # gwmi win32_networkadapter | ? NetEnabled

                    # Install & Config DHCP w/Scope
                        Invoke-Command -Session $ts -ScriptBlock { Install-WindowsFeature DHCP -IncludeManagementTools; netsh dhcp add securitygroups; Restart-Service dhcpserver -Verbose }
                        # (DOMAIN ONLY)Add-DhcpServerInDC -DnsName $env:computername MDT-AF

                    # create a DHCP scope
                        $scpnm = "$($newVM.Name.Split('-')[1,0] -Join '-') Scope" #"AF-MECM Scope"
                        Invoke-Command -Session $ts -ScriptBlock {
                            Add-DhcpServerv4Scope -name $using:scpnm -StartRange 172.16.$using:id.10 -EndRange 172.16.$using:id.20 -SubnetMask 255.255.255.0 -State Active
                            Set-DhcpServerv4OptionValue -OptionID 3 -Value 172.16.$using:id.1 -ScopeID 172.16.$using:id.0 -ComputerName $using:newVM.Name
                            Get-DhcpServerv4Binding
                            Set-DhcpServerv4Binding -BindingState $True -InterfaceAlias "MDTPriv"
                            }
                            # To Set the Primary DNS & Secondary DNS use below command
                            # Set-DnsClientServerAddress -InterfaceIndex 4 -ServerAddresses ('4.2.2.2','8.8.8.8')
                            # Get-DnsClientServerAddress
                            # Get-NetIPAddress
                    # Add MDT Admin account
                        $adm = 'MDT_Admin'  # 'MCEM_Admin' 
                        Invoke-Command -Session $ts -ScriptBlock {
                            New-LocalUser -Name $using:adm `
                                  -Description "$($using:adm -replace '_',' ') Account" `
                                  -Password (ConvertTo-SecureString -AsPlainText 'Password1234561!' -Force) `
                                  -AccountNeverExpires -UserMayNotChangePassword
                            Get-LocalUser -Name $using:adm | Add-LocalGroupMember -Group Administrators -Confirm:$false
                            }
                    # Create Format Data drive
                        If ($newVM.Set -eq 'CFG'){ $vol = "MECM Data Drive" }
                        Else { $vol = "DeploymentShares" }
                    
                        Invoke-Command -Session $ts -ScriptBlock {
                            Get-Disk | Where-Object PartitionStyle -eq 'raw' | 
                                Initialize-Disk -PartitionStyle GPT -PassThru |
                                New-Partition -UseMaximumSize -DriveLetter E <# -AssignDriveLetter#> | 
                                Format-Volume -FileSystem NTFS -NewFileSystemLabel $using:vol
                            }
                
                    # Set Timezone
                        Invoke-Command -Session $ts -ScriptBlock { Set-TimeZone -Id 'Eastern Standard Time' -Verbose }

                    # Set PS as default console (Server core)
                        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'PowerShell.exe -NoExit'

                    Checkpoint-VM -Name $newVM.Name -SnapshotName "$($newVM.Set) Pre-Config Complete"
                #endregion


                #region - Role Configuration
                    # Swap Dvds to run MECM install
                        Set-VMDvdDrive -VMName $newVM.Name -Path "$isoRoot\MDT_PSD_Tools.iso"

                    # MDT Install Scriptblock
                        $instADK = {
                            # Swap Dvds to install ADK & MDT components (Server ONLY)
                                Set-VMDvdDrive -VMName $newVM.Name -Path $newVM.iso2

                            $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds
                            # Install ADK
                                # Invoke-Command -Session $ts -ScriptBlock { D:\adksetup.exe /q }
                                # Invoke-Command -Session $ts -ScriptBlock { D:\adkwinpesetup.exe /q }
                                Invoke-Command -Session $ts -ScriptBlock { D:\MicrosoftDeploymentToolkit_x64.msi /passive /forcerestart }
                                Invoke-Command -Session $ts -ScriptBlock {
                                    $pex86 = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment"
                                    $pex86
                                    If ((Test-path ($pex86+'\x86\WinPE_OCs')) -eq $false){ xcopy "$pex86\amd64" "$pex86\x86" /E /H /C /I }
                                    }
                            Checkpoint-VM -Name $newVM.Name -SnapshotName 'MDT Components Installed'
                            }


                    $instEdge = ':\Microsoft Edge 125.0.2535.51\MicrosoftEdgeEnterpriseX64_2024-05-20.msi'
                    Switch ($newVM.Name)
                    {
                        {$_ -Match 'MECM$'}
                        {
                            # Image Corrections
                                Invoke-Command -VMName $newVM.Name -Credential $admCreds -ScriptBlock {
                                    If (!(Test-path c:\temp -PathType Container)){ New-Item C:\Temp -ItemType Directory }
                                    $dvd = (Get-Volume | Where FileSystemLabel -eq 'MDT_PSD_Tools').DriveLetter
                                    $install = "$dvd$using:instEdge"
                                    Start-Process -FilePath $install -ArgumentList '/passive' -Wait
                                    }
                        
                            # Swap Dvds to run MECM install
                                Set-VMDvdDrive -VMName $newVM.Name -Path "$isoRoot\SCCM Installer.iso"
                                Expand-Archive -Path "D:\MCM_Configmgr_2403.exe" -DestinationPath U:\MecmInst
                                # Manually install SDC as admin.
                                #Install (Defaults)
                            #region - Apps & Drivers
                                # Connect Driver|App Volume
                                    Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3 -Path $vhdRoot\Driver_Apps.vhdx
                                    $mdtDrvrs = Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Disk | Where OperationalStatus -eq 'Offline').number
                                        Set-Disk $dsk -IsOffline $false 
                                        Set-Disk $dsk -IsReadOnly 1
                                        Return (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter
                                        }
                    
                                # Add required Apps & Drivers

                                # Disconnect Driver|App Volume
                                    Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Partition -DriveLetter (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter | Get-Disk).Number
                                        Set-Disk $dsk -IsOffline $true
                                        }
                                    Remove-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3
                            #endregion

                            Checkpoint-VM -Name $newVM.Name -SnapshotName 'MS Edge & SDC Components Installed (MDT Version), C-Temp added'
                        }
                        {$_ -Match 'SDC$'}
                        {
                            & $instADK
                             # INSTALL ADK, ADKPE & MDT
                            # Swap Dvds to run SDC install
                                Set-VMDvdDrive -VMName $newVM.Name -Path "$isoRoot\Media-SDC-11.2209-X64-Deploy.iso"
                            # Manually install SDC as admin.
                                #Install (Defaults)
                                # Image Corrections
                                    Invoke-Command -VMName $newVM.Name -Credential $admCreds -ScriptBlock {
                                        If (!(Test-path c:\temp -PathType Container)){ New-Item C:\Temp -ItemType Directory }
                                        attrib /R C:\SDC\*.* /S /D
                                        If (!(Test-path C:\SDC\112209\ExtraFilesMedia -PathType Container)){ New-Item C:\SDC\112209\ExtraFilesMedia -ItemType Directory }
                                        $dvd = (Get-Volume | Where FileSystemLabel -eq 'MDT_PSD_Tools').DriveLetter
                                        $install = "$dvd$using:instEdge"
                                        Start-Process -FilePath $install -ArgumentList '/passive' -Wait
                                        }
                            #region - Apps & Drivers
                                # Connect Driver|App Volume
                                    Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3 -Path $vhdRoot\Driver_Apps.vhdx
                                    $mdtDrvrs = Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Disk | Where OperationalStatus -eq 'Offline').number
                                        Set-Disk $dsk -IsOffline $false 
                                        Set-Disk $dsk -IsReadOnly 1
                                        Return (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter
                                        }
                    
                                # Add required Apps & Drivers

                                # Disconnect Driver|App Volume
                                    Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Partition -DriveLetter (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter | Get-Disk).Number
                                        Set-Disk $dsk -IsOffline $true
                                        }
                                    Remove-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3
                            #endregion

                            Checkpoint-VM -Name $newVM.Name -SnapshotName 'MS Edge & SDC Components Installed (MDT Version), C-Temp added'
                        }
                        {$_ -Match 'SHB$'}
                        {
                            & $instADK
                            # Image Corrections
                                Invoke-Command -VMName $newVM.Name -Credential $admCreds -ScriptBlock {
                                    If (!(Test-path c:\temp -PathType Container)){ New-Item C:\Temp -ItemType Directory }
                                    $dvd = (Get-Volume | Where FileSystemLabel -eq 'MDT_PSD_Tools').DriveLetter
                                    $install = "$dvd$using:instEdge"
                                    Start-Process -FilePath $install -ArgumentList '/passive' -Wait
                                    }
                            #region - Install SHB
                                # Connect MDT_Solution Volume
                                    Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 4 -Path $vhdRoot\MDT_Solutions.vhdx
                                    Invoke-Command -VMName $newVM.Name -Credential $admCreds -ScriptBlock {
                                        $dsk = (Get-Disk | Where OperationalStatus -eq 'Offline').number
                                        Set-Disk $dsk -IsOffline $false 
                                        Set-Disk $dsk -IsReadOnly 1
                                        Return (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter
                                        }
                    
                                # Manually install SHB as admin.
                                    # Install Win11 Framework (Defaults)
                                        Checkpoint-VM -Name $newVM.Name -SnapshotName 'SHB Framework Installed'
                                    # Install Win11 DepShare (Install on C:\SHB\DeploymentShare)
                                        Restart-Computer -ComputerName $newVM.Name -Credential $admCreds -Force -ThrottleLimit 10
                                        Checkpoint-VM -Name $newVM.Name -SnapshotName 'SHB Win11 Deployment Share Installed'
                                    # Install Win11 DepShare Updates
                                    Checkpoint-VM -Name $newVM.Name -SnapshotName 'SHB Win11 Deployment Share Updated'

                                # Disconnect Driver|App Volume
                                    Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Partition -DriveLetter (Get-Volume | Where FileSystemLabel -eq 'MDT Solutions').DriveLetter | Get-Disk).Number
                                        Set-Disk $dsk -IsOffline $true
                                        }
                                    Remove-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 4
                            #endregion

                            #region - Apps & Drivers
                                # Connect Driver|App Volume
                                    Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3 -Path $vhdRoot\Driver_Apps.vhdx
                                    $mdtDrvrs = Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Disk | Where OperationalStatus -eq 'Offline').number
                                        Set-Disk $dsk -IsOffline $false 
                                        Set-Disk $dsk -IsReadOnly 1
                                        Return (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter
                                        }
                    
                                # Add required Apps & Drivers

                                # Disconnect Driver|App Volume
                                    Invoke-Command -Session $ts -ScriptBlock {
                                        $dsk = (Get-Partition -DriveLetter (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter | Get-Disk).Number
                                        Set-Disk $dsk -IsOffline $true
                                        }
                                    Remove-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3
                            #endregion

                            Checkpoint-VM -Name $newVM.Name -SnapshotName 'MS Edge & SHB Components Installed (MDT Version), C-Temp added'
                        }
                        {$_ -Match 'PSD$'}
                        {
                            & $instADK
                            # Swap Dvds to run SHB install
                                Set-VMDvdDrive -VMName $newVM.Name -Path "$isoRoot\Media-SDC-11.2209-X64-Deploy.iso"
                            # Manually install SDC as admin.
                                #Install (Defaults)
                                # Image Corrections
                                $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds
                                Invoke-Command -Session $ts -ScriptBlock {
                                    If (!(Test-path c:\temp -PathType Container)){ New-Item C:\Temp -ItemType Directory }
                                    attrib /R C:\SDC\*.* /S /D
                                    New-Item C:\SDC\112209\ExtraFilesMedia -ItemType Directory
                                    }
                            # Connect Driver|App Volume
                                Add-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3 -Path $vhdRoot\Driver_Apps.vhdx
                                $mdtDrvrs = Invoke-Command -Session $ts -ScriptBlock {
                                    $dsk = (Get-Disk | Where OperationalStatus -eq 'Offline').number
                                    Set-Disk $dsk -IsOffline $false 
                                    Set-Disk $dsk -IsReadOnly 1
                                    Return (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter
                                    }
                            # Disconnect Driver|App Volume
                                Invoke-Command -Session $ts -ScriptBlock {
                                    $dsk = (Get-Partition -DriveLetter (Get-Volume | Where FileSystemLabel -eq 'MDT Driver Volume').DriveLetter | Get-Disk).Number
                                    Set-Disk $dsk -IsOffline $true
                                    }
                                Remove-VMHardDiskDrive -VMName $newVM.Name -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 3

                            Checkpoint-VM -Name $newVM.Name -SnapshotName 'MS Edge & PSD Components Installed (MDT Extension), C-Temp added'
                        }
                        }
                #endregion
            #endregion
            #region - NAT?
                #NO OTHER SWITCHES BEFORE INSTALL?
                New-VMSwitch -SwitchName "NatTest" -SwitchType Internal
                $idx = (Get-NetAdapter | Where Name -match "NatTest").ifIndex
                New-NetIPAddress -IPAddress 192.168.122.1 -PrefixLength 24 -InterfaceIndex $idx
                New-NetNat -Name MyNATnetwork -InternalIPInterfaceAddressPrefix 192.168.122.0/24
                # Get-NetNat | Remove-NetNat
                # Remove-NetIPAddress -InterfaceAlias "vEthernet (NatVSwitch)" -IPAddress 172.16.122.1
                # Remove-NetIPAddress -InterfaceAlias "vEthernet (SwitchName)" -IPAddress 192.168.0.1
                # remove-vmswitch -SwitchName "SwitchName" -Force -Confirm:$false
                # Get-NetNatExternalAddress | Select ExternalAddressID,IPAddress
                # (6,7,14,15,16,17) | %{ Remove-NetNatExternalAddress -ExternalAddressID $_ -Confirm:$false }
            #endregion
            #region - Client
                New-VM -Name $newVMC.Name -NewVHDPath $newVMC.hdd1 -NewVHDSizeBytes ($newVMC.sz1 /1) -Generation $newVMC.Gen -Path $newVMC.Path

                Set-VM -Name $newVMC.Name `
                       -ProcessorCount $newVMC.Proc `
                       -StaticMemory -MemoryStartupBytes ($newVMC.ram /1) -Notes ((Dec64 $newVMC.notes) -replace '`n',[environment]::NewLine)


                Get-VM $newVMC.Name | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $newVMC.net1
                # SHB
                Get-VMIntegrationService 'Guest Service Interface' -VMName $newVMC.Name | Enable-VMIntegrationService
                Set-VMNetworkAdapter -VMName $newVMC.Name -StaticMacAddress $newVMC.mac

                $vmCD = Add-VMDvdDrive -VMName $newVMC.Name -Path $newVMC.iso1 -Verbose
                Switch ($newVMC.Gen)
                {
                    1  { Set-VMBios -VMName $newVMC.Name -StartupOrder @("CD","IDE","LegacyNetworkAdapter","Floppy") -EnableNumLock }
                    2  { Set-VMFirmware $newVMC.Name -FirstBootDevice (Get-VMDvdDrive -VMName $newVMC.Name) -Verbose }
                }
            
                # Add-Content -Path $env:windir\System32\drivers\etc\hosts -Value "`n172.16.$($Using:newVM.snet).1`t$($Using:newVM.Name)" -Force
                "net use \\mdt-shb\shb-dep$ /user:mdt`nPassw0rd" | Clip

            #endregion
        #endregion
        #region - Snag LiteTouch ISO for testing on DeployTest VM
            $srcPath = Switch ($newVM.Name)
            {{$_ -Match 'SDC$'}{'C:\SDC\112209\Boot'}{$_ -Match 'SHB$'}{'C:\SHB\Deployment Share\Boot'}{$_ -Match 'PSD$'}{'UNK'}}

            $ts = New-PSSession -VMName $newVM.Name -Credential $admCreds
            Copy-Item -FromSession $ts -Path "c:\temp\Win11Ent_SecPol.inf" -Destination "c:\temp\Win11Ent_SecPol.inf" -Force
        #endregion
    
        #region - TS MDT
            #region - Configure NTFS Permissions for the MDT Build Lab deployment share
                $DeploymentShareNTFS = "C:\SHB\23H2-Win11"
                icacls $DeploymentShareNTFS /grant '"WSUS01\MDT":(OI)(CI)(RX)'
                icacls $DeploymentShareNTFS /grant '"Administrators":(OI)(CI)(F)'
                icacls $DeploymentShareNTFS /grant '"SYSTEM":(OI)(CI)(F)'
                icacls "$DeploymentShareNTFS\Captures" /grant '"WSUS01\MDT":(OI)(CI)(M)'
            #endregion
            #region - Capture Logs
                #region - Create TS Shares (Dep Shares as needed)
                    Invoke-Command -VMName $newVM.Name -Credential $admCreds -ScriptBlock {
                        $drvLogs = If (!(Test-Path 'E:\Logs' -PathType Container)){ New-Item -Path 'E:\Logs' -ItemType Directory }
                        New-SmbShare -Path $drvLogs -Name TS-Logs -FullAccess 'Everyone' -Description 'MDT Troubleshooting Logs'
                        # Remove-SmbShare -Name TS-Logs -Force -Confirm:$false
                        Get-SmbShare
                        }
                #endregion
                "Net Use B: \\$($newVM.Name)\TS-Logs /user:$($newVM.Name)\MDT`nPassword1234561!" | Clip
                "Net Use Z: \\$($newVM.Name)\SHB-DEP$ /user:$($newVM.Name)\MDT`nPassword1234561!" | Clip
                "Net Use Z: \\$($newVM.Name)\SHB-DEP$ /user:$($newVM.Name)\MDT`nPassw0rd" | Clip


                "cd %temp%`n`nXcopy %temp% B:\Logs-Temp-03 /E /H /C /I`nXcopy C:\MININT\SMSOSD\OSDLOGS B:\Logs-Fail-03 /E /H /C'" | Clip
            #endregion
            #region - Import PS Commands
                Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1" -Verbose
                Get-Command -Module MicrosoftDeploymentToolkit
            #endregion
            #region - Fix ips and passwords in ini files (Config & bootstrap) at deployment and media level
                $pwd = 'Password1234561!'
                $ip = $rgxIP = '(?<![\d.])(?:(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])\.){3}(?:[1-9]?\d|1\d\d|2[0-4]\d|25[0-5])(?![\d.])'
                #$ip = (Get-NetIPAddress | ogv -PassThru).IPAddress #-InterfaceIndex (Get-NetAdapter -Name *shbnet*).ifIndex or gwmi win32_networkadapter | ? NetEnabled
                $Files = @("$depShare\Control\Bootstrap.ini","$depMedia\Content\Deploy\Control\Bootstrap.ini",
                           "$depShare\Control\CustomSettings.ini","$depMedia\Content\Deploy\Control\CustomSettings.ini")
                ForEach ($file in $Files)
                {
                    (GC $file) -replace $ip,$env:ComputerName `
                               -replace 'Central Standard Time','Eastern Standard Time' `
                               -replace 'UserPassword=\S+',"UserPassword=$pwd" `
                               -replace '%HOSTIP%','%HOSTNAME%' | SC $file
                }
            #endregion
            Get-LocalUser -Name MDT | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $pwd -Force) -Confirm:$false -Verbose
        #endregion
        #region - Build Reference Image Add-ons
            Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
            #region - Apps
                New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root "$depShare"
                #region - ADOBE
                    Import-MDTApplication -path "DS001:\Applications\Adobe" `
                                          -enable "True" -Name "Adobe Acrobat Reader DC 23.6.20320.0" `
                                          -ShortName "Acrobat Reader DC" -Version "23.6.20320.0" `
                                          -Publisher "Adobe" -Language "" `
                                          -CommandLine "AcroRdrDC2300620320_en_US.exe /qPB" `
                                          -WorkingDirectory ".\Applications\Adobe Acrobat Reader DC 23.6.20320.0" `
                                          -ApplicationSourcePath "C:\SHB_Mods\Applications\Adobe Acrobat Reader DC 23.6.20320.0" `
                                          -DestinationFolder "Adobe Acrobat Reader DC 23.6.20320.0" -Verbose
                #endregion
                #region - BROWSERS
                    Import-MDTApplication -path "DS001:\Applications\Browsers" `
                                          -enable "True" -Name "Google Chrome 125.0.6407.0" `
                                          -ShortName "Chrome" -Version "125.0.6407.0" `
                                          -Publisher "Google" -Language "" `
                                          -CommandLine "chrome_installer_2024-05-20.exe /silent /install" `
                                          -WorkingDirectory ".\Applications\Google Chrome 125.0.6407.0" `
                                          -ApplicationSourcePath "C:\SHB_Mods\Applications\Google Chrome 125.0.6407.0" `
                                          -DestinationFolder "Google Chrome 125.0.6407.0" -Verbose
                    Import-MDTApplication -path "DS001:\Applications\Browsers" `
                                          -enable "True" -Name "Mozilla Firefox 126.0" `
                                          -ShortName "Firefox" -Version "126.0" `
                                          -Publisher "Mozilla" -Language "" `
                                          -CommandLine "FirefoxSetup_2024-05-20.exe -ms" `
                                          -WorkingDirectory ".\Applications\Mozilla Firefox 126.0" `
                                          -ApplicationSourcePath "C:\SHB_Mods\Applications\Mozilla Firefox 126.0" `
                                          -DestinationFolder "Mozilla Firefox 126.0" -Verbose
                #endregion
                #region - #Microsoft
                    Import-MDTApplication -path "DS001:\Applications\Microsoft" `
                                          -enable "True" -Name "Microsoft Edge 125.0.2535.51" `
                                          -ShortName "Edge" -Version "125.0.2535.51" `
                                          -Publisher "Microsoft" -Language "" `
                                          -CommandLine "MicrosoftEdgeEnterpriseX64_2024-05-20.msi /passive" `
                                          -WorkingDirectory ".\Applications\Microsoft Edge 125.0.2535.51" `
                                          -ApplicationSourcePath "C:\SHB_Mods\Applications\Microsoft Edge 125.0.2535.51" `
                                          -DestinationFolder "Microsoft Edge 125.0.2535.51" -Verbose
                    Import-MDTApplication -path "DS001:\Applications\Microsoft" `
                                          -enable "True" -Name "Microsoft Office 2019 - 2024-05" `
                                          -ShortName "Office 2019" -Version "2024-05" `
                                          -Publisher "Microsoft" -Language "" `
                                          -CommandLine "setup.exe /Configure Office2019_32_2024-05-21.xml" `
                                          -WorkingDirectory ".\Applications\Microsoft Office 2019 - 2024-05" `
                                          -ApplicationSourcePath "C:\SHB_Mods\Applications\Microsoft Office 2019 - 2024-05" `
                                          -DestinationFolder "Microsoft Office 2019 - 2024-05" -Verbose
                #endregion
            #endregion
            #region - Import Drivers
                New-PSDrive -Name "DS002" -PSProvider MDTProvider -Root "$depShare"
                Import-MDTDriver -path "DS002:\Out-of-Box Drivers\Dell 7420"   -SourcePath "C:\SHB_Mods\Drivers 7420"   -Verbose
                Import-MDTDriver -path "DS002:\Out-of-Box Drivers\Dell 7920"   -SourcePath "C:\SHB_Mods\Drivers 7920"   -Verbose
                Import-MDTDriver -path "DS002:\Out-of-Box Drivers\Dell R740xd" -SourcePath "C:\SHB_Mods\Drivers R740xd" -Verbose
                Import-MDTDriver -path "DS002:\Out-of-Box Drivers\Dell R930"   -SourcePath "C:\SHB_Mods\Drivers R930"   -Verbose
            #endregion
            #region - Import Source|Custom Image
                New-PSDrive -Name "DS003" -PSProvider MDTProvider -Root "$depShare"
                $dest = @('Custom','Source')
                $trg = $dest[-1]
                # From WIM
                Import-MDTOperatingSystem -path "DS003:\Operating Systems\$trg" -SourceFile "C:\SHB\Captures\Automated\SHB_REF_2024-6-11_1004.wim" -DestinationFolder "SHB_REF_2024-6-11_1004" -Verbose
                # From ISO
                Import-MDTOperatingSystem -path "DS003:\Operating Systems\$trg" -SourcePath "D:\" -DestinationFolder "Windows 11 Enterprise Evaluation x64" -Verbose
            #endregion
            #region - Task Seq For Ref Build Capture
                New-PSDrive -Name "DS004" -PSProvider MDTProvider -Root "C:\SHB\Deployment Share"
                Import-MDTTaskSequence -path "DS004:\Task Sequences\Windows 11\Reference Build" `
                                       -Name "Capture Windows 11 Image" -Template "CaptureOnly.xml" `
                                       -Comments "Capture Updated Refence Images" -ID "Win11Capture" -Version "1.0" `
                                       -OperatingSystemPath "DS001:\Operating Systems\Source\Windows 11 Enterprise in Windows 11 Enterprise x64 install.wim" `
                                       -FullName "DoD User" -OrgName "Department of Defense" -HomePage "about:blank" -Verbose
                $tmpBini = (GC $vars.INIs[0])
                $tmpCini = (GC $vars.INIs[1])
                If ($Cap)
                { $tmpCini = $tmpCini -replace "SkipCapture=YES",('SkipCapture=NO' + [Environment]::NewLine +'OSCapture=YES') }
                Else { $tmpCini = $tmpCini -replace "OSCapture=YES" -replace 'SkipCapture=NO',"SkipCapture=YES" }
                                   $tmpCini -match ($([char]10) + 'OSCapture=YES')
                $tmpCini | SC $vars.INIs[1]
           
            #region - Update Dep Share
                New-PSDrive -Name "DS005" -PSProvider MDTProvider -Root $vars.depShare
                Update-MDTDeploymentShare -path "DS005:" -Verbose


            sl $vars.depShare
                        Update-MDTDeploymentShare
            "$($vars.depShare)"
                    #endregion
            'SkipBitLocker=YES 
            SkipCapture=NO
            OSCapture=YES 
            Sk'.ToCharArray() | %{ [int][Char]$_ } "$([char]10)"
            SkipCapture=YES 
            SkipCapture=YES 
            SkipCapture=YES 

         
        #endregion

        #region - Remove Un-needed Win Apps
            #News app
            Get-AppxPackage *BingNews* | Remove-AppxPackage
            #Weather
            Get-AppxPackage *BingWeather* | Remove-AppxPackage
            #PowerShell
            Get-AppxPackage *PowerShell* | Remove-AppxPackage
            #Music app
            Get-AppxPackage *ZuneMusic* | Remove-AppxPackage
            #Movies and TV
            Get-AppxPackage *ZuneVideo* | Remove-AppxPackage
            #MS Office
            Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage
            #People app
            Get-AppxPackage *People* | Remove-AppxPackage
            #Maps
            Get-AppxPackage *WindowsMaps* | Remove-AppxPackage
            #Help and tips
            Get-AppxPackage *GetHelp* | Remove-AppxPackage
            #Voice Recorder
            Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage
            #Sticky Notes
            Get-AppxPackage *MicrosoftStickyNotes* | Remove-AppxPackage
            #PowerAutomate
            Get-AppxPackage *PowerAutomateDesktop* | Remove-AppxPackage
            #Xbox and related apps
            Get-AppxPackage *Xbox* | Remove-AppxPackage
            #Feedback Hub
            Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage
            #Microsoft To-Do
            Get-AppxPackage *Todos* | Remove-AppxPackage
            #Calculator
            Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage
            #Alarms and Clocks
            Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage
            #Teams/Chat
            Get-AppxPackage *Teams* | Remove-AppxPackage
            #Your Phone
            Get-AppxPackage *YourPhone* | Remove-AppxPackage
            #Spotify
            Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage
            #Screen & Sketch/Snipping tool
            Get-AppxPackage *ScreenSketch* | Remove-AppxPackage
            #Solitaire Collection
            Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage
            #Photos
            Get-AppxPackage *Windows.Photos* | Remove-AppxPackage
            #OneDrive
            Get-AppxPackage *OneDriveSync* | Remove-AppxPackage
            #Skype
            Get-AppxPackage *SkypeApp* | Remove-AppxPackage
            #Xbox Console Companion
            Get-AppxPackage *GamingApp* | Remove-AppxPackage



            Import-Module Appx
            Import-Module Dism
            Get-AppxPackage -AllUsers | Where PublisherId -eq 8wekyb3d8bbwe | Format-List -Property PackageFullName,PackageUserInformation
        #endregion

        #region - Offline Media
            New-PSDrive -Name "DS010" -PSProvider MDTProvider -Root "C:\SHB\Deployment Share"
            New-Item -path "DS010:\Selection Profiles" -enable "True" `
                     -Name "Offline Win11 SHB" -Comments "Offline Install SHB media" `
                     -Definition "<SelectionProfile><Include path=`"Applications\DoD Secure Host Baseline\SHB Core Required\SHB Core Application Bundles`" /><Include path=`"Applications\Browsers`" /><Include path=`"Applications\Microsoft`" /><Include path=`"Applications\Adobe`" /><Include path=`"Operating Systems\Custom\SHB`" /><Include path=`"Out-of-Box Drivers\PE (x64)`" /><Include path=`"Out-of-Box Drivers\Dell 7920`" /><Include path=`"Task Sequences`" /></SelectionProfile>" `
                     -ReadOnly "False" -Verbose

            New-Item -path "DS010:\Media" -enable "True" -Name "MEDIA001" `
                     -Comments "Offline Media for SHB Install" -Root "C:\SHB\Media\Offline SHB" `
                     -SelectionProfile "Offline Win11 SHB" -SupportX86 "False" -SupportX64 "True" `
                     -GenerateISO "True" -ISOName "Win11_SHB.iso" -Verbose
            New-PSDrive -Name "MEDIA001" -PSProvider "MDTProvider" `
                        -Root "C:\SHB\Media\Offline SHB\Content\Deploy" `
                        -Description "Embedded media deployment share" -Force -Verbose
            New-PSDrive -Name "MEDIA002" -PSProvider FileSystem `
                        -Root "C:\SHB\Media\Offline SHB\Content\Deploy" `
                        -Description "Embedded media deployment share" -Force -Verbose
            (GCI "$($vars.depShare)\Control" -filter CustomSettings.ini) | %{ Copy-Item $_.FullName -Destination MEDIA002:\Control }
        #endregion}
        #region - WIN 11 Config Stepss
            # BY Shield
              $WScriptShell = New-Object -ComObject WScript.Shell
              $ShortcutFile = [Environment]::GetFolderPath('CommonDesktopDirectory') + "\Restore Icons (Restart Explorer).lnk"
              $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
              $Shortcut.TargetPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
              $Shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -Command "& {Stop-Process -Name explorer -Force}"'
              $Shortcut.IconLocation = 'C:\Windows\System32\user32.dll,6'
              $Shortcut.Save()
            # RD Manage
                $WScriptShell = New-Object -ComObject WScript.Shell
                $ShortcutFile = [Environment]::GetFolderPath('CommonDesktopDirectory') + "\Remote Admin.lnk"
                $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
                $Shortcut.TargetPath = 'C:\Windows\System32\RDCMan.exe'
                $Shortcut.Save()
                $bytes = [System.IO.File]::ReadAllBytes($ShortcutFile )
                $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
                [System.IO.File]::WriteAllBytes($ShortcutFile , $bytes)
            # Install Fonts
                #set font source location
                    $FontFolder = "C:\Users\adminCM\Downloads\Build Files\Fonts"
                    $FontItem = Get-Item -Path $FontFolder

                #go through all folders in source and list all fon, otf, ttc and ttf files
                    $FontList = Get-ChildItem -Path "$FontItem\*" -Include ('*.fon','*.otf','*.ttc','*.ttf') -Recurse

                foreach ($Font in $FontList) {
                    Write-Host 'Installing font -' $Font.BaseName
                    Copy-Item $Font -Destination ([Environment]::GetFolderPath('Fonts'))

                    #register font for all users
                    New-ItemProperty -Name $Font.BaseName -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Fonts" -PropertyType string -Value $Font.name
                }


        #endregion
    #endregion
        $skip_tpm_cmd = ($(Dec64 "QChzZXQgJyg9KXx8JyA8IyBsZWFuIGFuZCBtZWFuIGNtZCAvIHBvd2Vyc2hlbGwgaHlicmlkICM+QCcNCg0KOjojIEdldCAxMSBvbiAndW5zdXBwb3J0ZWQnIFBDIHZpYSBXaW5kb3dzIFVwZGF0ZSBvciBtb3VudGVkIElTTy
            Aobm8gcGF0Y2hpbmcgbmVlZGVkKQ0KOjojIGlmIFdVIGlzIHN0dWNrIHVzZSB3aW5kb3dzX3VwZGF0ZV9yZWZyZXNoLmJhdDsgQmV0YS9EZXYvQ2FuYXJ5IG5lZWRzIE9mZmxpbmVJbnNpZGVyRW5yb2xsDQo6OiMgVjEzOiBz
            a2lwIDJuZCB0cG0gY2hlY2sgb24gQ2FuYXJ5IGlzbzsgbm8gU2VydmVyIGxhYmVsOyBmdXR1cmUgcHJvb2Zpbmc7IHRlc3RlZCB3aXRoIDI2MDEwIGlzbywgd3UgYW5kIHd1IHJlcGFpciB2ZXJzaW9uDQo=") + "`n`n" + `

            $(Dec64 "QGVjaG8gb2ZmICYgdGl0bGUgZ2V0IDExIG9uICd1bnN1cHBvcnRlZCcgUEMgfHwgQXZlWW8gMjAyMy4xMi4wNw0KaWYgL2kgIiV+ZjAiIG5lcSAiJVN5c3RlbURyaXZlJVxTY3JpcHRzXGdldDExLmNtZCIgZ290byBzZXR1cA
            0KcG93ZXJzaGVsbCAtd2luIDEgLW5vcCAtYyAiOyINCnNldCBDTEk9JSomIHNldCBTT1VSQ0VTPSVTeXN0ZW1Ecml2ZSVcJFdJTkRPV1MufkJUXFNvdXJjZXMmIHNldCBNRURJQT0uJiBzZXQgTU9EPUNMSSYgc2V0IFBSRT1X
            VUEmIHNldCAvYSBWRVI9MTENCmlmIG5vdCBkZWZpbmVkIENMSSAoZXhpdCAvYikgZWxzZSBpZiBub3QgZXhpc3QgJVNPVVJDRVMlXFNldHVwSG9zdC5leGUgKGV4aXQgL2IpDQppZiBub3QgZXhpc3QgJVNPVVJDRVMlXFdpbm
            Rvd3NVcGRhdGVCb3guZXhlIG1rbGluayAvaCAlU09VUkNFUyVcV2luZG93c1VwZGF0ZUJveC5leGUgJVNPVVJDRVMlXFNldHVwSG9zdC5leGUNCnJlZyBhZGQgSEtMTVxTT0ZUV0FSRVxQb2xpY2llc1xNaWNyb3NvZnRcV2lu
            ZG93c1xXaW5kb3dzVXBkYXRlIC9mIC92IERpc2FibGVXVWZCU2FmZWd1YXJkcyAvZCAxIC90IHJlZ19kd29yZA0KcmVnIGFkZCBIS0xNXFNZU1RFTVxTZXR1cFxNb1NldHVwIC9mIC92IEFsbG93VXBncmFkZXNXaXRoVW5zdX
            Bwb3J0ZWRUUE1vckNQVSAvZCAxIC90IHJlZ19kd29yZA0Kc2V0IE9QVD0vQ29tcGF0IElnbm9yZVdhcm5pbmcgL01pZ3JhdGVEcml2ZXJzIEFsbCAvVGVsZW1ldHJ5IERpc2FibGUNCnNldCAvYSByZXN0YXJ0X2FwcGxpY2F0
            aW9uPTB4ODAwNzA1QkIgJiAoY2FsbCBzZXQgQ0xJPSUlQ0xJOiUxID0lJSkNCnNldCAvYSBpbmNvcnJlY3RfcGFyYW1ldGVyPTB4ODAwNzAwNTcgJiAoc2V0IFNSVj0lQ0xJOi9Qcm9kdWN0IENsaWVudCA9JSkNCnNldCAvYS
            BsYXVuY2hfb3B0aW9uX2Vycm9yPTB4YzE5MDAxMGEgJiAoc2V0IFNSVj0lU1JWOi9Qcm9kdWN0IFNlcnZlciA9JSkNCmZvciAlJVcgaW4gKCVDTEklKSBkbyBpZiAvaSAlJVcgPT0gL1ByZURvd25sb2FkIChzZXQgTU9EPVNS
            VikNCmZvciAlJVcgaW4gKCVDTEklKSBkbyBpZiAvaSAlJVcgPT0gL0luc3RhbGxGaWxlIChzZXQgUFJFPUlTTyYgc2V0ICJNRURJQT0iKSBlbHNlIGlmIG5vdCBkZWZpbmVkIE1FRElBIHNldCAiTUVESUE9JSV+ZHBXIg0KaW
            YgJVZFUiUgPT0gMTEgZm9yICUlVyBpbiAoIiVNRURJQSVhcHByYWlzZXJyZXMuZGxsIikgZG8gaWYgZXhpc3QgJSVXIGlmICUlfnpXID09IDAgc2V0IEFscmVhZHlQYXRjaGVkPTEgJiBzZXQgL2EgVkVSPTEwDQppZiAlVkVS
            JSA9PSAxMSBmaW5kc3RyIC9yICJQLnIuby5kLnUuYy50LlYuZS5yLnMuaS5vLm4uLi4xLjAuXC4uMC5cLi4yLlsyLTldIiAlU09VUkNFUyVcU2V0dXBIb3N0LmV4ZSA+bnVsIDI+bnVsIHx8IHNldCAvYSBWRVI9MTANCmlmIC
            VWRVIlID09IDExIGlmIG5vdCBleGlzdCAiJU1FRElBJUVJLmNmZyIgKGVjaG87W0NoYW5uZWxdPiVTT1VSQ0VTJVxFSS5jZmcgJiBlY2hvO19EZWZhdWx0Pj4lU09VUkNFUyVcRUkuY2ZnKQ0KaWYgJVZFUiVfJVBSRSUgPT0g
            MTFfSVNPICglU09VUkNFUyVcV2luZG93c1VwZGF0ZUJveC5leGUgL1Byb2R1Y3QgU2VydmVyIC9QcmVEb3dubG9hZCAvUXVpZXQgJU9QVCUpDQppZiAlVkVSJV8lUFJFJSA9PSAxMV9JU08gKGRlbCAvZiAvcSAlU09VUkNFUy
            VcYXBwcmFpc2VycmVzLmRsbCAyPm51bCAmIGNkLj4lU09VUkNFUyVcYXBwcmFpc2VycmVzLmRsbCAmIGNhbGwgOmNhbmFyeSkNCmlmICVWRVIlXyVNT0QlID09IDExX1NSViAoc2V0IEFSRz0lT1BUJSAlU1JWJSAvUHJvZHVj
            dCBTZXJ2ZXIpDQppZiAlVkVSJV8lTU9EJSA9PSAxMV9DTEkgKHNldCBBUkc9JU9QVCUgJUNMSSUpDQolU09VUkNFUyVcV2luZG93c1VwZGF0ZUJveC5leGUgJUFSRyUNCmlmICVlcnJvcmxldmVsJSA9PSAlcmVzdGFydF9hcH
            BsaWNhdGlvbiUgKGNhbGwgOmNhbmFyeSAmICVTT1VSQ0VTJVxXaW5kb3dzVXBkYXRlQm94LmV4ZSAlQVJHJSkNCmV4aXQgL2I=") + "`n`n" + `

            $(Dec64 "OmNhbmFyeSBpc28gc2tpcCAybmQgdHBtIGNoZWNrIGJ5IEF2ZVlvICANCnNldCBDPSAgJFg9JyVTT1VSQ0VTJVxod3JlcWNoay5kbGwnOyAkWT0nU1FfVHBtVmVyc2lvbiBHVEUgMSc7ICRaPSdTUV9UcG1WZXJzaW9uIEdURS
            AwJzsgaWYgKHRlc3QtcGF0aCAkWCkgeyANCnNldCBDPSVDJSAgdHJ5IHsgdGFrZW93bi5leGUgL2YgJFggL2E7IGljYWNscy5leGUgJFggL2dyYW50ICpTLTEtNS0zMi01NDQ6ZjsgYXR0cmliIC1SIC1TICRYOyBbaW8uZmls
            ZV06Ok9wZW5Xcml0ZSgkWCkuY2xvc2UoKSB9DQpzZXQgQz0lQyUgIGNhdGNoIHsgcmV0dXJuIH07ICRSPVtUZXh0LkVuY29kaW5nXTo6VVRGOC5HZXRCeXRlcygkWik7ICRsPSRSLkxlbmd0aDsgJGk9MjsgJHc9ITE7DQpzZX
            QgQz0lQyUgICRCPVtpby5maWxlXTo6UmVhZEFsbEJ5dGVzKCRYKTsgJEg9W0JpdENvbnZlcnRlcl06OlRvU3RyaW5nKCRCKSAtcmVwbGFjZSAnLSc7DQpzZXQgQz0lQyUgICRTPVtCaXRDb252ZXJ0ZXJdOjpUb1N0cmluZyhb
            VGV4dC5FbmNvZGluZ106OlVURjguR2V0Qnl0ZXMoJFkpKSAtcmVwbGFjZSAnLSc7DQpzZXQgQz0lQyUgIGRvIHsgJGk9JEguSW5kZXhPZigkUywgJGkgKyAyKTsgaWYgKCRpIC1ndCAwKSB7ICR3PSEwOyBmb3IgKCRrPTA7IC
            RrIC1sdCAkbDsgJGsrKykgeyAkQlskayArICRpIC8gMl09JFJbJGtdIH0gfSB9DQpzZXQgQz0lQyUgIHVudGlsICgkaSAtbHQgMSk7IGlmICgkdykgeyBbaW8uZmlsZV06OldyaXRlQWxsQnl0ZXMoJFgsICRCKTsgW0dDXTo6
            Q29sbGVjdCgpIH0gfQ0KaWYgJVZFUiVfJVBSRSUgPT0gMTFfSVNPIHBvd2Vyc2hlbGwgLW5vcCAtYyBpZXgoJGVudjpDKSA+bnVsIDI+bnVsDQpleGl0IC9i") + "`n`n" + `

            $(Dec64 "OnNldHVwDQo6OiMgZWxldmF0ZSB3aXRoIG5hdGl2ZSBzaGVsbCBieSBBdmVZbw0KPm51bCByZWcgYWRkIGhrY3Vcc29mdHdhcmVcY2xhc3Nlc1wuQWRtaW5cc2hlbGxccnVuYXNcY29tbWFuZCAvZiAvdmUgL2QgImNtZCAveC
            AvZCAvciBzZXQgXCJmMD0lJTJcIiYgY2FsbCBcIiUlMlwiICUlMyImIHNldCBfPSAlKg0KPm51bCBmbHRtY3x8IGlmICIlZjAlIiBuZXEgIiV+ZjAiIChjZC4+IiV0ZW1wJVxydW5hcy5BZG1pbiIgJiBzdGFydCAiJX5uMCIg
            L2hpZ2ggIiV0ZW1wJVxydW5hcy5BZG1pbiIgIiV+ZjAiICIlXzoiPSIiJSIgJiBleGl0IC9iKQ0KDQo6OiMgbGVhbiB4cCsgY29sb3IgbWFjcm9zIGJ5IEF2ZVlvOiAgJTwlOmFmICIgaGVsbG8gIiU+PiUgICYgICU8JTpjZi
            AiIHdcIm9yXCJsZCAiJT4lICAgZm9yIHNpbmdsZSBcIC8gIiB1c2UgLiV8JVwgIC4lfCUvICBcIiV8JVwiDQpmb3IgL2YgImRlbGltcz06IiAlJXMgaW4gKCdlY2hvO3Byb21wdCAkaCRzJGg6XnxjbWQgL2QnKSBkbyBzZXQg
            Inw9JSVzIiZzZXQgIj4+PVwuLlxjIG51bCZzZXQgL3Agcz0lJXMlJXMlJXMlJXMlJXMlJXMlJXM8bnVsJnBvcGQiDQpzZXQgIjw9cHVzaGQgIiVhcHBkYXRhJSImMj5udWwgZmluZHN0ciAvYzpcIC9hIiAmc2V0ICI+PSU+Pi
            UmZWNobzsiICZzZXQgInw9JXw6fjAsMSUiICZzZXQgL3Agcz1cPG51bD4iJWFwcGRhdGElXGMiDQoNCjo6IyB0b2dnbGUgd2hlbiBsYXVuY2hlZCB3aXRob3V0IGFyZ3VtZW50cywgZWxzZSBqdW1wIHRvIGFyZ3VtZW50czog
            Imluc3RhbGwiIG9yICJyZW1vdmUiDQpzZXQgQ0xJPSUqJiAoc2V0IElGRU89SEtMTVxTT0ZUV0FSRVxNaWNyb3NvZnRcV2luZG93cyBOVFxDdXJyZW50VmVyc2lvblxJbWFnZSBGaWxlIEV4ZWN1dGlvbiBPcHRpb25zKQ0Kd2
            1pYyAvbmFtZXNwYWNlOiJcXHJvb3Rcc3Vic2NyaXB0aW9uIiBwYXRoIF9fRXZlbnRGaWx0ZXIgd2hlcmUgTmFtZT0iU2tpcCBUUE0gQ2hlY2sgb24gRHluYW1pYyBVcGRhdGUiIGRlbGV0ZSA+bnVsIDI+bnVsICYgcmVtIHYx
            DQpyZWcgZGVsZXRlICIlSUZFTyVcdmRzbGRyLmV4ZSIgL2YgMj5udWwgJiByZW0gdjIgLSB2NQ0KaWYgL2kgIiVDTEklIj09IiIgcmVnIHF1ZXJ5ICIlSUZFTyVcU2V0dXBIb3N0LmV4ZVwwIiAvdiBEZWJ1Z2dlciA+bnVsID
            I+bnVsICYmIGdvdG8gcmVtb3ZlIHx8IGdvdG8gaW5zdGFsbA0KaWYgL2kgIiV+MSI9PSJpbnN0YWxsIiAoZ290byBpbnN0YWxsKSBlbHNlIGlmIC9pICIlfjEiPT0icmVtb3ZlIiBnb3RvIHJlbW92ZQ==") + "`n`n" + `

            $(Dec64 "Omluc3RhbGwNCm1rZGlyICVTeXN0ZW1Ecml2ZSVcU2NyaXB0cyA+bnVsIDI+bnVsICYgY29weSAveSAiJX5mMCIgIiVTeXN0ZW1Ecml2ZSVcU2NyaXB0c1xnZXQxMS5jbWQiID5udWwgMj5udWwNCnJlZyBhZGQgIiVJRkVPJV
            xTZXR1cEhvc3QuZXhlIiAvZiAvdiBVc2VGaWx0ZXIgL2QgMSAvdCByZWdfZHdvcmQgPm51bA0KcmVnIGFkZCAiJUlGRU8lXFNldHVwSG9zdC5leGVcMCIgL2YgL3YgRmlsdGVyRnVsbFBhdGggL2QgIiVTeXN0ZW1Ecml2ZSVc
            JFdJTkRPV1MufkJUXFNvdXJjZXNcU2V0dXBIb3N0LmV4ZSIgPm51bA0KcmVnIGFkZCAiJUlGRU8lXFNldHVwSG9zdC5leGVcMCIgL2YgL3YgRGVidWdnZXIgL2QgIiVTeXN0ZW1Ecml2ZSVcU2NyaXB0c1xnZXQxMS5jbWQiID
            5udWwNCmVjaG87DQolPCU6ZjAgIiBTa2lwIFRQTSBDaGVjayBvbiBEeW5hbWljIFVwZGF0ZSBWMTMgIiU+PiUgJiAlPCU6MmYgIiBJTlNUQUxMRUQgIiU+PiUgJiAlPCU6ZjAgIiBydW4gYWdhaW4gdG8gcmVtb3ZlICIlPiUN
            CmlmIC9pICIlQ0xJJSI9PSIiIHRpbWVvdXQgL3QgNw0KZXhpdCAvYg==") + "`n`n" + `

            $(Dec64 "OnJlbW92ZQ0KZGVsIC9mIC9xICIlU3lzdGVtRHJpdmUlXFNjcmlwdHNcZ2V0MTEuY21kIiAiJVB1YmxpYyVcZ2V0MTEuY21kIiAiJVByb2dyYW1EYXRhJVxnZXQxMS5jbWQiID5udWwgMj5udWwNCnJlZyBkZWxldGUgIiVJRk
            VPJVxTZXR1cEhvc3QuZXhlIiAvZiA+bnVsIDI+bnVsDQplY2hvOw0KJTwlOmYwICIgU2tpcCBUUE0gQ2hlY2sgb24gRHluYW1pYyBVcGRhdGUgVjEzICIlPj4lICYgJTwlOmRmICIgUkVNT1ZFRCAiJT4+JSAmICU8JTpmMCAi
            IHJ1biBhZ2FpbiB0byBpbnN0YWxsICIlPiUNCmlmIC9pICIlQ0xJJSI9PSIiIHRpbWVvdXQgL3QgNw0KZXhpdCAvYg==") + "`n`n" + `

            $(Dec64 "DQonQCk7ICQwID0gIiRlbnY6dGVtcFxTa2lwX1RQTV9DaGVja19vbl9EeW5hbWljX1VwZGF0ZS5jbWQiOyAkeyg9KXx8fSAtc3BsaXQgIlxyP1xuIiB8IG91dC1maWxlICQwIC1lbmNvZGluZyBkZWZhdWx0IC1mb3JjZTsgJi
            AkMA0KDQojIHByZXNzIGVudGVy"))

        #region - MDT PS Build Lab Walkthru 
            #region Step 2 - Create the MDT Build Lab Deployment Share
                Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
                New-PSDrive -Name "DS001" -PSProvider "MDTProvider" -Root "C:\MDTBuildLab" -Description "MDT Build Lab" -NetworkPath "\\WSUS01\MDTBuildLab$" -Verbose | Add-MDTPersistentDrive -Verbose

                # Fix Permissions
                    #Requires -RunAsAdministrator

                    # Configure NTFS Permissions for the MDT Build Lab deployment share
                        $DeploymentShareNTFS = "C:\MDTBuildLab"
                        icacls $DeploymentShareNTFS /grant '"WSUS01\MDT":(OI)(CI)(RX)'
                        icacls $DeploymentShareNTFS /grant '"Administrators":(OI)(CI)(F)'
                        icacls $DeploymentShareNTFS /grant '"SYSTEM":(OI)(CI)(F)'
                        icacls "$DeploymentShareNTFS\Captures" /grant '"WSUS01\MDT":(OI)(CI)(M)'

                    # Configure Sharing Permissions for the MDT Build Lab deployment share
                        $DeploymentShare = "MDTBuildLab$"
                        Grant-SmbShareAccess -Name $DeploymentShare -AccountName "EVERYONE" -AccessRight Change -Force
                        Revoke-SmbShareAccess -Name $DeploymentShare -AccountName "CREATOR OWNER" -Force
            #endregion
            #region Step 3 - Import the Windows 10 operating system
                New-Item -path "DS001:\Operating Systems" -enable "True" -Name "Windows 11" -Comments "Windows 11 Enterprise x64 23H2" -ItemType "folder" -Verbose
                # Mount OS ISO
                    $iso = "C:\VirtualMachines\ISOs\Windows_11_23H2_ENT_x64_en-us_MDTFriendly.iso"
                    Mount-DiskImage -ImagePath $iso -PassThru
                    $drvLtr = (Get-DiskImage -ImagePath $iso | Get-Volume).DriveLetter

                # Import OS
                    Import-MDTOperatingSystem -path "DS001:\Operating Systems\Windows 11" -SourcePath "$drvLtr`:\" -DestinationFolder "REFW11X64-23H2" -Verbose
                    $rename = [xml](GC "C:\MDTBuildLab\Control\OperatingSystems.xml")
                    $rename.oss.OS.Name = 'Windows 11 Enterprise x64 23H2.wim'
                    $rename.Save("C:\MDTBuildLab\Control\OperatingSystems.xml")
            #endregion
            #region Step 4 - Add applications
                New-PSDrive -Name "DS003" -PSProvider MDTProvider -Root "C:\SHB\23H2-Win11"
                import-MDTApplication -path "DS003:\Applications\Titus" -enable "True" -Name "Titus Classification Tool 2019 SP1 18.8.2027.2" -ShortName "Classification Tool 2019 SP1" -Version "18.8.2027.2" -Publisher "Titus" -Language "" -CommandLine "TITUSClassificationSetup.exe /quiet" -WorkingDirectory ".\Applications\Titus Classification Tool 2019 SP1 18.8.2027.2" -ApplicationSourcePath "C:\Users\adminCM\Downloads\MDT_ADK_SHB Research\Build Files\TITUS Classification Suite 2019.1 SP1 HF5\TITUS Classification Clients 2019.1 SP1 HF5" -DestinationFolder "Titus Classification Tool 2019 SP1 18.8.2027.2" -Verbose
            #endregion
            #region Step 5 - Create and Configure the MDT Task Sequence
                Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
                New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root "C:\MDTBuildLab"
                new-item -path "DS001:\Task Sequences" -enable "True" -Name "Windows 10" -Comments "" -ItemType "folder" -Verbose

                Import-Module "C:\Program Files\Microsoft Deployment Toolkit\bin\MicrosoftDeploymentToolkit.psd1"
                New-PSDrive -Name "DS001" -PSProvider MDTProvider -Root "C:\MDTBuildLab"
                import-mdttasksequence -path "DS001:\Task Sequences\Windows 10" -Name "Windows 11 Enterprise x64 23H2" -Template "Client.xml" -Comments "Reference Build" -ID "REFW11-X64-001" -Version "1.0" -OperatingSystemPath "DS001:\Operating Systems\Windows 11\Windows 11 Enterprise x64 23H2.wim" -FullName "DoD User" -OrgName "Department of Defense" -HomePage "about:blank" -Verbose


                # Added TZ fix
                # Added Sysprep Fixes and new state.ini to scriptroot
                # Mods applied
            #endregion

            Add-VMNetworkAdapterAcl -VMName 'Deploy Test VM' -RemoteIPAddress 192.168.1.137 -Direction Both -Action Deny
            Add-VMNetworkAdapterAcl -VMName 'Deploy Test VM' -RemoteIPAddress 10.10.10.1 -Direction Both -Action Deny
            Get-VMNetworkAdapterAcl
            Remove-VMNetworkAdapterAcl -VMName 'Deploy Test VM' -RemoteIPAddress 192.168.1.137 -Direction Both -Action Deny
        #endregion
        #region - INI creation
            Import-Module PsIni
            $Category1 = @{"Key1"="Value1";"Key2"="Value2"}
            $Category2 = @{"Key1"="Value1";"Key2"="Value2"}
            $NewINIContent = [ordered]@{"Category1"=$Category1;"Category2"=$Category2}
            Out-IniFile -InputObject $NewINIContent -FilePath "C:\settings.ini" -Force
            gc "C:\settings.ini"

            $FileContent = Get-IniContent "C:\settings.ini"
            $FileContent["Category2"]["Key2"]
        #endregion
        #region - Fixes?
            #MDT Fixes:
            #C:\Program Files\Microsoft Deployment Toolkit\Templates\Unattend_PE_x64.xml
            '<unattend xmlns="urn:schemas-microsoft-com:unattend">
                <settings pass="windowsPE">
                    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
                        <Display>
                            <ColorDepth>32</ColorDepth>
                            <HorizontalResolution>1024</HorizontalResolution>
                            <RefreshRate>60</RefreshRate>
                            <VerticalResolution>768</VerticalResolution>
                        </Display>
                        <RunSynchronous>
                            <RunSynchronousCommand wcm:action="add">
                                <Description>Fix HTA scripts error Windows 11 ADK 22H2</Description>
                                <Order>1</Order>
                                <Path>reg.exe add "HKLM\Software\Microsoft\Internet Explorer\Main" /t REG_DWORD /v JscriptReplacement /d 0 /f</Path>
                            </RunSynchronousCommand>
                            <RunSynchronousCommand wcm:action="add">
                                <Description>Lite Touch PE</Description>
                                <Order>2</Order>
                                <Path>wscript.exe X:\Deploy\Scripts\LiteTouch.wsf</Path>
                            </RunSynchronousCommand>
                        </RunSynchronous>
                    </component>
                </settings>
            </unattend>
            '
        #endregion
    #endregion
    #region - Inject Drivers into WIN11 ISO
        function New-ISOFilev2
        {
            <#
            .SYNOPSIS
                Create an ISO file from a source folder.

            .DESCRIPTION
                Create an ISO file from a source folder.
                Optionally speicify a boot image and media type.

                Based on original function by Chris Wu.
                https://gallery.technet.microsoft.com/scriptcenter/New-ISOFile-function-a8deeffd (link appears to be no longer valid.)

                Changes:
                    - Updated to work with PowerShell 7
                    - Added a bit more error handling and verbose output.
                    - Features removed to simplify code:
                        * Clipboard support.
                        * Pipeline input.

            .PARAMETER source
                The source folder to add to the ISO.

            .PARAMETER destinationIso
                The ISO file to create.

            .PARAMETER bootFile
                Optional. Boot file to add to the ISO.

            .PARAMETER media
                Optional. The media type of the resulting ISO (BDR, CDR etc). Defaults to DVDPLUSRW_DUALLAYER.

            .PARAMETER title
                Optional. Title of the ISO file. Defaults to "untitled".

            .PARAMETER force
                Optional. Force overwrite of an existing ISO file.

            .INPUTS
                None.

            .OUTPUTS
                None.

            .EXAMPLE
                New-ISOFile -source c:\forIso\ -destinationIso C:\ISOs\testiso.iso

                Simple example. Create testiso.iso with the contents from c:\forIso

            .EXAMPLE
                New-ISOFile -source f:\ -destinationIso C:\ISOs\windowsServer2019Custom.iso -bootFile F:\efi\microsoft\boot\efisys.bin -title "Windows2019"

                Example building Windows media. Add the contents of f:\ to windowsServer2019Custom.iso. Use efisys.bin to make the disc bootable.

            .LINK

            .NOTES
                01           Alistair McNair          Initial version.

            #>
            [CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact="Low")]
            Param
            (
                [parameter(Mandatory=$true,ValueFromPipeline=$false)]
                [string]$source,
                [parameter(Mandatory=$true,ValueFromPipeline=$false)]
                [string]$destinationIso,
                [parameter(Mandatory=$false,ValueFromPipeline=$false)]
                [string]$bootFile = $null,
                [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
                [ValidateSet("CDR","CDRW","DVDRAM","DVDPLUSR","DVDPLUSRW","DVDPLUSR_DUALLAYER","DVDDASHR","DVDDASHRW","DVDDASHR_DUALLAYER","DISK","DVDPLUSRW_DUALLAYER","BDR","BDRE")]
                [string]$media = "DVDPLUSRW_DUALLAYER",
                [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
                [string]$title = "untitled",
                [Parameter(Mandatory=$false,ValueFromPipeline=$false)]
                [switch]$force
                )
            Begin
            {
                Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
                Write-Verbose ("Function start.")
            }
            Process
            {

                Write-Verbose ("Processing nested system " + $vmName)

                ## Set type definition
                Write-Verbose ("Adding ISOFile type.")

                $typeDefinition = (Dec64 'CnB1YmxpYyBjbGFzcyBJU09GaWxlICB7DQogICAgcHVibGljIHVuc2FmZSBzdGF0aWMgdm9pZCBDcmVhdGUoc3RyaW5nIFBhdGgsIG9iamVjdCBTdHJlYW0sIGludCBCbG9ja1NpemUsIGludCBUb3RhbEJsb2Nrcykgew0KICAgICAgICBpbnQgYnl0ZXMgPSAwOw0KICAgICAgICBieXRlW10gYnVmID0gbmV3IGJ5dGVbQmxvY2tTaXplXTsNCiAgICAgICAgdmFyIHB0ciA9IChTeXN0ZW0uSW50UHRyKSgmYnl0ZXMpOw0KICAgICAgICB2YXIgbyA9IFN5c3RlbS5JTy5GaWxlLk9wZW5Xcml0ZShQYXRoKTsNCiAgICAgICAgdmFyIGkgPSBTdHJlYW0gYXMgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLklTdHJlYW07DQoNCiAgICAgICAgaWYgKG8gIT0gbnVsbCkgew0KICAgICAgICAgICAgd2hpbGUgKFRvdGFsQmxvY2tzLS0gPiAwKSB7DQogICAgICAgICAgICAgICAgaS5SZWFkKGJ1ZiwgQmxvY2tTaXplLCBwdHIpOyBvLldyaXRlKGJ1ZiwgMCwgYnl0ZXMpOw0KICAgICAgICAgICAgfQ0KDQogICAgICAgICAgICBvLkZsdXNoKCk7IG8uQ2xvc2UoKTsNCiAgICAgICAgfQ0KICAgIH0NCn0K')

                ## Create type ISOFile, if not already created. Different actions depending on PowerShell version
                if (!('ISOFile' -as [type])) {

                    ## Add-Type works a little differently depending on PowerShell version.
                    ## https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type
                    switch ($PSVersionTable.PSVersion.Major) {

                        ## 7 and (hopefully) later versions
                        {$_ -ge 7} {
                            Write-Verbose ("Adding type for PowerShell 7 or later.")
                            Add-Type -CompilerOptions "/unsafe" -TypeDefinition $typeDefinition
                        } # PowerShell 7

                        ## 5, and only 5. We aren't interested in previous versions.
                        5 {
                            Write-Verbose ("Adding type for PowerShell 5.")
                            $compOpts = New-Object System.CodeDom.Compiler.CompilerParameters
                            $compOpts.CompilerOptions = "/unsafe"

                            Add-Type -CompilerParameters $compOpts -TypeDefinition $typeDefinition
                        } # PowerShell 5

                        default {
                            ## If it's not 7 or later, and it's not 5, then we aren't doing it.
                            throw ("Unsupported PowerShell version.")

                        } # default

                    } # switch

                } # if


                ## Add boot file to image
                if ($bootFile) {

                    Write-Verbose ("Optional boot file " + $bootFile + " has been specified.")

                    ## Display warning if Blu Ray media is used with a boot file.
                    ## Not sure why this doesn't work.
                    if(@('BDR','BDRE') -contains $media) {
                            Write-Warning ("Selected boot image may not work with BDR/BDRE media types.")
                    } # if

                    if (!(Test-Path -Path $bootFile)) {
                        throw ($bootFile + " is not valid.")
                    } # if

                    ## Set stream type to binary and load in boot file
                    Write-Verbose ("Loading boot file.")

                    try {
                        $stream = New-Object -ComObject ADODB.Stream -Property @{Type=1} -ErrorAction Stop
                        $stream.Open()
                        $stream.LoadFromFile((Get-Item -LiteralPath $bootFile).Fullname)

                        Write-Verbose ("Boot file loaded.")
                    } # try
                    catch {
                        throw ("Failed to open boot file. " + $_.exception.message)
                    } # catch


                    ## Apply the boot image
                    Write-Verbose ("Applying boot image.")

                    try {
                        $boot = New-Object -ComObject IMAPI2FS.BootOptions -ErrorAction Stop
                        $boot.AssignBootImage($stream)

                        Write-Verbose ("Boot image applied.")
                    } # try
                    catch {
                        throw ("Failed to apply boot file. " + $_.exception.message)
                    } # catch


                    Write-Verbose ("Boot file applied.")

                }  # if

                ## Build array of media types
                $mediaType = @(
                    "UNKNOWN",
                    "CDROM",
                    "CDR",
                    "CDRW",
                    "DVDROM",
                    "DVDRAM",
                    "DVDPLUSR",
                    "DVDPLUSRW",
                    "DVDPLUSR_DUALLAYER",
                    "DVDDASHR",
                    "DVDDASHRW",
                    "DVDDASHR_DUALLAYER",
                    "DISK",
                    "DVDPLUSRW_DUALLAYER",
                    "HDDVDROM",
                    "HDDVDR",
                    "HDDVDRAM",
                    "BDROM",
                    "BDR",
                    "BDRE"
                )

                Write-Verbose ("Selected media type is " + $media + " with value " + $mediaType.IndexOf($media))

                ## Initialise image
                Write-Verbose ("Initialising image object.")
                try {
                    $image = New-Object -ComObject IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$title} -ErrorAction Stop
                    $image.ChooseImageDefaultsForMediaType($mediaType.IndexOf($media))

                    Write-Verbose ("initialised.")
                } # try
                catch {
                    throw ("Failed to initialise image. " + $_.exception.Message)
                } # catch


                ## Create target ISO, throw if file exists and -force parameter is not used.
                if ($PSCmdlet.ShouldProcess($destinationIso)) {

                    if (!($targetFile = New-Item -Path $destinationIso -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) {
                        throw ("Cannot create file " + $destinationIso + ". Use -Force parameter to overwrite if the target file already exists.")
                    } # if

                } # if


                ## Get source content from specified path
                Write-Verbose ("Fetching items from source directory.")
                try {
                    $sourceItems = Get-ChildItem -LiteralPath $source -ErrorAction Stop
                    Write-Verbose ("Got source items.")
                } # try
                catch {
                    throw ("Failed to get source items. " + $_.exception.message)
                } # catch


                ## Add these to our image
                Write-Verbose ("Adding items to image.")

                foreach($sourceItem in $sourceItems) {

                    try {
                        $image.Root.AddTree($sourceItem.FullName, $true)
                    } # try
                    catch {
                        throw ("Failed to add " + $sourceItem.fullname + ". " + $_.exception.message)
                    } # catch

                } # foreach

                ## Add boot file, if specified
                if ($boot) {
                    Write-Verbose ("Adding boot image.")
                    $Image.BootImageOptions = $boot
                }

                ## Write out ISO file
                Write-Verbose ("Writing out ISO file to " + $targetFile)

                try {
                    $result = $image.CreateResultImage()
                    [ISOFile]::Create($targetFile.FullName,$result.ImageStream,$result.BlockSize,$result.TotalBlocks)
                } # try
                catch {
                    throw ("Failed to write ISO file. " + $_.exception.Message)
                } # catch

                Write-Verbose ("File complete.")

                ## Return file details
                return $targetFile

            }
            End { Write-Verbose ("Function complete.") }

        }
        Function Get-Source
        {
            Param ($initDir,[switch]$folder,$ext)
            $psPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            # Add-MpPreference -ControlledFolderAccessAllowedApplications $psPath
            # If ((Get-MpPreference).EnableControlledFolderAccess -ne 0 ){ $mp = $true; Set-MpPreference -EnableControlledFolderAccess Disabled }
            $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

            If ($folder.IsPresent)
            {
                # (Dec64 'ICAgICAgICAgICAgICAgICMgKCR0cmdJdGVtID0gTmV3LU9iamVjdCBTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Gb2xkZXJCcm93c2VyRGlhbG9nKS5yb290Zm9sZGVyID0gIk15Q29tcHV0ZXIiCiAgICAgICAgICAgICAgICAkbW9kYWxmb3JtID0gTmV3LU9iamVjdCBTeXN0ZW0uV2luZG93cy5Gb3Jtcy5Gb3JtDQogICAgICAgICAgICAgICAgJG1vZGFsZm9ybS5Ub3BNb3N0ID0gJHRydWUNCgogICAgICAgICAgICAgICAgJHRyZ0l0ZW0gPSBOZXctT2JqZWN0IFN5c3RlbS5XaW5kb3dzLkZvcm1zLkZvbGRlckJyb3dzZXJEaWFsb2cKICAgICAgICAgICAgICAgICR0cmdJdGVtLlJvb3RGb2xkZXIgPSBbU3lzdGVtLkVudmlyb25tZW50K1NwZWNpYWxGb2xkZXJdOjpNeUNvbXB1dGVyCiAgICAgICAgICAgICAgICAkdHJnSXRlbS5TZWxlY3RlZFBhdGggPSAkaW5pdERpciAKCiAgICAgICAgICAgICAgICBpZiAoJHRyZ0l0ZW0uU2hvd0RpYWxvZygkbW9kYWxmb3JtKSAtZXEgIk9LIikgeyAkZmxkZXIgKz0gW3N0cmluZ10kdHJnSXRlbS5TZWxlY3RlZFBhdGggfQo=')

                $trgItem = New-Object System.Windows.Forms.OpenFileDialog
                $trgItem.initialDirectory = $initDir
                $trgItem.DereferenceLinks = $true
                $trgItem.CheckPathExists = $true
                $trgItem.FileName = "[Select this folder]"
                $trgItem.Filter = "Folders|`n"
                $trgItem.AddExtension = $false
                $trgItem.ValidateNames = $false
                $trgItem.CheckFileExists = $false

                If ($trgItem.ShowDialog() -eq "OK") { Return $trgItem.FileName -replace "\\\[Select this folder\]" }
                Else { Write-Error "Operation cancelled by user." }
            }
            Else
            {
                Switch ($ext)
                {
                    'iso'{ $fltr = 'ISO files (*.iso)| *.iso'}
                    Default { $fltr = 'All files (*.*)| *.*'}
                }
                ($trgItem = New-Object System.Windows.Forms.OpenFileDialog).initialDirectory = $initDir
                $trgItem.filter = $fltr
                $null = $trgItem.ShowDialog()
                $trgItem.filename
            }
            # Remove-MpPreference -ControlledFolderAccessAllowedApplications $psPath 
            # If ($mp -eq $true){ Set-MpPreference -EnableControlledFolderAccess Enabled }
        }
        #region - Constants and Lab Config
            $isoDir = 'U:\VirtualMachines\ISOs'
            $wrkDir = 'U:\IsoBuild'
            $labRoot = 'U:\IsoLab'
            $rptForm = (Dec64 'PE1GUj46IDxNREw+IDxERVNDPiAoPE5PVEVTPik=')
            $systems = ('Mfgr,Model,Desc,Notes,Env
                Dell,3660,Precision Tower,Nipr|Sipr,NS
                Dell,7670,Precision Laptop,Misc IT,IT
                Dell,7920,Precision Tower,Fabcon,FC
                Panasonic,FZ-55,ToughBook,T&E,TB
                All,--,--,--,ALL') | ConvertFrom-Csv -delim ','

            If ((Test-path $labRoot -PathType Container) -eq $false){ New-Item $labRoot -ItemType Directory }
            If ((Test-path $wrkDir -PathType Container) -eq $false){ New-Item $wrkDir -ItemType Directory }
            'Drivers','Mount' | %{ Try {New-Item "$labRoot\$_" -ItemType Directory -ea stop}Catch{} }
            New-Item "$wrkDir\Add-Ons" -ItemType Directory -ea Ignore


            $trgSys = $systems | OGV -PassThru -Title 'Select Target System(s)'
            $fwType = (("1,BIOS`n2,UEFI" |
                ConvertFrom-Csv -delim ',' -Header Idx,Type) | OGV -PassThru -Title 'Select System Firmware BootLoader').Type

            If ($trgSys.Mfgr -eq 'All'){$trgSys = $systems | Where Mfgr -ne 'All'}
            ForEach ($itm in $trgSys)
            {
                $rpt += "$($rptForm -replace '<MFR>',$itm.Mfgr -replace '<MDL>',$itm.Model -replace '<DESC>',$itm.Desc -replace '<NOTES>',$itm.Notes)`n"
            }
            $rpt | Out-File "$wrkDir\Driver_Models.txt" -Encoding ascii -Force
            $rpt = $null

            $osBuild = @{} | Select OS,ISO,DrvrPath,ISOName,ISOVol,BIOS
            $osBuild.OS = 'Win11'
            $osBuild.ISO =  Get-Source -initDir $isoDir -ext 'ISO' # SOURCE ISO
            $osBuild.DrvrPath = Get-Source -folder -initDir "$wrkDir\Drivers"
            $osBuild.ISOName = "$($osBuild.OS)-$($trgSys.Env)-$fwType.ISO"  # TARGET ISO
            $osBuild.ISOVol = "$($osBuild.OS)-$($trgSys.Env)"
            $osBuild.BIOS = $(Switch ($fwType){ 'BIOS'{"$wrkDir\boot\etfsboot.com"};'UEFI'{"$wrkDir\efi\microsoft\boot\efisys.bin"} })
        #endregion
        #region - Mount source image and modify
            Mount-DiskImage -ImagePath $osBuild.ISO -PassThru
            $cd = (Get-DiskImage -ImagePath $osBuild.ISO | Get-Volume)

            Copy-Item "$($CD.DriveLetter):\*" -Destination "$wrkDir\" -Recurse
            Get-ChildItem $wrkDir -Recurse -File | % { $_.IsReadOnly=$false }
            Copy-Item "$labRoot\Add-Ons\*" -Destination "$wrkDir\Add-Ons" -Recurse
            # Copy any other needed files into the $wrkDir\Add-Ons Folder

            $filename = $(If ($osBuild.OS -eq '2019'){'install.wim'} Else {'boot.wim'})
            $idxPref = (Get-WindowsImage -ImagePath $wrkDir\sources\$filename | OGV -PassThru -Title 'Select Image to Insert Drivers').ImageIndex

            Mount-WindowsImage -Path $labRoot\Mount -ImagePath $wrkDir\sources\$filename -Index $idxPref #-ReadOnly
            $instDrvrs = Add-WindowsDriver -Path "$labRoot\Mount" -Driver $osBuild.DrvrPath -Recurse
            $instDrvrs | Export-Csv -Delim ',' -NoTypeInformation -LiteralPath "$wrkDir\Add-Ons\DriverImport_Results.csv" -Force -Append
            $instDrvrs | OGV
            # (Dec64 'JGRydnJEYXRhID0gKCRpbnN0RHJ2cnMpLlNwbGl0KFtDaGFyXVtJTlRdMTApDQogICAgJGRwMSA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Ecml2ZXIiDQogICAgJGRwMiA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5PcmlnaW5hbEZpbGVOYW1lIg0KICAgICRkcDMgPSAkZHJ2ckRhdGEgLW1hdGNoICJeSW5ib3giDQogICAgJGRwNCA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5DbGFzc05hbWUiDQogICAgJGRwNSA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Cb290Q3JpdGljYWwiDQogICAgJGRwNiA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5Qcm92aWRlck5hbWUiDQogICAgJGRwNyA9ICRkcnZyRGF0YSAtbWF0Y2ggIl5EYXRlIg0KICAgICRkcDggPSAkZHJ2ckRhdGEgLW1hdGNoICJeVmVyc2lvbiINCg0KICAgICRyZXN1bHRzID0gW0NvbGxlY3Rpb25zLkFycmF5TGlzdF1AKCkgCiAgICAwLi4kZHAxLkNvdW50IHwgJXsKICAgICAgICAgICAgICAgICRyc3QgPSBAe30gfCBTZWxlY3QtT2JqZWN0IERyaXZlcixPcmlnaW5hbEZpbGVOYW1lLEluYm94LENsYXNzTmFtZSxCb290Q3JpdGljYWwsUHJvdmlkZXJOYW1lLERhdGUsVmVyc2lvbgogICAgICAgICAgICAgICAgJHJzdC5Ecml2ZXIgICAgICAgICAgID0gKCgoJGRwMVskX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0Lk9yaWdpbmFsRmlsZU5hbWUgPSAoKCgkZHAyWyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRyc3QuSW5ib3ggICAgICAgICAgICA9ICgoKCRkcDNbJF9dICAtcmVwbGFjZSAnXHN7Mn0nKSAtc3BsaXQgJz0nKS50cmltKCkpWzFdDQogICAgICAgICAgICAgICAgJHJzdC5DbGFzc05hbWUgICAgICAgID0gKCgoJGRwNFskX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0LkJvb3RDcml0aWNhbCAgICAgPSAoKCgkZHA1WyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRyc3QuUHJvdmlkZXJOYW1lICAgICA9ICgoKCRkcDZbJF9dICAtcmVwbGFjZSAnXHN7Mn0nKSAtc3BsaXQgJz0nKS50cmltKCkpWzFdDQogICAgICAgICAgICAgICAgJHJzdC5EYXRlICAgICAgICAgICAgID0gKCgoJGRwN1skX10gIC1yZXBsYWNlICdcc3syfScpIC1zcGxpdCAnPScpLnRyaW0oKSlbMV0NCiAgICAgICAgICAgICAgICAkcnN0LlZlcnNpb24gICAgICAgICAgPSAoKCgkZHA4WyRfXSAgLXJlcGxhY2UgJ1xzezJ9JykgLXNwbGl0ICc9JykudHJpbSgpKVsxXQ0KICAgICAgICAgICAgICAgICRudWxsID0gJHJlc3VsdHMuQWRkKCRyc3QpCiAgICAgICAgICAgICAgICB9CiAgICAkcmVzdWx0cyB8IE9HVgogICAgIyBTYXZlIHJlc3VsdHMKICAgICRyZXN1bHRzIHwgRXhwb3J0LUNzdiAtRGVsaW0gJywnIC1Ob1R5cGVJbmZvcm1hdGlvbiAtTGl0ZXJhbFBhdGggIiRsYWJSb290XElTT1xBZGQtT25zXERyaXZlckltcG9ydF9SZXN1bHRzLmNzdiIgLUZvcmNl')
        #endregion
        #region - Dismount all images and create ISO
            Dismount-WindowsImage -Path $labRoot\Mount -Save
            Dismount-DiskImage -ImagePath $osBuild.ISO

            $Params = @{
                Source = $wrkDir
                DestinationIso = "$labRoot\$($osBuild.ISOName)"
                Title = $osBuild.ISOVol
                BootFile = $osBuild.BIOS
                Force = $true
                }
            New-ISOFilev2 @Params
        #endregion
        #region - Clean-up
            # Clean ISO build folder
            GCI $wrkDir -Recurse | Remove-Item -Force -Recurse -Confirm:$false

            # Clear Lab MOUNT folder
            Remove-Item -Path $labRoot\Mount -Force -Recurse -Confirm:$false
        #endregion
    #endregion

    #region - FoD testing
        # mul_windows_11_languages_and_optional_features_x64_dvd_dbe9044b.iso
        $srcLP = 'E:\LanguagesAndOptionalFeatures'
        Get-WindowsCapability -Name RSAT* -Online -Source $srcLP | Select-Object -Property DisplayName, State

        Get-WindowsCapability -Name RSAT* -Online -Source $srcLP | Add-WindowsCapability -Online -Source $srcLP -ErrorAction SilentlyContinue 

        #
        #
        $trgDir = 'C:\Users\adminCM\Desktop\LanguagesAndOptionalFeatures'
        $subDir = "$trgDir\metadata"
        $f1 = gci $trgDir -Recurse:$false -File
        $f2 = gci $subDir -Recurse:$false -File
        $f2 | Where Name -match "`_[a-z][a-z]\-" | Where Name -NOTmatch "`_en\-US" | Remove-Item
        $f1 | Where Name -notmatch '\~\~' | Where Name -notmatch 'en-us' | Where Name -notmatch 'client.cab' | Remove-Item
        $f1 = gci $trgDir -Recurse:$false -File
        $f1 | Where Name -match '\~\~' | Where Name -match "`-[a-z][a-z]\-" | Where Name -notmatch '-en-us' | Remove-Item


        $s | Remove-Item
        $onlyInArray1 = Compare-Object -ReferenceObject $r -DifferenceObject $s -PassThru | Where-Object { $_.SideIndicator -eq "<=" }
        $onlyInArray2 = Compare-Object -ReferenceObject $r -DifferenceObject $s -PassThru | Where-Object { $_.SideIndicator -eq "=>" }

        $onlyInArray1
    #endregion

#endregion 

