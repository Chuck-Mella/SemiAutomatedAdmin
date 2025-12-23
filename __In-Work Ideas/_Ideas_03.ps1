


#region - Password Expiration
    Function Get-AcctPwdExpiration($a)
    { If ($a -eq $null ){ $a = $env:userName }; Get-Date ((Net user $a /Domain | Findstr /c:"d expires") -split ('' * 13))[-1] }
    Get-AcctPwdExpiration admincm
    Pause
#endregion

#region - Find-LockedFileProcess
    Function Find-LockedFileProcess
    {
        Param
        (
            [Parameter(Mandatory=$true)]$FileName = "C:\Windows\SoftwareDistribution\Download\c74714360cfa80db9cela92805bc26ae\MicrosoftEdgeEnterpriseX64.cab",
            $HandleFilePath = 'C :\windows\System32\handle.exe'
        )
        $splitter = ('-' * 60)
        $handleProcess = ((& $HandleFilePath) -join "`n" ) -split $splitter | Where-Object {$_ -match [regex]::Escape($FileName)}
        (($HandleProcess -split "`n")[2] -split'')[0]
    }
    Find-LockedFileProcess -FileName "c:\image\"
    Get-WmiObject win32_Process | Select-Object Name,commandline | Where-Object commandline -match 'softwareDistribution' | ForEach-Object{ stop-Process -ProcessName ($_.Name -replace '.exe' ) }
    "C:\Windows\SoftwareDistribution\Download\c74714360cfa80db9ce1a92805bc26ae\MicrosoftEdgeEnterpriseX64.cab"
#endregion

#region File Splitting ideas
    function join($path)
    {
        $files = Get-ChildItem -Path "$path.*.part" | Sort-Object -Property @{Expression={
            $shortName = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
            $extension = [System.IO.Path]::GetExtension($shortName)
            if ($null -ne $extension -and $extension -ne '')
            {
                $extension = $extension.Substring(1)
            }
            [System.Convert]::ToInt32($extension)
        }}
        $writer = [System.IO.File]::OpenWrite($path)
        foreach ($file in $files)
        {
            $bytes = [System.IO.File]::ReadAllBytes($file)
            $writer.Write($bytes, 0, $bytes.Length)
        }
        $writer.Close()
    }

    #join "C:\path\to\file"

    function split($path, $chunkSize=107374182)
    {
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($path)
        $directory = [System.IO.Path]::GetDirectoryName($path)
        $extension = [System.IO.Path]::GetExtension($path)

        $file = New-Object System.IO.FileInfo($path)
        $totalChunks = [int]($file.Length / $chunkSize) + 1
        $digitCount = [int][System.Math]::Log10($totalChunks) + 1

        $reader = [System.IO.File]::OpenRead($path)
        $count = 0
        $buffer = New-Object Byte[] $chunkSize
        $hasMore = $true
        while($hasMore)
        {
            $bytesRead = $reader.Read($buffer, 0, $buffer.Length)
            $chunkFileName = "$directory\$fileName$extension.{0:D$digitCount}.part"
            $chunkFileName = $chunkFileName -f $count
            $output = $buffer
            if ($bytesRead -ne $buffer.Length)
            {
                $hasMore = $false
                $output = New-Object Byte[] $bytesRead
                [System.Array]::Copy($buffer, $output, $bytesRead)
            }
            [System.IO.File]::WriteAllBytes($chunkFileName, $output)
            ++$count
        }

        $reader.Close()
    }

    #split "C:\path\to\file"
    Install-Module -Name 7Zip4Powershell -RequiredVersion 1.9.0
#endregion

#region Idears

    Function DecText($a)
    {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($a)
        $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $UnsecurePassword
    }

    function Remove-comObjects ($reflist)
    {
        foreach ($ref in $Reflist)
        {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) | out-null
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($ref) | out-null
             Remove-Variable $ref -Force | Out-Null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }


    $a = [adsisearcher]""
    $a.Filter = "(&(objectClass=user))"
    $a.SearchRoot = 'LDAP://OU=ASD,OU=MISCELLANEOUS,OU=Belvoir,OU=NCR,OU=Installations,DC=nae,DC=ds,DC=army,DC=mil'
    $a.FindAll() | Select-Object @{n='User';e={[string]$_.Properties.name}},
                          @{n='ECPI';e={($_.Properties.userprincipalname).substring(0,10)}},
                          @{n='PIV';e={($_.Properties.userprincipalname).substring(10,6)}},
                          @{n='Expiration';e={[datetime]::FromFileTime([string]$_.Properties.accountexpires)}} | Where-Object ECPI | Sort-Object User | Out-GridView -Title 'ASD Account PIVs & Expirations'



    ($a = [adsisearcher]"(&(objectClass=computer))").SearchRoot = 'LDAP://OU=ASD,OU=MISCELLANEOUS,OU=Belvoir,OU=NCR,OU=Installations,DC=nae,DC=ds,DC=army,DC=mil'
    $wks = ($a.FindAll() | Select-Object @{n='Workstation';e={$_.Properties.cn}}).Workstation | Sort-Object
    $S = ForEach ($wk in $wks){ "$WK Pingable: $((Test-NetConnection -ComputerName $wk).PingSucceeded)" }
    $rslt = ($S = $s -replace ' Pingable') | ConvertFrom-Csv -Delimiter ':' -Header Computer,Pingable
    $rslt | Where-Object Pingable -eq $True
    $rslt | Where-Object Pingable -eq $false









$isoInfo = (Dec64 'dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLklPOw0KdXNpbmcgU3lzdGVtLlRleHQ7DQoNCi8vIE5CIHRoaXMgY2FuIGFsc28gYmUgdXNlZCBmcm9tIFBvd2VyU2hlbGwgYXM6DQovLyAgICAgIEFkZC1UeXBlIC1QYXRoIElzb0luZm8uY3MNCi8vICAgICAgW0lzb0luZm9dOjpHZXRWb2x1bWVDcmVhdGlvbkRhdGUoJ215LmlzbycpDQpwdWJsaWMgY2xhc3MgSXNvSW5mbw0Kew0KICAgIC8vIHNlZSBodHRwczovL3dpa2kub3NkZXYub3JnL0lTT185NjYwI1RoZV9QcmltYXJ5X1ZvbHVtZV9EZXNjcmlwdG9yDQogICAgc3RhdGljIGJvb2wgSXNQcmltYXJ5Vm9sdW1lRGVzY3JpcHRvclNlY3RvcihieXRlW10gc2VjdG9yKQ0KICAgIHsNCiAgICAgICAgY29uc3QgYnl0ZSBQcmltYXJ5Vm9sdW1lRGVzY3JpcHRvclR5cGUgPSAxOw0KICAgICAgICBjb25zdCBieXRlIFZvbHVtZURlc2NyaXB0b3JWZXJzaW9uID0gMTsNCiAgICAgICAgdmFyIFZvbHVtZURlc2NyaXB0aW9ySWRlbnRpZmllciA9IG5ldyBieXRlW10geyhieXRlKSdDJywgKGJ5dGUpJ0QnLCAoYnl0ZSknMCcsIChieXRlKScwJywgKGJ5dGUpJzEnfTsNCg0KICAgICAgICBpZiAoc2VjdG9yWzBdICE9IFByaW1hcnlWb2x1bWVEZXNjcmlwdG9yVHlwZSkNCiAgICAgICAgew0KICAgICAgICAgICAgcmV0dXJuIGZhbHNlOw0KICAgICAgICB9DQoNCiAgICAgICAgZm9yICh2YXIgbiA9IDA7IG4gPCBWb2x1bWVEZXNjcmlwdGlvcklkZW50aWZpZXIuTGVuZ3RoOyArK24pDQogICAgICAgIHsNCiAgICAgICAgICAgIGlmIChzZWN0b3JbMStuXSAhPSBWb2x1bWVEZXNjcmlwdGlvcklkZW50aWZpZXJbbl0pDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlOw0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQoNCiAgICAgICAgaWYgKHNlY3Rvcls2XSAhPSBWb2x1bWVEZXNjcmlwdG9yVmVyc2lvbikNCiAgICAgICAgew0KICAgICAgICAgICAgcmV0dXJuIGZhbHNlOw0KICAgICAgICB9DQoNCiAgICAgICAgcmV0dXJuIHRydWU7DQogICAgfQ0KDQogICAgLy8gc2VlIGh0dHBzOi8vd2lraS5vc2Rldi5vcmcvSVNPXzk2NjAjRGF0ZS4yRnRpbWVfZm9ybWF0DQogICAgc3RhdGljIERhdGVUaW1lT2Zmc2V0IFJlYWREYXRlVGltZShieXRlW10gc2VjdG9yLCBpbnQgb2Zmc2V0KQ0KICAgIHsNCiAgICAgICAgdmFyIHllYXIgICAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzAsICA0KTsNCiAgICAgICAgdmFyIG1vbnRoICAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzQsICAyKTsNCiAgICAgICAgdmFyIGRheSAgICAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzYsICAyKTsNCiAgICAgICAgdmFyIGhvdXIgICAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzgsICAyKTsNCiAgICAgICAgdmFyIG1pbnV0ZSAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzEwLCAyKTsNCiAgICAgICAgdmFyIHNlY29uZCAgICAgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzEyLCAyKTsNCiAgICAgICAgdmFyIGh1bmRyZWR0aHMgID0gUmVhZEFzY2lpSW50KHNlY3Rvciwgb2Zmc2V0KzE0LCAyKTsNCiAgICAgICAgdmFyIHV0Y09mZnNldCAgID0gVGltZVNwYW4uRnJvbU1pbnV0ZXMoKGludClzZWN0b3Jbb2Zmc2V0KzE2XSoxNSk7DQoNCiAgICAgICAgcmV0dXJuIG5ldyBEYXRlVGltZU9mZnNldCh5ZWFyLCBtb250aCwgZGF5LCBob3VyLCBtaW51dGUsIHNlY29uZCwgaHVuZHJlZHRocyoxMCwgdXRjT2Zmc2V0KTsNCiAgICB9DQoNCiAgICBzdGF0aWMgaW50IFJlYWRBc2NpaUludChieXRlW10gc2VjdG9yLCBpbnQgb2Zmc2V0LCBpbnQgc2l6ZSkNCiAgICB7DQogICAgICAgIHZhciBzYiA9IG5ldyBTdHJpbmdCdWlsZGVyKHNpemUpOw0KDQogICAgICAgIGZvciAodmFyIG4gPSAwOyBuIDwgc2l6ZTsgKytuKQ0KICAgICAgICB7DQogICAgICAgICAgICBzYi5BcHBlbmQoKGNoYXIpc2VjdG9yW29mZnNldCtuXSk7DQogICAgICAgIH0NCg0KICAgICAgICByZXR1cm4gaW50LlBhcnNlKHNiLlRvU3RyaW5nKCkpOw0KICAgIH0NCg0KICAgIC8vIHNlZSBodHRwczovL3dpa2kub3NkZXYub3JnL0lTT185NjYwDQogICAgLy8gTkIgdGhpcyBpcyBlcXVpdmFsZW50IHRvOg0KICAgIC8vICAgICAgaXNvaW5mbyAtZGVidWcgLWQgLWkgbXkuaXNvDQogICAgcHVibGljIHN0YXRpYyBEYXRlVGltZU9mZnNldCBHZXRWb2x1bWVDcmVhdGlvbkRhdGUoc3RyaW5nIHBhdGgpDQogICAgew0KICAgICAgICB1c2luZyAodmFyIHN0cmVhbSA9IEZpbGUuT3BlbihwYXRoLCBGaWxlTW9kZS5PcGVuLCBGaWxlQWNjZXNzLlJlYWQpKQ0KICAgICAgICB7DQogICAgICAgICAgICBjb25zdCBpbnQgU2VjdG9yU2l6ZSA9IDIwNDg7DQogICAgICAgICAgICBjb25zdCBieXRlIFZvbHVtZURlc2NyaXB0b3JTZXRUZXJtaW5hdG9yVHlwZSA9IDI1NTsNCg0KICAgICAgICAgICAgLy8gcmVhZCB0aGUgUHJpbWFyeSBWb2x1bWUgRGVzY3JpcHRvci4NCiAgICAgICAgICAgIGZvciAodmFyIHNlY3RvckluZGV4ID0gMTY7IDsgKytzZWN0b3JJbmRleCkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB2YXIgc2VjdG9yID0gbmV3IGJ5dGVbU2VjdG9yU2l6ZV07DQoNCiAgICAgICAgICAgICAgICBzdHJlYW0uUG9zaXRpb24gPSBzZWN0b3JJbmRleCpTZWN0b3JTaXplOw0KICAgICAgICAgICAgICAgIGlmIChzdHJlYW0uUmVhZChzZWN0b3IsIDAsIHNlY3Rvci5MZW5ndGgpICE9IHNlY3Rvci5MZW5ndGgpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgQXBwbGljYXRpb25FeGNlcHRpb24oImZhaWxlZCB0byByZWFkIHNlY3RvciIpOw0KICAgICAgICAgICAgICAgIH0NCg0KICAgICAgICAgICAgICAgIGlmIChzZWN0b3JbMF0gPT0gVm9sdW1lRGVzY3JpcHRvclNldFRlcm1pbmF0b3JUeXBlKQ0KICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgYnJlYWs7DQogICAgICAgICAgICAgICAgfQ0KDQogICAgICAgICAgICAgICAgaWYgKCFJc1ByaW1hcnlWb2x1bWVEZXNjcmlwdG9yU2VjdG9yKHNlY3RvcikpDQogICAgICAgICAgICAgICAgew0KICAgICAgICAgICAgICAgICAgICBjb250aW51ZTsNCiAgICAgICAgICAgICAgICB9DQoNCiAgICAgICAgICAgICAgICB2YXIgdm9sdW1lQ3JlYXRpb25EYXRlVGltZSA9IFJlYWREYXRlVGltZShzZWN0b3IsIDgxMyk7DQoNCiAgICAgICAgICAgICAgICByZXR1cm4gdm9sdW1lQ3JlYXRpb25EYXRlVGltZTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIA0KICAgICAgICAgICAgdGhyb3cgbmV3IEFwcGxpY2F0aW9uRXhjZXB0aW9uKCJmYWlsZWQgdG8gZmluZCB0aGUgcHJpbWFyeSB2b2x1bWUgZGVzY3JpcHRvciBzZWN0b3IiKTsNCiAgICAgICAgfQ0KICAgIH0NCn0=')
$program = (Dec64 'dXNpbmcgU3lzdGVtOw0KDQpjbGFzcyBQcm9ncmFtDQp7DQogICAgc3RhdGljIHZvaWQgTWFpbihzdHJpbmdbXSBhcmdzKQ0KICAgIHsNCiAgICAgICAgdmFyIHBhdGggPSBhcmdzWzBdOw0KDQogICAgICAgIHZhciB2b2x1bWVDcmVhdGlvbkRhdGUgPSBJc29JbmZvLkdldFZvbHVtZUNyZWF0aW9uRGF0ZShwYXRoKTsNCg0KICAgICAgICBDb25zb2xlLldyaXRlTGluZSh2b2x1bWVDcmVhdGlvbkRhdGUuVG9TdHJpbmcoIk8iKSk7DQogICAgfQ0KfQ==')

Add-Type $isoInfo

[IsoInfo]::GetVolumeCreationDate("C:\Users\adminCM\Desktop\Win11_23H2_Ent_x64.iso").ToString('O')

Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.BootFromDisk -eq $TRUE }   
Get-Disk | Where-Object { $_.BootFromDisk -eq $TRUE }   
Get-Disk | Where-Object { $_.BusType -eq 'USB' }   
(Get-CimInstance Win32_LogicalDisk | Where-Object{ $_.DriveType -eq 5})[0] | Select-Object -exp CimSystemProperties
Get-CimInstance -ClassName Win32_CDROMDrive -Property *

Add-Type -Path IsoInfo.cs
[IsoInfo]::GetVolumeCreationDate('my.iso').ToString('O')

#endregion

#region - DISA
    Function DISAA_GPO_BASELINE_IMPORT
    {
        <#
            Author - chuck Mella 
            orig Author - David L Foster 
            Date Re-written - November 29, 2023 
            Date written - August 06, 2020 
            Descriptions - Import GPO backup to an AD envirnoment.
                Prompts user for import file.

            Package checks for existance of GPO in AD environment. If present, prompts user to
            overwrite existing GPO.

            This script can be used to input any GPO backups to any AD environment.
            User must update the input files and migration table prior to executing script.
        
            A sample migration table should be located under DISA STIG Baseline
            Support Files
        #>
        #Requires -RunAsAdministrator 
        Param
        (
            [Parameter(Mandatory=$false)]$gpoimportFile,
            [Parameter(Mandatory=$false)]$importtable,
            $workDir = [Environment]::GetFolderPath("MyDocuments"),
            $ZipFile = "\\AD-East\AD-IT\ Project - Group Policy Upgrades\U_STIG_GPO_Package_July_2023.zip",
            $prefix ='__ NEW_2023-07_'
        )
        Begin
        {
            #region - script Functions
                Function Check-Audio
                {
                    Try { $speak.speak( '' ); Return $true }
                    catch { Return $False }
                }
                Function Write-Log ($output){ Out-File -Filepath $logfile -Inputobject $output -Append }
                Function Get-InputFile ($type,$trgDir)
                {
                    $dlgOpenFile = New-Object System.Windows.Forms.OpenFileDialog
                    $dlgOpenFile.Initialoirectory = $trgDir
                    $dlgOpenFile.Filter = "Input Files (*.$type)l*.$type"
                    $null = $dlgOpenFile.ShowDialog()
                    $dlgOpenFile.FileName
                    if ([String]::IsNullOrEmpty($dlgOpenFile.FileName))
                    {
                        Write-Warning "Exiting script.Press any key to continue..."
                        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                        Exit
                    }
                }
                Function Get-Logfile
                {
                    #verify log file exist.
                    write-Host "checking for Log file"
                    #checking for the the log directory and log file.
                    If (Test-Path $logfolder)
                    {
                        # checking if log file exist
                        If (Test-Path $logfile)
                        {
                            If ((check-Audio) -ne $False){ $speak.speak('Log file located') }
                            Write-Host "$logfile was located"
                            Write-Log "$logfile was located $date"
                        }
                        Else
                        {
                            If ((check-Audio) -ne $False){ $speak.speak('Log file was not found. We will now create.')}
                            Write-Host "$logfile was not present. we will now create"
                            Write-Log "$logfile was not present, we will now create $date"
                        }
                    }
                    Else
                    {
                        If ((check-Audio) -ne $False){ $speak.speak('Log folder was not found. we will now create') }
                        Write-Host "$logfolder was not found. we will now create." 
                        $createlogfolder = "$logfolder was not found, we will now create $date"
                        New-Item $logfolder -Type Directory -Force
                        Write-Log $createlogfolder
                        Write-Log "$logfile was not found, we will now create $date"
                    }
                }
                Function Import-DISAGPO
                {
                    <#
                        Function will loop through GPO input file. Will check for exitance of
                        GPO and prompt user to overwrite.
                        If the GPO is not present, the GPO is created.
                    #>
                    Param
                    (
                        $importfile,
                        $migrationtable,
                        $logfile
                    )
                    # Logging source file and date
                    $importfile,$migrationtable,$date | Out-File -FilePath $logfile
                    If ($null -eq $migrationtable )
                    {
                        <#
                            selecting migration table to be used in GPO import.
                            sample migration table provide DISA STIG Baseline Package support Files
                        #>
                        If ((Check-Audio) -ne $False) { $speak.speak('select migration table file. File is available in DISA quarterly baseline support files directory.') }
                        Write-Host "Select migration table file. File is available in DISA quarterly baseline support files directory."

                        $migrationtable = Get-InputFile -type 'migtable' -trgDir $spprtDir

                        # Import and loops through each line in import file
                        $gpolist = Import-csv -Path $importfile -ErrorAction stop
                        $gpDom = ([System.Directoryservices.ActiveDirectory.Domain]::GetcurrentDomain()).Name
                        $gpFQDN = ($gpDom.split('.') | ForEach-Object{'DC='+$_}) -join ','
                        $gpDC = ($env:Logonserver -replace '\\' )
                }
                    Foreach($gpo in $gpolist)
                    {
                        # checking if the GPO already exist
                        If ((check-Audio) -ne $False){ $speak.speak($gpo.gponame) }
                        write-Host $gpo.gponame
                        $locate = Get-GPO -Name $gpo.gponame -ErrorAction silentlycontinue
                        If ($null -eq $locate.DisplayName )
                        {
                            # If GPO does not exist the GPO is imported to AD environment
                            If ((check-Audio) -ne $False){ $speak.speak('GPO not found. we will create and | mport GPO.') }
                            write-Host "No GPO named [$($gpo.gponame)] was found. We will now create and import GPO."
                            write-Log "No GPO named [$( $gpo.gponame)] was present. [$($gpo.gponame)] was created and settings imported."
                            # Importing GPO from backup.
                            $Params = [ordered] @{
                                BackupGpoName  = $gpo.gponame
                                Path           = $gpo.path
                                TargetName     = ($prefix + $gpo.gponame)
                                MigrationTable = $migrationtable
                                CreateifNeeded = $true
                                Domain         = $gpDom
                                server         = $gpDC
                                }
                            Import-GPO @Params
                        }
                        Else
                        {
                            # If GPO does exist notifies user and prompts to overwrite
                                If ((Check-Audio) -ne $False){ $speak.speak('GPO found') }
                                Write-Host "GPO named $($locate.DisplayName) was found"
                                $gpodisplayname = $locate.DisplayName

                                If ((check-Audio) -ne $False){ $speak.speak( 'Do you want to overwrite existing GPO?' ) }
                                $userinput = Read-Host "Do you want to overwrite existing GPO" $locate.DisplayName "(Y/N)"
                                If ($userinput.Toupper() -eq 'Y' )
                                {
                                    If ((Check-Audio) -ne $False){ $speak.speak('we will overwrite existing GPO.') }
                                    Write-Host "we will overwrite existing GPO"
                                    $locate.DisplayName

                                    # Importing GPO from backup. Migration table is predefined. user must update table before excution of script
                                    Import-GPO -BackupGpoName $gpo.gponame -Path $gpo.path -TargetName $gpo.gponame -createifNeeded -MigrationTable $migrationtable
                                    Write-Log "$gpodisplayname was overwritten with GPO backup"
                                }
                                Else
                                {
                                    # GPO is not imported.
                                    If ((check-Audio) -ne $False){ $speak.speak('The GPO was not overwritten') }
                   
                                    Write-Host "The GPO $($locate.DisplayName) was not overwritten"
                                    Write-Log = "$gpodisplayname was not overwritten"
                                }
                        }
                    }
                }
                Function Get-Importfile
                {
                    # Ensuring user has modifed import file (prepared)
                    Param
                    (
                        $gpoimportFile,
                        $1mporttable
                    )
                    If ((Check-Audio) -ne $False) { $speak.speak( 'Do you want to use an available DISA Import File? Yes or No.' ) }
                    $msgBox1 = [System.windows.Forms.MessageBox]::show($THIS,'Do you want use a DISA supplied import file?','use DISA Import Files','YesNo','Question' )
                    switch ($msgBox1)
                    {
                        'Yes'
                        {
                            If ((check-Audio) -ne $False){ $speak.speak('select GPO import file. File is available in DISA quarterly baseline support files directory.') }
                            Write-Host "Select GPO import file. File is available in DISA quarterly baseline support files directory."

                            If ((Check-Audio) -ne $False) { $speak.speak( 'Message box, Have you made all required updates to the DISA import files? Yes No cancel' ) }
                            $msgBoxinput = [System.Windows.Forms.MessageBox]::show($THIS,'Have you made all required updates to import file?','DISA Import File updates','YesNoCancel','Question' )
                            switch ($msgBoxinput)
                            {
                                'Yes'
                                {
                                    If ([string]::IsNullorEmpty($gpoimportFile))
                                    {
                                        $importfile = Get-InputFile -type 'csv' -trgDir $spprtDir
                                        Write-Host $importfile
                                        Import-DISAGPO -importfile $importfile -migrationtable $importtable -logfile $logfile
                                    }
                                    Else { Import-DISAGPO -migrationtable $importtable -logfile $logfile }
                                }
                                'No'
                                {
                                    If ((Check-Audio) -ne $False){ $speak.speak( 'You must complete prework before executing script. No changes made to environment.' ) }
                                    Write-Warning "You must complete prework before executing script.`nPlease make all required updates to import files available within DISA STIG Baseline Package support Files.`nScript will exit"
                                    Write-Log "You must complete prework before executing script. No changes made to environment."
                                    Exit
                                }
                                'cancel'
                                {
                                    If ((Check-Audio) -ne $False){ $speak.speak('No changes made. script was canceled.') }
                                }
                            }
                        }
                        'No'
                        {
                            Write-Warning "closing script... "
                            Write-Log "No changes made. Script was canceled."
                            Exit
                        }
                    }
                    If ((Check-Audio) -ne $False) { $speak.speak("Adding all GPOs present and prepending'_ NEW_' to the GPO names.") }
                    # Adds all availble GPOs with'_ NEW_' prepended to all imported GPOs
                    $importfile = "$workDir\tmpGPOs.csv"
                    Write-Log "No input file selected, adding all GPOs present and prepending '_NEW_'to the 1mported GPO names."
                    Import-DISAGPO -importfile $importfile -migrationtable $importtable -logfile $logfile
                }
                Function Get-PackagePolinfo
                {
                    Param
                    (
                        $pkgRoot = $gpoDir,
                        [switch]$Local
                    )
                    switch ($Local.IsPresent)
                    {
                        $true
                        { $trgGPOs = Get-ChildItem "$pkgRoot\Support Files" -Recurse -Filter 'Backup.XML' }
                        $false
                        { $trgGPOs = Get-ChildItem $pkgRoot -Directory -Filter '*DoD*' | ForEach-Object{Get-ChildItem $_.Ful1Name -Recurse -Filter 'Backup.XML'}}
                    }
                    $gpData = ForEach ($xml in $trgGPOs)
                    {
                        $test = [xml](Get-Content $xml.FullName)
                        "$($test.GroupPolicyBackupscheme.GroupPolicyobject.GroupPolicycoresettings.DisplayName.'#cdata-section')," +
                        "$($test.GroupPolicyBackupscheme.GroupPolicyobject.GroupPolicycoresettings.ID.'#cdatasection')," +
                        "$($xml.Name)," + "$($xml.DirectoryName)" | ConvertFrom-Csv -Delimiter ',' -header DisplayName,ID,File,Path
                    }
                    Return $gpoata
                }
            #endregion
        }
        Process
        {
            # Load Forms access
                [void][system.Reflection.Assembly]::LoadWithPartialName('System.windows.Forms')
                [void][System.Reflection.Assembly]::LoadwithPartialName('Microsoft.VisualBasic')
                [void][System.Reflection.Assembly]::LoadwithPartialName('System.speech')
                $Speak = New-Object -TypeName System.Speech.synthesis.Speechsynthesizer
            # Establish Initial Folders (Script Run and GPO Locations)
                $scriptHome = $Myinvocation.MyCommand.source
                $gpoDir = "C:\Temp\$Prefix 'DISA._GPO_Updates"
                If (!(Test-Path $gpoDir)){ New-Item $gpoDir -ItemType Directory; $nz = $true }
                $spprtDir = (Get-ChildItem $gpoDir -Directory -Filter '*Support*' ).FullName
            # Download DISA zip File contents
                If ($nz -eq $true) { Expand-Archive -Path $ZipFile -DestinationPath $gpoDir -Force }
            # Determine Available GPO Updates
                $trgPolicies = Get-PackagePolinfo #*Local
                If ((Get-Host).Name -match 'ISE' )
                {
                    $newGPOs = $trgPolicies |
                        Select-Object @{n='GPOName';e={$_.DisplayName}},@{n='Path';e={$_.Path -replace '\\+[^\\]+$'}} |
                            Out-GridView -Title 'select Desired Policies' -PassThru
                }
                Else
                {
                    $newGPOs = $trgPolicies |
                        Select-Object @{n='GPOName';e={$_.DisplayName}},@{n='Path';e={$_.Path -replace'\\+[^\\]+$'}}
                }
                $newGPOs | Export-csv -Delimiter ',' -Path "$workDir\tmpGPOs.csv" -NoTypeInformation
             # Import required module
                Import-Module grouppolicy
            # create script variables
                $date = Get-Date
                $workDir = [Environment]::GetFolderPath("MyDocuments")
                If ([string]::IsNullOrEmpty($importtable)){ $importtable  = Get-Inputfile -type 'migtable' -trgDir $spprtDir }
                $logfolder = $workDir + "\GPO_Automation_Logs"
                $logfile = $logfolder + "\STIG_GPO_Import.log"
        }
        End
        {
            If ((Check-Audio) -ne $False){ $speak.speak('checking for log files.') }
            Get-Logfile
            If ($null -eq $gpoimportFile -or $null -eq $importtable )
            {
                If ((check-Audio) -ne $False){ $speak.speak('Requesting import files.') }
                Get-Importfile -gpoimportFile $gpoimportFile -importtable $importtable
            }
            Else { Import-DISAGPO -importfile $gpoimportFile -migrationtable $importtable -logfile $logfile }
        }
    }
    function Import-SecurityBaselineGPO
    {
        <#
            .Synopsis
               Import-SecurityBaselineGPO

            .DESCRIPTION
               Import-SecurityBaselineGPO

            .PARAMETER GPOBackupPath
              The path that constains the Security baselines GPO backup
 
            .EXAMPLE
                Import-SecurityBaselineGPO -GPOBackupPath "C:\data\Security Baselines\Microsoft 1903 - September 2019\GPOs" -Verbose 

                The above command imports all Windows 10 1903 baselines

            .EXAMPLE
                Import-SecurityBaselineGPO -GPOBackupPath "C:\data\Security Baselines\Microsoft - Office365\GPOs" -Verbose 

                The above command imports all Microsoft Office baselines

            .NOTES
                Author: Alex Verboon
                version: 1.0
                Date: 07.10.2019
        #>
        [CmdletBinding(SupportsShouldProcess)]
        Param
        (
            # MS Security Baseline GPO Backup path
            [Parameter(Mandatory=$true,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            [string]$GPOBackupPath
        )

        Begin
        {
            If (-not(Test-Path -Path $GPOBackupPath))
            {
                Write-Error "Unable to find GPO backup folder: $GPOBackupPath"
                Break
            }

            # Retrieve GPO backup information
            $gpoBackupFiles = Get-ChildItem -Path $gpoBackupPath -Filter "bkupinfo.xml" -Recurse -Attributes Hidden,Normal,System,ReadOnly,Archive

            If ([string]::IsNullOrEmpty($gpoBackupFiles))
            {
                    Write-Error "Unable to find GPO backup files (bkupinfo.xml) under folder: $GPOBackupPath"
                    Break
            }

            $DomainName = (Get-ADDomain).DistinguishedName

        }
        Process
        {

        $NewGPOObjects = @()
        ForEach ($gpobackupfile in $gpoBackupFiles)
        {
            $bkupInfoFile = "$($gpobackupfile.FullName)"
            [xml]$bkupInfo = @(Get-Content -Path $bkupInfoFile)
            ForEach ($GPO in $bkupInfo.BackupInst)
            {
                $GPOName = $GPO.GPODisplayName.'#cdata-section'
                write-verbose "Processing $GPOName"
                If (Get-GPO -Name "$GPOName" -ErrorAction SilentlyContinue)
                {
                    write-warning "GPO Object $GPOName already exists. Delete or rename the existing GPO object first if you want to import a new version"
                }
                Else
                {
                    Try{
                        #Write-verbose "Creating GPO Object $GPOName"
                         if ($PSCmdlet.ShouldProcess($DomainName, 'Creating GPO Object.'))
                         {
                            $null = New-GPO "$GPOName"
                            $gpobject = [PSCustomObject] @{
                                GPOName = $GPOName
                            }
                            $NewGPOObjects = $NewGPOObjects + $gpobject
                        }
                  
                    }
                    Catch{
                          Write-Error "Error creating GPO Object $GPOName"
                    }

                    Try{
                        #Write-verbose "Importing settings into GPO Object $GPOName"
                    
                         if ($PSCmdlet.ShouldProcess($GPOName, 'Importing settings'))
                         {
                            $null = Import-gpo -Path "$gpoBackupPath" -TargetName "$GPOName" -BackupGpoName "$GPOName"
                            # add a little wait to prevent errors
                            Start-Sleep -Seconds 2
                        }
                    }
                    Catch{
                        Write-Error "Error importing settings for $GPOName"
                    }
                }
            }
        }
        }
        End
        {
             $NewGPOObjects | Select-Object GPOName
        }
    } 
#endregion
