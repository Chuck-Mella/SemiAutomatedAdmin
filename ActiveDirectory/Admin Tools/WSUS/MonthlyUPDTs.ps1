# Updates
If ((gwmi Win32_LogicalDisk | Where VolumeName -match "(Jenny|Fortress)").DeviceID -eq $null){ $xferDrive = 'C:\TEMP' }
Else { $xferDrive = (gwmi Win32_LogicalDisk | Where VolumeName -match "(Jenny|Fortress)").DeviceID }
If ($xferDrive -eq $null){ BREAK }
$updPath = Join-Path $xferDrive " Monthly_Updates\$(Get-Date -f yyyy-MM)"
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
#region - DL Latest Adobe Reader
    # rv ftp*
    $lclPath = $updPath 
    $ftpFolderUrl = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"

    #connect to ftp, and get directory listing
        $ftpRequest = [System.Net.FtpWebRequest]::Create("$ftpFolderUrl") 
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftpResponse = $ftpRequest.GetResponse()
        $ResponseStream = $ftpResponse.GetResponseStream()
        $ftpReader = New-Object System.IO.Streamreader -ArgumentList $ResponseStream
        $DirList = $ftpReader.ReadToEnd()

    # from Directory Listing get last entry in list of any numeric version
        $LatestUpdate = $DirList -split '[\n]' | Where {$_ -match '^\d'} | Sort | Select -Last 1

    # build file name & download url for latest file
        $LatestFile = "AcroRdrDCUpd" + $LatestUpdate + "_MUI.msp"
        $DownloadURL = "$ftpFolderUrl$LatestUpdate/$LatestFile"

    # download the file
        (New-Object System.Net.WebClient).DownloadFile($DownloadURL, $LatestFile)
        (New-Object System.Net.WebClient).DownloadFile($DownloadURL, ($lclPath + '\' + $LatestFile))
#endregion
#region - WSUS
    [DateTime]$starttime = Get-Date
    # Connect and Verify Removable Device
        $drvWSUS = 'U:\WSUS'
        $drvRem = gwmi Win32_LogicalDisk | Where VolumeName -match "(Jenny|Fortress)" | Select -Exp DeviceID
        If ($drvRem -eq $null) { Write-Warning "$trgVol Device not connected; EXITING"; Break }
        Else { Write-Host -f Green "Jenny/Fortress device located as [$drvRem]" }


    # Export WSUS Data
        Write-Host -f Cyan "Exporting WSUS Data Locally to $drvWSUS (2-5 Min)"
        SL "$env:ProgramFiles\Update Services\Tools"
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
	Agent - VMs
	Composer - VSphere
	HView - Horizon
	VMWareTools
#endregion
#region - Office (Currently: Office Pro 2019 Plus)
    Function Install-Office
    {
        Param
        (
            [ValidatePattern('(DLoad|Config|Install)')]$mode,
            [ValidatePattern('(32|64)')][string]$bits,
            $instPath = "C:\temp\ Monthly_Updates\Office Deployment Tools"
        )
        $urlConfig = 'https://config.office.com/deploymentsettings'
        $urlDeployInf = 'https://www.microsoft.com/en-US/download/details.aspx?id=49117'
        $urlDeploy = 'https://download.microsoft.com/download/2/7/A/27AF1BE6-DD20-4CB4-B154-EBAB8A7D4A7E/officedeploymenttool_16731-20354.exe'
        $dst = [string](Get-Date -f yyyy-MM-dd)
        Switch ($mode)
        {
            'DLoad'
            {
                # Check for Insaller file and DL if needed
                    If ((GCI $instPath -Filter *.exe | Where Name -match 'Ofc_Deploy') -eq $null)
                    { Invoke-WebRequest -uri $urlDeploy -OutFile ($oFile = "$instPath\Ofc_Deploy_$(Get-Date -f yyyy-MM-dd).exe") -Verbose }
                    Else { $oFile = (GCI $instPath -Filter *.exe | Where Name -match 'Ofc_Deploy').FullName }
                
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
                    $cfgConfig = (GCI $instPath -Filter *.xml | Where {$_.Name -match $dst -and $_.Name -match ("_"+$bits+"_")})
                    SL $instPath\$dst
                    Copy-Item $cfgConfig.FullName
                    Start-Process -FilePath $cfgTool -ArgumentList "/download $($cfgConfig.Name)" -Wait
            }
            'Install'
            {
                # load install and install Office
                    $dplyTool = "Setup.exe"
                    $cfgConfig = (GCI $instPath -Filter *.xml | Where {$_.Name -match $dst -and $_.Name -match ("_"+$bits+"_")})
                    SL $instPath\$dst
                    Start-Process -FilePath $dplyTool -ArgumentList "/configure $($cfgConfig.Name)" -Wait
            }
        }
    }
    Install-Office -mode DLoad -bits 32
    Install-Office -mode Config -bits 32
    Install-Office -mode Install -bits 32
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
    SL $mctDir
    $cfg = '/Eula Accept /Retail /MediaLangCode en-us /MediaArch x64 /MediaEdition Enterprise'
    Invoke-WebRequest -Uri $mct10  -OutFile Win10-22H2.exe
    Invoke-WebRequest -Uri $mct11  -OutFile Win11-23H2.exe
    Start-Process -FilePath 'Win10-22H2.exe' -ArgumentList $cfg
    Start-Process -FilePath 'Win11-23H2.exe' -ArgumentList $cfg
   # https://www.microsoft.com/en-US/software-download/


    'https://www.microsoft.com/en-us/evalcenter/download-windows-server-2019'

#endregion
