# Updates
If ((gwmi Win32_LogicalDisk | Where VolumeName -match "(Jenny|Fortress)").DeviceID -eq $null){ $xferDrive = 'C:\TEMP' }
Else { $xferDrive = (gwmi Win32_LogicalDisk | Where VolumeName -match "(Jenny|Fortress)").DeviceID }
If ($xferDrive -eq $null){ BREAK }
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

#region - Office (Currently: Office Pro 2019 Plus)
    Function Install-Office
    { 
        Param
        (
            [ValidatePattern('(DLoad|Config|Install)')]$mode = 'DLoad',
            [ValidatePattern('(32|64)')][string]$bits = 32,
            $instPath = "U:\_Monthly_Updates\Office Deployment Tools"
        )
        $urlODT = 'https://www.microsoft.com/en-us/download/details.aspx?id=49117'
        $urlDeploy = ((Invoke-WebRequest -uri $urlODT).Links | Where InnerText -eq 'Download').href
        $urlConfig = 'https://config.office.com/deploymentsettings'
        $dst = [string](Get-Date -f yyyy-MM-dd)
        If ((Test-path -Path $instPath -PathType Container) -eq $false){ New-Item -Path $instPath -ItemType Directory -Force }
        Switch ($mode)
        {
            'DLoad'
            {
                # Check for Insaller file and DL if needed
                    $oFile = (GCI $instPath -Filter *.exe | Where Name -match 'Ofc_Deploy' | Sort | Select -Last 1)
                    If ($oFile -eq $null)
                    { Invoke-WebRequest -uri $urlDeploy -OutFile ($oFile = "$instPath\Ofc_Deploy_$(Get-Date -f yyyy-MM-dd).exe") -Verbose }
                    Else { $oFile = $oFile.FullName }
                
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
                    $cfgConfig = (GCI $instPath -Filter *.xml | Where {$_.Name -match ("_"+$bits+"_")})
                    SL $instPath\$dst
                    Copy-Item $cfgConfig.FullName
                    Start-Process -FilePath $cfgTool -ArgumentList "/download ..\$($cfgConfig.Name)" -Wait
            }
            'Install'
            {
                # load install and install Office
                    $dplyTool = "Setup.exe"
                    $cfgConfig = (GCI $instPath -Filter *.xml | Where {$_.Name -match ("_"+$bits+"_")})
                    SL $instPath\$dst
                    Start-Process -FilePath $dplyTool -ArgumentList "/configure ..\$($cfgConfig.Name)" -Wait
            }
        }
    }
    Install-Office -mode DLoad -bits 32 -instPath "U:\_Monthly_Updates\Office Deployment Tools"
    Install-Office -mode Config -bits 32 -instPath "U:\_Monthly_Updates\Office Deployment Tools"
    Install-Office -mode Install -bits 32 -instPath "U:\_Monthly_Updates\Office Deployment Tools"
#endregion

