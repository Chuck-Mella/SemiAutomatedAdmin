# Version 1.9 - Initial Testing
#Requires -RunAsAdministrator
Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
Function Dec64v2 { Param($a) $b = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($a));Return $b }
#region - Post-OS Install tweaks
    Write-Host -f Green "Applying Post OS Install tweaks"
    # Post-OS
        Write-Host -f Cyan "`tSetting CD|DVD path and working dirs"
        $cdPath = ([System.IO.DriveInfo]::getdrives() | Where DriveType -eq 'CDROM' | Where VolumeLabel -ne $null).Name
        $wrkDir = $cdPath + "Add-Ons\Win11_Installs"

    # Create Temp Folder
        Write-Host -f Cyan "`tCreating $env:SystemDrive\Temp"
        New-Item $env:SystemDrive\Temp -ItemType Directory

    # Copy Backgrounds to Windows folder
        Write-Host -f Cyan "`tCopying background images to $env:SystemRoot\Web\Wallpaper\Windows"
        $pngs = "$wrkDir\Final Tweaks\Images"
        Copy-Item -Path "$pngs\*" -Destination "$env:SystemRoot\Web\Wallpaper\Windows" -Force -Confirm:$false    

    # Fix Timezone   timedate.cpl
        $aPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
        $autoTmAdj = Get-ItemProperty $aPath | Select -Exp DynamicDaylightTimeDisabled
        If ($autoTmAdj -ne 0) { Set-ItemProperty $aPath -Name DynamicDaylightTimeDisabled -Type DWord -Value 0 }

        $refTZ = ("TZ`nPacific`nMountain`nCentral`nEastern" | ConvertFrom-Csv | OGV -Title 'Select Timezone' -PassThru).TZ
        If ([String]::IsNullOrEmpty($refTZ)){ $refTZ = "Eastern" }
        $curzone = (Get-WMIObject –Class Win32_TimeZone).Caption
        $destzone = [System.TimeZoneInfo]::FindSystemTimeZoneById("$refTZ Standard Time").DisplayName
        if ($curzone -eq $destzone)
        {
            Write-Host "Current Time Zone already set to:"$curzone
        }
        Else
        {
            C:\Windows\System32\tzutil.exe /s "$refTZ Standard Time"
            $newcurzone = (Get-WMIObject –Class Win32_TimeZone).Caption
            Write-Host "Time Zone updated to:"$newcurzone
        }
        (Dec64 'DQokdGltZSA9IChHZXQtRGF0ZSkuVG9TaG9ydFRpbWVTdHJpbmcoKQ0KV3JpdGUtSG9zdCAiQ3VycmVudCBUaW1lOiAkdGltZSINCiRkZXN0e
                m9uZSA9IFtTeXN0ZW0uVGltZVpvbmVJbmZvXTo6RmluZFN5c3RlbVRpbWVab25lQnlJZCgiJHJlZlRaIFN0YW5kYXJkIFRpbWUiKQ0KJGRlc3
                R0aW1lID0gW1N5c3RlbS5UaW1lWm9uZUluZm9dOjpDb252ZXJ0VGltZUZyb21VdGMoKEdldC1EYXRlKS5Ub1VuaXZlcnNhbFRpbWUoKSwkZGV
                zdHpvbmUpDQokZGVzdHRpbWUgPSAkZGVzdHRpbWUuVG9TaG9ydFRpbWVTdHJpbmcoKQ0KV3JpdGUtSG9zdCAiVVRDJCgkZGVzdHpvbmUuQmFz
                ZVV0Y09mZnNldC5Ib3VycykgPSAkZGVzdHRpbWUiDQppZiAoJG5ld3RpbWUgLWVxICRkZXN0dGltZSl7IFdyaXRlLUhvc3QgIm9rIiB9DQplb
                HNlIHsgQzpcV2luZG93c1xTeXN0ZW0zMlx0enV0aWwuZXhlIC9zICIkcmVmVFogU3RhbmRhcmQgVGltZSIgfQ0KW0N1bHR1cmVJbmZvXTo6Q3
                VycmVudEN1bHR1cmUuQ2xlYXJDYWNoZWREYXRhKCkNCiRuZXd0aW1lID0gKEdldC1EYXRlKS5Ub1Nob3J0VGltZVN0cmluZygpDQpXcml0ZS1
                Ib3N0ICJDdXJyZW50IFRpbWU6ICRuZXd0aW1lIg0K')
        # Write-Host -f Cyan "`tSetting Timezone to 'Eastern'"
        # Set-TimeZone 'Eastern Standard Time'

    # Fix DEP
        Write-Host -f Cyan "`tApplying Stig correction for Data Execution Prevention (DEP) OptOut"
        BCDEDIT /set "{current}" nx Optout # No quotes if run in CMD

    # Set default DA acct pwd to not expire
        $trgAcct = "DoD_Admin"
        Write-Host -f Cyan "`tApplying PWD corrections to ($trgAcct) Account"
        Set-LocalUser -Name $trgAcct -AccountNeverExpires $true

    # Update PS Help (in-work)
        # Write-Host -f Cyan "`tUpdating PowerShell Help files"
        # Update-Help -Recurse -SourcePath xxx
#endregion
#region - Apply STIGs
    Write-Host -f Green "Applying STIGs to local group and security policies"
    # Install Hardened Security Policy
        Write-Host -f Cyan "`tApplying Security Policy modifications"
        $pol = "$wrkDir\Local Policy Tools\Hardened & Tweaked\Win11Ent_SecPol.inf"
        $SecDB = "$env:SystemRoot\securitylocal.sdb"
        secedit.exe /configure /db $SecDB /cfg $pol

    # Install hardened local policy (lgpo from DISA)
        Write-Host -f Cyan "`tApplying Local Group Policy modifications"
        $pthLGPO ="$wrkDir\Local Policy Tools"
        $pthLPOs = "$pthLGPO\Hardened & Tweaked\Win11LocPol\DomainSysvol\GPO"
        Start-Process "$pthLGPO\LGPO_30\LGPO.exe" -ArgumentList "/g","`"$pthLPOs`"","/v"
        # Modifying Local Policies
            # Dec64v2 'cwB1AGIAcwB0ACAAYQA6ACAAJwBVADoAXABJAHMAbwBMAGEAYgBcAEkAUwBPAFwAQQBkAGQALQBPAG4AcwBcAFcAaQBuADEAMQBfAEkAbgBzAHQAYQBsAGwAcwBcAEwAbwBjAGEAbAAgAFAAbwBsAGkAYwB5ACAAVABvAG8AbABzAFwASABhAHIAZABlAG4AZQBkACAAJgAgAFQAdwBlAGEAawBlAGQAXABXAGkAbgAxADEATABvAGMAUABvAGwAXABEAG8AbQBhAGkAbgBTAHkAcwB2AG8AbABcAEcAUABPACcADQAKAHMAdQBiAHMAdAAgAGIAOgAgACcAVQA6AFwASQBzAG8ATABhAGIAXABJAFMATwBcAEEAZABkAC0ATwBuAHMAXABXAGkAbgAxADEAXwBJAG4AcwB0AGEAbABsAHMAXABMAG8AYwBhAGwAIABQAG8AbABpAGMAeQAgAFQAbwBvAGwAcwBcAEwARwBQAE8AXwAzADAAJwANAAoAYgA6AFwAbABnAHAAbwAuAGUAeABlACAALwBiACAAQwA6AFwAVABlAG0AcAAgAC8AbgAgABwgQgBhAGMAawB1AHAAHSANAAoADQAKAGIAOgBcAEwARwBQAE8ALgBlAHgAZQAgAC8AcABhAHIAcwBlACAALwBtACAAIgBhADoAXABtAGEAYwBoAGkAbgBlAFwAcgBlAGcAaQBzAHQAcgB5AC4AcABvAGwAIgAgAD4APgAgAEMAOgBcAFQAZQBtAHAAXABsAGcAcABvAC4AdAB4AHQADQAKAGIAOgBcAEwARwBQAE8ALgBlAHgAZQAgAC8AcABhAHIAcwBlACAALwB1ACAAIgBhADoAXABVAHMAZQByAFwAcgBlAGcAaQBzAHQAcgB5AC4AcABvAGwAIgAgAD4APgAgAEMAOgBcAFQAZQBtAHAAXABsAGcAcABvAC4AdAB4AHQADQAKAA0ACgAjACAATQBvAGQAaQBmAHkAIAB0AHgAdAAgAGYAaQBsAGUADQAKAA0ACgBiADoAXABMAEcAUABPAC4AZQB4AGUAIAAvAHIAIABDADoAXABUAGUAbQBwAFwAbABnAHAAbwAuAHQAeAB0ACAALwB3ACAAIgBhADoAXABtAGEAYwBoAGkAbgBlAFwAcgBlAGcAaQBzAHQAcgB5AC4AcABvAGwAIgAgAC8AdgANAAoAYgA6AFwATABHAFAATwAuAGUAeABlACAALwByACAAQwA6AFwAVABlAG0AcABcAGwAZwBwAG8ALgB0AHgAdAAgAC8AdwAgACIAYQA6AFwAVQBzAGUAcgBcAHIAZQBnAGkAcwB0AHIAeQAuAHAAbwBsACIAIAAvAHYADQAKACMAIABiADoAXABMAEcAUABPAC4AZQB4AGUAIAAvAHQAIABDADoAXABUAGUAbQBwAFwAbABnAHAAbwAuAHQAeAB0AA0ACgAjACAARwBQAFUAUABEAEEAVABFACAALwBGAE8AUgBDAEUADQAKAGIAOgBcAA=='
#endregion
#region - Add/Remove features
    Write-Host -f Green "Add|Remove OS Features"
    # Add DotNet 3.5 Support (in-work)
        Write-Host -f Cyan "`tEnabling DotNet 3.5 Support"
        Enable-WindowsOptionalFeature -Online -FeatureName NetFx3

    # Disable PowerShell v2
        Write-Host -f Cyan "`tRemoving PowerShell v2"
        Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

    # Disable Defender FW (If Policies fail)
        # Write-Host -f Cyan "`tDisabling Windows Defender Firewall"
        # Set-NetFirewallProfile -Profile <#Domain,#>Public,Private -Enabled False
#endregion
#region - Add icons to Public desktop
    Write-Host -f Green "Adding Icons to the Public Desktop"
    # Add 'Icon Restore' to Public Desktop
        Write-Host -f Cyan "`tCreating 'Icon Restore'"
	    $WScriptShell = New-Object -ComObject WScript.Shell
	    $ShortcutFile = [Environment]::GetFolderPath('CommonDesktopDirectory') + "\Restore Icons (Restart Explorer).lnk"
	    $Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
	    $Shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
	    $Shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -Command "& {Stop-Process -Name explorer -Force}"'
	    $Shortcut.IconLocation = "$env:SystemRoot\System32\user32.dll,6"
	    $Shortcut.Save()

    # Add 'GodMode' shortcut to Public Desktop
        Write-Host -f Cyan "`tCreating 'God-Mode'"
        New-Item -Path ([Environment]::GetFolderPath('CommonDesktopDirectory')) -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType "Directory"
#endregion
#region - Add connectors and policy defs
    Write-Host -f Green "Adding ODBC Connectors & Policy definitions"
    # Add ODBC connector for AssetManager DB (as Needed)
        Write-Host -f Cyan "`tCreating 'Asset Management' connector"
        $cfgODBC1 = [ordered] @{
            Name = 'AssetMgmt2010'
            DriverName = 'SQL server'
            Platform = '32-bit'
            DsnType = 'system'
            }
        $cfgODBC2 = @("Description=Asset Management Database","server=SQLSVR2","Trusted_connection=Yes","Database=AssetMng2010")
        Add-odbcDsn @cfgODBC1 -setPropertyvalue $cfgODBC2

    # Add NetBanner Policy Templates to local store
        Write-Host -f Cyan "`tAdding NetBanner Policy Templates to local store"
        $pthDefs = "$env:SystemRoot\PolicyDefinitions"
        $pthDefl = "$pthDefs\en-US"
        $pthRepo = "$wrkDir\SHB Core Required\Microsoft NetBanner - 210211\Files\x86\Settings"
        GCI $pthRepo -Filter '*.admx' | %{ Copy-Item $_.FullName -Destination $pthDefs -Force -Confirm:$false -WhatIf }
        GCI $pthRepo -Filter '*.adml' | %{ Copy-Item $_.FullName -Destination $pthDefl -Force -Confirm:$false -WhatIf }
#endregion
#region - Add Fonts
    Write-Host -f Green "Adding Fonts"
    # Install Fonts
        Write-Host -f Cyan "`tInstalling for all users"
        $ShellObject = New-Object -ComObject shell.application
        $Fonts = $ShellObject.NameSpace(0x14)

        $FontsToInstallDirectory = "$wrkDir\Final Tweaks\_Fonts"
        $FontsToInstall = Get-ChildItem $FontsToInstallDirectory -Recurse -Include '*.ttf','*.ttc','*.otf'

        $Ctr = 1
        $Total = $FontsToInstall.Count

        ForEach ($F in $FontsToInstall){
            $FullPath = $F.FullName
            $Name = $F.Name
            $UserInstalledFonts = "$ENV:USERPROFILE\AppData\Local\Microsoft\Windows\Fonts"
            If (!(Test-Path "$UserInstalledFonts\$Name")){
                $Fonts.CopyHere($FullPath)
                Write-Host "[$Ctr of $Total] || Installed Font [$Name]..." -ForegroundColor Cyan
            }
            else{
                Write-Host "[$Ctr of $Total] || Font [$Name] is already installed..." -ForegroundColor Green
            }
            $Ctr++
        }
        # Dec64 'DQpmdW5jdGlvbiBJbnN0YWxsLUZvbnQgew0KcGFyYW0oDQpbUGFyYW1ldGVyKE1hbmRhdG9yeSldDQpbc3RyaW5nXSRGaWxlTmFtZQ0KKQ0KDQokc2lnbmF0dXJlID0gQCcNCltEbGxJbXBvcnQoImZvbnRleHQuZGxsIiwgQ2hhclNldCA9IENoYXJTZXQuQXV0byldDQpwdWJsaWMgc3RhdGljIGV4dGVybiB2b2lkIEluc3RhbGxGb250RmlsZShJbnRQdHIgaHduZCwgc3RyaW5nIGZpbGVQYXRoLCBpbnQgZmxhZ3MpOw0KJ0ANCg0KJGZvbnRleHRkbGwgPSBBZGQtVHlwZSAtTWVtYmVyRGVmaW5pdGlvbiAkc2lnbmF0dXJlIC1OYW1lIEludm9rZSAtTmFtZXNwYWNlIEluc3RhbGxGb250RmlsZSAtUGFzc1RocnUNCiRmb250ZXh0ZGxsOjpJbnN0YWxsRm9udEZpbGUoIChHZXQtUHJvY2VzcyAtSWQgJHBpZCkuTWFpbldpbmRvd0hhbmRsZSwgJEZpbGVOYW1lLCAwICkNCn0NCkluc3RhbGwtRm9udCAiQzpcVXNlcnNcYWRtaW5DTVxEZXNrdG9wXFdpbjExX0luc3RhbGxzXEZpbmFsIFR3ZWFrc1xfRm9udHNcMzc4OThfdGltZXNfbjEudHRmIg0K'
#endregion
#region - Install Browser(s)
    Write-Host -f Green "Adding Required Browsers"
    # Install required browsers
        Write-Host -f Cyan "`tSelecting browser(s) to be installed"
        $trgApps = GCI "$wrkDir\Final Tweaks\Other Apps\2024-07 Updates" -Recurse -File | where Name -match '(chrome|Edge|Fox)'
        $newobject = new-object -comobject wscript.shell
        # Add-Type -AssemblyName System.Windows.Forms
        ForEach ($app in $trgApps)
        {
            $InstB = $newobject.popup($app.name,5,"Do you want to run installer? (Exit in 5 sec)",4)
            # $InstB = [System.windows.Forms.MessageBox]::show($app.name,'Do you want to run installer?','YesNo','Question' )
            If ($InstB -eq 'No' -or $InstB -eq 7 -or $InstB -eq -1){ CONTINUE }
            Else
            {
                switch ($app.FullName)
                {
                    {$_ -match 'Edge' } { $sw = '/passive' }
                    {$_ -match 'chrome' } { $sw = '/silent /install' }
                    {$_ -match 'Fox' } { $sw = '-ms' }
                    {$_ -match 'AcroRdr' } { $sw = '/qPB' }
                }
                start-Process -FilePath $app.FullName -ArgumentList $sw -wait
            }
        }
#endregion
#region - Install Office
    Write-Host -f Green "Installing Office"
    Write-Host -f Cyan "`tInstalling version 2019"
    $srcDir = (GCI "$wrkDir\Final Tweaks\Other Apps" -Directory | Where Name -Match '\d{4}\-\d{2}\-\d{2}').FullName
    $trgDir = 'B:'
    Subst $trgDir $srcDir
    Set-Location $trgDir
    Start-Process -FilePath "$trgDir\Setup.Exe" -ArgumentList '/configure',$((GCI $trgDir -Filter '*.XML' ).FullName) -Wait
    Set-Location $env:SystemDrive
    Subst $trgDir /d
#endregion
#region - Install DoD Certs
    Write-Host -f Green "Installing DoD Certs"
    Write-Host -f Cyan "`tInstalling to default store"
    $srcDir = "$wrkDir\SHB Core Required\DoD NIPR Certificates"
    $trgDir = 'B:'
    Subst $trgDir $srcDir
    Set-Location $trgDir
    Write-Host -f Cyan "Installing SHB Core Required - DOD NIPR Certificates"
    Start-Process -FilePath "$trgDir\Deploy-application.exe" -ArgumentList "-DeployMode 'NonInteractive'" -Wait
    Set-Location $env:SystemDrive
    Subst $trgDir /d
#endregion
#region - NetBanner
    Write-Host -f Green "Installing NetBanner"
    Write-Host -f Cyan "`tInstalling|Configuring application"
    $srcDir = "$wrkDir\SHB Core Required\Microsoft NetBanner - 210211"
    $trgDir = 'B:'
    Subst $trgDir $srcDir
    Set-Location $trgDir
    Write-Host -f Cyan "Installing SDC Microsoft NetBanner"
    Start-Process -FilePath "$trgDir\Deploy-application.exe" -ArgumentList "-DeployMode 'NonInteractive'" -Wait
    Set-Location $env:SystemDrive
    Subst $trgDir /d
#endregion
#region - Install ADReader or Acrobat PENDING
    # Write-Host -f Green "Installing Adobe"
    # Write-Host -f Cyan "`tInstalling Acrobat Pro DC"
    # Write-Host -f Cyan "`tInstalling Acrobat Reader DC"
#endregion
#region - Remove Apps (Bloatware)
    Write-Host -f Green "Removing Un-needed Apps (Bloatware)"
    $lstApps = ('3dbuilder','alarms','AV1Video','communications','Clipchamp','549981C3F5F10','ECApp','Feedback','GamingApp','GetHelp','officehub','getstarted','HEIF','maps','RawImage','solitaire','Todos','MixedReality','Zune','BingNews','OneDriveSync','people','photos','PowerAutomate','skype','Spotify','StickyNotes','sway','Teams','soundrecorder','VP9VideoExtensions','WebpImage','WebExperience','camera','Xbox','yourphone')
    Write-Host -f Cyan "`tRemoving $($lstApps.Count) applications"
    $remApps = "($($lstApps -join '|'))"
    # Failed removes: Microsoft.Windows.CapturePicker  Microsoft.XboxGameCallableUI

    $trgApps = Get-AppxPackage | Where Name -match $remApps | Select -Exp Name
    $trgApps | %{ Get-AppxPackage $_ | Remove-AppxPackage -AllUsers -Verbose }
    # Disable Bloatware Vs Removal
	  # Computer| AdminTmplts | WindowsComponents | App Privacy > “Let Windows Apps Access Trusted Devices” Set to Enabled
	  #  Force Deny by PackageFamilyName (PFN)
#endregion
#region - WKS Final Tweaks
    Write-Host -f Green "Applying Workstation Final Tweaks"
    # Kill tasks for auto updates
        Write-Host -f Cyan "`tDisabling application auto-updates tasks"
    	$trgTasks = '(Google|Fox|Edge|Adobe|oneDrive)'
        Get-scheduledTask | where TaskName -Match $trgTasks | Stop-ScheduledTask -verbose
        Get-scheduledTask | where TaskName -Match $trgTasks | Disable-ScheduledTask -verbose
    <#
        #region -  Modify backgroud images (In-Work)
            Write-Host -f Cyan "`tModifying background image text data"
            # $Overline = [char]::ConvertFromUtf32(0x203e)
            $net = 'R'
            $env = @{G='VU5DTEFTU0lGSUVE';R='U0VDUkVU';P='U0VDUkVULy9TQVI=';Y='VE9QIFNFQ1JFVC8vU0NJ'}
            $txt = @{H1='VEhJUyBJTkZPUk1BVElPTiBTWVNURU0gSVMgQUNDUkVESVRFRCBUTyBQUk9DRVNT';H5='Rk9SIEFVVEhPUklaRUQgUFVSUE9TRVMgT05MWQ==';F='Rm9yIElUIFN1cHBvcnQgcGxlYXNlIGNhbGwgNzAzLTQyOC05MDM5'}
            $Texts = [Collections.ArrayList]@()
              ((Dec64 $txt.H1),'Stencil',28),(('‾' * 49),'Stencil',28),
              ((Dec64 $env.$net),'Stencil',72),(('_' * 49),'Stencil',28),
              ((Dec64 $txt.H5),'Stencil',28),
              ((Dec64 $txt.F),'Arial Narrow',28)|%{
                $rst = @{} | Select-Object Font,Size,Text
                $rst.Font = $_[1]
                $rst.Size = $_[2]
                $rst.Text = $_[0]
                $null = $Texts.Add($rst)
                }
            $Texts
        #endregion

        $env1.g = @{G='VU5DTEFTU0lGSUVE';R='U0VDUkVU';P='U0VDUkVULy9TQVI=';Y='VE9QIFNFQ1JFVC8vU0NJ'} | ConvertFrom-Csv -Header Env,Text
    #>
#endregion

# Toggle taskbar auto-hide ideas
    <#
        Function Toggle-Taskbar
        {
            # Toggle taskbar auto-hide 122 - off  123 - on (Other code uses 02 and 03)
            $location = @{Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3'; Name = 'Settings'}
            $value = Get-ItemPropertyValue @location
            $value[8] = if ($value[8] -Eq 122) {123} Else {122}
            Set-ItemProperty @location $value
            Stop-Process -Name Explorer
        }
    #>
 # https://www.tenforums.com/tutorials/23817-turn-off-auto-hide-taskbar-desktop-mode-windows-10-a.html
 # How do I local policy this? Run following as a logon script via local policy
    # powershell -ExecutionPolicy bypass -command "&{$p='HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3';$v=(Get-ItemProperty -Path $p).Settings;If ($v[8] -eq 2){$v[8]=3;&Set-ItemProperty -Path $p -Name Settings -Value $v;&Stop-Process -f -ProcessName explorer}}"
#region - Support Links
    [ValidateSet('msedge','chrome','Firefox')]$prefBrwsr = "chrome"
    $url = ("TB Support Center,https://connect.na.panasonic.com/toughbook/support
        TB Support Search,https://global-pc-support.connect.panasonic.com/
        TB Client DXeployment Support,https://dl-pc-support.connect.panasonic.com/itn/drivers/deployment_support.html
        Drivers - TB Support,https://global-pc-support.connect.panasonic.com/recv-dls-w11
        
        Win11 Recovery Img,https://dl-pc-support.connect.panasonic.com/public/soft_update/d_appli/recvdiscdl/recvdiscdl_manual_w11w10_e_r10.pdf
        " | ConvertFrom-Csv -Header Site,Link | OGV -Title 'Select Support Site' -PassThru).Link

    [system.Diagnostics.Process]::Start($prefBrwsr,$url)
#endregion






