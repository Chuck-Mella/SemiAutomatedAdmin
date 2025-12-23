 #region - Build-Code.psl
        Param ($action)
        #region - Functions Etc..
            Function Dec64 {Param($a) $b = [System.Text.Encoding]::ASCII.Getstring([System.Convert]::FromBase64String($a));Return $b };
            Function Enc64 { Param ($a) $b = [System.convert]::ToBase64String($a.TocharArray()); Return $b}
        #endregion
        Switch ($action)
        {
            '01'
            {
                #region update Powershell Help Files
                    $params = @{
                        Name = 'Updts'
                        PSProvider = 'Filesystem'
                        Root = "\\ad-east\ad-it\scripts\Chuck PSDev\psHelp"
                        credential = (Get-Credential -UserName 'DOMAIN\ADMIN' -Message 'Enter PWD' )
                        }
                    New-PSDrive @params
                    update-help -sourcePath updts:\ # -credential (Get-Credential -UserName 'DOMAIN\ADMIN' -Message 'Enter PWD' )


                    #region - Update-Help
                        Save-Help -DestinationPath C:\Temp\psHelp

                        Function Get-UpdateHelpVersion
                        {
                            Param
                            (
                                [parameter(Mandatory=$False)]
                                [String[]]
                                $Module
                            )      

                            $HelpInfoNamespace = @{helpInfo="http://schemas.microsoft.com/powershell/help/2010/05"}
                            if ($Module) { $Modules = Get-Module $Module -ListAvailable | where {$_.HelpInfoUri} }
                            else { $Modules = Get-Module -ListAvailable | where {$_.HelpInfoUri} }
                            foreach ($mModule in $Modules)
                            {
                                $mDir = $mModule.ModuleBase
                                if (Test-Path $mdir\*helpinfo.xml)
                                {
                                    $mName=$mModule.Name
                                    $mNodes = dir $mdir\*helpinfo.xml -ErrorAction SilentlyContinue |
                                        Select-Xml -Namespace $HelpInfoNamespace -XPath "//helpInfo:UICulture"
                                    foreach ($mNode in $mNodes)
                                    {
                                        $mCulture=$mNode.Node.UICultureName
                                        $mVer=$mNode.Node.UICultureVersion
                                        [PSCustomObject]@{"ModuleName"=$mName; "Culture"=$mCulture; "Version"=$mVer}
                                    }
                                }
                            }
                        }
                        Get-Module -l | Where Name -match 'Hyper-V' | %{ Get-UpdateHelpVersion -Module $_.Name } | Sort Version
                    #endregion

                #endregion
            }
            '02'
            {
                #region - Install Office
                    $trgDir = (GCI C:\Temp -Directory -Recurse | where Name -Match '\d{4}\\d{2}\*\d{2}' ).FullName
                    Start-Process -FilePath "$trgDir\Setup.Exe" -ArgumentList "/configure
                    $((GCI $trgDir -Filter '*.XML' ).FullName)" -wait
                    #subst x: c: \ Temp\YYYY-MM-DD (replace with DL'd folder name)
                    #X:

                    # Kill Office Online nag
                    Set-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Common\General -Name PreferCloudSaveLocations -Type DWord -Value 0x0
                    New-Item -Path HKCU:\Software\Microsoft\Office\16.0\Common -Name SignIn -ItemType Directory
                    Set-ItemProperty -Path HKCU:\Software\Microsoft\Office\16.0\Common\SignIn -Name SignInOptions -Type DWord -Value 0x3

            }
            '03'
            {
                #Setup /configure (XML 32 -bit)
                #C:
                #Subst x: /D
                #endregion
                # Install browsers and Adobe Reader
                $trgApps = GCI c:\Temp -Recurse -File | where Name -match '(AcroRdrlchromeiEdgeiFox)'
            }
            '04'
            {
                ForEach ($app in $trgApps)
                {
                    switch ($app.FullName)
                    {
                        {$_ -match 'Edge' } { $sw = '/passive' }
                        {$_ -match 'chrome' } { $sw = '/silent /install' }
                        {$_ -match 'Fox' } { $sw = '-ms' }
                        {$_ -match 'AcroRdr' } { $sw = '/qPB' }
                    }
                    start-Process -FilePath $app.FullName -ArgumentList $sw -wait
                    # Install TITUS
                    Start-Process -FilePath '\\ad-east\SWLib\(U) TITUS\TITUS Classification Clients\TITUSClassificationSetup.exe' -Wait
                }
            }
            '05'
            {
            }
            '06'
            {
                # Install Trellix
                Start-Process -FilePath '\\ad-east\SWLib\(U) McAfee\Trellix_Agent_Mar2023.exe' -wait

                # Install scanners
                # Epson
                Start-Process -FilePath '\\ad-east\SWLib\(U) scanner\EPSON ds860\DS860_ES2_6.4.3.0.exe' -wait -verbose
                Start-Process -FilePath '\\ad-east\SWLib\(U) scanner\EPSON ds860\DS860_ISIS_l_6_11810_25002_AM.exe' -wait -verbose
                # Cannon
                Start-Process -FilePath '\\ad-east\SWLib\(U) scanner\Canon DR*C240\DRC240_Driver_V.l.4.11712.18001SP3_windows\DR-C240_Driver_l.4.11712.18001SP3.exe' -wait -verbose
                start-Process -FilePath '\\ad-east\SWLib\(U) scanner\Canon DRC240\CaptureOnTouch_Pro_v5.1.1523.718\setup.exe' -wait -Verbose
            }
            '07'
            {
                #Asset Management connector
                $cfgODBC1 = [ordered] @{
                    Name = 'AssetMgmt2010'
                    DriverName = 'SQL server'
                    Platform = '32-bit'
                    DsnType = 'system'
                    }
                $cfgODBC2 = @("Description=Asset Management Database","server=SQLSVR2","Trusted_connection=Yes","Database=AssetMng2010")
                Add-odbcDsn @cfgODBC1 -setPropertyvalue $cfgODBC2
            }
            '08'
            {

            }
            '09'
            {
                # DEP
                BCDEDIT /set "{current}" nx Optout # No quotes if run in CMD
                Pause
            }
            '10'
            {
                # Move \TEMP files
                Move-Item -Path 'C:\Temp\RDCMan.exe' -Destination 'c:\Windows\System32' -Force -verbose
                Move-Item -Path 'C:\Temp\DfltFileAssoc.xml' -Destination 'c:\Windows\System32' -Force -verbose
                Move-Item -Path 'C:\Temp\img*. jpg' -Destination 'C:\Windows\Web\WallPaper\Windows' -Force -verbose
                Move-Item -Path 'c:\Temp\Restore Icons (restart explorer).lnk'-Destination 'C :\Users\Public\Desktop' -Force -verbose
                Move-Item -Path 'c:\Temp\RDP Manager.lnk' -Destination 'C:\Users\Public\Documents' -Force -verbose
                Move-Item -Path 'C:\Temp\StartLayout.xml' -Destination 'C:\Users\Public\Documents' -Force -verbose
                GCI C:\Temp -Recurse | where Name -NotMatch 'Build_code' | Remove-Item -Recurse -Force -confirm: $false -verbose
            }
            '11'
            {
                # set wallpapers
                # Set File ASSOC
                # Set file associations (Ignore ADD ROM FILE EXT MAP error)
                DISM /Online /ImportDefaultAppAssociations:c:\Windows\System32\DfltFileAssoc.xml
                # GPEdit (as Admin): computer|Administrative Templates|windows components|File Explorer - 'set a default associations configuration file' Enabled, point to DfltFileAssoc.xml
            }
            '12 '
            {
                # Left Justify Taskbar
                New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
                $tbarPath = 'HKU:\.DEFAULT\Software\Microsoft\Windows\Currentversion\Explorer\Advanced'
                $pthTest = Test-Path $tbarPath
                If (!$pthTest){ New-Item -path ($tbarPath -replace '\\+[A\\]+$') -Name 'Advanced' } #
                Set-ItemProperty $tbarPath -Name TaskbarAl -value 0 -Force # 0-Left 1-center 2-Right
                Get-ItemProperty $tbarPath | select TaskbarAl

            }
            '13'
            {
                # Disable widgets
                #region - optional Disable Widgets
                    $trgPath = 'HKLM:\SOFTWARE\Policies\Microsoft'
                    $pthTest = Test-Path "$trgPath\Dsh"
                    If (!$pthTest)
                    {
                        New-Item -path $trgPath -Name 'Dsh'
                        set-ItemProperty "$trgPath\Dsh" -Name AllowNewsAndInterests -value 0 -Force # 0-Disable 1-Enable
                        Get-ItemProperty "$trgPath\Dsh" | select AllowNewsAndInterests
                    }
                #endregion
            }
            '14'
            {
                #Remove Adobe Pro Nag
                $regPath ='HKLM:\SOFTWARE\WOW6432Node\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown'
                Set-ItemProperty $regPath -Name bAcrosuppressupsell -value Ox1
                Get-ItemProperty $regPath | select bAcrosuppressupsell
                #Remove Edge as default PDF reader
                $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
                Set-ItemProperty $regPath -Name AlwaysopenPdfExternally -value Ox1
                Get-ItemProperty $regPath | Select AlwaysopenPdfExternally
            }
            '15'
            {
                #Disable Application update checks (Elevated Powershell)
                $trgTasks = '(Google|Fox|Edge|Adobe|oneDrive)'
                Get-scheduledTask | where TaskName -Match $trgTasks | Stop-ScheduledTask -verbose
                Get-scheduledTask | where TaskName -Match $trgTasks | Disable-ScheduledTask -verbose
            }
            '16'
            {
                # Remove Defender
            }
            '17'
            {
    $remApps = "(3dbuilder|alarms*|AV1Video|communications|Capture|Clipchamp|549981C3F5F10|
      ECApp|Feedback|GamingApp|GetHelp|officehub|getstarted|HEIF|maps|
      RawImage|solitaire|Todos|MixedReality|Zune|BingNews|OneDriveSync|
      people|photos|PowerAutomate|skype|Spotify|StickyNotes|sway|Teams|soundrecorder|
    VP9VideoExtensions|WebpImage|WebExperience|camera|Xbox|yourphone)"

    $trgApps = Get-AppxPackage | Where Name -match $remApps | Select -Exp Name
    $trgApps | %{ Get-AppxPackage $_ | Remove-AppxPackage -AllUsers -Verbose }
        Desktop Installer,Get-AppxProvisionedPackage -Online | ? PackageName -match 'desktopI' | Remove-AppxProvisionedPackage -Online -AllUsers
               #Remove windows Bloatware
                ### FIX ### FIX ### FIX ### $appData = (Dec64 'DQozRCBCdWlsZGVyLEdldC1BcHB4UGFja2FnZSAqM2RidWlsZGVyKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCkFsYXJtcyAmiENsb2NrLEdldC1BcHB4UGFja2FnZSAqYWxhcm1zKiB8IFJlbW92ZS1BcHB4UGFja2FnZSxZLFkNCkFWMSBDb2RlYyxHZXQtQXBweFBhY2thZ2UgKkFWMVZpZGVvRXh0ZW5zaW9uKiB8IFJlbW92ZS1BCHB4UGFja2FnZSXZLFkNCkNhbGN1bGF0b3IsR2VOLUFwcHhQYWNrYWdliCpjYWxjdWxhdG9yKiB8IFJlbW92ZS1BcHB4UGFja2FnZSxOLE4NCkNhbGVuZGFyiGFuZCBNYWlsLEdldC1BcHB4UGFja2FnZSAqY29tbXVuaWNhdGlvbnNhcHBzKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCkNhcHRlcmUgUGlja2VyLEdldC1BcHB4UGFja2FnZSAqQ2FwdHVyZVBpY2tlcio9fCBSZW1vdmUtQXBweFBhY2thZ2UsSSXJDQpDbGlwiENoYW1wLEdldC1BcHB4UGFja2FnZSAqQ2xpcGNoYW1WKlB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCkNvcnRhbmEsR2V0LUFwcHhQYWNrYWdliCpNaWNyb3NvZnQuNTQ50TgXQZNGNUYXMCogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSXZDQpEZXNrdG9wiEluc3RhbGxlcixHZXQtQXBweFByb3Zpc2lvbmVkUGFja2FnZSAtT25saW5liHwgPyBQYWNrYWdlTmFtZSAtbWF0Y2ggiCpkZXNrdG9wSSogfCBSZW1vdmUtQXBweFByb3Zpc2lvbmVkUGFja2FnZSAtT25saW5liC1BbGxVc2VycyxJLEkNCkVDQXBWLEdldC1BcHB4UGFja2FnZSAqRUNBCHAqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLEksSQ0KRmVlZGJhY2sgSHViLEdldC1BcHB4UGFja2FnZSAqV2luZG93c0ZlZWRiYWNrSHViKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCkdhbWluZ0FwcHMsR2V0LUFWCHhQYWNrYWdliCpHYW1pbmdBcHAqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFksWQ0KR2V0IEhlbHAgYXBWLEdldC1BCHB4UGFja2FnZSAqR2V0SGVscCogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSXZDQpHZXQgT2ZmaWNliHwgTVMgT2ZmaWNlLEdldC1BcHB4UGFja2FnZSAqb2ZmaWNlaHViKiB8IFJlbW92ZS1BCHB4UGFja2FnZSXZLFkNCkdldCBTdGFydGVkLEdldC1BcHB4UGFja2FnZSAqZ2V0c3RhcnRlZCogfCBSZW1vdmUtQXBWeFBhY2thZ2UsWSXZDQpiRUlGIGltYWdliHN1cHBvcnQsR2V0LUFWCHhQYWNrYWdliCpiRUlGSW1hZ2VFeHRlbnNpb24qiHWgUmVtb3ZlLUFwcHhQYWNrYWdlLE4sTg0KTWFwcyxHZXQtQXBweFBhY2thZ2UgKm1hcHMqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFkSWQ0KTWljcm9zb2Z0IEVkZ2UsR2V0LUFwcHhQYWNrYWdliCpNaWNyb3NvznRFZGdlKiB8IFJlbW92ZS1BCHB4UGFja2FnZSxOLE4NCk1pY3Jvc29mdCBTb2xpdGFpcmUgQ29sbGVjdGlvbixHZXQtQXBweFBhY2thZ2UgKnNvbG10YWlyZSogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSxZDQpNaWNyb3NvZnQgU3RvcmUsR2V0LUFwcHhQYWNrYWdliCp3aW5kb3dzc3RvcmUqiHwgUmVtb3ZlLUFWCHhQYWNrYWdlLEksSQ0KTWljcm9zb2Z0IFRvLURVLEdldC1BcHB4UGFja2FnZSAqVG9kb3MqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFksWQ0KTW14ZWQgUmVhbG10eSBQb3J0YWwsR2V0LUFwcHhQYWNrYWdliCpNaXhlZFJlYWXpdHkqiHWgUmVtb3ZlLUFWCHhQYWNrYWdlLFksWQ0KTW92aWVziGFUZCBUVixHZXQtQXBweFBhY2thZ2UgKlplbmVWaWRlbyogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSXZDQpNUyBQYWludCXHZXQtQXBweFBhY2thZ2UgK1BhaW50KiB8IFJlbW92ZS1BcHB4UGFja2FnZSxOLE4NCk11c2ljiGFwcCxHZXQtQXBweFBhY2thZ2UgKlp1bmVNdXNpYyogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSxZDQpOZXdziGFwcCxHZXQtQXBweFBhY2thZ2UgKkJpbmdOZXdzKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCk5ld3MvU3BvcnRziCYgV2VhdGhlciBhcHBZLEdldC1BcHB4UGFja2FnZSAqYmluZyogfCBSZW1vdmUtQXBweFBhY2thZ2UsWSXZDQpOb3RlcGFkLEdldC1BcHB4UGFja2FnZSAqV2luZG93c05vdGVWYWQqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLE4sTg0KT251RHJpdmUsR2V0LUFwcHhQYWNrYWdliCpPbmVEcml2ZVN5bmMqiHWgUmVtb3ZlLUFwcHhQYWNrYWdlLEksSQ0KT251Tm90ZSXHZXQtQXBWeFBhY2thZ2UgKm9uZW5vdGUqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLEksSQ0KUGVVCGX1LEdldC1BcHB4UGFja2FnZSAqcGVvcGxlKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXJLEkNClBob3RvcyxHZXQtQXBweFBhY2thZ2UgKnBob3RvcyogfCBSZW1vdmUtQXBweFBhY2thZ2USWSXZDQpQb3dlckF1dG9tYXRlLEdldC1BcHB4UGFja2FnZSAqUG93ZXJBdXRvbWF0ZURlc2t0b3AqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFksWQ0KUG93ZXJTaGVsbCXHZXQtQXBweFBhY2thZ2UgK1Bvd2VyU2hlbGwqiHWgUmVtb3ZlLUFWCHhQYWNrYWdlLE4sTg0KU2NyZWVUICYgU2tldGNoL1NuaXBwaW5niHRvb2wsR2V0LUFwcHhQYWNrvwdliCpTY3JlZW5Ta2V0Y2gqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLE4sTg0KU2t5cGUsR2V0LUFwcHhQYWNrYWdliCpza3lWZSogfCBSZW1vdmUtQXBweFBhY2thZ2UsSSXJDQpTb2xpdGFpcmUgQ29sbGVjdGlvbixHZXQtQXBweFBhY2thZ2UgKk1pY3Jvc29mdFNvbGl0YWlyZUNvbGxlY3Rpb24qiHwgUmVtb3ZlLUFWCHhQYWNrYWdlLFksWQ0KU3BvcnRZLEdldC1BcHB4UGFja2FnZSAqYmluZ3Nwb3J0cyogfCBSZWlvdmUtQXBweFBhY2thZ2UsWSxZDQpTcG90aWZ5LEdldC1BcHB4UGFja2FnZSAqU3BvdGlmeUFCLlNwb3RpZnlNdXNpYyogfCBSZW1vdmUtQXBweFBhY2thZ2UsSSXJDQpTdGlja3kgTm90ZXMsR2V0LUFWCHhQYWNrYWdliCpNaWNyb3NvZnRTdGlja3lOb3RlcyogfCBSZWlvdmUtQXBweFBhY2thZ2UsTixODQpTd2F5LEdldC1BcHB4UGFja2FnZSAqc3dheSogfCByZWlvdmUtQXBweFBhY2thZ2UsSSXJDQpUZWFtcy9DaGF0LEdldClBCHB4UGFja2FnZSAqVGVhbXMqiHwgUmVtb3ZlLUFWCHhQYWNrvwdlLFksWQ0KVm9pY2UgUmVjb3JkZXIsR2V0LUFwcHhQYWNrvwdliCpzb3VuZHJlY29yZGVyKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNClZQOSBWaWRlbyBFeHRlbnNpb25zLEdldC1BcHB4UGFja2FnZSAqVlA5VmlkZW9FeHRlbnNpb25zKiB8IFJlbW92ZS1BcHB4UGFja2FnZSXZLFkNCldlYXROZXIsR2V0LUFwcHhQYWNrYWdliCpCaW5nV2VhdGhlciogfCBSZWlvdmUtQXBweFBhY2thZ2UsWSXZDQpXZWJQIGltvwdliHNlcHBVcnQsR2V0LUFWCHhQYWNrvwdliCpXZWJWSWlhZ2VFeHRlbnNpb24qiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFksWQ0KV2lkZ2V0cyxHZXQtQXBweFBhY2thZ2UgKldlYkV4CGVyaWVuY2UqiHwgUmVtb3ZlLUFWCHhQYWNrYWdlLEksSQ0KV2luZG93cyBDYW1lcmEsR2V0LUFwcHhQYWNrYWdliCpjYW1lcmEqiHwgUmVtb3ZlLUFwcHhQYWNrYWdlLFksWQ0KV2luZG93cyBUZXJtaW5hbCxHZXQtQXBweFBhY2thZ2UgKldpbmRvd3NUZXJtaW5hbCogfCBSZWlvdmUtQXBweFBhY2thZ2UsTixODQpYYm94IGFuZCBhbGwgcmVSYXR1ZCBhcHBzLEdldC1BcHB4UGFja2FnZSAqWGJvecogfCBSZW1vdmUtQXBWeFBhY2thZ2UsSSXJDQpYYm94IEdhbWUgQ2FsbGFibGUsR2V0LUFWCHhQYWNrYWdliCpYYm94R2FtZUNhbGxhYmxlKiB8IFJlbW92ZSlBCHB4UGFja2FnZSXJLEkNClhib3ggR2FtaW5niE92ZXJSYXksR2V0LUFWCHhQYWNrYWdliCpYYm94R2FtaW5nT3ZlcmxheSogfCBSZW1vdmUtQXBWeFBhY2thZ2UsSSXJDQpYYm94IFNWZWVjaCBUbyBUZXh0IE92ZXJsYXksR2VOLUFwcHhQYWNrYWdliCpYYm94U3BlZWNoVG9UZXh0T3ZlcmxheSogfCBSZWlvdmUtQXBweFBhY2thZ2UsSSxJDQpYYm94IFRDVUksR2V0LUFWCHhQYWNrYWdliCpYYm94LlRDVUkqiHWgUmVtb3ZlLUFwcHhQYWNrYWdlLEksSQ0KWW9lciBQaG9uZSBDb21wYW5pb24sR2V0LUFwcHhQYWNrYWdliCp5b3VycGhvbmUqiHwgumvtb3ZlLUFwcHhQvwNrvwdlLFkswQOK') | ConvertFrom-Csv -Delimiter ',' -Header App,RemoveCMD,RmvPurple,RmvYellow
                $rmvApps = ($appData | Where RmvPurple -eq 'y' | select @{n='Command';e={$_.RemoveCMD +'-Allusers -verbose' }}).Command
                $rmvApps | %{ $_; iex $_ }
            }
            '18 '
            {
                # Remove Teams/Chat
                #region - Disable chat Icon - If teams won't unload
                    # Remove from Taskbar
                        $trgPath = 'HKCU:\Software\Microsoft\Windows\Currentversion\Explorer'
                        If ((Get-PSDrive).Name -notcontains 'HKU'){ New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS }
                        $pthTest = Test-Path "$trgPath\Advanced"
                        If (!$pthTest){ New-Item -path $trgPath -Name 'Advanced' }
                        New-ItemProperty "$trgPath\Advanced" -Name TaskbarMn -value 0 -Force # 0-Disable 1-Enable
                        Get-ItemProperty "$trgPath\Advanced" | select TaskbarMn
                    # Remove from Settings
                        $trgPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'
                        $pthTest = Test-Path "$trgPath\windows chat"
                        If (!$pthTest){ New-Item -path $trgPath -Name 'Windows chat'}
                        New-ItemProperty "$trgPath\Windows chat" -Name chaticon -value Ox3 -Force
                        Get-ItemProperty "$trgPath\Windows chat" | select chaticon
                #endregion
            }
            '19'
            {
                # Apply Pre-Defined start Menu
            }
            '20'
            {
                #Local Policy <WSUS> = WSUSSVR:8530
                # Register and sync with domain wsus by opening Powershell (as admin) and run the following code:
                    wuauclt /detectnow
                    $upt = New-Object -ComObject 'Microsoft.update.session'
                    $upt.Createupdatesearcher().search($criteria).Updates
                    wuauclt /reportnow
                #After the current updates are applied, pause updates (5 weeks) by opening Powershell (as admin) and run the following code:
                    $regPath = 'HKLM :\ SOFTWARE\ Microsoft\Windowsupdate\UX\Settings '
                    $pause = (Get-Date).AddDays(35).TouniversalTime().ToString("yyyy-MMddTHH:mm:ssz")

                    Set-ItemProperty -path $regPath -Name PauseupdatesExpiryTime -value $pause
                    Get-ItemProperty -path $regPath | select PauseupdatesExpiryTime
            }
            '21'
            {
                # Register and sync with domain wsus by opening Powershell (as admin) and run following code:
                    wuauclt /detectnow
                    $upt = New-Object -ComObject 'Microsoft.update.session'
                    $upt.CreateUpdatesearcher().Search($criteria).Updates
                    wuauclt /reportnow
                #Delay the Disable Updates
                    $regPath = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
                    $pause = (Get-Date).AddDays(35).ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" );
                    Set-ItemProperty -Path $regPath -Name 'PauseUpdatesExpiryTime' -Value $pause
                    Get-ItemProperty -Path $regPath | Select-Object PauseUpdatesExpiryTime
                    # Disable Service
                    Get-Service WUAU* | Stop-Service -Force
                    Get-Service WUAU* | Set-Service -startupType Disabled
            }
            '22'
            {
                # Remove the printers from the Printers list using Powershell (as Admin) with the following code (Drivers will NOT be removed):
                Get-Printer | where Type -ne 'Local' | Remove-Printer -whatIf
                #  $ptr = qwmi win32_printer | ?{$_.Network -eq $true}
                #  (New-ObJect -comobject wscript.network).RemovePrinterconnection( $ptr)

            }
            '23'
            {
                # Replace Default Profile
            }
            '24'
            {
                #Remove domain profiles
                $regProfiles = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProFileList'
                $regList = ls $regProfiles | where Name -match 'S-\d{1}-\d{1}-\d{2}-+' | select -Exp Name 
                $regList = $regList | %{ $_.split('\')[-1] }
                # $regList = $regList | %{ $x = $_; DO {$X = $x -replace "A\w+(A\\]+\\"} while ($x -match '\\'); Return $x}
                $killList = $regList | %{ Get-ItemProperty "$regProfiles\$_" | select @{n='UserPath';e={ $_.ProfileImagePath}},@{n='Sid';e={$_.PSChildName}}}
                ### FIX ### FIX ### FIX ### where userPath -NotMatch $env:userName
                # Kill user Profile
                $killList | %{ Remove-Item -Path "$regProfiles\$($_.sid)" -Recurse -Force -confirm:$False -whatif }
                # Kill user Dir
                $killList | %{ Remove-Item -Path "$($_.UserPath)" -Recurse -Force -Confirm:$False -whatif }
            }
            '25'
            {
                #region - Edge Address search
                    $trgKey = 'HKLM :\Software\ Policies\ Microsoft\Edge '
                    Get-Item $trgKey
                    Get-ItemProperty $trgKey -Name searchsuggestEnabled
                    Set-ItemProperty $trgKey -Name searchsuggestEnabled -value OxO -whatrf # 1 to enable
                    Remove-ItemProperty $trgKey -Name searchsuggestEnabled
                    #Tutorial: https://www.tenforums.com/tutorials/115069-enable-disableautofill-microsoft-edge-windows-10-a.html
                    $trgKey = 'HKLM :\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main'
                    Get-Item $trgKey
                    Get-ItemProperty $trgKey -Name 'use Formsuggest'
                    Set-ItemProperty $trgKey -Name 'use Formsuggest' -value 'no'
                    Remove-ItemProperty $trgKey -Name 'use Formsuggest'
                    Get-Item HKLM:\SOFTWARE\Policies\Microsoft\Edge
                    Get-Itemproperty HKLM: \ SOFTWARE\Policies\Microsoft\Edge
                    Set-ItemProperty HKLM: \ SOFTWARE\Policies\Microsoft\Edge -Name webwidgetAllowed -value OxO
                    Remove-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Edge -Name webwidgetAllowed
                #endregion
            }
            '26'
            {
                #region - Profilecopy script (run as admin but NOT as profile being copied)
                    #Requires -RunAsAdministrator
                    # Get user Profiles (exclude Hidden & Readonly)
                        $fldrList = Get-childitem C:\Users -Force | where Attributes -notMatch 'Hidden|Readonly'
                        write-Host -f green "select the Profile you want to make the new DEFAULT:"
                        for ($i = 1; $i -le $fldrList.count; $i ++) { write-Host -f yellow "$i - $($fldrList[$i-1]) " }
                        Do {[validatePattern('\d')]$srcchoice = Read-Host "select the Profile Number and press ENTER"} UNTIL($null -ne $srcchoice -AND $srcchoice -le $fldrList.Count)
                        $trgProfile = 'Default'
                        $srcProfile = ($fldrList[$srcchoice-1]).Name
                        write-Host -f c "`n[$srcProfile] Profile has been selected.`n"
                        # Exit if chosen profile matches current user
                        If ($srcProfile -eq $env:userName){ write-warning "script cannot be run under active profile, EXITING!" ; sleep -sec 5; EXIT }
                        Pause
                    # Backup CURRENT Default Profile
                        # backupdefaultprofile
                        attrib -h "C:\Users\Default"
                        if (Test-Path "c:\Users\Default_Backup"){ Remove-Item -Path "C:\Users\Default_Backup" -Force -confirm:$false -verbose }
                        Sleep -seconds 5
                        if (Test-Path "C:\Users\Default_Backup"){ Throw "ERROR - Removal of old Backup Folder Failed!" }
                        Rename-Item "C:\users\Default" "Default_Backup" -Force -confirm:$false
                        if (!(Test-Path "c:\users\Default_Backup")){ Throw "ERROR - Creating Backup Folder Failed!" }
                        write-Host -f Green "Existing Default Profile successfully Backed up`n"

                        sleep -seconds 5
                    # copyinstallerprofile
                        New-Item "C:\Users\Default" -ItemType Directory
                        xcopy "C:\Users\$srcProfile\*.*" "C:\Users\Default" /e /c /h /k /y `
                            "C:\Users\Default\AppData\Local\Packages", `
                            "C:\users\Default\Appoata\Local\microsoft\Windows\Temporary Internet Files","C:\users\Default\AppData\Local\temp\" |
                                %{ if (Test-Path $_) { Remove-Item -Path $_ -Recurse -Force -confirm:$false -verbose } }
                            "C:\users\Default\AppData\Local\microsoft\Windows\usrclass.dat" |
                                %{ if (Test-Path $_ -PathType Leaf ) { Remove-Item -Path $_ -Force -confirm:$false -verbose } }
                        Write-Host -f Green "New Default Profile created successfully . . .`n"
                #endregion
            
                $wallPaperstyle = '
                Center,0
                Tile,1
                Stretch,2
                Fit,3
                Fill,4
                Span,S' | ConvertFrom-Csv -Delimiter ',' -Header Style,Data | Sort Data
                #what is 10?
            }
            '27'
            {
                # Set time to logon prompt screen
                    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\Currentversion\Authentication\LogonUI
                    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\Currentversion\Authentication\LogonUI | select IdleTimeout
                    Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\Currentversion\Authentication\LogonUI -Name IdleTimeout -Type DWord -value Ox258
                    <#
                        Get-Timezone
                        (((1908734/100)/60)/60)
                        (((616969/100)/60)/60)
                        New-Timespan -seconds (1204860/100)
                        1908734 !Format-Hex
                        Ox001dlffe
                        powercfg /list
                        powercfg /query ((powercfg /getactivescheme) -replace '.* ([0-9a-f-]{36}).*','$1') | Select-String -Pattern '^  GUID ALIAS'


                        /SETACVALUEINDEX
                        /SETDCVALUEINDEX
                        powercfg /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK
                        powercfg /?
                    #>
                    pnputil.exe /scan-devices
            }
        }
    #endregion
    