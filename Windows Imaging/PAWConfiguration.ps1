#region - PAW Configuration
    Function Global:Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
    $fldrDL = ($env:USERPROFILE + '\' + 'Downloads' + '\' + 'PAW DLs')
    If (!(Test-path $fldrDL -PathType Container)){ New-Item -Path $fldrDL -ItemType Directory }
    #region - DL Installers
        # SysInternals
            $url = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'SysinternalsSuite.zip')
            # RDP Manager

        # Putty
            $url = 'https://the.earth.li/~sgtatham/putty/0.81/w64/putty-64bit-0.81-installer.msi'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'putty-64bit-0.81-installer.msi')

        # Notepad++
            # Installer
            $url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.7/npp.8.6.7.Installer.x64.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'npp.8.6.7.Installer.x64.exe')
            #Portable
            $url = 'https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.6.7/npp.8.6.7.portable.x64.zip'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'npp.8.6.7.portable.x64.zip')

        # WINSCP
            $url = 'https://cdn.winscp.net/files/WinSCP-6.3.4-Setup.exe?secure=9DTnZXHIm5q-rVLIhRQWQQ==,1725031779'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'WinSCP-6.3.4-Setup.exe')

        # MS Account Lockout Toolkit
            $url = 'https://download.microsoft.com/download/1/f/0/1f0e9569-3350-4329-b443-822976f29284/ALTools.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'MS-AD-ALTools.exe')

        # 7Zip
            $url = 'https://www.7-zip.org/a/7z2408-x64.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + '7z2408-x64.exe')

        # Beyond Compare
            # v4
            $url = 'https://www.scootersoftware.com/files/BCompare-4.4.7.28397.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'BC_4.4.7.28397.exe')
            # v5
            $url = 'https://www.scootersoftware.com/files/BCompare-5.0.2.30045.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'BC_5.0.2.30045.exe')

        # WireShark
            # Installer
            $url = 'https://2.na.dl.wireshark.org/win64/Wireshark-4.4.0-x64.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'Wireshark-4.4.0-x64')
            # Portable
            $url = 'https://2.na.dl.wireshark.org/win64/WiresharkPortable64_4.4.0.paf.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'WiresharkPortable64_4.4.0.paf.exe')
    
        # SQL Mgmt Studio
            $url = 'https://aka.ms/ssmsfullsetup'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'SQL_MGMT_Studio.exe')

        # VS Code
            $url = 'https://vscode.download.prss.microsoft.com/dbazure/download/stable/fee1edb8d6d72a0ddff41e5f71a671c23ed924b9/VSCodeSetup-x64-1.92.2.exe'
            Invoke-WebRequest -Uri $url -OutFile ($fldrDL + '\' + 'VSCodeSetup-x64-1.92.2.exe')

    #endregion
    #region - Other Installs
        # RSAT:
            Get-WindowsFeature *rsat*
            #region - RSAT I(Nstall
            # dism /online /enable-feature /featurename:RSATClient-Roles-AD
            # dism /online /enable-feature /featurename:RSATClient-Roles-AD-DS
            # dism /online /enable-feature /featurename:RSATClient-Roles-AD-DS-SnapIns
    #endregion

            # ADUC/Sites & Services
            # WSUS Console
        #Server Manager
            Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0

        # VMware PowerCLI
        # BExec Remote admin - From SWLib
        # Roxio - From SWLib
    #endregion

    New-Item -Path ([Environment]::GetFolderPath('Desktop')) -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType "Directory"
#region - Add Posh Context Keys
    #region - FileHasher.cmd
        (Dec64 'QEVjaG8gT2ZmDQpSZW0gTUQ1DQpSZWcgQWRkICJIS0NVXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxoYXNoZmlsZU1ENSIgL1ZFIC9EICJDb3B5IE1EJjUiIC9GPk51bA0KUmVnIEFkZCAiSEtDVVxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcaGFzaGZpbGVNRDVcY29tbWFuZCIgL1ZFIC9EICJDbWQgL1EgL1Y6T04gL0MgXCJGb3IgL0YgXCJEZWxpbXM9XCIgJSUlJUEgSW4gKCdDZXJ0VXRpbCAtaGFzaGZpbGUgXCIlJUxcIiBNRDVeXl58RmluZFN0ci92L3IvYzpcIlsgXVwiJykgRG8gU2V0IFwiaGFzaD0lJSUlQVwiXiZTZXQvUCBcIj0haGFzaDogPSFcIl48TnVsXnxDbGlwLmV4ZVwiIiAvRj5OdWwNClJlbSBTSEExDQpSZWcgQWRkICJIS0NVXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxoYXNoZmlsZVNIQTEiIC9WRSAvRCAiQ29weSBTSEEmMSIgL0Y+TnVsDQpSZWcgQWRkICJIS0NVXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxoYXNoZmlsZVNIQTFcY29tbWFuZCIgL1ZFIC9EICJDbWQgL1EgL1Y6T04gL0MgXCJGb3IgL0YgXCJEZWxpbXM9XCIgJSUlJUEgSW4gKCdDZXJ0VXRpbCAtaGFzaGZpbGUgXCIlJUxcIiBTSEExXl5efEZpbmRTdHIvViBcIjpcIicpIERvIFNldCBcImhhc2g9JSUlJUFcIl4mU2V0L1AgXCI9IWhhc2g6ID0hXCJePE51bF58Q2xpcFwiIiAvRj5OdWwNClJlbSBTSEEyNTYNClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlU0hBMjU2IiAvVkUgL0QgIkNvcHkgU0hBJjI1NiIgL0Y+TnVsDQpSZWcgQWRkICJIS0NVXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxoYXNoZmlsZVNIQTI1Nlxjb21tYW5kIiAvVkUgL0QgIkNtZCAvUSAvVjpPTiAvQyBcIkZvciAvRiBcIkRlbGltcz1cIiAlJSUlQSBJbiAoJ0NlcnRVdGlsIC1oYXNoZmlsZSBcIiUlTFwiIFNIQTI1Nl5eXnxGaW5kU3RyL1YgXCI6XCInKSBEbyBTZXQgXCJoYXNoPSUlJSVBXCJeJlNldC9QIFwiPSFoYXNoOiA9IVwiXjxOdWxefENsaXBcIiIgL0Y+TnVsDQpSZW0gU0hBMzg0DQpSZWcgQWRkICJIS0NVXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxoYXNoZmlsZVNIQTM4NCIgL1ZFIC9EICJDb3B5IFNIQSYzODQiIC9GPk51bA0KUmVnIEFkZCAiSEtDVVxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcaGFzaGZpbGVTSEEzODRcY29tbWFuZCIgL1ZFIC9EICJDbWQgL1EgL1Y6T04gL0MgXCJGb3IgL0YgXCJEZWxpbXM9XCIgJSUlJUEgSW4gKCdDZXJ0VXRpbCAtaGFzaGZpbGUgXCIlJUxcIiBTSEEzODReXl58RmluZFN0ci9WIFwiOlwiJykgRG8gU2V0IFwiaGFzaD0lJSUlQVwiXiZTZXQvUCBcIj0haGFzaDogPSFcIl48TnVsXnxDbGlwXCIiIC9GPk51bA0KUmVtIFNIQTUxMg0KUmVnIEFkZCAiSEtDVVxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcaGFzaGZpbGVTSEE1MTIiIC9WRSAvRCAiQ29weSBTSEEmNTEyIiAvRj5OdWwNClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlU0hBNTEyXGNvbW1hbmQiIC9WRSAvRCAiQ21kIC9RIC9WOk9OIC9DIFwiRm9yIC9GIFwiRGVsaW1zPVwiICUlJSVBIEluICgnQ2VydFV0aWwgLWhhc2hmaWxlIFwiJSVMXCIgU0hBNTEyXl5efEZpbmRTdHIvViBcIjpcIicpIERvIFNldCBcImhhc2g9JSUlJUFcIl4mU2V0L1AgXCI9IWhhc2g6ID0hXCJePE51bF58Q2xpcFwiIiAvRj5OdWwNClJlbSBNQUNUcmlwbGVERVMNClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlTUFDVHJpcGxlREVTIiAvVkUgL0QgIkNvcHkgTUFDVHJpcGxlREVTIiAvRj5OdWwNClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlTUFDVHJpcGxlREVTXGNvbW1hbmQiIC9WRSAvRCAiQ21kIC9RIC9WOk9OIC9DIFwiRm9yIC9GIFwiRGVsaW1zPVwiICUlJSVBIEluICgnQ2VydFV0aWwgLWhhc2hmaWxlIFwiJSVMXCIgTUFDVHJpcGxlREVTXl5efEZpbmRTdHIvViBcIjpcIicpIERvIFNldCBcImhhc2g9JSUlJUFcIl4mU2V0L1AgXCI9IWhhc2g6ID0hXCJePE51bF58Q2xpcFwiIiAvRj5OdWwNClJlbSBSSVBFTUQxNjANClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlUklQRU1EMTYwIiAvVkUgL0QgIkNvcHkgUklQRU1EMTYwIiAvRj5OdWwNClJlZyBBZGQgIkhLQ1VcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXGhhc2hmaWxlUklQRU1EMTYwXGNvbW1hbmQiIC9WRSAvRCAiQ21kIC9RIC9WOk9OIC9DIFwiRm9yIC9GIFwiRGVsaW1zPVwiICUlJSVBIEluICgnQ2VydFV0aWwgLWhhc2hmaWxlIFwiJSVMXCIgUklQRU1EMTYwXl5efEZpbmRTdHIvViBcIjpcIicpIERvIFNldCBcImhhc2g9JSUlJUFcIl4mU2V0L1AgXCI9IWhhc2g6ID0hXCJePE51bF58Q2xpcFwiIiAvRj5OdWwNClJFTSByZXBsYWNlIEhLQ1VcU29mdHdhcmVcQ2xhc3NlcyB3aXRoIEhLRVlfQ0xBU1NFU19ST09UPyANCg0KY21kIC9rIGNlcnR1dGlsIC1oYXNoZmlsZSAiQzpcVXNlcnNcY2hhcmxlcy5hLm1lbGxhLmN0clxPbmVEcml2ZSAtIERlZmVuc2UgSW5mb3JtYXRpb24gU3lzdGVtcyBBZ2VuY3lcRGVza3RvcFxGaWxlSGFzaGVyLnR4dCIgbWQ1fEZpbmRTdHIgL3YgL3IgL2M6IlsgXSJ8Y2xpcA0KY21kIC9rIGNlcnR1dGlsIC1oYXNoZmlsZSAlMSBtZDUNCg==')
    #endregion
    #region - Hash4ContextMenu.reg
        (Dec64 'DQpXaW5kb3dzIFJlZ2lzdHJ5IEVkaXRvciBWZXJzaW9uIDUuMDANCg0KDQpbSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXQ0KIk1VSVZlcmIiPSJIYXNoX1BTIg0KIlN1Yk
            NvbW1hbmRzIj0iIg0KDQpbSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXHNoZWxsXDAxU0hBMV0NCiJNVUlWZXJiIj0iU0hBMSINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNv
            ZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaFxzaGVsbFwwMVNIQTFcY29tbWFuZF0NCkA9InBvd2Vyc2hlbGwuZXhlIC1ub3Byb2ZpbGUgLW5vZXhpdCBnZXQtZmlsZWhhc2ggLWxpdGVyYWxwYXRoICclMScgLW
            FsZ29yaXRobSBTSEExIHwgZm9ybWF0LWxpc3QiDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2hcc2hlbGxcMDJTSEEyNTZdDQoiTVVJVmVyYiI9IlNIQTI1NiINCg0K
            W0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaFxzaGVsbFwwMlNIQTI1Nlxjb21tYW5kXQ0KQD0icG93ZXJzaGVsbC5leGUgLW5vcHJvZmlsZSAtbm9leGl0IGdldC1maWxlaG
            FzaCAtbGl0ZXJhbHBhdGggJyUxJyAtYWxnb3JpdGhtIFNIQTI1NiB8IGZvcm1hdC1saXN0Ig0KDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2hcc2hlbGxcMDNTSEEz
            ODRdDQoiTVVJVmVyYiI9IlNIQTM4NCINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaFxzaGVsbFwwM1NIQTM4NFxjb21tYW5kXQ0KQD0icG93ZXJzaGVsbC5leGUgLW
            5vcHJvZmlsZSAtbm9leGl0IGdldC1maWxlaGFzaCAtbGl0ZXJhbHBhdGggJyUxJyAtYWxnb3JpdGhtIFNIQTM4NCB8IGZvcm1hdC1saXN0Ig0KDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hl
            bGxcR2V0RmlsZUhhc2hcc2hlbGxcMDRTSEE1MTJdDQoiTVVJVmVyYiI9IlNIQTUxMiINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaFxzaGVsbFwwNFNIQTUxMlxjb2
            1tYW5kXQ0KQD0icG93ZXJzaGVsbC5leGUgLW5vcHJvZmlsZSAtbm9leGl0IGdldC1maWxlaGFzaCAtbGl0ZXJhbHBhdGggJyUxJyAtYWxnb3JpdGhtIFNIQTUxMiB8IGZvcm1hdC1saXN0Ig0KDQpbSEtFWV9DVVJSRU5UX1VT
            RVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXHNoZWxsXDA1TUFDVHJpcGxlREVTXQ0KIk1VSVZlcmIiPSJNQUNUcmlwbGVERVMiDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXC
            pcc2hlbGxcR2V0RmlsZUhhc2hcc2hlbGxcMDVNQUNUcmlwbGVERVNcY29tbWFuZF0NCkA9InBvd2Vyc2hlbGwuZXhlIC1ub3Byb2ZpbGUgLW5vZXhpdCBnZXQtZmlsZWhhc2ggLWxpdGVyYWxwYXRoICclMScgLWFsZ29yaXRo
            bSBNQUNUcmlwbGVERVMgfCBmb3JtYXQtbGlzdCINCg0KDQpbSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXHNoZWxsXDA2TUQ1XQ0KIk1VSVZlcmIiPSJNRDUiDQoNCltIS0
            VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2hcc2hlbGxcMDZNRDVcY29tbWFuZF0NCkA9InBvd2Vyc2hlbGwuZXhlIC1ub3Byb2ZpbGUgLW5vZXhpdCBnZXQtZmlsZWhhc2ggLWxp
            dGVyYWxwYXRoICclMScgLWFsZ29yaXRobSBNRDUgfCBmb3JtYXQtbGlzdCINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaFxzaGVsbFwwN1JJUEVNRDE2MF0NCiJNVU
            lWZXJiIj0iUklQRU1EMTYwIg0KDQpbSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXHNoZWxsXDA3UklQRU1EMTYwXGNvbW1hbmRdDQpAPSJwb3dlcnNoZWxsLmV4ZSAtbm9w
            cm9maWxlIC1ub2V4aXQgZ2V0LWZpbGVoYXNoIC1saXRlcmFscGF0aCAnJTEnIC1hbGdvcml0aG0gUklQRU1EMTYwIHwgZm9ybWF0LWxpc3QiDQoNCg0KDQoNCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZX
            NcKlxzaGVsbFxHZXRGaWxlSGFzaDJdDQoiTVVJVmVyYiI9Ikhhc2hfQ2VydCINCiJTdWJDb21tYW5kcyI9IiINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hl
            bGxcMDFTSEExXQ0KIk1VSVZlcmIiPSJTSEExIg0KDQpbSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoMlxzaGVsbFwwMVNIQTFcY29tbWFuZF0NCkA9ImNtZCAvayBjZXJ0dX
            RpbCAtaGFzaGZpbGUgXCIlMVwiIFNIQTEiDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2gyXHNoZWxsXDAyU0hBMjU2XQ0KIk1VSVZlcmIiPSJTSEEyNTYiDQoNCltI
            S0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2gyXHNoZWxsXDAyU0hBMjU2XGNvbW1hbmRdDQpAPSJjbWQgL2sgY2VydHV0aWwgLWhhc2hmaWxlIFwiJTFcIiBTSEEyNTYiDQoNCl
            tIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFzc2VzXCpcc2hlbGxcR2V0RmlsZUhhc2gyXHNoZWxsXDAzU0hBMzg0XQ0KIk1VSVZlcmIiPSJTSEEzODQiDQoNCltIS0VZX0NVUlJFTlRfVVNFUlxTb2Z0d2FyZVxDbGFz
            c2VzXCpcc2hlbGxcR2V0RmlsZUhhc2gyXHNoZWxsXDAzU0hBMzg0XGNvbW1hbmRdDQpAPSJjbWQgL2sgY2VydHV0aWwgLWhhc2hmaWxlIFwiJTFcIiBTSEEzODQiDQoNCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXE
            NsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMDRTSEE1MTJdDQoiTVVJVmVyYiI9IlNIQTUxMiINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hl
            bGxcMDRTSEE1MTJcY29tbWFuZF0NCkA9ImNtZCAvayBjZXJ0dXRpbCAtaGFzaGZpbGUgXCIlMVwiIFNIQTUxMiINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2
            hlbGxcMDVNQUNUcmlwbGVERVNdDQoiTVVJVmVyYiI9Ik1BQ1RyaXBsZURFUyINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMDVNQUNUcmlwbGVERVNc
            Y29tbWFuZF0NCkA9ImNtZCAvayBjZXJ0dXRpbCAtaGFzaGZpbGUgXCIlMVwiIE1BQ1RyaXBsZURFUyINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMD
            ZNRDVdDQoiTVVJVmVyYiI9Ik1ENSINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMDZNRDVcY29tbWFuZF0NCkA9ImNtZCAvayBjZXJ0dXRpbCAtaGFz
            aGZpbGUgXCIlMVwiIE1ENSINCg0KW0hLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMDdSSVBFTUQxNjBdDQoiTVVJVmVyYiI9IlJJUEVNRDE2MCINCg0KW0hLRV
            lfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJcc2hlbGxcMDdSSVBFTUQxNjBcY29tbWFuZF0NCkA9ImNtZCAvayBjZXJ0dXRpbCAtaGFzaGZpbGUgXCIlMVwiIFJJUEVNRDE2MCIN
            Cg0KI2VuZHJlZ2lvbg0KI3JlZ2lvbiAtIEhhc2g0Q29udGV4dE1lbnUtUmVtb3ZlLnJlZw0KV2luZG93cyBSZWdpc3RyeSBFZGl0b3IgVmVyc2lvbiA1LjAwDQoNClstSEtFWV9DVVJSRU5UX1VTRVJcU29mdHdhcmVcQ2xhc3
            Nlc1wqXHNoZWxsXEdldEZpbGVIYXNoXQ0KDQpbLUhLRVlfQ1VSUkVOVF9VU0VSXFNvZnR3YXJlXENsYXNzZXNcKlxzaGVsbFxHZXRGaWxlSGFzaDJdDQoNCg==')
    #endregion
    New-PSDrive -PSProvider Registry -Name HKCR -Root HKEY_CLASSES_ROOT
    $psShellPath = 'HKCR:\Microsoft.PowerShellScript.1\Shell'
    $subPath = @('PowerShellISE_Elevated','PowerShellISEx86_Elevated','Edit with PowerShell (Admin)','Run with PowerShell (Admin)')
    $dfltVals = @('Edit with PowerShell ISE (as Admin)','Edit with PowerShell ISE (x86) (as Admin)',$($subPath[2]),$subPath[3])

    # Add Edit W/Powershell ISE as Admin
        New-Item -Path $psShellPath -Name $subPath[0] -ItemType Key
        Set-ItemProperty -Path "$psShellPath\$($subPath[0])" -Name '(Default)' -Value $dfltVals[0]
            
            # Un-REM next line to make menu item only visible w/shift
            # New-ItemProperty -Path "$psShellPath\$($subPath[0])" -Name "Extended" -PropertyType "STRING" -Value ""
            
            New-ItemProperty -Path "$psShellPath\$($subPath[0])" -Name "HasLUAShield" -PropertyType "STRING" -Value ""
            New-ItemProperty -Path "$psShellPath\$($subPath[0])" -Name "Icon" -PropertyType "STRING" -Value "PowerShell_ISE.exe"

            New-Item -Path "$psShellPath\$($subPath[0])" -Name 'Command' -ItemType Key
            Set-ItemProperty -Path "$psShellPath\$($subPath[0])\Command" -Name '(Default)' -Value "PowerShell -windowstyle hidden -Command \`"Start-Process cmd -ArgumentList '/s,/c,start PowerShell_ISE.exe \`"\`"%1\`"\`"'  -Verb RunAs\`""

    ## Remove-Item -Path "$psShellPath\$($subPath[0])" -Force -Recurse -Confirm:$false

    # Add Edit W/PowerShell ISE x86 As Admin
        New-Item -Path $psShellPath -Name $subPath[1] -ItemType Key
        Set-ItemProperty -Path "$psShellPath\$($subPath[1])" -Name '(Default)' -Value $dfltVals[1]
            
            # Un-REM next line to make menu item only visible w/shift
            # New-ItemProperty -Path "$psShellPath\$($subPath[1])" -Name "Extended" -PropertyType "STRING" -Value ""

            New-ItemProperty -Path "$psShellPath\$($subPath[1])" -Name "HasLUAShield" -PropertyType "STRING" -Value ""
            New-ItemProperty -Path "$psShellPath\$($subPath[1])" -Name "Icon" -PropertyType "STRING" -Value "PowerShell_ISE.exe"

            New-Item -Path "$psShellPath\$($subPath[1])" -Name 'Command' -ItemType Key
            Set-ItemProperty -Path "$psShellPath\$($subPath[0])\Command" -Name '(Default)' -Value "PowerShell -windowstyle hidden -Command \`"Start-Process cmd -ArgumentList '/s,/c,start C:\\WINDOWS\\syswow64\\WindowsPowerShell\\v1.0\\powershell_ise.exe \`"\`"%1\`"\`"'  -Verb RunAs\`""
    
    ## Remove-Item -Path "$psShellPath\$($subPath[1])" -Force -Recurse -Confirm:$false

    # Add Edit with PowerShell (Admin)
        New-Item -Path $psShellPath -Name $($subPath[2]) -ItemType Key
        # Set-ItemProperty -Path "$psShellPath\$($subPath[2])" -Name '(Default)' -Value $($dfltVals[2])
            
            # Un-REM next line to make menu item only visible w/shift
            # New-ItemProperty -Path "$psShellPath\$($subPath[2])" -Name "Extended" -PropertyType "STRING" -Value ""

            # New-ItemProperty -Path "$psShellPath\$($subPath[2])" -Name "HasLUAShield" -PropertyType "STRING" -Value ""
            New-ItemProperty -Path "$psShellPath\$($subPath[2])" -Name "Icon" -PropertyType "STRING" -Value "PowerShell_ISE.exe"

            New-Item -Path "$psShellPath\$($subPath[2])" -Name 'Command' -ItemType Key
            Set-ItemProperty -Path "$psShellPath\$($subPath[2])\Command" -Name '(Default)' -Value "\`"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\`" \`"-Command\`" \`"\`"& {Start-Process PowerShell_ise.exe -argument list  -File \\\`"%1\\\`"' }\`""
    
    ## Remove-Item -Path "$psShellPath\$($subPath[2])" -Force -Recurse -Confirm:$false

    # Add Edit with PowerShell (Admin)
        New-Item -Path $psShellPath -Name $($subPath[3]) -ItemType Key
        # Set-ItemProperty -Path "$psShellPath\$($subPath[3])" -Name '(Default)' -Value $($dfltVals[3])
            
            # Un-REM next line to make menu item only visible w/shift
            # New-ItemProperty -Path "$psShellPath\$($subPath[3])" -Name "Extended" -PropertyType "STRING" -Value ""

            # New-ItemProperty -Path "$psShellPath\$($subPath[3])" -Name "HasLUAShield" -PropertyType "STRING" -Value ""
            New-ItemProperty -Path "$psShellPath\$($subPath[3])" -Name "Icon" -PropertyType "STRING" -Value "PowerShell.exe"

            New-Item -Path "$psShellPath\$($subPath[3])" -Name 'Command' -ItemType Key
            Set-ItemProperty -Path "$psShellPath\$($subPath[3])\Command" -Name '(Default)' -Value "\`"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\`" \`"-Command\`" \`"\`"& {Start-Process PowerShell.exe -ArgumentList '-ExecutionPolicy RemoteSigned -File \\\`"%1\\\`"' -Verb RunAs}\`""
    
    ## Remove-Item -Path "$psShellPath\$($subPath[3])" -Force -Recurse -Confirm:$false

#endregion

#endregion
New-Item -Path ([Environment]::GetFolderPath('Desktop')) -Name "GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -ItemType "Directory"

