        #region - Find installed profiles (SIDs)


            $a = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore | Where-Object Name -match 'S-\d{1}-\d{1}-\d{2}-+'
            $a.name | ForEach-Object{ $x = $_; DO {$X = $x -replace "^\w+[^\\]+\\"} While ($x -match '\\'); Return $x }

        #endregion
        #region Pin Unping taskbar/startmenu
            $appname = 'Costpoint'

            function Add-ToTaskbar
            {
                [CmdletBinding()]
                [Alias("pin_taskbar")]
                Param([string]$appname)
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
                    Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Pin to taskbar'} | ForEach-Object{$_.DoIt()}
            }

            function Remove-FromTaskbar
            {
                [CmdletBinding()]
                [Alias("unpin_taskbar")]
                Param([string]$appname)
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
                    Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Unpin from taskbar'} | ForEach-Object{$_.DoIt()}
            }

            function Add-ToStartMenu
            {
                [CmdletBinding()]
                [Alias("pin_startmenu")]
                Param([string]$appname)
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
                    Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Pin to Start'} | ForEach-Object{$_.DoIt()}
            }

            function Remove-FromStartMenu
            {
                [CmdletBinding()]
                [Alias("unpin_startmenu")]
                Param([string]$appname)
                ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
                    Where-Object{$_.Name -eq $appname}).Verbs() | Where-Object{$_.Name.replace('&','') -match 'Unpin from Start'} | ForEach-Object{$_.DoIt()}
            }

            foreach ($taskbarapp in 'Tips') {
                Write-Host Pinning $taskbarapp
                pin_taskbar("$taskbarapp")
            }

            foreach ($startmenuapp in 'Tips') {
                Write-Host Pinning $startmenuapp
                pin_startmenu("$startmenuapp")
            }

            foreach ($taskbarapp in 'Microsoft Store') {
                Write-Host unpinning $taskbarapp
                unpin_taskbar("$taskbarapp")
            }

            foreach ($startmenuapp in 'ESPN', 'Spotify') {
                Write-Host unpinning $startmenuapp
                unpin_startmenu("$startmenuapp")
            }

            $a = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Select-Object Name,@{n='Verbs';e={($_|Where-Object{$_.Name -eq $appname}).Verbs()}}
            $a = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Select-Object Name,@{n='Verbs';e={($_).Verbs()}}
            $a = (New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object Name -eq $appname | Select-Object Name,@{n='Verbs';e={($_).Verbs()}}
            $a.count
            $a.GetValue(3).Verbs

        #endregion
        #region SecPol

        Function Parse-SecPol($CfgFile){
            # Will turn Local Security Policy into a PsObject. You can view all the properties and make changed to the object.
            $null = secedit /export /cfg "$CfgFile"
            $obj = New-Object psobject
            $index = 0
            $contents = Get-Content $CfgFile -raw
            [regex]::Matches($contents,"(?<=\[)(.*)(?=\])") | ForEach-Object{
                $title = $_
                [regex]::Matches($contents,"(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | ForEach-Object{
                    $section = new-object psobject
                    $_.value -split "\r\n" | Where-Object{$_.length -gt 0} | ForEach-Object{
                        $value = [regex]::Match($_,"(?<=\=).*").value
                        $name = [regex]::Match($_,".*(?=\=)").value
                        $null = $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue
                    }
                    $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
                }
                $index += 1
            }
            return $obj
        }

        Function Set-SecPol($Object, $CfgFile){
        # Will turn the Parse-SecPol object back into a config file and import it to into the Local Security Policy.
           $SecPool.psobject.Properties.GetEnumerator() | ForEach-Object{
                "[$($_.Name)]"
                $_.Value | ForEach-Object{
                    $_.psobject.Properties.GetEnumerator() | ForEach-Object{
                        "$($_.Name)=$($_.Value)"
                    }
                }
            } | out-file $CfgFile -ErrorAction Stop
            secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
        }

        $SecPool = Parse-SecPol -CfgFile C:\test\Test.cgf
        $SecPool.'System Access'.PasswordComplexity = 1
        $SecPool.'System Access'.MinimumPasswordLength = 8
        $SecPool.'System Access'.MaximumPasswordAge = 60

        Set-SecPol -Object $SecPool -CfgFile C:\Test\Test.cfg
        #endregion

        $xmlFile = "C:\Users\charles.a.mella.ctr\Desktop\Repos.ps1xml"
        $xmlTest = [xml](Get-Content $xmlFile)
        $xmlTest.Repository.Functions.Function

                    $getXML = { Param($XPath,$xmlFile) $out = Select-Xml -Path $xmlFile -XPath $Xpath | Select-Object -ExpandProperty Node; Return $out }
                    & $getXML -xmlFile $xmlFile -XPath "//Filter"
                    & $getXML -xmlFile $xmlFile -XPath "//Function" | Where-Object module -match xml | Sort-Object name | Format-Table
                    & $getXML -xmlFile $xmlFile -XPath "//Idea"
                    & $getXML -xmlFile $xmlFile -XPath "//Mime"
                    & $getXML -xmlFile $xmlFile -XPath "//Module"
                    & $getXML -xmlFile $xmlFile -XPath "//PowerTip"
                    & $getXML -xmlFile $xmlFile -XPath "//Note"
                    & $getXML -xmlFile $xmlFile -XPath "//ScriptBlock"
                    & $getXML -xmlFile $xmlFile -XPath "//Script" | Select-Object Name

                    Dec64 (& $getXML -xmlFile $xmlFile -XPath "//Variable" | Where-Object module -match fn_SysTools | Sort-Object name | Where-Object {$_. Name -eq 'RandomNamespace' } | Select-Object -exp Code | Select-Object -exp '#cdata-section' )
                    & $getXML -xmlFile $xmlFile -XPath "//Variable" | Where-Object {$_. Name -eq 'myQueries' } | Select-Object -exp Code | Select-Object -exp '#cdata-section'

        Dec64 $out | Clip

        $xmlTest.Repository.Functions.Function | Select-Object module -uniq

        "SystemMetrics$(Get-Random -Maximum 100)"  


        # powershell.exe -nologo -noprofile -executionpolicy bypass -file SystemReporterv2.ps1

 

        $kPath = 'HKCU:\Control Panel\Desktop'

        $k1 = 'Win8DpiScaling'

        $k2 = 'LogPixels'

        $v1 = 1

        $v2 = 125 #  "$('{0:x}' -f 125)"

        Set-ItemProperty -Path $kPath `
                         -Name $k1 `
                         -Value $v1 `
                         -Type DWord -WhatIf

 

        Set-ItemProperty -Path $kPath `
                         -Name $k2 `
                         -Value $v2 `
                         -Type DWord -WhatIf
        New-Item -Path $kPath -Name $k2 -ItemType DWord -Value $v2 -f -whatIf
        # Server 2019 Ping fix (Disabled by default)

        New-NetFirewallRule -DisplayName 'Allow Inbound ICMPv4' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress LocalSubnet -Action Allow

        New-NetFirewallRule -DisplayName 'Allow Inbound ICMPv6' -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -RemoteAddress LocalSubnet -Action Allow
