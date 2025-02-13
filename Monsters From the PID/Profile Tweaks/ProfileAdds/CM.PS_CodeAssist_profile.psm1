    $global:msdnProdKeyTypes = (Dec64 'S2V5IFR5cGUsRGVzY3JpcHRpb24NCk5vdCBBcHBsaWNhYmxlLE5vIGtleSBpcyBuZWVkZWQgdG8gaW5zdGFsbCB0aGlzIHByb2R1Y3QuDQpSZXRhaWwsUmV0YWlsIGtleXMgYWxsb3cgbXVsdGlwbGUgYWN0aXZhdGlvbnMgYW5kIGFyZSB1c2VkIGZvciByZXRhaWwgYnVpbGRzIG9mIHRoZSBwcm9kdWN0LiBJbiBtYW55IGNhc2VzLCAxMCBhY3RpdmF0aW9ucyBhcmUgYWxsb3dlZCBwZXIga2V5LCB0aG91Z2ggb2Z0ZW4gbW9yZSBhcmUgYWxsb3dlZCBvbiB0aGUgc2FtZSBtYWNoaW5lLg0KTXVsdGlwbGUgQWN0aXZhdGlvbixBIE11bHRpcGxlIEFjdGl2YXRpb24gS2V5IChNQUspIGVuYWJsZXMgeW91IHRvIGFjdGl2YXRlIG11bHRpcGxlIGluc3RhbGxhdGlvbnMgb2YgYSBwcm9kdWN0IHdpdGggdGhlIHNhbWUga2V5LiBNQUtzIGFyZSB1c2VkIHdpdGggVm9sdW1lIExpY2Vuc2luZyB2ZXJzaW9ucyBvZiBwcm9kdWN0cy4gVHlwaWNhbGx5LCBvbmx5IG9uZSBNQUsga2V5IGlzIHByb3ZpZGVkIHBlciBzdWJzY3JpcHRpb24uDQpTdGF0aWMgQWN0aXZhdGlvbiBLZXksU3RhdGljIGFjdGl2YXRpb24ga2V5cyBhcmUgcHJvdmlkZWQgZm9yIHByb2R1Y3RzIHRoYXQgZG8gbm90IHJlcXVpcmUgYWN0aXZhdGlvbi4gVGhleSBjYW4gYmUgdXNlZCBmb3IgYW55IG51bWJlciBvZiBpbnN0YWxsYXRpb25zLg0KQ3VzdG9tIEtleSxDdXN0b20ga2V5cyBwcm92aWRlIHNwZWNpYWwgYWN0aW9ucyBvciBpbmZvcm1hdGlvbiB0byBhY3RpdmF0ZSBvciBpbnN0YWxsIHRoZSBwcm9kdWN0Lg0KVkEgMS4wLE11bHRpcGxlIGFjdGl2YXRpb24ga2V5cywgc2ltaWxhciB0byBhIE1BSy4NCk9FTSBLZXksT3JpZ2luYWwgRXF1aXBtZW50IE1hbnVmYWN0dXJlciBrZXlzIHRoYXQgYWxsb3cgbXVsdGlwbGUgYWN0aXZhdGlvbnMuDQpEcmVhbVNwYXJrIFJldGFpbCBLZXksUmV0YWlsIGtleXMgZm9yIERyZWFtU3BhcmsgYWxsb3cgb25lIGFjdGl2YXRpb24uIERyZWFtU3BhcmsgUmV0YWlsIGtleXMgYXJlIGlzc3VlZCBpbiBiYXRjaGVzIGFuZCBhcmUgcHJpbWFyaWx5IGludGVuZGVkIGZvciBzdHVkZW50IGNvbnN1bXB0aW9uLg0KRHJlYW1TcGFyayBMYWIgS2V5LExhYiB1c2Uga2V5cyBmb3IgRHJlYW1TcGFyayBwcm9ncmFtcyB0aGF0IGFsbG93IG11bHRpcGxlIGFjdGl2YXRpb25zLiBEcmVhbVNwYXJrIExhYiBLZXlzIGFyZSBpbnRlbmRlZCBmb3IgdXNlIGluIHVuaXZlcnNpdHkgY29tcHV0ZXIgbGFiIHNjZW5hcmlvcy4NCkRyZWFtU3BhcmsgTUFLIEtleSxNQUsga2V5cyBmb3IgRHJlYW1TcGFyayBwcm9ncmFtIGN1c3RvbWVycy4NCg==') | ConvertFrom-CSV

    Function Add-PS7ISEAddOn 
    {
        $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Clear()
        $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Switch to PowerShell 7", { 
                function New-OutOfProcRunspace {
                    param($ProcessId)

                    $ci = New-Object -TypeName System.Management.Automation.Runspaces.NamedPipeConnectionInfo -ArgumentList @($ProcessId)
                    $tt = [System.Management.Automation.Runspaces.TypeTable]::LoadDefaultTypeFiles()

                    $Runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($ci, $Host, $tt)

                    $Runspace.Open()
                    $Runspace
                }

                $PowerShell = Start-Process PWSH -ArgumentList @("-NoExit") -PassThru -WindowStyle Hidden
                $Runspace = New-OutOfProcRunspace -ProcessId $PowerShell.Id
                $Host.PushRunspace($Runspace)
        }, "ALT+F5") | Out-Null

        $psISE.CurrentPowerShellTab.AddOnsMenu.Submenus.Add("Switch to Windows PowerShell", { 
            $Host.PopRunspace()

            $Child = Get-CimInstance -ClassName win32_process | Where-Object {$_.ParentProcessId -eq $Pid}
            $Child | ForEach-Object { Stop-Process -Id $_.ProcessId }

        }, "ALT+F6") | Out-Null
    }

    function Stop-ISE
    {
        $dirISEBU = "$($profile.CurrentUserCurrentHost -replace '\\+[^\\]+$')\ISE_BUs"
        if (-not(Test-Path $dirISEBU)){ New-Item -Path $dirISEBU -ItemType Directory }
        $psise | Export-Clixml "$dirISEBU\MyISESession_$(& Hostname)_$(Get-Date -f yyyyMMdd_HHmm).xml"
        Stop-Process $PID -Force
    }
    Set-Alias -Name Kill-ISE -Value 'Stop-ISE' -Scope Global -Force

    function Global:Dump-ISEFiles
    {
        $iseRecovery = @{} | Select-Object Tabs,ActiveTab,CurrentFile,ActiveFiles
        $iseRecovery.Tabs = $psISE.PowerShellTabs.DisplayName
        $iseRecovery.ActiveTab = $psISE.CurrentPowerShellTab.DisplayName
        $iseRecovery.CurrentFile = $psISE.CurrentFile.FullPath
        $iseRecovery.ActiveFiles = $psISE.PowerShellTabs | Select-Object @{n='Tab';e={$_.DisplayName}},
                                                                  @{n='Saved';e={$_.Files.IsSaved}},
                                                                  @{n='Untitled';e={$_.Files.IsUntitled}},
                                                                  @{n='FullPath';e={$_.Files.FullPath}},
                                                                  @{n='DisplayName';e={$_.Files.DisplayName}},
                                                                  @{n='Encoding';e={$_.Files.Encoding}},
                                                                  @{n='Recovered';e={$_.Files.IsRecovered}}
        $iseRecovery | Export-Clixml $dirISEBU\MyISESession_$(& Hostname)_$(Get-Date -f yyyyMMdd_HHmm).xml
    }

    function Show-Process($Process, [Switch]$Maximize)
    {
      $sig = '
        [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll")] public static extern int SetForegroundWindow(IntPtr hwnd);
      '
  
      if ($Maximize) { $Mode = 3 } else { $Mode = 4 }
      $type = Add-Type -MemberDefinition $sig -Name WindowAPI -PassThru
      $hwnd = $process.MainWindowHandle
      $null = $type::ShowWindowAsync($hwnd, $Mode)
      $null = $type::SetForegroundWindow($hwnd) 
    }

    Function Textify
    {
        Param ([Array]$Files, $Path, $Ext)
        ForEach ($File in $Files){
            If ([string]::IsNullOrEmpty($Path)){ $nPath = $file } Else { $nPath = "$Path\$file" }
            Copy-Item $nPath ($nPath -replace ".$Ext",".$Ext.txt") -Force
            } #FE File
    }

    Function Get-HistoryPlus
    {
        Get-History |
            Out-GridView -Title "Command History - press CTRL to select multiple - Selected commands copied to clipboard" -OutputMode Multiple |
                ForEach-Object -Begin { [Text.StringBuilder]$sb = ""} -Process { $null = $sb.AppendLine($_.CommandLine) } -End { $sb.ToString() | clip }
    } 
    Set-Alias -Name h+ -Value Get-HistoryPlus

    Function Restore-IsoTool
    {
        # ISO Drag/Drop Creation Tool Creator
        $fileContents = @{
            cmd = 'VGl0bGU9Q3JlYXRpbmcgSVNPIEltYWdlIGZyb20gIiUxIg0KSWYgW109PVslMV0gRXhpdA0KIiVTeXN0ZW1Sb290JVxzeXN0ZW0zMl
            xXaW5kb3dzUG93ZXJTaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiAtTm9Qcm9maWxlIC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNzIC1GaWxlICI8
            U0NSSVBUTkFNRT4iIC1zcmNEaXIgJTENCjpQYXVzZQ0K'
            ps1 = 'UGFyYW0gKCRzcmNEaXIpDQojIFNsZWVwIDEwIC1TZWNvbmRzDQojICROZXdJU08gPSBGaW5kLUZ1bmN0aW9uQnlOYW1lIE5ldy1Jc2
            9GaWxlIHwgQ2xpcA0KRnVuY3Rpb24gRGVjNjQgeyBQYXJhbSgkYSkgJGIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJp
            bmcoW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkYSkpO1JldHVybiAkYiB9Ow0KRnVuY3Rpb24gTmV3LUlzb0ZpbGUgew0KIC
            AgIDwjIA0KICAgICAgIC5TeW5vcHNpcyANCiAgICAgICAgQ3JlYXRlcyBhIG5ldyAuaXNvIGZpbGUgDQogICAgICAgLkRlc2NyaXB0aW9uIA0K
            ICAgICAgICBUaGUgTmV3LUlzb0ZpbGUgY21kbGV0IGNyZWF0ZXMgYSBuZXcgLmlzbyBmaWxlIGNvbnRhaW5pbmcgY29udGVudCBmcm9tIGNob3
            NlbiBmb2xkZXJzIA0KICAgICAgIC5FeGFtcGxlIA0KICAgICAgICBOZXctSXNvRmlsZSAiYzpcdG9vbHMiLCJjOkRvd25sb2Fkc1x1dGlscyIg
            DQogICAgICAgICAgICAtIFRoaXMgY29tbWFuZCBjcmVhdGVzIGEgLmlzbyBmaWxlIGluICRlbnY6dGVtcCBmb2xkZXIgKGRlZmF1bHQgbG9jYX
            Rpb24pIHRoYXQgY29udGFpbnMgDQogICAgICAgICAgICAtIGM6XHRvb2xzIGFuZCBjOlxkb3dubG9hZHNcdXRpbHMgZm9sZGVycy4gVGhlIGZv
            bGRlcnMgdGhlbXNlbHZlcyBhcmUgYWRkZWQgaW4gdGhlIHJvb3QgDQogICAgICAgICAgICAtIG9mIHRoZSAuaXNvIGltYWdlLiANCiAgICAgIC
            AgZGlyIGM6XFdpblBFIHwgTmV3LUlzb0ZpbGUgLVBhdGggYzpcdGVtcFxXaW5QRS5pc28gLUJvb3RGaWxlIGV0ZnNib290LmNvbSAtTWVkaWEg
            RFZEUExVU1IgLVRpdGxlICJXaW5QRSIgDQogICAgICAgICAgICAtIFRoaXMgY29tbWFuZCBjcmVhdGVzIGEgYm9vdGFibGUgLmlzbyBmaWxlIG
            NvbnRhaW5pbmcgdGhlIGNvbnRlbnQgZnJvbSBjOlxXaW5QRSBmb2xkZXIsIA0KICAgICAgICAgICAgLSBidXQgdGhlIGZvbGRlciBpdHNlbGYg
            aXNuJ3QgaW5jbHVkZWQuIEJvb3QgZmlsZSBldGZzYm9vdC5jb20gY2FuIGJlIGZvdW5kIGluIFdpbmRvd3MgQUlLLiANCiAgICAgICAgICAgIC
            0gUmVmZXIgdG8gSU1BUElfTUVESUFfUEhZU0lDQUxfVFlQRSBlbnVtZXJhdGlvbiBmb3IgcG9zc2libGUgbWVkaWEgdHlwZXM6IA0KICAgICAg
            ICAgICAgLSBodHRwOi8vbXNkbi5taWNyb3NvZnQuY29tL2VuLXVzL2xpYnJhcnkvd2luZG93cy9kZXNrdG9wL2FhMzY2MjE3KHY9dnMuODUpLm
            FzcHggDQogICAgIz4gDQogICAgUGFyYW0gKCANCiAgICAgICAgW3BhcmFtZXRlcihQb3NpdGlvbj0wLE1hbmRhdG9yeT0kdHJ1ZSxWYWx1ZUZy
            b21QaXBlbGluZT0kdHJ1ZSldJFNvdXJjZSwNCiAgICAgICAgW3BhcmFtZXRlcihQb3NpdGlvbj0xLE1hbmRhdG9yeT0kZmFsc2UsVmFsdWVGcm
            9tUGlwZWxpbmU9JHRydWUpXVtBbGlhcygnUGF0aCcpXQ0KICAgICAgICBbU3RyaW5nXSAkdHJnUGF0aCA9ICIkKCRlbnY6dXNlcnByb2ZpbGUp
            XERlc2t0b3BcJCgoR2V0LURhdGUpLlRvU3RyaW5nKCJ5eXl5TU1kZC1ISG1tc3MuZmZmZiIpKS5pc28iLCANCiAgICAgICAgW3N0cmluZ10gJE
            Jvb3RGaWxlID0gJG51bGwsIA0KICAgICAgICBbc3RyaW5nXSAkTWVkaWEgPSAiRGlzayIsIA0KICAgICAgICBbc3RyaW5nXSAkVGl0bGUgPSAo
            R2V0LURhdGUpLlRvU3RyaW5nKCJ5eXl5TU1kZC1ISG1tc3MuZmZmZiIpLCANCiAgICAgICAgW3N3aXRjaF0gJEZvcmNlIA0KICAgICAgICApDQ
            ogICAgQmVnaW4gew0KICAgICAgICBGdW5jdGlvbiBEZWM2NCgkYSl7JGIgPSBbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJp
            bmcoW1N5c3RlbS5Db252ZXJ0XTo6RnJvbUJhc2U2NFN0cmluZygkYSkpO1JldHVybiAkYn0gIw0KICAgICAgICAoJGNwID0gbmV3LW9iamVjdC
            BTeXN0ZW0uQ29kZURvbS5Db21waWxlci5Db21waWxlclBhcmFtZXRlcnMpLkNvbXBpbGVyT3B0aW9ucyA9ICIvdW5zYWZlIiANCiAgICAgICAg
            SWYgKCEoIklTT0ZpbGUiIC1hcyBbdHlwZV0pKSB7IA0KICAgICAgICAgICAgJFR5cGUgPSBEZWM2NCAiY0hWaWJHbGpJR05zWVhOeklFbFRUMF
            pwYkdVTkNuc05DaUFnSUNCd2RXSnNhV01nZFc1ellXWmxJSE4wWVhScFl5QjJiMmxrSUUNCiAgICAgICAgICAgICAgICBOeVpXRjBaU2h6ZEhK
            cGJtY2dVR0YwYUN3Z2IySnFaV04wSUZOMGNtVmhiU3dnYVc1MElFSnNiMk5yVTJsNlpTd2dhVzUwSUZSdmRHRnNRbXh2WTJ0ektRMA0KICAgIC
            AgICAgICAgICAgIEtJQ0FnSUhzTkNpQWdJQ0FnSUNBZ2FXNTBJR0o1ZEdWeklEMGdNRHNOQ2lBZ0lDQWdJQ0FnWW5sMFpWdGRJR0oxWmlBOUlH
            NWxkeUJpZVhSbFcwSnNiMk5yDQogICAgICAgICAgICAgICAgVTJsNlpWMDdEUW9nSUNBZ0lDQWdJRk41YzNSbGJTNUpiblJRZEhJZ2NIUnlJRD
            BnS0ZONWMzUmxiUzVKYm5SUWRISXBLQ1ppZVhSbGN5azdEUW9nSUNBZ0kNCiAgICAgICAgICAgICAgICBDQWdJRk41YzNSbGJTNUpUeTVHYVd4
            bFUzUnlaV0Z0SUc4Z1BTQlRlWE4wWlcwdVNVOHVSbWxzWlM1UGNHVnVWM0pwZEdVb1VHRjBhQ2s3RFFvZ0lDQWdJQw0KICAgICAgICAgICAgIC
            AgIEFnSUZONWMzUmxiUzVTZFc1MGFXMWxMa2x1ZEdWeWIzQlRaWEoyYVdObGN5NURiMjFVZVhCbGN5NUpVM1J5WldGdElHa2dQU0JUZEhKbFlX
            MGdZWE1nVTNsDQogICAgICAgICAgICAgICAgemRHVnRMbEoxYm5ScGJXVXVTVzUwWlhKdmNGTmxjblpwWTJWekxrTnZiVlI1Y0dWekxrbFRkSE
            psWVcwN0RRb05DaUFnSUNBZ0lDQWdhV1lnS0c4Z1BUMGcNCiAgICAgICAgICAgICAgICBiblZzYkNrZ2V5QnlaWFIxY200N0lIME5DaUFnSUNB
            Z0lDQWdkMmhwYkdVZ0tGUnZkR0ZzUW14dlkydHpMUzBnUGlBd0tTQjdEUW9nSUNBZ0lDQWdJQ0FnSQ0KICAgICAgICAgICAgICAgIENCcExsSm
            xZV1FvWW5WbUxDQkNiRzlqYTFOcGVtVXNJSEIwY2lrN0lHOHVWM0pwZEdVb1luVm1MQ0F3TENCaWVYUmxjeWs3RFFvZ0lDQWdJQ0FnSUgwTkNp
            DQogICAgICAgICAgICAgICAgQWdJQ0FnSUNBZ2J5NUdiSFZ6YUNncE95QnZMa05zYjNObEtDazdEUW9nSUNBZ2ZRMEtmUT09Ig0KICAgICAgIC
            AgICAgQWRkLVR5cGUgLUNvbXBpbGVyUGFyYW1ldGVycyAkY3AgLVR5cGVEZWZpbml0aW9uICRUeXBlICMtSWdub3JlV2FybmluZ3MNCiAgICAg
            ICAgICAgIH0gI0lmDQogICAgICAgIElmICgkQm9vdEZpbGUgLWFuZCAoVGVzdC1QYXRoICRCb290RmlsZSkpIHsgDQogICAgICAgICAgICAoJF
            N0cmVhbSA9IE5ldy1PYmplY3QgLUNvbU9iamVjdCBBRE9EQi5TdHJlYW0pLk9wZW4oKSANCiAgICAgICAgICAgICRTdHJlYW0uVHlwZSA9IDEg
            ICMgYWRGaWxlVHlwZUJpbmFyeSANCiAgICAgICAgICAgICRTdHJlYW0uTG9hZEZyb21GaWxlKChHZXQtSXRlbSAkQm9vdEZpbGUpLkZ1bGxuYW
            1lKSANCiAgICAgICAgICAgICgkQm9vdCA9IE5ldy1PYmplY3QgLUNvbU9iamVjdCBJTUFQSTJGUy5Cb290T3B0aW9ucykuQXNzaWduQm9vdElt
            YWdlKCRTdHJlYW0pIA0KICAgICAgICAgICAgfSAjSWYgDQogICAgICAgICRNZWRpYVR5cGUgPSBbT3JkZXJlZF1Ae0JEUj0xODsgQkRSRT0xOT
            tDRFI9MjsgQ0RSVz0zO0RJU0s9MTI7RFZEREFTSFI9OTtEVkREQVNIUlc9MTA7RFZEREFTSFJfRFVBTExBWUVSPTExOw0KICAgICAgICAgICAg
            RFZEUExVU1I9NjsgRFZEUExVU1JXPTc7RFZEUExVU1JfRFVBTExBWUVSPTg7RFZEUExVU1JXX0RVQUxMQVlFUj0xMztEVkRSQU09NTt9ICNNVH
            lwZQ0KICAgICAgICBJZiAoJE1lZGlhVHlwZVskTWVkaWFdIC1lcSAkbnVsbCl7DQogICAgICAgICAgICB3cml0ZS1kZWJ1ZyAiVW5zdXBwb3J0
            ZWQgTWVkaWEgVHlwZTogJE1lZGlhIjsNCiAgICAgICAgICAgIHdyaXRlLWRlYnVnICgiQ2hvb3NlIG9uZSBmcm9tOiAiICsgJE1lZGlhVHlwZS
            5LZXlzKTsNCiAgICAgICAgICAgIEJyZWFrDQogICAgICAgICAgICB9ICNJZg0KICAgICAgICAoJEltYWdlID0gbmV3LW9iamVjdCAtY29tIElN
            QVBJMkZTLk1zZnRGaWxlU3lzdGVtSW1hZ2UgLVByb3BlcnR5IEB7Vm9sdW1lTmFtZT0kVGl0bGV9KS5DaG9vc2VJbWFnZURlZmF1bHRzRm9yTW
            VkaWFUeXBlKCRNZWRpYVR5cGVbJE1lZGlhXSkgDQogICAgICAgIElmICgoVGVzdC1QYXRoICR0cmdQYXRoKSAtYW5kICghJEZvcmNlKSkgeyAi
            RmlsZSBFeGlzdHMgJHRyZ1BhdGgiOyBCcmVhayB9IA0KICAgICAgICBJZiAoISgkVGFyZ2V0ID0gTmV3LUl0ZW0gLVBhdGggJHRyZ1BhdGggLU
            l0ZW1UeXBlIEZpbGUgLUZvcmNlKSkgeyAiQ2Fubm90IGNyZWF0ZSBmaWxlICR0cmdQYXRoIjsgQnJlYWsgfSANCiAgICAgICAgfSAjQmVnaW4N
            CiAgICBQcm9jZXNzIHsgDQogICAgICAgIFN3aXRjaCAoJFNvdXJjZSkgeyANCiAgICAgICAgICAgIHsgJF8gLWlzIFtzdHJpbmddIH0geyAkSW
            1hZ2UuUm9vdC5BZGRUcmVlKChHZXQtSXRlbSAkXykuRnVsbE5hbWUsICR0cnVlKTsgY29udGludWUgfSANCiAgICAgICAgICAgIHsgJF8gLWlz
            IFtJTy5GaWxlSW5mb10gfSB7ICRJbWFnZS5Sb290LkFkZFRyZWUoJF8uRnVsbE5hbWUsICR0cnVlKTsgY29udGludWUgfSANCiAgICAgICAgIC
            AgIHsgJF8gLWlzIFtJTy5EaXJlY3RvcnlJbmZvXSB9IHsgJEltYWdlLlJvb3QuQWRkVHJlZSgkXy5GdWxsTmFtZSwgJHRydWUpOyBjb250aW51
            ZSB9IA0KICAgICAgICAgICAgfSNTd2l0Y2ggDQogICAgICAgIH0gI1Byb2Nlc3MgDQogICAgRW5kIHsgDQogICAgICAgIElmICgkQm9vdCkgey
            AkSW1hZ2UuQm9vdEltYWdlT3B0aW9ucz0kQm9vdCB9IA0KICAgICAgICAkUmVzdWx0ID0gJEltYWdlLkNyZWF0ZVJlc3VsdEltYWdlKCkgDQog
            ICAgICAgIFtJU09GaWxlXTo6Q3JlYXRlKCRUYXJnZXQuRnVsbE5hbWUsJFJlc3VsdC5JbWFnZVN0cmVhbSwkUmVzdWx0LkJsb2NrU2l6ZSwkUm
            VzdWx0LlRvdGFsQmxvY2tzKSANCiAgICAgICAgJFRhcmdldCANCiAgICAgICAgfSAjRW5kIA0KDQp9DQpJZiAoKFRlc3QtUGF0aCAkc3JjRGly
            KSAtZXEgJEZhbHNlKXt9DQojIElFWCAiRnVuY3Rpb24gTmV3LUlzb0ZpbGUge2BuJE5ld0lTT2BuYHR9ICNOZXctSXNvRmlsZSINCkdDSSAkc3
            JjRGlyIHwgTmV3LUlTT0ZpbGUgLVBhdGggIiRzcmNEaXIuaXNvIiAtVGl0bGUgIiQoJHNyY0Rpci5SZXBsYWNlKCcgJywnXycpLlNwbGl0KCdc
            JylbLTFdKS0kKEdldC1EYXRlIC1mIHl5eXlNTWRkKSkiIC1Gb3JjZQ0KDQoNCg=='
            }
        $trgPath = $infScript.prefWrkSpace
        $scriptName = 'Drag2ISO.ps1'
        # Create Batch Drop
            If ((Test-Path "$trgPath\2Burn.cmd") -eq $false){
                (Dec64 $fileContents.cmd) -replace '<SCRIPTNAME>',"$($trgPath -replace '\\+[^\\]+$')\$scriptName" | 
                    Out-File "$trgPath\2Burn.cmd" -Encoding ascii -Force
                }
        # Create PS Script
            $trgPath = $trgPath -replace '\\+[^\\]+$'
            If ((Test-Path "$trgPath\$scriptName") -eq $false){
                (Dec64 $fileContents.ps1) | Out-File "$trgPath\$scriptName" -Encoding ascii -Force
                }
    }

    function Get-ModuleStatus
    { 
        Param
        (
            [parameter(ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Mandatory=$true, HelpMessage="No module name specified!")] 
            [string]$name
        )
	    if (!(Get-Module -name "$name"))
        { 
		    if (Get-Module -ListAvailable | Where-Object {$_.name -eq "$name"})
            { 
			    Import-Module -Name "$name" 
			    # module was imported
			    return $true
		    }
            else
            {
                # module was not available
                return $false
            }
	    }
        else
        {
		    # module was already imported
		    # Write-Host "$name module already imported"
		    return $true
	    }
    }

    Function Save-Session
    {
        $trgFolder = $dirISEBU
        $tabList = $psise.PowerShellTabs.DisplayName
        $tabCurrent = $psise.CurrentPowerShellTab.DisplayName
        [System.Collections.ArrayList]$tabFiles = @()
        ForEach ($tab in $tabList)
        {
            $curTab = $psise.PowerShellTabs | Where-Object displayname -eq $tab
            ForEach ($itm in $curTab.Files)
            {
                $obj = [psCustomObject]@{
                    IsSaved = $itm.IsSaved
                    IsUntitled = $itm.IsUntitled
                    IsRecovered = $itm.IsRecovered
                    FullPath = $itm.FullPath
                    IsActiveFile = $(If ($psise.CurrentFile.FullPath -eq $itm.FullPath){$true} Else {$false})
                    Tab = $curTab.DisplayName
                    IsActiveTab = $(If ($curTab.DisplayName -eq $tabCurrent){$true} Else {$false})
                    ZoomLevel = $curTab.ZoomLevel
                    }
                $tabFiles.Add($obj) | Out-Null
            }
        }
        Return $tabFiles
    }
   
   function Convert-ObjectToHashtable
    {
        param
        (
            [Parameter(Mandatory,ValueFromPipeline)]
            $object,
 
            [Switch]
            $ExcludeEmpty
        )
 
        process
        {
            $object.PSObject.Properties | 
            # sort property names
            Sort-Object -Property Name |
            # exclude empty properties if requested
            Where-Object { $ExcludeEmpty.IsPresent -eq $false -or $_.Value -ne $null } |
            ForEach-Object { 
                $hashtable = [Ordered]@{}} { 
                $hashtable[$_.Name] = $_.Value 
                } { 
                $hashtable 
                } 
        }
    } 

    Function Rename-PsIseTab
    {
        Switch ($psise.CurrentPowerShellTab.files.DisplayName){ 
        {$_ -contains 'inworks.ps1'}{ "`$psise.CurrentPowerShellTab.DisplayName = 'My Inworks' "}
        {$_ -contains 'azurelab.ps1'}{ "`$psise.CurrentPowerShellTab.DisplayName = 'Azure' "}
        {$_ -contains 'CM.PowerShell.Profils.ps1'}{ "`$psise.CurrentPowerShellTab.DisplayName = 'Profiles' "}
        {$_ -contains 'LabConfig.ps1'}{ "`$psise.CurrentPowerShellTab.DisplayName = 'Labs' "}
        }
    }

    Function Start-RSJob
    {
        <#
            .SYNOPSIS
                Starts a background job using runspaces.

            .DESCRIPTION
                This will run a command in the background, leaving your console available to perform other tasks. This uses
                runspaces in runspacepools which allows for throttling of running jobs. As the jobs are finished, they will automatically
                dispose of each runspace and allow other runspace jobs in queue to begin based on the throttling of the runspacepool.

                This is available on PowerShell V3 and above. By doing this, you can use the $Using: variable to take variables
                in the local scope and apply those directly into the scriptblock of the background runspace job.

            .PARAMETER ScriptBlock
                The scriptblock that holds all of the commands which will be run in the background runspace. You must specify
                at least one Parameter in the Param() to account for the item that is being piped into Start-Job.

            .PARAMETER FilePath
                This is the path to a file containing code that will be run in the background runspace job.

            .PARAMETER InputObject
                The object being piped into Start-RSJob or applied via the parameter.

            .PARAMETER Name
                The name of a background runspace job

            .PARAMETER Batch
                Name of the batch of RSJobs that will be run

            .PARAMETER ArgumentList
                List of values that will be applied at the end of the argument list in the Param() statement.

            .PARAMETER Throttle
                Number of concurrent running runspace jobs which are allowed at a time.

            .PARAMETER ModulesToImport
                A collection of modules that will be imported into the background runspace job.

            .PARAMETER PSSnapinsToImport
                A collection of PSSnapins that will be imported into the background runspace job.

            .PARAMETER FunctionsToImport
                A collection of functions that will be imported for use with a background runspace job.

            .PARAMETER FunctionFilesToImport
                A collection of files containing custom functions that will be imported into the background runspace job.

            .PARAMETER VariablesToImport
                A collection of variables that will be imported for use with a background runspace job.
                If used, $using:variable not expanded !

            .NOTES
                Name: Start-RSJob
                Author: Boe Prox/Max Kozlov

            .LINKS
                https://github.com/proxb/PoshRSJob/blob/master/PoshRSJob/Public/Start-RSJob.ps1

            .EXAMPLE
                Get-ChildItem -Directory | Start-RSjob -Name {$_.Name} -ScriptBlock {
                    Param($Directory)
                    Write-Verbose $_
                    $Sum = (Get-ChildItem $Directory.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                    Measure-Object -Property Length -Sum).Sum
                    [pscustomobject]@{
                        Name = $Directory.Name
                        SizeMB = ([math]::round(($Sum/1MB),2))
                    }
                }

                Id  Name                 State           HasMoreData  HasErrors    Command
                --  ----                 -----           -----------  ---------    -------
                13  Contacts             Running         False        False        ...
                14  Desktop              Running         False        False        ...
                15  Documents            Running         False        False        ...
                16  Downloads            Running         False        False        ...
                17  Favorites            Running         False        False        ...
                18  Links                Running         False        False        ...
                19  Music                Running         False        False        ...
                20  OneDrive             Running         False        False        ...
                21  Pictures             Running         False        False        ...
                22  Saved Games          Running         False        False        ...
                23  Searches             Running         False        False        ...
                24  Videos               Running         False        False        ...

                Get-RSJob | Receive-RSJob

                Name          SizeMB
                ----          ------
                Contacts           0
                Desktop         7.24
                Documents      83.99
                Downloads    10259.6
                Favorites          0
                Links              0
                Music       16691.89
                OneDrive     1485.24
                Pictures     1734.91
                Saved Games        0
                Searches           0
                Videos         17.19

                Description
                -----------
                Starts a background runspace job that looks at the total size of each folder. Using Get-RSJob | Recieve-RSJob shows
                the results when the State is Completed.

            .EXAMPLE
                $Test = 'test'
                $Something = 1..10
                1..5|start-rsjob -Name {$_} -ScriptBlock {
                    Param($Object) [pscustomobject]@{
                        Result=($Object*2)
                        Test=$Using:Test
                        Something=$Using:Something
                    }
                }

                Id  Name                 State           HasMoreData  HasErrors    Command
                --  ----                 -----           -----------  ---------    -------
                76  1                    Completed       True         False        ...
                77  2                    Running         False        False        ...
                78  3                    Running         False        False        ...
                79  4                    Completed       False        False        ...
                80  5                    Completed       False        False        ...

                Get-RSjob | Receive-RSJob

                Result Test Something
                ------ ---- ---------
                     2 test {1, 2, 3, 4...}
                     4 test {1, 2, 3, 4...}
                     6 test {1, 2, 3, 4...}
                     8 test {1, 2, 3, 4...}
                    10 test {1, 2, 3, 4...}

                Description
                -----------
                Shows an example of the $Using: variable being used in the scriptblock.

            .EXAMPLE
                $Test = 42
                $AnotherTest = 7
                $String = 'SomeString'
                $ProcName = 'powershell_ise'
                $ScriptBlock = {
                    Param($y,$z)
                    [pscustomobject] @{
                        Test = $y
                        Proc = (Get-Process -Name $Using:ProcName)
                        String = $Using:String
                        AnotherTest = ($z+$_)
                        PipedObject = $_
                    }
                }

                1..5|Start-RSJob $ScriptBlock -ArgumentList $test, $anothertest

                Description
                -----------
                Shows an example of the $Using: variable being used in the scriptblock as well as $_ and multiple -ArgumentList parameters.

        #>
        [OutputType('RSJob')]
        [cmdletbinding(
            DefaultParameterSetName = 'ScriptBlock'
        )]
        Param (
            [parameter(Mandatory = $True, Position = 0, ParameterSetName = 'ScriptBlock')]
            [ScriptBlock]$ScriptBlock,
            [parameter(Position = 0, ParameterSetName = 'ScriptPath')]
            [string]$FilePath,
            [parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [object]$InputObject,
            [parameter()]
            [object]$Name,
            [parameter()]
            [string]$Batch = $([guid]::NewGuid().ToString()),
            [parameter()]
            [array]$ArgumentList = @(),
            [parameter()]
            [int]$Throttle = 5,
            [parameter()]
            [Alias('ModulesToLoad')]
            [string[]]$ModulesToImport,
            [parameter()]
            [Alias('PSSnapinsToLoad')]
            [string[]]$PSSnapinsToImport,
            [parameter()]
            [Alias('FunctionsToLoad')]
            [string[]]$FunctionsToImport,
            [parameter()]
            [Alias('FunctionFilesToLoad')]
            [string[]]$FunctionFilesToImport,
            [parameter()]
            [Alias('VariablesToLoad')]
            [string[]]$VariablesToImport
        )
        Begin {

            If ($PSBoundParameters['Debug']) {
                $DebugPreference = 'Continue'
            }

            Write-Debug "[BEGIN]"

            If ($PSBoundParameters.ContainsKey('Verbose')) {
                Write-Verbose "Displaying PSBoundParameters"
                $PSBoundParameters.GetEnumerator() | ForEach-Object {
                    Write-Verbose $_
                }
            }

            If ($PSBoundParameters.ContainsKey('Name')) {
                If ($Name -isnot [scriptblock]) {
                    $JobName = [scriptblock]::Create("Write-Output `"$Name`"")
                }
                Else {
                    $JobName = [scriptblock]::Create( ($Name -replace '\$_', '$Item'))
                }
            }
            Else {
                Write-Verbose "Creating default Job Name"
                $JobName = [scriptblock]::Create('Write-Output Job$($Id)')
            }

            $InitialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

            If ($PSBoundParameters['ModulesToImport']) {
                [void]$InitialSessionState.ImportPSModule($ModulesToImport)
            }

            If ($PSBoundParameters['PSSnapinsToImport']) {
                ForEach ($PSSnapin in $PSSnapinsToImport) {
                    [void]$InitialSessionState.ImportPSSnapIn($PSSnapin, [ref]$Null)
                }
            }

            If ($PSBoundParameters['FunctionsToImport']) {
                Write-Verbose "Loading custom functions: $($FunctionsToImport -join '; ')"
                ForEach ($Function in $FunctionsToImport) {
                    Try {
                        RegisterScriptScopeFunction -Name $Function
                        $Definition = Get-Content Function:\$Function -ErrorAction Stop
                        Write-Debug "Definition: $($Definition)"
                        $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function, $Definition
                        $InitialSessionState.Commands.Add($SessionStateFunction)
                    }
                    Catch {
                        Write-Warning "$($Function): $($_.Exception.Message)"
                    }

                    #Check for an alias and add it as well
                    If ($Alias = Get-Alias | Where-Object { $_.Definition -eq $Function }) {
                        $AliasEntry = New-Object System.Management.Automation.Runspaces.SessionStateAliasEntry -ArgumentList $Alias.Name, $Alias.Definition
                        $InitialSessionState.Commands.Add($AliasEntry)
                    }
                }
            }

            If ($PSBoundParameters['FunctionFilesToImport']) {
                Write-Verbose "Loading custom function files : $($FunctionFilesToImport -join '; ')"
                $functionsInFiles = GetFunctionByFile -FilePath $FunctionFilesToImport

                if ($null -eq $functionsInFiles) {
                    Write-Warning "Cannot find any functions in given files"
                }
                else {
                    ForEach ($function in $functionsInFiles) {
                        $functionName = $function.Name
                        Write-Verbose "Loading custom function : $functionName"

                        try {
                            $functionDefinition = GetFunctionDefinitionByFunction -FunctionItem $function
                            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $functionName, $functionDefinition
                            $InitialSessionState.Commands.Add($SessionStateFunction)
                        }
                        catch {
                            Write-Warning "$($functionName): $($_.Exception.Message)"
                        }

                        #Check for an alias and add it as well
                        if ($Alias = Get-Alias | Where-Object { $_.Definition -eq $Function }) {
                            $AliasEntry = New-Object System.Management.Automation.Runspaces.SessionStateAliasEntry -ArgumentList $Alias.Name, $Alias.Definition
                            $InitialSessionState.Commands.Add($AliasEntry)
                        }
                    }
                }
            }

            If ($PSBoundParameters['VariablesToImport']) {
                Write-Verbose "Loading variables: $($VariablesToImport -join '; ')"
                $UserVariables = New-Object System.Collections.ArrayList
                $vartable = $null
                foreach ($varname in $VariablesToImport) {
                    If ($MyInvocation.CommandOrigin -eq 'Runspace') {
                        $vars = @(Get-Variable $varname -ErrorAction Continue | Where-Object { $_.Options -notmatch 'Constant' })
                    }
                    else {
                        # matching support uses powershell internals
                        if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($varname)) {
                            if (-not $vartable) {
                                $Flags = 'static', 'nonpublic', 'instance'
                                $internal_p = $PSCmdlet.SessionState.GetType().GetProperty('Internal',$Flags)
                                $internal = $internal_p.GetValue($PSCmdlet.SessionState, $null)
                                $vartable_m = $internal.GetType().GetMethod('GetVariableTable',$Flags)
                                $vartable = $vartable_m.Invoke($internal, $null).GetEnumerator() | Select-Object -ExpandProperty Key
                            }
                            $vars = @($vartable | Where-Object { $_ -like $varname } | ForEach-Object {
                                $PSCmdlet.SessionState.PSVariable.Get($_)
                            })
                        }
                        else {
                            $vars = @($PSCmdlet.SessionState.PSVariable.Get($varname))
                        }
                    }
                    [void]$UserVariables.AddRange($vars)
                }
                if ($UserVariables.Count -gt 0) {
                    Write-Verbose "Loaded variables: $(($UserVariables | Select-Object -ExpandProperty Name) -join '; ')"
                    foreach($var in $UserVariables)
                    {
                        $v = New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $var.Name, $var.Value, $var.Description
                        $InitialSessionState.Variables.Add($v)
                    }
                }
            }

            If ($PSBoundParameters['FilePath']) {
                $ScriptBlock = [scriptblock]::Create((Get-Content $FilePath | Out-String))
            }

            $List = New-Object System.Collections.ArrayList
            $ForeachDetected = $false
            $ForeachValue = $null
            # in v2 $_ variable always defined, so $ForeachDetected always be true on this state
            If ($PSCmdlet.SessionState.PSVariable.Get('_')) {
                   Write-Debug 'it may be ForEach loop'
                $ForeachDetected = $true
                # on v2 $_ always exists in begin block, on v3+ only in process for foreach loop like    $data | Foreach-Object { "here it is: $_" }
                Try {
                    $ForeachValue = $PSCmdlet.SessionState.PSVariable.Get('_') | Select-Object -ExpandProperty Value
                    if ($ForeachValue -eq $null) {
                        $ForeachDetected = $false # since psv2 traps on above code, we always do not support $null in $_
                    }
                }
                Catch {
                    #useless message: always exists on v2 when $_ absent and never on v3+
                    # Write-Warning "Start-RSJob : Error adding pipeline variable $($_.Exception.Message)"
                    $ForeachDetected = $false # on psv2 we doesn't support "$null | %{ Start-RSJob }" pattern
                }
            }
            Write-Debug "ListCount: $($List.Count)"
        }

        Process {
            Write-Debug "[PROCESS]"
            If ($PSBoundParameters.ContainsKey('InputObject')) {
                [void]$List.AddRange(@($InputObject))
                # If we here - it is not foreach loop
                $ForeachDetected = $false
            }
        }

        End {
            Write-Debug "[END]"
            $SBParamVars = @(GetParamVariable -ScriptBlock $ScriptBlock)
            $SBParamCount = $SBParamVars.Count
            $ArgumentCount = $ArgumentList.Count
            # We add $_ into list only if there is no InputObject
            # so in case: $data | Foreach-Object { $_.Value | Start-RSJob }
            # rsjob get as input $_.Value but not $_
            # but for:  $data | Foreach-Object { Start-RSJob }
            # rsjob can get $_ as input
            ### for long param() lists it can lead to insert null as first param
            ###if ($List.Count -eq 0 -and -not $ForeachDetected) {
            ###    #make empty call ( Start-RSJob ) like   ( $null | Start-RSJob ) call to support $null as InputObject in  $null | Foreach-Object { Start-RSJob } case
            ###    $ForeachDetected = $true
            ###}
            if ($ForeachDetected) {
                Write-Debug 'it is ForEach loop'
                [void]$List.Add($ForeachValue)
            }
            # NewParam variant
            if ($List.Count) {
                $ArgumentCount++
            }
            # we add $_ into param() block when (ArgumentList+InputObject).Count > scriptBlock.Param().Count #or ForeachDetected
            #$InsertPSItemParam = ($ArgumentCount -gt $SBParamCount -and $List.Count)

            # Current version behaviour variant
            $ArgumentCount = $ArgumentList.Count
            # Without 'Ignore' fix
            #$InsertPSItemParam = ($SBParamCount -ne 1 -or (($SBParamCount -ne $ArgumentCount) -xor $List.Count))
            # With 'Ignore' fix
            $InsertPSItemParam = (($SBParamCount -ne 1 -or $SBParamCount -eq $ArgumentCount) -and $List.Count)
            #

            Write-Debug ("ArgumentCount: $ArgumentCount | List.Count: $($List.Count) | SBParamCount: $SBParamCount | InsertPSItemParam: $InsertPSItemParam")
            #region Convert ScriptBlock for $Using:
            $PreviousErrorAction = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'
            Write-Verbose "PowerShell Version: $($PSVersionTable.PSVersion.Major)"
            $UsingVariables = $UsingVariableValues = @()
            if (-Not $PSBoundParameters['VariablesToImport']) {
                Switch ($PSVersionTable.PSVersion.Major) {
                    2 {
                        Write-Verbose "Using PSParser with PowerShell V2"
                        $UsingVariables = @(GetUsingVariablesV2 -ScriptBlock $ScriptBlock)
                        Write-Verbose "Using Count: $($UsingVariables.count)"
                        Write-Verbose "$($UsingVariables|Out-String)"
                        Write-Verbose "CommandOrigin: $($MyInvocation.CommandOrigin)"
                        If ($UsingVariables.count -gt 0) {
                            $UsingVariableValues = @($UsingVariables | ForEach-Object {
                                $Name = $_.Content -replace 'Using:'
                                Try {
                                    If ($MyInvocation.CommandOrigin -eq 'Runspace') {
                                        $Value = (Get-Variable -Name $Name).Value
                                    }
                                    Else {
                                        $Value = $PSCmdlet.SessionState.PSVariable.Get($Name).Value
                                        If ([string]::IsNullOrEmpty($Value)) {
                                            Throw 'No value!'
                                        }
                                    }
                                    New-Object V2UsingVariable -Property @{
                                        Name = $Name
                                        NewName = '$__using_{0}' -f $Name
                                        Value = $Value
                                        NewVarName = ('__using_{0}') -f $Name
                                    }
                                }
                                Catch {
                                    Throw "Start-RSJob : The value of the using variable '$($Var.SubExpression.Extent.Text)' cannot be retrieved because it has not been set in the local session."
                                }
                            })

                            Write-Verbose ("Found {0} `$Using: variables!" -f $UsingVariableValues.count)
                        }
                    }
                    Default {
                        Write-Debug "Using AST with PowerShell V3+"
                        $UsingVariables = @(GetUsingVariables $ScriptBlock)
                        #region Get Variable Values
                        If ($UsingVariables.count -gt 0) {
                            $UsingVar = $UsingVariables | Group-Object SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}
                            Write-Debug "CommandOrigin: $($MyInvocation.CommandOrigin)"
                            $UsingVariableValues = @(ForEach ($Var in $UsingVar) {
                                Try {
                                    If ($MyInvocation.CommandOrigin -eq 'Runspace') {
                                        $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath
                                    }
                                    Else {
                                        $Value = ($PSCmdlet.SessionState.PSVariable.Get($Var.SubExpression.VariablePath.UserPath))
                                        If ([string]::IsNullOrEmpty($Value)) {
                                            Throw 'No value!'
                                        }
                                    }
                                    [pscustomobject]@{
                                        Name = $Var.SubExpression.Extent.Text
                                        Value = $Value.Value
                                        NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                        NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    }
                                }
                                Catch {
                                    Throw "Start-RSJob : The value of the using variable '$($Var.SubExpression.Extent.Text)' cannot be retrieved because it has not been set in the local session."
                                }
                            })
                            #endregion Get Variable Values
                            Write-Verbose ("Found {0} `$Using: variables!" -f $UsingVariableValues.count)
                        }
                    }
                }
            }
            $ConvertScriptParams = @{
                ScriptBlock = $ScriptBlock
                HasParam = ($SBParamVars.Count -ne 0)
                UsingVariables = $UsingVariables
                UsingVariableValues = $UsingVariableValues
                InsertPSItem = $InsertPSItemParam
            }
            If ($UsingVariableValues.Count -gt 0 -OR $InsertPSItemParam) {
                Switch ($PSVersionTable.PSVersion.Major) {
                    2 {
                        $NewScriptBlock = ConvertScriptBlockV2 @ConvertScriptParams
                    }
                    Default {
                        $NewScriptBlock = ConvertScript @ConvertScriptParams
                    }
                }
            }
            Else {
                $NewScriptBlock = $ScriptBlock
            }

            $ErrorActionPreference = $PreviousErrorAction
            #endregion Convert ScriptBlock for $Using:

            Write-Debug "NewScriptBlock: $($NewScriptBlock)"

            #region RunspacePool Creation
            [System.Threading.Monitor]::Enter($PoshRS_RunspacePools.syncroot)
            try {
                $__RSPObject = $PoshRS_RunspacePools | Where-Object {
                    $_.RunspacePoolID -eq $Batch
                }
                If ($__RSPObject) {
                    Write-Verbose "Using current runspacepool <$($__RSPObject.RunspacePoolID)>"
                    $RunspacePoolID = $__RSPObject.RunspacePoolID
                    $RSPObject = $__RSPObject
                    $RSPObject.LastActivity = Get-Date
                }
                Else {
                    Write-Verbose "Creating new runspacepool <$Batch>"
                    $RunspacePoolID = $Batch
                    $PSModulePath = $env:PSModulePath
                    $RunspacePool = [runspacefactory]::CreateRunspacePool($InitialSessionState)
                    If ($RunspacePool.psobject.Properties["ApartmentState"]) {
                        #ApartmentState doesn't exist in Nano Server
                        $RunspacePool.ApartmentState = 'STA'
                    }
                    [void]$RunspacePool.SetMaxRunspaces($Throttle)
                    If ($PSVersionTable.PSVersion.Major -gt 2) {
                        $RunspacePool.CleanupInterval = [timespan]::FromMinutes(2)
                    }
                    $RunspacePool.Open()
                    $RSPObject = New-Object RSRunspacePool -Property @{
                        RunspacePool = $RunspacePool
                        MaxJobs = $RunspacePool.GetMaxRunspaces()
                        RunspacePoolID = $RunspacePoolID
                        LastActivity = Get-Date
                    }

                    #[System.Threading.Monitor]::Enter($PoshRS_RunspacePools.syncroot) #Temp add
                    [void]$PoshRS_RunspacePools.Add($RSPObject)
                    $env:PSModulePath = $PSModulePath
                }
            }
            finally {
                [System.Threading.Monitor]::Exit($PoshRS_RunspacePools.syncroot)
            }
            #endregion RunspacePool Creation

            Write-Debug "ListCount: $($List.Count)"
            $RealPipeline = $List.Count -gt 0;
            if (-Not $RealPipeline) {
                [void]$List.Add($null) # fake job creation cycle
            }
            ForEach ($Item in $List) {
                $ID = Increment
                $PowerShell = [powershell]::Create().AddScript($NewScriptBlock, $True)
                $PowerShell.RunspacePool = $RSPObject.RunspacePool

                if ($RealPipeline) {
                    Write-Verbose "Using $($Item) as pipeline variable"
                    [void]$PowerShell.AddArgument($Item)
                }
                else {
                    Write-Verbose "No InputObject"
                }
                Write-Verbose "Checking for Using: variables"
                If ($UsingVariableValues.count -gt 0) {
                    For ($i=0;$i -lt $UsingVariableValues.count;$i++) {
                        Write-Verbose "Adding Param: $($UsingVariableValues[$i].Name) Value: $($UsingVariableValues[$i].Value)"
                        [void]$PowerShell.AddParameter($UsingVariableValues[$i].NewVarName, $UsingVariableValues[$i].Value)
                    }
                }
                Write-Verbose "Checking for ArgumentList"
    #            if ($ArgumentList.Count -eq 1) {
    #                Write-Verbose "Adding Argument: $($ArgumentList[0]) <$($ArgumentList[0].GetType().Fullname)>"
    #                [void]$PowerShell.AddArgument($ArgumentList[0])
    #            }
    #            else {
                    ForEach ($Argument in $ArgumentList) {
                        Write-Verbose "Adding Argument: $($Argument) <$($Argument.GetType().Fullname)>"
                        [void]$PowerShell.AddArgument($Argument)
                    }
    #            }

                Write-Verbose "Invoking Runspace"
                $Handle = $PowerShell.BeginInvoke()
                Write-Verbose "Determining Job Name"
                $_JobName = If ($PSVersionTable.PSVersion.Major -eq 2) {
                    $JobName.Invoke()
                }
                Else {
                    $JobName.InvokeReturnAsIs()
                }
                $Object = New-Object RSJob -Property @{
                    Name = $_JobName
                    InputObject = $Item
                    InstanceID = [guid]::NewGuid().ToString()
                    ID = $ID
                    Handle = $Handle
                    InnerJob = $PowerShell
                    Runspace = $PowerShell.Runspace
                    Finished = $Handle.IsCompleted
                    Command  = $ScriptBlock.ToString()
                    RunspacePoolID = $RunSpacePoolID
                    Batch          = $Batch
                }

                $RSPObject.LastActivity = Get-Date
                Write-Verbose "Adding RSJob to Jobs queue"
                [System.Threading.Monitor]::Enter($PoshRS_Jobs.syncroot)
                [void]$PoshRS_Jobs.Add($Object)
                [System.Threading.Monitor]::Exit($PoshRS_Jobs.syncroot)
                Write-Verbose "Display RSJob"
                $Object

            }
        }
    }

    function Get-Software
    {
        <#
            .SYNOPSIS
            Reads installed software from registry

            .PARAMETER DisplayName
            Name or part of name of the software you are looking for

            .EXAMPLE
            Get-Software -DisplayName *Office*
            Get-Software -DisplayName *Office* | Select-Object -Property DisplayName, InstallSource
            returns all software with "Office" anywhere in its name

        #>

        param
        (
        # emit only software that matches the value you submit:
        [string]
        $DisplayName = '*'
        )


        #region define friendly texts:
        $Scopes = @{
            HKLM = 'All Users'
            HKCU = 'Current User'
        }

        $Architectures = @{
            $true = '32-Bit'
            $false = '64-Bit'
        }
        #endregion

        #region define calculated custom properties:
            # add the scope of the software based on whether the key is located
            # in HKLM: or HKCU:
            $Scope = @{
                Name = 'Scope'
                Expression = {
                $Scopes[$_.PSDrive.Name]
                }
            }

            # add architecture (32- or 64-bit) based on whether the registry key 
            # contains the parent key WOW6432Node:
            $Architecture = @{
            Name = 'Architecture'
            Expression = {$Architectures[$_.PSParentPath -like '*\WOW6432Node\*']}
            }
        #endregion

        #region define the properties (registry values) we are after
            # define the registry values that you want to include into the result:
            $Values = 'AuthorizedCDFPrefix',
                        'Comments',
                        'Contact',
                        'DisplayName',
                        'DisplayVersion',
                        'EstimatedSize',
                        'HelpLink',
                        'HelpTelephone',
                        'InstallDate',
                        'InstallLocation',
                        'InstallSource',
                        'Language',
                        'ModifyPath',
                        'NoModify',
                        'PSChildName',
                        'PSDrive',
                        'PSParentPath',
                        'PSPath',
                        'PSProvider',
                        'Publisher',
                        'Readme',
                        'Size',
                        'SystemComponent',
                        'UninstallString',
                        'URLInfoAbout',
                        'URLUpdateInfo',
                        'Version',
                        'VersionMajor',
                        'VersionMinor',
                        'WindowsInstaller',
                        'Scope',
                        'Architecture'
        #endregion

        #region Define the VISIBLE properties
            # define the properties that should be visible by default
            # keep this below 5 to produce table output:
            [string[]]$visible = 'DisplayName','DisplayVersion','Scope','Architecture'
            [Management.Automation.PSMemberInfo[]]$visibleProperties = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',$visible)
        #endregion

        #region read software from all four keys in Windows Registry:
            # read all four locations where software can be registered, and ignore non-existing keys:
            Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                                'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Ignore |
            # exclude items with no DisplayName:
            Where-Object DisplayName |
            # include only items that match the user filter:
            Where-Object { $_.DisplayName -like $DisplayName } |
            # add the two calculated properties defined earlier:
            Select-Object -Property *, $Scope, $Architecture |
            # create final objects with all properties we want:
            Select-Object -Property $values |
            # sort by name, then scope, then architecture:
            Sort-Object -Property DisplayName, Scope, Architecture |
            # add the property PSStandardMembers so PowerShell knows which properties to
            # display by default:
            Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $visibleProperties -PassThru
        #endregion 
    }

    Function Get-MSDNProductId
    {
        Param
        (
            $searchText,
            $file,
            [switch]$V2
        )
        $keys = [xml](Get-Content $file)
        $trgKey = '/root/YourKey/Product_Key'
        If ($V2.IsPresent -eq $false)
        {
            $Result = Invoke-Expression "`$keys.$($trgKey -replace '/','.' -replace '^.')" |
                Where-Object Name -match $searchText |
                ForEach-Object{ "$($_.name + "  :  " + $_.key."#text")" }
        }
        Else
        {
            $Result = Select-Xml -Path $file -XPath $trgKey |
                Where-Object { $_.Node.name -match $searchText } |
                    ForEach-Object{ $_.Node.name + "  :  " + $_.node.key."#text" }
        }
        Return $Result
    }

    Function Test-IsAdmin
    {
        # If ((Test-IsAdmin) -eq $false){ Write-Host -f Magenta 'The current user context requires adminitrative rights.  EXITING  '}
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    Function Unblock-MyScannedDocs
    {
        Param
        (
            $scanDir = "$env:OneDriveConsumer\Documents\Scanned Documents\HP Scanner Dump\HPSCANS",
            $isePath = "$env:SystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe"
        )
        Write-Output -Verbose "Unblocking Scanned Images from Mirkwood"
        Get-ChildItem $scanDir -Recurse | Unblock-File -Verbose
        Pause
        }

    Function Restore-IseProfileEdits
    {
        $path = $env:OneDriveConsumer + "\Documents\WindowsPowerShell"
        $path2 = $path + "\ProfileAdds"
        psedit -filenames (Get-ChildItem "$path\*.ps1" | Select-Object -exp FullName)
        psedit -filenames (Get-ChildItem "$path2\*.psm1" | Select-Object -exp FullName)
        psedit -filenames (Get-ChildItem "$path\Snippets\myPersonal.snippets.ps1xml" | Select-Object -exp FullName)
    }

    function Convert-GeoDecToDMS ($Lat=35.843620, $Long=-83.483009)
    {
        If([INT]$Long -LT 0 ){$ew = 'W'} Else {$ew = 'E'}
        If([INT]$Lat -LT 0 ){$ns = 'S'} Else {$ns = 'N'}
        $calc = {
            Param ($geoVal)
            $geoVal = [Math]::abs($geoVal)
            $Deg = [Math]::abs([int]([string]$geoVal).split('.')[0])
            $Min = [Math]::abs([int]([string](($geoVal-$Deg)*60)).split('.')[0])
            $Sec = [Math]::abs([Math]::ROUND((((($geoVal-$Deg)*60)-$Min)*60),2))
            return "$Deg⁰ $Min' $Sec`""
            }
        $rLong = "Longitude: $ew " + (& $calc $Long) + " ($Long)"
        $rLat  = "Latitude: $ns " + (& $calc $Lat ) + " ($Lat)"
        return $rLat, $rLong
    }

    Function Write-Log
    {
        <#
            .Synopsis
               Write-Log writes a message to a specified log file with the current time stamp.

            .DESCRIPTION
               The Write-Log function is designed to add logging capability to other scripts.
               In addition to writing output and/or verbose you can write to a log file for
               later debugging.

            .NOTES
               Created by: Jason Wasser @wasserja
               Modified: 11/24/2015 09:30:19 AM  

               Changelog:
                * Code simplification and clarification - thanks to @juneb_get_help
                * Added documentation.
                * Renamed LogPath parameter to Path to keep it standard - thanks to @JeffHicks
                * Revised the Force switch to work as it should - thanks to @JeffHicks

               To Do:
                * Add error handling if trying to create a log file in a inaccessible location.
                * Add ability to write $Message to $Verbose or $Error pipelines to eliminate
                  duplicates.

            .PARAMETER Message
               Message is the content that you wish to add to the log file. 

            .PARAMETER Path
               The path to the log file to which you would like to write. By default the function will 
               create the path and file if it does not exist. 

            .PARAMETER Level
               Specify the criticality of the log information being written to the log (i.e. Error, Warning, Informational)

            .PARAMETER NoClobber
               Use NoClobber if you do not wish to overwrite an existing file.

            .EXAMPLE
               Write-Log -Message 'Log message' 
               Writes the message to c:\Logs\PowerShellLog.log.

            .EXAMPLE
               Write-Log -Message 'Restarting Server.' -Path c:\Logs\Scriptoutput.log
               Writes the content to the specified log file and creates the path and file specified.

            .EXAMPLE
               Write-Log -Message 'Folder does not exist.' -Path c:\Logs\Script.log -Level Error
               Writes the message to the specified log file as an error message, and writes the message to the error pipeline.

            .LINK
               https://gallery.technet.microsoft.com/scriptcenter/Write-Log-PowerShell-999c32d0
        #>
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory=$true,
                       ValueFromPipelineByPropertyName=$true)]
            [ValidateNotNullOrEmpty()]
            [Alias("LogContent")]
            [string]$Message,

            [Parameter(Mandatory=$false)]
            [Alias('LogPath')]
            [string]$Path='C:\Logs\PowerShellLog.log',
        
            [Parameter(Mandatory=$false)]
            [ValidateSet("Error","Warn","Info")]
            [string]$Level="Info",
        
            [Parameter(Mandatory=$false)]
            [switch]$NoClobber
        )
        Begin
        {
            # Set VerbosePreference to Continue so that verbose messages are displayed.
            $VerbosePreference = 'Continue'
        }
        Process
        {
        
            # If the file already exists and NoClobber was specified, do not write to the log.
            if ((Test-Path $Path) -AND $NoClobber) {
                Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name."
                Return
                }

            # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
            elseif (!(Test-Path $Path)) {
                Write-Verbose "Creating $Path."
                $NewLogFile = New-Item $Path -Force -ItemType File
                }

            else {
                # Nothing to see here yet.
                }

            # Format Date for our Log File
            $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            # Write message to error, warning, or verbose pipeline and specify $LevelText
            switch ($Level) {
                'Error' {
                    Write-Error $Message
                    $LevelText = 'ERROR:'
                    }
                'Warn' {
                    Write-Warning $Message
                    $LevelText = 'WARNING:'
                    }
                'Info' {
                    Write-Verbose $Message
                    $LevelText = 'INFO:'
                    }
                }
        
            # Write log entry to $Path
            "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append
        }
        End
        {
        }
    }

    Function Get-CmdHelpByModule ($module)
    {
        # Get-CmdHelpByModule 'PowerShell-Beautifier'
        # Get-CmdHelpByModule 'pki'
        $module| ForEach-Object{
            If ((Get-Module $_).Name -notmatch $_){ "Install-Module -Name $_" }
            Get-Command -Module $_ | Out-GridView -PassThru | Help -s
            }
    }

    Function Write-Junk
    {
        # Write-Junk -PathName 'C:\Users\Chuck' -FileName 'JunkData' -FileSize 50mb -UseFSUtil 
        # Write-Junk -FileName 'JunkData' -FileSize 50mb -UseFSUtil 
        Param 
        (
            $PathName,
            $FileName,
            $FileExt = 'JNK',
            $FileSize,
            [Switch]$UseFSUtil
        )
        If (!([string]::IsNullOrEmpty($PathName)) -and ((Test-Path $PathName) -eq $false))
        {
            Write-Error "Invalid Path"
            Break
        }
        If (!([string]::IsNullOrEmpty($PathName)))
        {
            $dstName = (Get-Item $PathName).FullName + [char](92) + $FileName + "_<ENG>_" + $FileSize + "." + $FileExt
        }
        Else
        {
            $dstName = ($FileName + "_<ENG>_" + $FileSize + "." + $FileExt)
       }
        Switch ($UseFSUtil.IsPresent)
        {
            $true
            {
                $dstName = [string]($dstName -replace '<ENG>',"fs$(Get-Random -Maximum 1KB)")
                # write-host "fsutil file createnew $dstName $FileSize" -f Green
                Invoke-Expression "fsutil file createnew $dstName $FileSize"
            }
            $false
            {
                $dstName = $dstName -replace '<ENG>',"ps$(Get-Random -Maximum 1KB)"
                $out = New-Object byte[] $FileSize
                (New-Object Random).NextBytes($out)
                [IO.File]::WriteAllBytes($dstName, $out)
            }
        }
    }


    # PSDrive WSMan:\.
# Get TrustedHosts
#  Get-Item $psTrustedHosts
# Set TrustedHosts
# provide a single, comma-separated, string of computer names
# Set-Item $psTrustedHosts -Value 'machineA,machineB'
# or (dangerous) a wild-card
# Set-Item $psTrustedHosts -Value '*'
# to append to the list, the -Concatenate parameter can be used
# Set-Item $psTrustedHosts -Value '10.114.187.133' -Concatenate
