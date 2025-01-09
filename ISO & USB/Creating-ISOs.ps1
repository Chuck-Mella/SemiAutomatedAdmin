    #region - ISOs
        #region - ISOBurning.ps1
            #region - Recreate Burn2ISO Scripts & Links
                $Burn2ISO = [Ordered]@{
                    cmdContent = (Dec64 'VGl0bGU9Q3JlYXRpbmcgSVNPIEltYWdlIGZyb20gIiUxIg0KSWYgW109PVslMV0gRXhpdA0KIiVTeXN0ZW1Sb290JVxzeXN0ZW0zMlxXaW5kb3dzUG93ZXJTaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiAtTm9Qcm9maWxlIC1FeGVjdXRpb25Qb2xpY3kgQnlwYXNzIC1GaWxlICJDOlxVc2Vyc1xQdWJsaWNcRHJhZzJJU08ucHMxIiAtc3JjRGlyICUxDQo6UGF1c2UNCg==')
                    ps1Content = (Dec64 'UGFyYW0gKCRzcmNEaXIpCkZ1bmN0aW9uIE5ldy1Jc29GaWxlDQp7DQogICAgPCMgDQogICAgICAgIC5TeW5vcHNpcyANCiAgICAgICAgQ3JlYXRlcyBhIG5ldyAuaXNvIGZpbGUNCiAgICAgICAgDQogICAgICAgIC5EZXNjcmlwdGlvbiANCiAgICAgICAgVGhlIE5ldy1Jc29GaWxlIGNtZGxldCBjcmVhdGVzIGEgbmV3IC5pc28gZmlsZSBjb250YWluaW5nIGNvbnRlbnQgZnJvbQ0KICAgICAgICBjaG9zZW4gZm9sZGVycyANCiAgICAgICANCiAgICAgICAgLkV4YW1wbGUgDQogICAgICAgIE5ldy1Jc29GaWxlICJjOlx0b29scyIsImM6RG93bmxvYWRzXHV0aWxzIiANCg0KICAgICAgICAgICAgVGhpcyBjb21tYW5kIGNyZWF0ZXMgYSAuaXNvIGZpbGUgaW4gJGVudjp0ZW1wIGZvbGRlciAoZGVmYXVsdA0KICAgICAgICAgICAgbG9jYXRpb24pIHRoYXQgY29udGFpbnMgYzpcdG9vbHMgYW5kIGM6XGRvd25sb2Fkc1x1dGlscyBmb2xkZXJzLg0KICAgICAgICAgICAgVGhlIGZvbGRlcnMgdGhlbXNlbHZlcyBhcmUgYWRkZWQgaW4gdGhlIHJvb3Qgb2YgdGhlIC5pc28gaW1hZ2UuDQogICAgICAgICAgICAgDQogICAgICAgIGRpciBjOlxXaW5QRSB8IA0KICAgICAgICAgICAgTmV3LUlzb0ZpbGUgLVBhdGggYzpcdGVtcFxXaW5QRS5pc28gYA0KICAgICAgICAgICAgICAgICAgICAgICAgLUJvb3RGaWxlIGV0ZnNib290LmNvbSBgDQogICAgICAgICAgICAgICAgICAgICAgICAtTWVkaWEgRFZEUExVU1IgYA0KICAgICAgICAgICAgICAgICAgICAgICAgLVRpdGxlICJXaW5QRSIgDQoNCiAgICAgICAgICAgIFRoaXMgY29tbWFuZCBjcmVhdGVzIGEgYm9vdGFibGUgLmlzbyBmaWxlIGNvbnRhaW5pbmcgdGhlDQogICAgICAgICAgICBjb250ZW50IGZyb20gYzpcV2luUEUgZm9sZGVyLCBidXQgdGhlIGZvbGRlciBpdHNlbGYgaXNuJ3QgaW5jbHVkZWQuDQogICAgICAgICAgICBCb290IGZpbGUgZXRmc2Jvb3QuY29tIGNhbiBiZSBmb3VuZCBpbiBXaW5kb3dzIEFJSy4NCiAgICAgICAgICAgIA0KICAgICAgICAgICAgUmVmZXIgdG8gSU1BUElfTUVESUFfUEhZU0lDQUxfVFlQRSBlbnVtZXJhdGlvbiBmb3IgcG9zc2libGUNCiAgICAgICAgICAgIG1lZGlhIHR5cGVzOiANCiAgICAgICAgICAgIGh0dHA6Ly9tc2RuLm1pY3Jvc29mdC5jb20vZW4tdXMvbGlicmFyeS93aW5kb3dzL2Rlc2t0b3AvYWEzNjYyMTcodj12cy44NSkuYXNweCANCiAgICAjPiANCiAgICBQYXJhbQ0KICAgICggDQogICAgICAgIFtwYXJhbWV0ZXIoUG9zaXRpb249MCxNYW5kYXRvcnk9JHRydWUsVmFsdWVGcm9tUGlwZWxpbmU9JHRydWUpXSRTb3VyY2UsDQogICAgICAgIFtwYXJhbWV0ZXIoUG9zaXRpb249MSxNYW5kYXRvcnk9JGZhbHNlLFZhbHVlRnJvbVBpcGVsaW5lPSR0cnVlKV1bQWxpYXMoJ1BhdGgnKV0NCiAgICAgICAgW1N0cmluZ10gJHRyZ1BhdGggPSAiJCgkZW52OnVzZXJwcm9maWxlKVxEZXNrdG9wXCQoKEdldC1EYXRlKS5Ub1N0cmluZygieXl5eU1NZGQtSEhtbXNzLmZmZmYiKSkuaXNvIiwgDQogICAgICAgIFtzdHJpbmddICRCb290RmlsZSA9ICRudWxsLCANCiAgICAgICAgW3N0cmluZ10gJE1lZGlhID0gIkRpc2siLCANCiAgICAgICAgW3N0cmluZ10gJFRpdGxlID0gKEdldC1EYXRlKS5Ub1N0cmluZygieXl5eU1NZGQtSEhtbXNzLmZmZmYiKSwgDQogICAgICAgIFtzd2l0Y2hdICRGb3JjZSANCiAgICApDQogICAgQmVnaW4NCiAgICB7DQogICAgICAgICMgRGVjb2RlIGhlcmUgc3RyaW5nIGZvciBJU08gcHVibGljIGNsYXNzIGRlZmluaXRpb24NCiAgICAgICAgRnVuY3Rpb24gRGVjNjQoJGEpeyRiID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGEpKTtSZXR1cm4gJGJ9ICMNCiAgICAgICAgKCRjcCA9IG5ldy1vYmplY3QgU3lzdGVtLkNvZGVEb20uQ29tcGlsZXIuQ29tcGlsZXJQYXJhbWV0ZXJzKS5Db21waWxlck9wdGlvbnMgPSAiL3Vuc2FmZSIgDQogICAgICAgIElmICghKCJJU09GaWxlIiAtYXMgW3R5cGVdKSkNCiAgICAgICAgeyANCiAgICAgICAgICAgICRUeXBlID0gKERlYzY0ICJjSFZpYkdsaklHTnNZWE56SUVsVFQwWnBiR1VOQ25zTkNpQWdJQ0J3ZFdKc2FXTWcNCiAgICAgICAgICAgICAgICBkVzV6WVdabElITjBZWFJwWXlCMmIybGtJRU55WldGMFpTaHpkSEpwYm1jZ1VHRjBhQ3dnYjJKcVpXTg0KICAgICAgICAgICAgICAgIDBJRk4wY21WaGJTd2dhVzUwSUVKc2IyTnJVMmw2WlN3Z2FXNTBJRlJ2ZEdGc1FteHZZMnR6S1EwS0lDDQogICAgICAgICAgICAgICAgQWdJSHNOQ2lBZ0lDQWdJQ0FnYVc1MElHSjVkR1Z6SUQwZ01Ec05DaUFnSUNBZ0lDQWdZbmwwWlZ0ZEkNCiAgICAgICAgICAgICAgICBHSjFaaUE5SUc1bGR5QmllWFJsVzBKc2IyTnJVMmw2WlYwN0RRb2dJQ0FnSUNBZ0lGTjVjM1JsYlM1Sg0KICAgICAgICAgICAgICAgIGJuUlFkSElnY0hSeUlEMGdLRk41YzNSbGJTNUpiblJRZEhJcEtDWmllWFJsY3lrN0RRb2dJQ0FnSUNBDQogICAgICAgICAgICAgICAgZ0lGTjVjM1JsYlM1SlR5NUdhV3hsVTNSeVpXRnRJRzhnUFNCVGVYTjBaVzB1U1U4dVJtbHNaUzVQY0cNCiAgICAgICAgICAgICAgICBWdVYzSnBkR1VvVUdGMGFDazdEUW9nSUNBZ0lDQWdJRk41YzNSbGJTNVNkVzUwYVcxbExrbHVkR1Z5Yg0KICAgICAgICAgICAgICAgIDNCVFpYSjJhV05sY3k1RGIyMVVlWEJsY3k1SlUzUnlaV0Z0SUdrZ1BTQlRkSEpsWVcwZ1lYTWdVM2x6DQogICAgICAgICAgICAgICAgZEdWdExsSjFiblJwYldVdVNXNTBaWEp2Y0ZObGNuWnBZMlZ6TGtOdmJWUjVjR1Z6TGtsVGRISmxZVzANCiAgICAgICAgICAgICAgICA3RFFvTkNpQWdJQ0FnSUNBZ2FXWWdLRzhnUFQwZ2JuVnNiQ2tnZXlCeVpYUjFjbTQ3SUgwTkNpQWdJQw0KICAgICAgICAgICAgICAgIEFnSUNBZ2QyaHBiR1VnS0ZSdmRHRnNRbXh2WTJ0ekxTMGdQaUF3S1NCN0RRb2dJQ0FnSUNBZ0lDQWdJDQogICAgICAgICAgICAgICAgQ0JwTGxKbFlXUW9ZblZtTENCQ2JHOWphMU5wZW1Vc0lIQjBjaWs3SUc4dVYzSnBkR1VvWW5WbUxDQXcNCiAgICAgICAgICAgICAgICBMQ0JpZVhSbGN5azdEUW9nSUNBZ0lDQWdJSDBOQ2lBZ0lDQWdJQ0FnYnk1R2JIVnphQ2dwT3lCdkxrTg0KICAgICAgICAgICAgICAgIHNiM05sS0NrN0RRb2dJQ0FnZlEwS2ZRPT0iKQ0KICAgICAgICAgICAgQWRkLVR5cGUgLUNvbXBpbGVyUGFyYW1ldGVycyAkY3AgLVR5cGVEZWZpbml0aW9uICRUeXBlICMtSWdub3JlV2FybmluZ3MNCiAgICAgICAgfSAjSWYNCiAgICAgICAgSWYgKCRCb290RmlsZSAtYW5kIChUZXN0LVBhdGggJEJvb3RGaWxlKSkNCiAgICAgICAgeyANCiAgICAgICAgICAgICgkU3RyZWFtID0gTmV3LU9iamVjdCAtQ29tT2JqZWN0IEFET0RCLlN0cmVhbSkuT3BlbigpIA0KICAgICAgICAgICAgJFN0cmVhbS5UeXBlID0gMSAgIyBhZEZpbGVUeXBlQmluYXJ5IA0KICAgICAgICAgICAgJFN0cmVhbS5Mb2FkRnJvbUZpbGUoKEdldC1JdGVtICRCb290RmlsZSkuRnVsbG5hbWUpIA0KICAgICAgICAgICAgKCRCb290ID0gTmV3LU9iamVjdCAtQ29tT2JqZWN0IElNQVBJMkZTLkJvb3RPcHRpb25zKS5Bc3NpZ25Cb290SW1hZ2UoJFN0cmVhbSkgDQogICAgICAgIH0gI0lmIA0KICAgICAgICAkTWVkaWFUeXBlID0gW09yZGVyZWRdQHtCRFI9MTg7IEJEUkU9MTk7Q0RSPTI7IENEUlc9MztESVNLPTEyOw0KICAgICAgICAgICAgICAgICAgICAgICAgRFZEREFTSFI9OTtEVkREQVNIUlc9MTA7RFZEREFTSFJfRFVBTExBWUVSPTExOw0KICAgICAgICAgICAgICAgICAgICAgICAgRFZEUExVU1I9NjsgRFZEUExVU1JXPTc7RFZEUExVU1JfRFVBTExBWUVSPTg7DQogICAgICAgICAgICAgICAgICAgICAgICBEVkRQTFVTUldfRFVBTExBWUVSPTEzO0RWRFJBTT01O30gI01lZGlhVHlwZQ0KICAgICAgICBJZiAoJE1lZGlhVHlwZVskTWVkaWFdIC1lcSAkbnVsbCkNCiAgICAgICAgew0KICAgICAgICAgICAgd3JpdGUtZGVidWcgIlVuc3VwcG9ydGVkIE1lZGlhIFR5cGU6ICRNZWRpYSI7DQogICAgICAgICAgICB3cml0ZS1kZWJ1ZyAoIkNob29zZSBvbmUgZnJvbTogIiArICRNZWRpYVR5cGUuS2V5cyk7DQogICAgICAgICAgICBCcmVhaw0KICAgICAgICB9ICNJZg0KICAgICAgICAoJEltYWdlID0gbmV3LW9iamVjdCAtY29tIElNQVBJMkZTLk1zZnRGaWxlU3lzdGVtSW1hZ2UgYA0KICAgICAgICAgICAgLVByb3BlcnR5IEB7Vm9sdW1lTmFtZT0kVGl0bGV9KS5DaG9vc2VJbWFnZURlZmF1bHRzRm9yTWVkaWFUeXBlKCRNZWRpYVR5cGVbJE1lZGlhXSkgDQogICAgICAgIElmICgoVGVzdC1QYXRoICR0cmdQYXRoKSAtYW5kICghJEZvcmNlKSkNCiAgICAgICAgew0KICAgICAgICAgICAgIkZpbGUgRXhpc3RzICR0cmdQYXRoIg0KICAgICAgICAgICAgQnJlYWsNCiAgICAgICAgfSANCiAgICAgICAgSWYgKCEoJFRhcmdldCA9IE5ldy1JdGVtIC1QYXRoICR0cmdQYXRoIC1JdGVtVHlwZSBGaWxlIC1Gb3JjZSkpDQogICAgICAgIHsNCiAgICAgICAgICAgICJDYW5ub3QgY3JlYXRlIGZpbGUgJHRyZ1BhdGgiDQogICAgICAgICAgICBCcmVhaw0KICAgICAgICB9IA0KICAgIH0gI0JlZ2luDQogICAgUHJvY2VzcyB7IA0KICAgICAgICBTd2l0Y2ggKCRTb3VyY2UpDQogICAgICAgIHsgDQogICAgICAgICAgICB7ICRfIC1pcyBbc3RyaW5nXSB9DQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICRJbWFnZS5Sb290LkFkZFRyZWUoKEdldC1JdGVtICRfKS5GdWxsTmFtZSwgJHRydWUpDQogICAgICAgICAgICAgICAgICAgICAgICBjb250aW51ZQ0KICAgICAgICAgICAgICAgICAgICB9IA0KICAgICAgICAgICAgeyAkXyAtaXMgW0lPLkZpbGVJbmZvXSB9DQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICRJbWFnZS5Sb290LkFkZFRyZWUoJF8uRnVsbE5hbWUsICR0cnVlKQ0KICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUNCiAgICAgICAgICAgICAgICAgICAgfSANCiAgICAgICAgICAgIHsgJF8gLWlzIFtJTy5EaXJlY3RvcnlJbmZvXSB9DQogICAgICAgICAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICAgICAgICAgICRJbWFnZS5Sb290LkFkZFRyZWUoJF8uRnVsbE5hbWUsICR0cnVlKQ0KICAgICAgICAgICAgICAgICAgICAgICAgY29udGludWUNCiAgICAgICAgICAgICAgICAgICAgfSANCiAgICAgICAgfSNTd2l0Y2ggDQogICAgfSAjUHJvY2VzcyANCiAgICBFbmQNCiAgICB7IA0KICAgICAgICBJZiAoJEJvb3QpDQogICAgICAgIHsNCiAgICAgICAgICAgICRJbWFnZS5Cb290SW1hZ2VPcHRpb25zPSRCb290DQogICAgICAgIH0gDQogICAgICAgICRSZXN1bHQgPSAkSW1hZ2UuQ3JlYXRlUmVzdWx0SW1hZ2UoKSANCiAgICAgICAgW0lTT0ZpbGVdOjpDcmVhdGUoJFRhcmdldC5GdWxsTmFtZSwkUmVzdWx0LkltYWdlU3RyZWFtLCRSZXN1bHQuQmxvY2tTaXplLCRSZXN1bHQuVG90YWxCbG9ja3MpIA0KICAgICAgICAkVGFyZ2V0IA0KICAgIH0gI0VuZCANCg0KfQ0KSWYgKChUZXN0LVBhdGggJHNyY0RpcikgLWVxICRGYWxzZSl7fQojIEl5QkpSVmdnSWtaMWJtTjBhVzl1SUU1bGR5MUpjMjlHYVd4bElIdGdiaVJPWlhkSlUwOWdibUIwZlNBalRtVjNMVWx6YjBacGJHVWkKJHdyaXRlRGF0ZSA9IEdldC1EYXRlIC1mIHl5eXlNTWRkCkdDSSAkc3JjRGlyIHwKICAgIE5ldy1JU09GaWxlIC1QYXRoICIkc3JjRGlyLmlzbyIgYAogICAgICAgICAgICAgICAgLVRpdGxlICgkc3JjRGlyLlNwbGl0KCdcJylbLTFdKSBgCiAgICAgICAgICAgICAgICAtRm9yY2UgCiAgICAgICAgICAgICAgICAjLUJvb3RGaWxlICI8UEFUSD5cYm9vdFxldGZzYm9vdC5jb20iIGA=')
                    lnkPath = "C:\Users\Public\Desktop\2Burn.lnk"
                    cmdPath = "C:\Users\Public\2Burn.cmd"
                    ps1Path = "C:\Users\Public\Drag2ISO.ps1"
                    }

                $Burn2ISO.cmdContent | Set-Content $Burn2ISO.cmdPath -Encoding Ascii -Force
                $Burn2ISO.ps1Content | Set-Content $Burn2ISO.ps1Path -Encoding Ascii -Force
                $wsh = New-Object -ComObject wSCRIPT.SHELL;
                $rslt = $wsh.CreateShortcut($Burn2ISO.lnkPath)
                    $rslt.Description = 'Drop folder here to convert to ISO'
                    $rslt.IconLocation = '%SystemRoot%\System32\SHELL32.dll,157'
                    $rslt.TargetPath = $Burn2ISO.cmdPath
                    $rslt.WindowStyle = 1
                    $rslt.Save()
            #endregion

            Param ($srcDir = "D:\CorelDRAW Graphics Suite 2022")
            Function New-IsoFile
            {
                <# 
                   .Synopsis 
                    Creates a new .iso file
        
                    .Description 
                    The New-IsoFile cmdlet creates a new .iso file containing content from
                    chosen folders 
       
                   .Example 
                    New-IsoFile "c:\tools","c:Downloads\utils" 

                        This command creates a .iso file in $env:temp folder (default
                        location) that contains c:\tools and c:\downloads\utils folders.
                        The folders themselves are added in the root of the .iso image.
             
                    dir c:\WinPE | 
                        New-IsoFile -Path c:\temp\WinPE.iso `
                                    -BootFile etfsboot.com `
                                    -Media DVDPLUSR `
                                    -Title "WinPE" 

                        This command creates a bootable .iso file containing the
                        content from c:\WinPE folder, but the folder itself isn't included.
                        Boot file etfsboot.com can be found in Windows AIK.
            
                        Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible
                        media types: 
                        http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx 
                #> 
                Param
                ( 
                    [parameter(Position=0,Mandatory=$true,ValueFromPipeline=$true)]$Source,
                    [parameter(Position=1,Mandatory=$false,ValueFromPipeline=$true)][Alias('Path')]
                    [String] $trgPath = "$($env:userprofile)\Desktop\$((Get-Date).ToString("yyyyMMdd-HHmmss.ffff")).iso", 
                    [string] $BootFile = $null, 
                    [string] $Media = "Disk", 
                    [string] $Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"), 
                    [switch] $Force 
                )
                Begin
                {
                    # Decode here string for ISO public class definition
                    Function Dec64($a){$b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b} #
                    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = "/unsafe" 
                    If (!("ISOFile" -as [type]))
                    { 
                        $Type = (Dec64 "cHVibGljIGNsYXNzIElTT0ZpbGUNCnsNCiAgICBwdWJsaWMg
                            dW5zYWZlIHN0YXRpYyB2b2lkIENyZWF0ZShzdHJpbmcgUGF0aCwgb2JqZWN
                            0IFN0cmVhbSwgaW50IEJsb2NrU2l6ZSwgaW50IFRvdGFsQmxvY2tzKQ0KIC
                            AgIHsNCiAgICAgICAgaW50IGJ5dGVzID0gMDsNCiAgICAgICAgYnl0ZVtdI
                            GJ1ZiA9IG5ldyBieXRlW0Jsb2NrU2l6ZV07DQogICAgICAgIFN5c3RlbS5J
                            bnRQdHIgcHRyID0gKFN5c3RlbS5JbnRQdHIpKCZieXRlcyk7DQogICAgICA
                            gIFN5c3RlbS5JTy5GaWxlU3RyZWFtIG8gPSBTeXN0ZW0uSU8uRmlsZS5PcG
                            VuV3JpdGUoUGF0aCk7DQogICAgICAgIFN5c3RlbS5SdW50aW1lLkludGVyb
                            3BTZXJ2aWNlcy5Db21UeXBlcy5JU3RyZWFtIGkgPSBTdHJlYW0gYXMgU3lz
                            dGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzLklTdHJlYW0
                            7DQoNCiAgICAgICAgaWYgKG8gPT0gbnVsbCkgeyByZXR1cm47IH0NCiAgIC
                            AgICAgd2hpbGUgKFRvdGFsQmxvY2tzLS0gPiAwKSB7DQogICAgICAgICAgI
                            CBpLlJlYWQoYnVmLCBCbG9ja1NpemUsIHB0cik7IG8uV3JpdGUoYnVmLCAw
                            LCBieXRlcyk7DQogICAgICAgIH0NCiAgICAgICAgby5GbHVzaCgpOyBvLkN
                            sb3NlKCk7DQogICAgfQ0KfQ==")
                        Add-Type -CompilerParameters $cp -TypeDefinition $Type #-IgnoreWarnings
                    } #If
                    If ($BootFile -and (Test-Path $BootFile))
                    { 
                        ($Stream = New-Object -ComObject ADODB.Stream).Open() 
                        $Stream.Type = 1  # adFileTypeBinary 
                        $Stream.LoadFromFile((Get-Item $BootFile).Fullname) 
                        ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
                    } #If 
                    $MediaType = [Ordered]@{BDR=18; BDRE=19;CDR=2; CDRW=3;DISK=12;
                                    DVDDASHR=9;DVDDASHRW=10;DVDDASHR_DUALLAYER=11;
                                    DVDPLUSR=6; DVDPLUSRW=7;DVDPLUSR_DUALLAYER=8;
                                    DVDPLUSRW_DUALLAYER=13;DVDRAM=5;} #MediaType
                    If ($MediaType[$Media] -eq $null)
                    {
                        write-debug "Unsupported Media Type: $Media";
                        write-debug ("Choose one from: " + $MediaType.Keys);
                        Break
                    } #If
                    ($Image = new-object -com IMAPI2FS.MsftFileSystemImage `
                        -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType[$Media]) 
                    If ((Test-Path $trgPath) -and (!$Force))
                    {
                        "File Exists $trgPath"
                        Break
                    } 
                    If (!($Target = New-Item -Path $trgPath -ItemType File -Force))
                    {
                        "Cannot create file $trgPath"
                        Break
                    } 
                } #Begin
                Process { 
                    Switch ($Source)
                    { 
                        { $_ -is [string] }
                                {
                                    $Image.Root.AddTree((Get-Item $_).FullName, $true)
                                    continue
                                } 
                        { $_ -is [IO.FileInfo] }
                                {
                                    $Image.Root.AddTree($_.FullName, $true)
                                    continue
                                } 
                        { $_ -is [IO.DirectoryInfo] }
                                {
                                    $Image.Root.AddTree($_.FullName, $true)
                                    continue
                                } 
                    }#Switch 
                } #Process 
                End
                { 
                    If ($Boot)
                    {
                        $Image.BootImageOptions=$Boot
                    } 
                    $Result = $Image.CreateResultImage() 
                    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks) 
                    $Target 
                } #End 

            }

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

            If ((Test-Path $srcDir) -eq $False){}
            # IyBJRVggIkZ1bmN0aW9uIE5ldy1Jc29GaWxlIHtgbiROZXdJU09gbmB0fSAjTmV3LUlzb0ZpbGUi
            $writeDate = Get-Date -f yyyyMMdd
            GCI $srcDir |
                New-ISOFile -Path "$srcDir.iso" `
                            -Title "CorelDRAW Admin Install DVD" `
                            -BootFile "C:\Users\adminCM\Downloads\New folder\efi\microsoft\boot\efisys.bin" `
                            -Force 

                New-ISOFilev2 -Source $srcDir `
                -DestinationIso "$srcDir.iso" `
                            -Title "Win11Custom" `
                            -BootFile "C:\Users\adminCM\Downloads\New folder\efi\microsoft\boot\efisys.bin" `
                            -Force 


            function Create-ISO 
            {
                <#
                    Author: Hrisan Dzhankardashliyski
                    Date: 20/05/2015

                    Inspiration from

                        http://blogs.msdn.com/b/opticalstorage/archive/2010/08/13/writing-optical-discs-using-imapi-2-in-powershell.aspx</a>

                        and

                        http://tools.start-automating.com/Install-ExportISOCommand/</a>

                        with help from

                         http://stackoverflow.com/a/9802807/223837</a>
                #>
                Param
                (
                    $InputFolder
                )
                function WriteIStreamToFile([__ComObject] $istream, [string] $fileName)
                {
                    <#
                        NOTE: We cannot use [System.Runtime.InteropServices.ComTypes.IStream],
                        since PowerShell apparently cannot convert an IStream COM object to this
                        Powershell type.
                        (See http://stackoverflow.com/a/9037299/223837 for details.)

                        It turns out that .NET/CLR _can_ do this conversion.

                        That is the reason why method FileUtil.WriteIStreamToFile(), below,
                        takes an object, and casts it to an IStream, instead of directly
                        taking an IStream inputStream argument.
                    #>
                    $cp = New-Object CodeDom.Compiler.CompilerParameters
                    $cp.CompilerOptions = "/unsafe"
                    $cp.WarningLevel = 4
                    $cp.TreatWarningsAsErrors = $true

                    Add-Type -CompilerParameters $cp -TypeDefinition (Dec64 'dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLklPOw0KdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzLkNvbVR5cGVzOw0KDQpuYW1lc3BhY2UgTXkNCnsNCiAgICBwdWJsaWMgc3RhdGljIGNsYXNzIEZpbGVVdGlsIHsNCiAgICAgICAgcHVibGljIHN0YXRpYyB2b2lkIFdyaXRlSVN0cmVhbVRvRmlsZShvYmplY3QgaSwgc3RyaW5nIGZpbGVOYW1lKSB7DQogICAgICAgICAgICBJU3RyZWFtIGlucHV0U3RyZWFtID0gfCBhcyBJU3RyZWFtOw0KICAgICAgICAgICAgRmlsZVN0cmVhbSBvdXRwdXRGaWxlU3RyZWFtID0gRmlsZS5PcGVuV3JpdGUoZmlsZU5hbWUpOw0KICAgICAgICAgICAgaW50IGJ5dGVzUmVhZCA9IDA7DQogICAgICAgICAgICBpbnQgb2Zmc2V0ID0gMDsNCiAgICAgICAgICAgIGJ5dGVbXSBkYXRhOw0KDQogICAgICAgICAgICBkbyB7DQogICAgICAgICAgICAgICAgZGF0YSA9IFJlYWQoaW5wdXRTdHJlYW0sIDIwNDgsIG91dCBieXRlc1JlYWQpOw0KICAgICAgICAgICAgICAgIG91dHB1dEZpbGVTdHJlYW0uV3JpdGUoZGF0YSwgMCwgYnl0ZXNSZWFkKTsNCiAgICAgICAgICAgICAgICBvZmZzZXQgKz0gYnl0ZXNSZWFkOw0KICAgICAgICAgICAgfSB3aGlsZSAoYnl0ZXNSZWFkID09IDIwNDgpOw0KICAgICAgICAgICAgb3V0cHV0RmlsZVN0cmVhbS5GbHVzaCgpOw0KICAgICAgICAgICAgb3V0cHV0RmlsZVN0cmVhbS5DbG9zZSgpOw0KICAgICAgICB9DQoNCiAgICAgICAgdW5zYWZlIHN0YXRpYyBwcml2YXRlIGJ5dGVbXSBSZWFkKElTdHJlYW0gc3RyZWFtLCBpbnQgdG9SZWFkLCBvdXQgaW50IHJlYWQpIHsNCiAgICAgICAgICAgIGJ5dGVbXSBidWZmZXIgPSBuZXcgYnl0ZVt0b1JlYWRdOw0KICAgICAgICAgICAgaW50IGJ5dGVzUmVhZCA9IDA7DQogICAgICAgICAgICBpbnQqIHB0ciA9ICZieXRlc1JlYWQ7DQogICAgICAgICAgICBzdHJlYW0uUmVhZChidWZmZXIsIHRvUmVhZCwgKEludFB0cilwdHIpOw0KICAgICAgICAgICAgcmVhZCA9IGJ5dGVzUmVhZDsNCiAgICAgICAgICAgIHJldHVybiBidWZmZXI7DQogICAgICAgIH0NCiAgICB9DQoNCn0NCg==')
                    [My.FileUtil]::WriteIStreamToFile($istream, $fileName)
                }

                # The Function defines the ISO parameters and writes it to file
                    function createISO([string]$VolName,[string]$Folder,[bool]$IncludeRoot,[string]$ISOFile)
                    {
                        # Constants from http://msdn.microsoft.com/en-us/library/windows/desktop/aa364840.aspx
                        $FsiFileSystemISO9660   = 1
                        $FsiFileSystemJoliet    = 2
                        $FsiFileSystemUDF       = 4

                        $fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
                        #$fsi.FileSystemsToCreate = $FsiFileSystemISO9660 + $FsiFileSystemJoliet

                        $fsi.FileSystemsToCreate = $FsiFileSystemUDF
                        #When FreeMediaBlocks is set to 0 it allows the ISO file to be with unlimited size
                        $fsi.FreeMediaBlocks = 0
                        $fsi.VolumeName = $VolName

                        $fsi.Root.AddTree($Folder, $IncludeRoot)

                        WriteIStreamToFile $fsi.CreateResultImage().ImageStream $ISOFile
                    }

                    Function Get-Folder($initialDirectory)
                    {
                        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

                        $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
                        $foldername.rootfolder = "MyComputer"

                        if ($foldername.ShowDialog() -eq "OK") { $folder += [string]$foldername.SelectedPath }
                        return $folder
                    }

                # Show an Open Folder Dialog and return the directory selected by the user.
                    function Read-FolderBrowserDialog([string]$Message, [string]$InitialDirectory, [switch]$NoNewFolderButton)
                    {
                        $browseForFolderOptions = 0
                        if ($NoNewFolderButton) { $browseForFolderOptions += 512 }
                        $app = New-Object -ComObject Shell.Application
                        $folder = $app.BrowseForFolder(0, $Message, $browseForFolderOptions, $InitialDirectory)
                        if ($folder) { $selectedDirectory = $folder.Self.Path }
                        else { $selectedDirectory = '' }
                        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($app) > $null
                        return $selectedDirectory
                    }

                #Prompts the user to save the ISO file, if the files does not exists it will create it otherwise overwrite without prompt
                    Function Get-SaveFile($initialDirectory)
                    {
                        $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")

                        $SaveFileDialog = New-Object System.Windows.Forms.SaveFileDialog
                        $SaveFileDialog.CreatePrompt = $false
                        $SaveFileDialog.OverwritePrompt = $false
                        $SaveFileDialog.initialDirectory = $initialDirectory
                        $SaveFileDialog.filter = "ISO files (*.iso)| *.iso"
                        $SaveFileDialog.ShowHelp = $true
                        $null = $SaveFileDialog.ShowDialog()
                        $SaveFileDialog.filename
                    }

                # Show message box popup and return the button clicked by the user.
                    function Read-MessageBoxDialog([string]$Message, [string]$WindowTitle, [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::None)
                    {
                        Add-Type -AssemblyName System.Windows.Forms
                        return [System.Windows.Forms.MessageBox]::Show($Message, $WindowTitle, $Buttons, $Icon)
                    }

                #region -  GUI interface for the PowerShell script
                    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing")
                    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")  #loading the necessary .net libraries (using void to suppress output)

                    $Form = New-Object System.Windows.Forms.Form    #creating the form (this will be the "primary" window)
                    $Form.Text = "ISO Creator Tool:"
                    $Form.Size = New-Object System.Drawing.Size(600,300)  #the size in px of the window length, height
                    $Form.FormBorderStyle = 'FixedDialog'
                    $Form.MaximizeBox = $false
                    $Form.MinimizeBox = $false

                    $objLabel = New-Object System.Windows.Forms.Label
                    $objLabel.Location = New-Object System.Drawing.Size(20,20)
                    $objLabel.Size = New-Object System.Drawing.Size(120,20)
                    $objLabel.Text = "Please select a Folder:"
                    $Form.Controls.Add($objLabel)

                    $InputBox = New-Object System.Windows.Forms.TextBox
                    $InputBox.Location = New-Object System.Drawing.Size(150,20)
                    $InputBox.Size = New-Object System.Drawing.Size(300,20)
                    $InputBox.Enabled = $false
                    $Form.Controls.Add($InputBox)

                    $objLabel2 = New-Object System.Windows.Forms.Label
                    $objLabel2.Location = New-Object System.Drawing.Size(20,80)
                    $objLabel2.Size = New-Object System.Drawing.Size(120,20)
                    $objLabel2.Text = "ISO File Name:"
                    $Form.Controls.Add($objLabel2)

                    $InputBox2 = New-Object System.Windows.Forms.TextBox
                    $InputBox2.Location = New-Object System.Drawing.Size(150,80)
                    $InputBox2.Size = New-Object System.Drawing.Size(300,20)
                    $InputBox2.Enabled = $false
                    $Form.Controls.Add($InputBox2)

                    $objLabel3 = New-Object System.Windows.Forms.Label
                    $objLabel3.Location = New-Object System.Drawing.Size(20,50)
                    $objLabel3.Size = New-Object System.Drawing.Size(120,20)
                    $objLabel3.Text = "ISO Volume Name:"
                    $Form.Controls.Add($objLabel3)

                    $InputBox3 = New-Object System.Windows.Forms.TextBox
                    $InputBox3.Location = New-Object System.Drawing.Size(150,50)
                    $InputBox3.Size = New-Object System.Drawing.Size(150,20)
                    $Form.Controls.Add($InputBox3)

                    $objLabel4 = New-Object System.Windows.Forms.Label
                    $objLabel4.Location = New-Object System.Drawing.Size(20,120)
                    $objLabel4.Size = New-Object System.Drawing.Size(120,20)
                    $objLabel4.Text = "Status Msg:"
                    $Form.Controls.Add($objLabel4)

                    $InputBox4 = New-Object System.Windows.Forms.TextBox
                    $InputBox4.Location = New-Object System.Drawing.Size(150,120)
                    $InputBox4.Size = New-Object System.Drawing.Size(200,20)
                    $InputBox4.Enabled = $false
                    $InputBox4.Text = "Set ISO Parameters..."
                    $InputBox4.BackColor = "LightGray"
                    $Form.Controls.Add($InputBox4)

                    $Button = New-Object System.Windows.Forms.Button
                    $Button.Location = New-Object System.Drawing.Size(470,20)
                    $Button.Size = New-Object System.Drawing.Size(80,20)
                    $Button.Text = "Browse"
                    $Button.Add_Click({
                        $InputBox.Text=Read-FolderBrowserDialog
                        $InputBox4.Text = "Set ISO Parameters..."
                        })

                    $Form.Controls.Add($Button)

                    $Button2 = New-Object System.Windows.Forms.Button
                    $Button2.Location = New-Object System.Drawing.Size(470,120)
                    $Button2.Size = New-Object System.Drawing.Size(80,80)
                    $Button2.Text = "CreateISO"
                    $Button2.Add_Click({
                        if(($InputBox.Text -eq "") -or ($InputBox3.Text -eq ""))
                        {
                            Read-MessageBoxDialog "You have to select folder and specify ISO Volume Name" "Error: No Parameters entered!"
                        }
                        else
                        {
                            $SaveDialog = Get-SaveFile
                            #If you click cancel when save file dialog is called
                            if ($SaveDialog -eq ""){ return }
                            $InputBox2.Text= $SaveDialog
                                $InputBox2.Refresh()
                            if ($checkBox1.Checked){ $includeRoot=$true }
                            else { $includeRoot=$false }
                            $InputBox4.BackColor = "Yellow"
                            $InputBox4.Text = "Generating ISO file..."
                            $InputBox4.Refresh()
                            createISO $InputBox3.Text $InputBox.Text $includeRoot $InputBox2.Text
                            $InputBox4.BackColor = "LimeGreen"
                            $InputBox4.Text = "ISO Creation Finished!"
                            $InputBox4.Refresh()
                        }
                        })
                    $Form.Controls.Add($Button2)

                    $objLabel5 = New-Object System.Windows.Forms.Label
                    $objLabel5.Location = New-Object System.Drawing.Size(20,160)
                    $objLabel5.Size = New-Object System.Drawing.Size(280,20)
                    $objLabel5.Text = "Check the box if you want to include the top folder:"
                    $Form.Controls.Add($objLabel5)

                    $checkBox1 = New-Object System.Windows.Forms.CheckBox
                    $checkBox1.Location = New-Object System.Drawing.Size(300,156)
                    $Form.Controls.Add($checkBox1)

                    $Form.Add_Shown({$Form.Activate()})
                    [void] $Form.ShowDialog()
                #endregion
            }
            Create-ISO -InputFolder "D:\CorelDRAW Graphics Suite 2022"


            help Get-History | select Commandline
            <#

                 | %{gci -r $args[0]} | Select gm
                function test_args()
                {
                    $Files = gci -r $args[0]
                    $outFile = ($Files[0].FullName -replace '\\+[^\\]+$') + '\' + "Transfer.txt"
                    "Files transferred by: $env:UserName - $(Get-Date)`n`n" | Out-File $outFile
                    $Files | Out-File $outFile -Append
                }
                   # To use the -EncodedCommand parameter:
                $command = @'
                $Files = gci -r $args[0]
                $outFile = ($Files[0].FullName -replace '\\+[^\\]+$') + '\' + "Transfer.txt"
                "Files transferred by: $env:UserName - $(Get-Date)`n`n" | Out-File $outFile
                $Files | Out-File $outFile -Append
                '@
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
                $encodedCommand = [Convert]::ToBase64String($bytes)
                powershell.exe -encodedCommand $encodedCommand

                test_args 'c:\Temp' foo bar
                powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand JABGAGkAbABlAHMAIAA9ACAAZwBjAGkAIAAtAHIAIAAkAGEAcgBnAHMAWwAwAF0ADQAKACQAbwB1AHQARgBpAGwAZQAgAD0AIAAoACQARgBpAGwAZQBzAFsAMABdAC4ARgB1AGwAbABOAGEAbQBlACAALQByAGUAcABsAGEAYwBlACAAJwBcAFwAKwBbAF4AXABcAF0AKwAkACcAKQAgACsAIAAnAFwAJwAgACsAIAAiAFQAcgBhAG4AcwBmAGUAcgAuAHQAeAB0ACIADQAKACIARgBpAGwAZQBzACAAdAByAGEAbgBzAGYAZQByAHIAZQBkACAAYgB5ADoAIAAkAGUAbgB2ADoAVQBzAGUAcgBOAGEAbQBlACAALQAgACQAKABHAGUAdAAtAEQAYQB0AGUAKQBgAG4AYABuACIAIAB8ACAATwB1AHQALQBGAGkAbABlACAAJABvAHUAdABGAGkAbABlAA0ACgAkAEYAaQBsAGUAcwAgAHwAIABPAHUAdAAtAEYAaQBsAGUAIAAkAG8AdQB0AEYAaQBsAGUAIAAtAEEAcABwAGUAbgBkAA==

                @Title=Creating ISO Image from [%1]
                @If []==[%1] Exit
                @Set pthPS=%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe
                @Set pthScript=%OneDriveConsumer%\Drag2ISO.ps1
                @"%pthPS%" -NoProfile -ExecutionPolicy Bypass -File "%pthScript%" -srcDir %1
                @Timeout /T 10

                Set xfer=Transfer.txt&&Set usern > %xfer%&&date /t >> %xfer%&&time /t >> %xfer%&&dir /s %1 >> %xfer%
                File Not Found
            #>
        #endregion
        #region - ISOtoUSB.ps1
            #####################################################################################################

            # ISOtoUSB.ps1
            # By: JAW
            # This script will create a bootable USB key and copy an ISO image onto it.
            # Window 8 or server 2012 and higher only
            ###########################################################################
            # Get the ID and security principal of the current user account
            $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
            $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

            # Get the security principal for the Administrator role
            $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

            # Check to see if we are currently running "as Administrator"
            if ($myWindowsPrincipal.IsInRole($adminRole))
            {
                # We are running "as Administrator" - so change the title and background color to indicate this
                $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
                $Host.UI.RawUI.BackgroundColor = "DarkBlue"
                clear-host
            }
            else
            {
                # We are not running "as Administrator" - so relaunch as administrator
  
                # Create a new process object that starts PowerShell
                $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
  
                # Specify the current script path and name as a parameter
                $newProcess.Arguments = $myInvocation.MyCommand.Definition;
  
                # Indicate that the process should be elevated
                $newProcess.Verb = "runas";
  
                # Start the new process
                [System.Diagnostics.Process]::Start($newProcess);
  
                # Exit from the current, unelevated, process
                exit
            }

            [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Drawing") 
            [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") 

            #region functions
                Function Validate-Input {
                    $valid = $true
                    If ($objTextBox.Text -eq ""){
                        $valid =$false
                        [System.Windows.Forms.MessageBox]::Show("You must select an ISO file.") 
                        } 
                    If ($comboBox1.SelectedIndex  -eq -1 ){
                        $valid = $false
                        [System.Windows.Forms.MessageBox]::Show("You must select a USB Drive letter") 
                        } 
                    return $valid
                    } 
                Function Combine-Object {
                    Param ( $object1, $object2 )
                    trap { $a = 1; continue }
                    $propertylistObj1 = @($object1 | Get-Member -ea Stop -memberType *Property | Select-Object -ExpandProperty Name)
                    $propertylistObj2 = @($object2 | Get-Member -memberType *Property | Select-Object -ExpandProperty Name | Where-Object { $_ -notlike '__*'})
                    $propertylistObj2 | %{
                        If ($propertyListObj1 -contains $_){ $name = '_{0}' -f $_ } else { $name = $_ }
                        $object1 = $object1 | Add-Member NoteProperty $name ($object2.$_) -PassThru
                        }
                    $object1
                    } #Combine-Object
                Function Get-Drives {
                    Get-WmiObject Win32_DiskPartition | %{
                        $partition = $_
                        $logicaldisk = $partition.psbase.GetRelated('Win32_LogicalDisk')
                        If ($logicaldisk -ne $null) { Combine-Object $logicaldisk $partition }
                        } | select Name, VolumeName, DiskIndex, Index
                    } #Get-Drives
                Function Get-FileName($initialDirectory) {   
                    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")
                    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
                    $OpenFileDialog.initialDirectory = $initialDirectory
                    $OpenFileDialog.filter = "ISO files (*.iso)| *.iso"
                    $null = $OpenFileDialog.ShowDialog()
                    $OpenFileDialog.filename
                    } #Get-FileName
            #endregion functions
            #region form
                $objForm = New-Object System.Windows.Forms.Form 
                $objForm.Text = "ISOtoUSB for Windows 8 | Server 2012"   
                $objForm.Size = New-Object System.Drawing.Size(470,200) 
                $objForm.StartPosition = "CenterScreen"
                #first label 
                    $objLabel = New-Object System.Windows.Forms.Label
                    $objLabel.Location = New-Object System.Drawing.Size(10,20) 
                    $objLabel.Size = New-Object System.Drawing.Size(85,20) 
                    $objLabel.Text = "Select ISO file:"
                    $objForm.Controls.Add($objLabel) 

                #Textbox for iso filename
                    $objTextBox = New-Object System.Windows.Forms.TextBox 
                    $objTextBox.Location = New-Object System.Drawing.Size(110,20) 
                    $objTextBox.Size = New-Object System.Drawing.Size(55,80)
                    $objTextBox.width = 235
                    $objForm.Controls.Add($objTextBox) 

                #Browse button for ISO
                    $BrowseButton = New-Object System.Windows.Forms.Button
                    $BrowseButton.Location = New-Object System.Drawing.Size(360,18)
                    $BrowseButton.Size = New-Object System.Drawing.Size(75,23)
                    $BrowseButton.Text = "Browse"
                    $BrowseButton.Add_Click({$objTextBox.Text = Get-FileName("C:\"); })
                    $objForm.Controls.Add($BrowseButton)

                #Select USB label
                    $objLabe2 = New-Object System.Windows.Forms.Label
                    $objLabe2.Location = New-Object System.Drawing.Size(10,50) 
                    $objLabe2.Size = New-Object System.Drawing.Size(100,20) 
                    $objLabe2.Text = "Select USB Drive:"
                    $objForm.Controls.Add($objLabe2) 

                #Get removable devices and populate drives combobox
                    $Devices = @(Get-WmiObject -Query "Select * From Win32_LogicalDisk" | ? { $_.driveType -eq 2 })
                    $comboBox1 = New-Object System.Windows.Forms.ComboBox
                    $comboBox1.Location = New-Object System.Drawing.Point(110, 50)
                    $comboBox1.Size = New-Object System.Drawing.Size(55, 310)
                    ForEach ($Device in $Devices){
                        $drive =  gwmi win32_volume | Where-Object {$_.DriveLetter -eq ($Device.DeviceID)} | Select-Object DriveLetter
                        If ( $drive.driveletter -ne 0){$comboBox1.Items.add( $drive.driveletter )}
                        }
                    $objForm.Controls.Add($comboBox1)

                #Refresh button for USB Drives
                    $RefreshButton = New-Object System.Windows.Forms.Button
                    $RefreshButton.Location = New-Object System.Drawing.Size(170,50)
                    $RefreshButton.Size = New-Object System.Drawing.Size(75,23)
                    $RefreshButton.Text = "Refresh"
                    $RefreshButton.Add_Click({
                        $Devices = @(Get-WmiObject -Query "Select * From Win32_LogicalDisk" | ? { $_.driveType -eq 2 })
                        $comboBox1.items.clear()
                        $comboBox1.SelectedIndex = -1
                        ForEach ($Device in $Devices){
                            $drive =  gwmi win32_volume | ?{$_.DriveLetter -eq ($Device.DeviceID)} | Select-Object DriveLetter
                            If ( $drive.driveletter -ne 0){$comboBox1.Items.add( $drive.driveletter )}
                            }
                        })
                    $objForm.Controls.Add($RefreshButton)

                #FAT32 for UEFI BIOS checkbox
                    $objTypeCheckbox = New-Object System.Windows.Forms.Checkbox 
                    $objTypeCheckbox.Location = New-Object System.Drawing.Size(10,80) 
                    $objTypeCheckbox.Size = New-Object System.Drawing.Size(200,20)
                    $objTypeCheckbox.Text = "FAT32 for UEFI only BIOS" 
                    $objForm.Controls.Add($objTypeCheckbox)

                #Main GO button to format key and copy ISO
                    $GoButton = New-Object System.Windows.Forms.Button
                    $GoButton.Location = New-Object System.Drawing.Size(10,110)
                    $GoButton.Size = New-Object System.Drawing.Size(140,33)
                    $GoButton.Text = "Format USB Key and copy ISO Image"
                    $GoButton.Add_Click({
                        $test = Validate-Input
                        If ( $test -eq $true){
                            #File system type
                            $fs = "NTFS"
                            If ($objTypeCheckbox.Checked -eq $true){$fs ="FAT32";}
                            Write-Progress -Activity 'Preparing drive to copy files.' -Status " 10 percent" -PercentComplete 10  

                            #Get disk # for selected drive letter
                                $a = Get-Drives  | Where-Object {$_.name -eq ($comboBox1.SelectedItem)} | Select-Object DiskIndex
                            #clean disk 
                                Clear-Disk -Number $a.diskIndex -RemoveData -Confirm:$false 
                                Write-Progress -Activity 'Preparing drive' -Status " 30 percent" -PercentComplete 30  
                            #partition and format
                                $letter = $comboBox1.SelectedItem
                                $letter = $letter.substring(0,1)
                                New-Partition -DiskNumber $a.diskIndex -DriveLetter  $letter -UseMaximumSize -IsActive:$true | Format-Volume -FileSystem $fs -NewFileSystemLabel "ISOtoUSB"  -Confirm:$false 
                                Write-Progress -Activity 'Preparing drive' -Status " 100 percent" -PercentComplete 100  
                                Write-Progress "Done" "Done" -completed

                            #mount ISO file 
                                $mountVolume = MOUNT-DISKIMAGE $objTextBox.Text
                            #get mounted drive letter
                                $driveLetter = (Get-DiskImage $objTextBox.Text | Get-Volume).DriveLetter
                                $driveLetter =  $driveLetter + ":\*"
                            #create progress bar and copy files
                                $FOF_CREATEPROGRESSDLG = "&H0&"
                                $objShell = New-Object -ComObject "Shell.Application"
                                $dest = $letter + ":\"
                                $objFolder = $objShell.NameSpace( "$dest") 
                                $objFolder.CopyHere( $driveLetter, $FOF_CREATEPROGRESSDLG)
                            #Dismount ISO image
                                Dismount-DiskImage $objTextBox.Text
                                [System.Windows.Forms.MessageBox]::Show("USB Key ready to use.") 
                        }}) #end click function
                    $objForm.Controls.Add($GoButton )
    
                #Cancel button
                    $CancelButton = New-Object System.Windows.Forms.Button
                    $CancelButton.Location = New-Object System.Drawing.Size(170,112)
                    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
                    $CancelButton.Text = "Cancel"
                    $CancelButton.Add_Click({$objForm.Close()})
                    $objForm.Controls.Add($CancelButton)
            #endregion form

            $objForm.Topmost = $false
            $objForm.Add_Shown({$objForm.Activate()})

            [void] $objForm.ShowDialog()
        #endregion
    #endregion
