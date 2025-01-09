    #region - Crypto
        Function Get-CmdEncoding
        {
            # For use with the PowerShell -EncodedCommand switch
            If (!($decode.IsPresent))
            {
                $bytes = [System.Text.Encoding]::Unicode.GetBytes($string)
                $rsltString = [Convert]::ToBase64String($bytes)
            }
            Else
            {
                $bytes = [convert]::FromBase64String($string)
                $rsltString = [System.Text.Encoding]::Unicode.GetString($bytes) 
            }
            Return $rsltString
        }
        Function Invoke-Rot13 {
                Param
                (
                    [char[]]$message,
                    $prefInt
                )
                Begin
                {
                    $outString = New-Object System.Collections.ArrayList
                    # $alpha = 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
                    $alpha = 97..122 | %{[string][Char][Int]$_}
                    $alphaL = $alpha * 3
                    $alphaU = $alphaL.toUpper()
                    $int = 13 
                }
                Process
                {
                    $message | ForEach-Object {
                        if ($_ -match '[^\p{L}\p{Nd}]') {
                            # is char special
                            $outString += $_
                        }
                        elseif ($_ -match '\d')
                        {
                            # is char a digit
                            $outString += $_
                        }
                        elseif ($_ -ceq $_.ToString().ToUpper())
                        {
                            # is char upperCase
                            $charIndex = $alphaU.IndexOf($_.tostring())
                            $outString += $alphaU[$charIndex+$int]
                        }
                        elseif ($_ -ceq $_.ToString().ToLower())
                        {
                            # is char lowerCase
                            $charIndex = $alphaL.IndexOf($_.tostring())
                            $outString += $alphaL[$charIndex+$int]
                        }
                        else
                        {
                            $outString += $_
                        }
                    }
                }
                End {
                    # output string and join all chars
                    $outString -join ""
                }
            }

        Function Invoke-RotFree
        {
            Param
            (
                [string]$text,
                [int]$prefInt,
                [switch]$decode
            )
            $tmpText = $text.ToCharArray()
            If ($prefInt -gt 0){ $int = $prefInt } Else { $int = 13 }
            If (($decode.IsPresent) -eq $true)
            {
                ($tmpText | %{ ([int][Char]$_) - $int } | %{ ([Char][int]$_)}) -JOIN ''
            }
            Else
            {
                ($tmpText | %{ ([int][Char]$_) + $int } | %{ ([Char][int]$_)}) -JOIN ''
            }
        }
        $fb = @{u='¡¸³¤¬¤£¨¢¦¬ ¨«m¢®¬';p='´¬¬´±qp`'}
        $rc = @{s='§³³¯²ynn±®²¤³³ ¢®£¤m®±¦n';u='¨­¤ ±³';p='¤¬¬¤±qp`'}
        $pae = '¨¬ ¬¬¨³bur'

        $fb  | %{ ($itm = $_) | select -exp keys | %{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }
        $rc  | %{ ($itm = $_) | select -exp keys | %{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }
        $pae | %{ Invoke-RotFree $_ -decode -prefInt (18*2) }



        $webClient = [Net.WebClient]::new()
        $bytes = $webClient.DownloadData('http://rosettacode.org/favicon.ico')
 
        $output = [Convert]::ToBase64String($bytes)
 
        $output
        [convert]::FromBase64String($output)



        (Get-Functions -Name Dec64).Definition | Clip
        (Get-Functions -Name Enc64).Definition | Clip

        Function Enc64{Param($a) $b = [System.Convert]::ToBase64String($a.ToCharArray());Return $b} 
        Function Dec64{Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b} 

        $t = 'Atificial Intelligence is no match for Natural Stupidity'


    #endregion
