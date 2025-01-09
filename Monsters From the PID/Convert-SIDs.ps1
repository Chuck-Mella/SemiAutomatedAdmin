        Function Convert-SID
        {
            <#
                .Synopsis
                    SID - UserName/ComputerName Translator
           
                .Parameter srcAcct
                    The samAccountName or SID of the User or computer to be translated. The default is the current username.
   
                .Parameter Script
                    Switch to limit output to return only the result data (for use with scripts requiring a translation).
                    (e.g. 'Username' instead of a Acctname/SID table output
   
                .Usage:  Convert-SID <DOMAIN/COMPUTER>\<User/Group>, see examples
                         Convert-SID <DOMAIN>\<computer$>, see examples
                         Convert-SID <SID>, see examples
   
                .Example
                    Convert-SID Administrator
                    Convert-SID Administrators
                    Convert-SID MyDomain\UserName
                    Convert-SID MyDomain\GroupName
                        Returns: Acctname    SID                                           
                                 -------*   --*                                          
                                 GroupName   S-1-n-nn-nnnnnnnnn-nnnnnnnnnn-nnnnnnnnnn
   
                    Converts supplied user/group name and returns a Acctname/SID table output.
   
                .Example
                    Convert-SID ComputerName
                    Convert-SID ComputerName$
                    Convert-SID MyDomain\ComputerName
                    Convert-SID MyDomain\ComputerName$
                        Returns: Acctname      SID                                           
                                 -------*     --*                                          
                                 ComputerName  S-1-n-nn-nnnnnnnnn-nnnnnnnnnn-nnnnnnnnnn
   
                    Converts supplied computer name and returns a Acctname/SID table output.
   
                .Example
                    Convert-SID S-1-n-nn-nnnnnnnnn-nnnnnnnnnn-nnnnnnnnnn-nnnn
                        Returns: SID                                       Acctname                                 
                                 --*                                      --------
                                 S-1-n-nn-nnnnnnnnn-nnnnnnnnnn-nnnnnnnnnn  UserName
  
                    Converts supplied SID and returns a SID/Acctname table output.
   
                .INPUTS
                    System.String
   
                .OUTPUTS
                    System.String
   
                .NOTES
                   Written by Chuck Mella (2014), semiautomatedadmin.wordpress.com
                   As always, this script is provided 'as is' with no warantee implied. I strive towards
                   clean and safe code but you use this code at your own risk.
   
                .LINK
                   <blockquote class="wp-embedded-content" data-secret="8K2J4e8obw"><a href="https://semiautomatedadmin.wordpress.com/">Beware the Monsters from the $PID</a></blockquote><iframe class="wp-embedded-content" sandbox="allow-scripts" security="restricted" style="position: absolute; clip: rect(1px, 1px, 1px, 1px);" title=""Beware the Monsters from the $PID" - The Semi-Automated Admin" src="https://semiautomatedadmin.wordpress.com/embed/#?secret=LSklbSutvG#?secret=8K2J4e8obw" data-secret="8K2J4e8obw" width="600" height="338" frameborder="0" marginwidth="0" marginheight="0" scrolling="no"></iframe>
            #>
            Param
            (
                [string]$srcAcct = $ENV:UserName,
                [switch]$Script
            )
            $sb_Convert = {
                Param ($xltIn)
                If ($xltIn -match "^S-1-"){ $Trg = 'SecurityIdentifier' } Else { $Trg = 'NTAccount' }
                $objXlat = New-Object System.Security.Principal.$Trg($xltIn)
                Try {
                    If ($xltIn -match "^S-1-"){ $XLout = $objXlat.Translate([System.Security.Principal.NTAccount]) }
                    Else { $XLout = $objXlat.Translate([System.Security.Principal.SecurityIdentifier]) }
                    }
                Catch [System.Management.Automation.MethodInvocationException]{
                    $objXlat = New-Object System.Security.Principal.$Trg("$xltIn$")
                    $XLout = $objXlat.Translate([System.Security.Principal.SecurityIdentifier])
                    }
                Catch { $XLout = "No Data" }
                Return $XLout
                }
            $domPC = (GWMI Win32_ComputerSystem).partofdomain 
            If (!$domPC)
            {
                If ($srcAcct -match "\\"){ $srcAcct = $srcAcct -replace  '^\w+[^\\]\\' } # Strip Machine Name
                $locAccts = (GWMI -Class Win32_UserAccount -Filter  "LocalAccount='True'"),(GWMI -Class Win32_Group) | %{ $_ | Select Name,Domain,SID }
                If ($srcAcct -match "^S-1-")
                {
                    If ($locAccts.SID -contains $srcAcct){ $Rslt = ($locAccts | ?{$_.SID -match $srcAcct}).Name }
                    ElseIf ($locAccts.SID  -replace '-[^-]+$' -contains ($srcAcct)){ $Rslt = ($locAccts[0].Domain) }
                    Else { $Rslt = "No Data" }
                }
                Else
                {
                    If ($locAccts.Name -contains $srcAcct){ $Rslt = ($locAccts | ?{$_.Name -eq $srcAcct}).SID }
                    ElseIf ($locAccts.Domain -contains $srcAcct){ $Rslt = ($locAccts[0].SID  -replace '-[^-]+$') }
                    Else { $Rslt = "No Data" }
                }
            } #If Non-Domain PC
            Else { $Rslt = [string](& $sb_Convert $srcAcct) } #Else Domain PC
            If ($Script){ Return $Rslt }
            Else
            {
                If ($srcAcct -match "^S-1-"){ Return $Rslt| Select @{n='SID';e={$srcAcct}},@{n='Acctname';e={$Rslt}} }
                Else { Return $Rslt| Select @{n='Acctname';e={$srcAcct}},@{n='SID';e={$Rslt}} }        
            }
        }
        #  Convert-SID  $env:COMPUTERNAME
        #  Convert-SID  $env:UserName
        #  Convert-SID  'S-1-5-32-545'
        
