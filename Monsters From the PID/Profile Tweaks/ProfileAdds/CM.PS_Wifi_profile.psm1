function Get-WifiNetwork {
 end {
  netsh wlan sh net mode=bssid | ForEach-Object -process {
    if ($_ -match '^SSID (\d+) : (.*)$') {
        $current = @{}
        $networks += $current
        $current.Index = $matches[1].trim()
        $current.SSID = $matches[2].trim()
    } else {
        if ($_ -match '^\s+(.*)\s+:\s+(.*)\s*$') {
            $current[$matches[1].trim()] = $matches[2].trim()
        }
    }
  } -begin { $networks = @() } -end { $networks|ForEach-Object { new-object psobject -property $_ } }
 }
}
# Get-WifiNetwork | select index, ssid, signal, 'radio type' | sort signal -desc | ft -autos


function Set-WifiNetFilter {
    Param (
        [string]$wifiName,
        [switch]$Remove
        )
    $rcmd = "netsh wlan <ACTION> filter permission=block ssid=`"" + $wifiName + "`" networktype=infrastructure"
    Switch ($Remove.IsPresent){
        $true  { $rcmd = $rcmd -replace '<ACTION>','delete' }
        $false { $rcmd = $rcmd -replace '<ACTION>','add' }
        }
    Invoke-Expression $rcmd
    }
# Set-WifiNetFilter 'Hidden Network' -Remove
# netsh wlan show filters
# netsh wlan show networks mode=bssid


function Show-WiFiPasswords { 
    $knownWiFis = (netsh wlan show profiles) | Select-String "\:(.+)$"
    $knownWiFis | ForEach-Object{$name=$_.Matches.Groups[1].Value.Trim(); $_} |
        ForEach-Object{(netsh wlan show profile name="$name" key=clear)} | 
            Select-String "Key Content\W+\:(.+)$" | 
                ForEach-Object{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | 
                    ForEach-Object{[PSCustomObject]@{ 'WiFi Profile'=$name;Password=$pass }} #| 
                        #ogv #Format-Table -AutoSize 
    }
# Show-WiFiPasswords | ft -a
# Show-WiFiPasswords | ogv

#region wifi State
class WiFiState
{
    [string]$IPv4Address
    [string]$IPv6Address
    [string]$SSID
    [string]$BSSID
    [string]$State
    [string]$Authentication
    [string]$Channel
    [string]$Signal
    [string]$RxRate
    [string]$TxRate
    [datetime]$StateTime
}

    function Show-WifiState()
    {
    <#
    
    .DESCRIPTION
       This function will diplay the current wireless connection state.
       Displayed information based on built in Windows command:
       netsh wlan show interfaces
 
 
    .EXAMPLE
        Show-WifiState
    #>
        $SelectedAdapter=Get-NetAdapter | Where-Object {$_.Name -like "Wi*"}
    
            [WifiState]$CurrentState=[WiFiState]::new()
            $CurrentState.StateTime=get-date
            $FullStat=$(netsh wlan show interfaces)
            $CurrentState.IPv4Address=(Get-NetIPAddress -InterfaceAlias $SelectedAdapter.Name).IPv4Address
            $CurrentState.IPv6Address=(Get-NetIPAddress -InterfaceAlias $SelectedAdapter.Name).IPv6Address
            $FullStat=$FullStat.split("`n")
            foreach($nextLine in $FullStat)
            {
                if($nextLine -match "^ SSID\s{10,35}:\s(.*)"){$CurrentState.SSID=$Matches[1]}
                if($nextLine -match "^ BSSID\s{10,35}:\s(.*)"){$CurrentState.BSSID=$Matches[1]}
                if($nextLine -match "^ State\s{10,35}:\s(.*)"){$CurrentState.State=$Matches[1]}
                if($nextLine -match "^ Authentication\s{5,35}:\s(.*)"){$CurrentState.Authentication=$Matches[1]}
                if($nextLine -match "^ Channel\s{10,35}:\s(.*)"){$CurrentState.Channel=$Matches[1]}
                if($nextLine -match "^ Signal\s{10,35}:\s(.*)"){$CurrentState.Signal=$Matches[1]}
                if($nextLine -match "^ Receive\srate\s\(Mbps\)\s{2,15}:\s(.*)"){$CurrentState.RxRate=$Matches[1]}
                if($nextLine -match "^ Transmit\srate\s\(Mbps\)\s{2,15}:\s(.*)"){$CurrentState.TxRate=$Matches[1]}
            

            }

        
            return $CurrentState 
    
    }

    function Get-WifiState()
    {
    <#
    
    .DESCRIPTION
       This function will help you to monitor wireless connection.
 
    .PARAMETER refreshTime
       Set refresh time.
 
    .PARAMETER LogMode
        Switch between monitor and log mode.
 
    .EXAMPLE
       Monitor-WifiState 5
       Monitor-WifiState -refreshTime 5
 
       Will dispaly and refresh wirless connection state in every 5 sec.
 
    .EXAMPLE
       Monitor-WifiState 5 -LogMode
       Monitor-WifiState -refreshTime 5 -LogMode
 
       Will dispaly and refresh a log about wirless connection state in every 5 sec.
 
 
    #>

        param([Parameter(Mandatory=$true)][int]$refreshTime, [switch]$LogMode=$false)
    
    
            while($true)
            {
            
                 $CurrentState=Show-WifiState 
             
                 if($LogMode -eq $true)
                 {
                    $($CurrentState | Format-Table -HideTableHeaders | Out-String).trim() | DateEcho
                
                 }
                 else
                 {
                    Clear-host
                    $CurrentState | Write-Output
                 }
            
            
                Start-Sleep $refreshTime
            }
    
    }
    Set-Alias -Name Monitor-WifiState -Value Get-WifiState

    Function Get-WifiState_v2()
    {
     <#
    
    .DESCRIPTION
       This function will monitor periodicly the state of wifi interface.
    
        
    .PARAMETER InterfaceName
       You can specify the exact wifi interface name, where you want to connect.
 
 
    .EXAMPLE
       Get-WifiState -InterfaceName Wi-Fi
 
    
    #>
        [CmdletBinding()]
        param([int]$CheckTime=1)
    
        DynamicParam {
        
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        

            $ParameterNameInterface="InterfaceName"
            $AttributeCollectionInterface = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttributeInterface = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttributeInterface.Mandatory = $false
            $ParameterAttributeInterface.Position = 2
            $AttributeCollectionInterface.Add($ParameterAttributeInterface)
            $arrSetInterface=get-netadapter | where-Object {$_.PhysicalMediaType -eq "Native 802.11"} | & {process{return $_.Name}}
            $ValidateSetAttributeInterface=New-Object System.Management.Automation.ValidateSetAttribute($arrSetInterface)
            $AttributeCollectionInterface.Add($ValidateSetAttributeInterface)
            $RuntimeParameterInterface = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterNameInterface, [string], $AttributeCollectionInterface)
            $RuntimeParameterDictionary.Add($ParameterNameInterface, $RuntimeParameterInterface)




            return $RuntimeParameterDictionary
        }
        begin{
            $SelectedInterface=$PsBoundParameters[$ParameterNameInterface]
        }
        process
        {
    
            while($true)
            {

                if($SelectedInterface -eq $null)
                {
                    $CurrentState=Get-WifiState
                    DateEcho $CurrentState.LogLine
                }
                else
                {
                    $CurrentState=Get-WifiState -InterfaceName $SelectedInterface
                    DateEcho $CurrentState.LogLine
                }

                Start-Sleep $CheckTime
            }

        }
    }
    Set-Alias -Name Monitor-WifiState_v2 -Value Get-WifiState_v2

    function Get-WifiState_v3()
    {
        <#
    
    .DESCRIPTION
       This function will return with object that contain the state of wifi interface.
    
        
    .PARAMETER InterfaceName
       You can specify the exact wifi interface name, where you want to connect.
 
 
    .EXAMPLE
       Get-WifiState -InterfaceName Wi-Fi
 
    
    #>
        [CmdletBinding()]
        param()
    
        DynamicParam {
        
            $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        

            $ParameterNameInterface="InterfaceName"
            $AttributeCollectionInterface = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
            $ParameterAttributeInterface = New-Object System.Management.Automation.ParameterAttribute
            $ParameterAttributeInterface.Mandatory = $false
            $ParameterAttributeInterface.Position = 2
            $AttributeCollectionInterface.Add($ParameterAttributeInterface)
            $arrSetInterface=get-netadapter | where-Object {$_.PhysicalMediaType -eq "Native 802.11"} | & {process{return $_.Name}}
            $ValidateSetAttributeInterface=New-Object System.Management.Automation.ValidateSetAttribute($arrSetInterface)
            $AttributeCollectionInterface.Add($ValidateSetAttributeInterface)
            $RuntimeParameterInterface = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterNameInterface, [string], $AttributeCollectionInterface)
            $RuntimeParameterDictionary.Add($ParameterNameInterface, $RuntimeParameterInterface)




            return $RuntimeParameterDictionary
        }
        begin{
            $SelectedInterface=$PsBoundParameters[$ParameterNameInterface]
        }
        process
        {
            $InterfaceIP=""
            $State=""
            $ESSID=""
            $BSSID=""
            $Authentication=""
            $ReceiveRate=""
            $TransmitRate=""
            $Signal=""
            $CurrentChannel=""
            $LogHeader=""
            $LogLine=""
            $LogCsvHeader=""
            $logCsvLine=""
        
        

            if($SelectedInterface -eq $null)
            {
                $SelectedInterface=get-netadapter  | where-Object {$_.PhysicalMediaType -eq "Native 802.11"}|Select-Object -First 1 | & {process{return $_.Name}}
            }
            $InterfaceIP=((Get-NetIPAddress | Where-Object {$_.interfacealias -like $($SelectedInterface) -and $_.AddressFamily -eq "IPv4"}).IPv4Address).ToString()
        
            $Interface=""
            $Interface=netsh wlan show interface $SelectedInterface
        
            $State=$Interface[7].Split(":")[1].Trim()
            if( "$($State)" -eq "connected" )
            {
                $ESSID=$Interface[8].Split(":")[1].Trim()
                $BSSID=$Interface[9].Substring($Interface[9].IndexOf(" : ")+3).Trim()
                $Authentication=$Interface[12].Split(":")[1].Trim()
                $ReceiveRate=$Interface[16].Split(":")[1].Trim()
                $TransmitRate=$Interface[17].Split(":")[1].Trim()
                $Signal=$Interface[18].Split(":")[1].Trim()
                $CurrentChannel=$Interface[15].Split(":")[1].Trim()            
            }
            $LogHeader="{0,-16} {1,-15} {2,-20} {3,-18} {4,-15} {5,-7} {6,-7} {7,-7} {8,-7}" -f "InterfaceIP", "State", "ESSID", "BSSID", "Authentication", "RxRate","TxRate", "Signal", "Channel" 
            $LogHeader+="`n"+"{0} {1} {2} {3} {4} {5} {6} {7} {8}" -f "".PadLeft(16,"-"), "".PadLeft(15,"-"), "".PadLeft(20,"-"), "".PadLeft(18,"-"), "".PadLeft(15,"-"), "".PadLeft(7,"-"), "".PadLeft(7,"-"), "".PadLeft(7,"-"), "".PadLeft(7,"-")
            $LogLine="{0,-16} {1,-15} {2,-20} {3,-18} {4,-15} {5,-7} {6,-7} {7,-7} {8,-7}" -f $InterfaceIP, $State, $ESSID, $BSSID, $Authentication, $ReceiveRate, $TransmitRate, $Signal, $CurrentChannel
            $LogCsvHeader="{0};{1};{2};{3};{4};{5};{6};{7};{8}" -f "InterfaceIP", "State", "ESSID", "BSSID", "Authentication", "RxRate","TxRate", "Signal", "Channel" 
            $logCsvLine="{0};{1};{2};{3};{4};{5};{6};{7};{8}" -f $InterfaceIP, $State, $ESSID, $BSSID, $Authentication, $ReceiveRate, $TransmitRate, $Signal, $CurrentChannel

            return [pscustomobject]@{InterfaceIP=$InterfaceIP;State=$State;ESSID=$ESSID;BSSID=$BSSID;Authentication=$Authentication;ReceiveRate=$ReceiveRate;TransmitRate=$TransmitRate;Signal=$Signal;CurrentChannel=$CurrentChannel;`
            LogHeader=$LogHeader;LogLine=$LogLine;LogCsvHeader=$LogCsvHeader;logCsvLine=$logCsvLine;}

        }
    }

#endregion

#region wifi Profiles
Function Get-WifiProfiles()
{
    $AllProfiles=$(netsh wlan show profiles)
    $ArrayProfiles=@()
    foreach($nextline in $AllProfiles)
    {
        if($nextline -match " All User Profile : (.*)")
        {
            $ArrayProfiles+=$Matches[1]
        }

    }
    return $ArrayProfiles
}

function Show-WifiProfiles()
{
    <#
        .DESCRIPTION
           This function can help you to list available wireless profiles.
    
        .PARAMETER profileName
            You can specify the exact profile to list profiles.
   
        .PARAMETER profileRegex
            You can specify a regex pattern to list profiles.
        
        .PARAMETER profileContain
            You can specify a string that profile name must contain to list.

        .PARAMETER profileWildCard
            You can specify a wildcard to list profiles.
 
        .EXAMPLE
            List-WifiProfiles -profileName TP007
 
        .EXAMPLE
            List-WifiProfiles -profileRegex TP.*$
 
        .EXAMPLE
            List-WifiProfiles -profileContain TP
 
        .EXAMPLE
            List-WifiProfiles -profileWildCard T*07
    #>
    Param
    (
        $profileName,
        $profileRegex,
        $profileContain,
        $profileWildCard
    )
    $AllProfiles = $(netsh wlan show profiles)
    If (-not ($profileName -eq "" -or $profileName -eq $null))
    {
        foreach ($nextLine in $AllProfiles)
        {
            if($nextLine -like "* : *" -and $nextLine.split(":")[1] -eq " $profileName") {Write-Host $nextLine}
                
        }
    }
    elseIf (-not ($profileContain -eq "" -or $profileContain -eq $null))
    { 
        foreach ($nextLine in $AllProfiles)
        {
            if ($nextLine -like "* : *")
            {
                if ($nextLine.split(":")[1] -like "*$profileContain*") { Write-Host $nextLine }
            }
        }   
    }
    elseIf (-not($profileRegex -eq "" -or $profileRegex -eq $null))
    {
        foreach ($nextLine in $AllProfiles)
        {
            if ($nextLine -like "* : *")
            {
                if($nextLine.split(":")[1] -match $profileRegex) { Write-Host $nextLine }
            }
        }           
    }
    elseIf (-not($profileWildCard -eq "" -or $profileWildCard -eq $null))
    {
        foreach ($nextLine in $AllProfiles)
        {
            if ($nextLine -like "* : *")
            {
                if ($nextLine.split(":")[1] -like "?$profileWildCard") { Write-Host $nextLine }
            }
        }           
    }
    else
    {
        Write-Host ($AllProfiles | Out-String)
    }
}
Set-Alias -Name List-WifiProfiles -Value Show-WifiProfiles
    

function Remove-WifiProfiles()
{
<#
    
.DESCRIPTION
   This function can help you to delete wireless profiles.
    
        
.PARAMETER profileName
   You can specify the exact profile to delete profiles.
.PARAMETER profileRegex
   You can specify a regex pattern to delete profiles.
.PARAMETER profileContain
   You can specify a string that profile name must contain to delete.
.PARAMETER profileWildCard
   You can specify a wildcard to delete profiles.
 
.EXAMPLE
   Delete-WifiProfiles -profileName TP007
 
.EXAMPLE
   Delete-WifiProfiles -profileRegex TP.*$
 
.EXAMPLE
   Delete-WifiProfiles -profileContain TP
 
.EXAMPLE
   Delete-WifiProfiles -profileWildCard T*07
 
#>
    [CmdletBinding()]
    param( $profileRegex, $profileContain, $profileWildCard)
    DynamicParam {
        $ParameterName="profileName"
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $false
        $ParameterAttribute.Position = 1
        $AttributeCollection.Add($ParameterAttribute)
        $arrSet = Get-WifiProfiles
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }
    begin{
        $profileName = $PsBoundParameters[$ParameterName]
    }


    process{
        $AllProfiles=$(netsh wlan show profiles)
    
        if(-not ($profileName -eq "" -or $profileName -eq $null))
        {
            foreach($nextLine in $AllProfiles)
            {
                if($nextLine -like "* : *" -and $nextLine.split(":")[1] -eq " $profileName") 
                {
                    $ProfielToDelete=$nextLine.split(":")[1].Trim(" ")
                    netsh wlan delete profile $ProfielToDelete
                }
            }
        }
        elseif(-not ($profileContain -eq "" -or $profileContain -eq $null))
        {
            foreach($nextLine in $AllProfiles)
            {
                if($nextLine -like "* : *")
                {
                    if($nextLine.split(":")[1] -like "*$profileContain*")
                    {
                        $ProfielToDelete=$nextLine.split(":")[1].Trim(" ")
                        netsh wlan delete profile $ProfielToDelete
                    }
                }
            }   
        }
        elseif(-not($profileRegex -eq "" -or $profileRegex -eq $null))
        {
            foreach($nextLine in $AllProfiles)
            {
                if($nextLine -like "* : *")
                {
                    if($nextLine.split(":")[1] -match $profileRegex)
                    {
                        $ProfielToDelete=$nextLine.split(":")[1].Trim(" ")
                        netsh wlan delete profile $ProfielToDelete
                    }
                }
            }           
        }
        elseif(-not($profileWildCard -eq "" -or $profileWildCard -eq $null))
        {
            foreach($nextLine in $AllProfiles)
            {
                if($nextLine -like "* : *")
                {
                    if($nextLine.split(":")[1] -like "?$profileWildCard")
                    {
                        $ProfielToDelete=$nextLine.Trim(" ")
                        netsh wlan delete profile $ProfielToDelete
                    }
                }
            }           
        }
        else
        {
            foreach($nextLine in $AllProfiles)
            {
                if($nextLine -like "* : *")
                {
                    $ProfielToDelete=$nextLine.split(":")[1].Trim(" ")
                    netsh wlan delete profile $ProfielToDelete
                }
            }
        }
    
    }
}
Set-Alias -Name Delete-WifiProfiles -Value Remove-WifiProfiles

function New-WifiProfile()
{
    <#
    
.DESCRIPTION
    This funtcion Will create a Wireless Profile
        
.PARAMETER WLanName
    Define SSID for the wireless network.
.PARAMETER Passwd
    Define the secretkey of wireless network.
.PARAMETER WPA
    This switch can help to generate a WPA profile(Default:WPA2)
    
 
.EXAMPLE
    Create-WifiProfile -WlanName "MyNetworkName" -Passwd "networkpassword"
    Create-WifiProfile "MyNetworkName" "networkpassword"
 
    These command will generate a WPA2 wireless profile with the defined name and password.
 
.EXAMPLE
    Create-WifiProfile -WlanName MyOpenWifiNetwork
 
    This command will generate a profile for unprotected wireless network.
 
.EXAMPLE
    Create-WifiProfile -WlanName "MyNetworkName" -Passwd "networkpassword" -WPA
    Create-WifiProfile "MyNetworkName" "networkpassword" -WPA
 
    These command will generate a WPA wireless profile with the defined name and password.
 
#>
    param([Parameter(Mandatory=$true, HelpMessage="Please add Wireless network name")]
    [string]$WLanName, 
    [string]$Passwd,
    [Parameter(Mandatory=$false, HelpMessage="This switch will generate a WPA profile instead of WPA2")]
    [switch]$WPA=$false)


    if($WPA -eq $false)
    {
        $WpaState="WPA2PSK"
        $EasState="AES"
    }
    else
    {
        $WpaState="WPAPSK"
        $EasState="AES"
    }

$XMLProfile= @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>$WlanName</name>
        <SSIDConfig>
            <SSID>
                <name>$WLanName</name>
            </SSID>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>auto</connectionMode>
        <MSM>
            <security>
                <authEncryption>
                    <authentication>$WpaState</authentication>
                    <encryption>$EasState</encryption>
                    <useOneX>false</useOneX>
                </authEncryption>
                <sharedKey>
                    <keyType>passPhrase</keyType>
                    <protected>false</protected>
    <keyMaterial>$Passwd</keyMaterial>
    </sharedKey>
    </security>
    </MSM>
</WLANProfile>
"@

    if($Passwd -eq "")
                                                                                                        {
$XMLProfile= @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$WLanName</name>
    <SSIDConfig>
    <SSID>
    <name>$WLanName</name>
    </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
    <security>
    <authEncryption>
    <authentication>open</authentication>
    <encryption>none</encryption>
    <useOneX>false</useOneX>
    </authEncryption>
    </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
    <enableRandomization>false</enableRandomization>
    </MacRandomization>
</WLANProfile>
 
 
"@
    }


    $currentlocation=Get-Location
    Set-Location $env:TEMP
    $TempLocation=Get-Location
    $XMLProfile | Set-Content "$WLanName.xml"
    Netsh WLAN add profile filename=$TempLocation\$WLanName.xml
    remove-item "$WLanName.xml"
    Set-Location $currentlocation


}
Set-Alias -Name Create-WifiProfile -Value New-WifiProfile

function New-W4AWifiProfile()
{
<#
    
.DESCRIPTION
    This funtcion Will create a W4A Wireless Profile.
        
.PARAMETER NetworkName
    Specifies custom name for W4A network
    
 
.EXAMPLE
    Create-W4AProfile "Custom Wi-Free"
 
#>
    param($NetworkName)
    if($NetworkName -eq $null)
    {
        $NetworkName = "Horizon Wi-Free"
    }
$XMLProfile= @"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$NetworkName</name>
    <SSIDConfig>
    <SSID>
    
    <name>$NetworkName</name>
    </SSID>
    <nonBroadcast>false</nonBroadcast>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
    <security>
    <authEncryption>
    <authentication>WPA2</authentication>
    <encryption>AES</encryption>
    <useOneX>true</useOneX>
    <FIPSMode xmlns="http://www.microsoft.com/networking/WLAN/profile/v2">false</FIPSMode>
    </authEncryption>
    <PMKCacheMode>enabled</PMKCacheMode>
    <PMKCacheTTL>720</PMKCacheTTL>
    <PMKCacheSize>128</PMKCacheSize>
    <preAuthMode>disabled</preAuthMode>
    <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
    <cacheUserData>true</cacheUserData>
    <authMode>user</authMode>
    <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">25</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</AuthorId></EapMethod><Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>25</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV1"><ServerValidation><DisableUserPromptForServerValidation>false</DisableUserPromptForServerValidation><ServerNames></ServerNames></ServerValidation><FastReconnect>true</FastReconnect><InnerEapOptional>false</InnerEapOptional><Eap xmlns="http://www.microsoft.com/provisioning/BaseEapConnectionPropertiesV1"><Type>26</Type><EapType xmlns="http://www.microsoft.com/provisioning/MsChapV2ConnectionPropertiesV1"><UseWinLogonCredentials>false</UseWinLogonCredentials></EapType></Eap><EnableQuarantineChecks>false</EnableQuarantineChecks><RequireCryptoBinding>false</RequireCryptoBinding><PeapExtensions><PerformServerValidation xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</PerformServerValidation><AcceptServerName xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2">false</AcceptServerName><PeapExtensionsV2 xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV2"><AllowPromptingWhenServerCANotFound xmlns="http://www.microsoft.com/provisioning/MsPeapConnectionPropertiesV3">true</AllowPromptingWhenServerCANotFound></PeapExtensionsV2></PeapExtensions></EapType></Eap></Config></EapHostConfig></EAPConfig>
    </OneX>
    </security>
    </MSM>
</WLANProfile>
 
"@

    $currentlocation=Get-Location
    Set-Location $env:TEMP
    $TempLocation=Get-Location
    $XMLProfile | Set-Content "$NetworkName.xml"
    Netsh WLAN add profile filename=$TempLocation\$NetworkName.xml
    remove-item "$NetworkName.xml"
    Set-Location $currentlocation

}
Set-Alias -Name Create-W4AWifiProfile -Value New-W4AWifiProfile

#endregion


Function Get-PublicIP()
{
<#
    
.DESCRIPTION
   This function will return with IPv4 public address
    
   This function need live internet connection, otherwise will throw an exception.
 
.EXAMPLE
    Get-PublicIP
 
#>

    $Uri = 'ipv4bot.whatismyipaddress.com'
    Invoke-WebRequest -Uri $Uri -UseBasicParsing -DisableKeepAlive | Select-Object -ExpandProperty Content
}

function Connect-WiFi()
{
<#
    
.DESCRIPTION
   This function can help you to connet specified wireless network.
    
        
.PARAMETER ProfileName
   You can specify the exact profile name, where you want to connect.
 
.EXAMPLE
   Connect-WiFi -ProfileName TP007
    
   Connection will be proceed only if profile exists.
 
.EXAMPLE
   Connect-WiFi -ProfileName TP007 -InterfaceName Wi-Fi
 
   Connection will be procced, if profile exists on the specified interface.
#>
    [CmdletBinding()]
    param()
    
    DynamicParam {
        $ParameterName="ProfileName"
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1
        $AttributeCollection.Add($ParameterAttribute)
        $arrSet = Get-WifiProfiles
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)


        $ParameterNameInterface="InterfaceName"
        $AttributeCollectionInterface = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttributeInterface = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttributeInterface.Mandatory = $false
        $ParameterAttributeInterface.Position = 2
        $AttributeCollectionInterface.Add($ParameterAttributeInterface)
        $arrSetInterface=get-netadapter | where-Object {$_.PhysicalMediaType -eq "Native 802.11"} | & {process{return $_.Name}}
        $ValidateSetAttributeInterface=New-Object System.Management.Automation.ValidateSetAttribute($arrSetInterface)
        $AttributeCollectionInterface.Add($ValidateSetAttributeInterface)
        $RuntimeParameterInterface = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterNameInterface, [string], $AttributeCollectionInterface)
        $RuntimeParameterDictionary.Add($ParameterNameInterface, $RuntimeParameterInterface)




        return $RuntimeParameterDictionary
    }
    begin{
        $ProfileName = $PsBoundParameters[$ParameterName]
        $SelectedInterface=$PsBoundParameters[$ParameterNameInterface]
    }
    process{
    $allProfiles=$(netsh wlan show profiles)
    $IsProfileExist=$false
    foreach($nextline in $allProfiles)
    {
        if($nextline -match "^.*Profile\s*:\s$ProfileName$")
        {
            $IsProfileExist=$true      
        }
    }
    if($IsProfileExist)
    {
        if($SelectedInterface -eq $null)
        {
            $SelectedInterface=get-netadapter  | where-Object {$_.PhysicalMediaType -eq "Native 802.11"}|Select-Object -First 1 | & {process{return $_.Name}}
        } 
        netsh wlan connect name=$ProfileName interface=$SelectedInterface   
    }
    else
    {
        Write-host "Network profile does not exists."
    }
    }
}

Function Show-WifiInterface()
{
<#
    
.DESCRIPTION
   This funtcion will display the same information that "netsh wlan show interfaces command" do.
        
.EXAMPLE
   Show-WifiInterface
 
#>
    netsh wlan show interfaces
}

Function Show-IPConfig
{
<#
    
.DESCRIPTION
   This function display the same information as the traditional ipconfig /all,
   but in userfriendly filterable format.
        
.PARAMETER Interface
   Specifies the nam of the interface.
    
 
.EXAMPLE
   Show-IPConfig -interface Ethernet
   Show-IPConfig Eth
 
   You can use only part of the full interface name.
    
   get-netAdapter command will list the available network intrafaces.
 
#>
    [CmdletBinding()]
    param()

    DynamicParam {
        $ParameterName="Interface"
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 0
        $AttributeCollection.Add($ParameterAttribute)
        $arrSet = (Get-NetAdapter).Name
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)
        return $RuntimeParameterDictionary
    }
    begin{
        $Interface = $PsBoundParameters[$ParameterName]
    }


    Process{
        $SelectedAdapter=Get-NetAdapter | Where-Object {$_.Name -eq $Interface}
        $Interface=$SelectedAdapter.Name
        
        $AllIpConifig=$(ipconfig /all)
        $needToPrintNextLine=$false
        $ignoreWhiteSpace=$false
        foreach($nextline in $AllIpConifig)
        {
            if($ignoreWhiteSpace -eq $true)
            {
                Write-Host $nextline
                $ignoreWhiteSpace=$false
            }
            else
            {
                if($nextline -match "^(?!\s).*")
                {
                    if($nextline -match "^.*$($Interface):$")
                    {
                        Write-Host $nextline
                        $needToPrintNextLine=$true
                        $ignoreWhiteSpace=$true
                    }
                    else
                    {
                        $needToPrintNextLine=$false
                        $ignoreWhiteSpace=$false
                    }
            

                }
                else
                {
                    if($needToPrintNextLine)
                    {
                        Write-Host $nextline
                    }
                }
            }
        }
    }
}

function Get-NewIP()
{
<#
    
.DESCRIPTION
   This funtcion Will proceed the complete dhcp release renew cycle
    
 
.EXAMPLE
    Release-Renew-IP
 
#>
    ipconfig /release
    Start-Sleep 5
    ipconfig /renew
}
Set-Alias -Name Release-Renew-IP -Value Get-NewIP

function Disconnect-Wifi()
{
<#
    
.DESCRIPTION
   This funtcion Will disconnect from current wireless network
 
    
 
.EXAMPLE
   Disconnect-Wifi
 
.EXAMPLE
   Disconnect-Wifi -interface Wi-Fi
 
#>
    [CmdletBinding()]
    param()

     DynamicParam {
 
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $ParameterNameInterface="InterfaceName"
        $AttributeCollectionInterface = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttributeInterface = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttributeInterface.Mandatory = $false
        $ParameterAttributeInterface.Position = 1
        $AttributeCollectionInterface.Add($ParameterAttributeInterface)
        $arrSetInterface=get-netadapter | where-Object {$_.PhysicalMediaType -eq "Native 802.11"} | & {process{return $_.Name}}
        $ValidateSetAttributeInterface=New-Object System.Management.Automation.ValidateSetAttribute($arrSetInterface)
        $AttributeCollectionInterface.Add($ValidateSetAttributeInterface)
        $RuntimeParameterInterface = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterNameInterface, [string], $AttributeCollectionInterface)
        $RuntimeParameterDictionary.Add($ParameterNameInterface, $RuntimeParameterInterface)




        return $RuntimeParameterDictionary
    }
    begin{
        
        $SelectedInterface=$PsBoundParameters[$ParameterNameInterface]
    }

    process{
        if($SelectedInterface -eq $null)
        {
            $SelectedInterface=get-netadapter  | where-Object {$_.PhysicalMediaType -eq "Native 802.11"}  |Select-Object -First 1 | & {process{return $_.Name}}
        } 
        netsh wlan disconnect interface=$SelectedInterface
    }
    
}



class WifiAP
{
    [string]$Name
    [string]$Authentication
    [string]$Encryption
    [string]$BSSID
    [string]$Signal
    [string]$Radio
    [string]$Channel


}
Function Show-WifiAPs()
{
 
<#
    
.DESCRIPTION
   This funtcion designed to list available APs and details
        
.PARAMETER profileNameWildCard
   Specifies wildcard filter for SSID
.PARAMETER BSSIDWildCard
   Specifies wildcard filter for BSSID
 
.EXAMPLE
   Scan-WifiAPs -profileNameWildCard TP007
 
    Name : TP007
    Authentication : WPA2-Personal
    Encryption : CCMP
    BSSID : 64:70:02:9a:2a:c8
    Signal : 80%
    Radio : 802.11n
    Channel : 11
 
.EXAMPLE
   Scan-WifiAPs | Format-Table
 
    Name Authentication Encryption BSSID Signal Radio Channel
    ---- -------------- ---------- ----- ------ ----- -------
    Horizon Wi-Free WPA2-Enterprise CCMP de:53:1c:ae:a3:b4 99% 802.11n 5
    Horizon Wi-Free WPA2-Enterprise CCMP 0a:95:2a:5d:1b:cc 56% 802.11n 1
    Horizon Wi-Free WPA2-Enterprise CCMP 5c:a3:9d:e9:25:19 28% 802.11n 6
    VM521D7B9 WPA2-Personal CCMP dc:53:7c:ae:a3:b4 99% 802.11n 5
    VM521D7B9-5 WPA2-Personal CCMP dc:53:7c:ae:a3:ac 98% 802.11ac 40
    PS4-BE73F184585B WPA2-Personal CCMP 60:5b:b4:45:f2:3f 46% 802.11n 6
    UPC5912998 WPA2-Personal CCMP 08:95:2a:5d:1b:ca 65% 802.11n 1
    TP007 WPA2-Personal CCMP 64:70:02:9a:2a:c8 60% 802.11n 11
#>

   param([string]$profileNameWildCard, [string]$BSSIDWildCard)
    
    #clear-host
    $AllAP=$(netsh wlan show networks mode=bssid)
    #Write-Host $($AllAP | Out-String)
    $ListOfAPs=@()
    $ProcessNextLine=$false
    $lastLineisChannel=$false
    foreach($nextline in $AllAP)
    {
        if($nextline -match "^SSID\s[0-9]{1,4}\s:\s(.*)")
        {
            $ProcessNextLine=$true
            $Name=[regex]::match($nextline,"^SSID\s[0-9]{1,4}\s:\s(.*)").captures.groups[1].value
            
        }
        else
        {
            if($ProcessNextLine -eq $true)
            {
                if($nextline -eq "")
                {
                    $ProcessNextLine=$false
                    [WifiAP]$NewAP = [WifiAP]::new()
                    $NewAP.Name=$Name
                    $NewAP.Authentication=$Authentication
                    $NewAP.BSSID=$BSSID
                    $NewAP.Channel=$Channel
                    $NewAP.Encryption=$Encryption
                    $NewAP.Signal=$Signal
                    $NewAP.Radio=$Radio
                    $ListOfAPs+=$NewAP
                    $lastLineisChannel=$false
                    #$ListOfAPs+=(@{Name=$Name; Authentication=$Authentication; Encryption=$Encryption; BSSID=$BSSID; Signal=$Signal; Radio=$Radio; Channel=$Channel })
                }
                else
                {
                    
                    if($nextline -match "^\s{4}Authentication\s{1,24}\s:\s(.*)"){$Authentication=$Matches[1]}
                    if($nextline -match "^\s{4}Encryption\s{1,24}\s:\s(.*)"){ $Encryption=$Matches[1]}
                    if($nextline -match "^\s{4}BSSID\s[0-9]{1,5}\s{1,24}\s:\s(.*)")
                    { 
                        if($lastLineisChannel -eq $true)
                        {
                            [WifiAP]$NewAP = [WifiAP]::new()
                            $NewAP.Name=$Name
                            $NewAP.Authentication=$Authentication
                            $NewAP.BSSID=$BSSID
                            $NewAP.Channel=$Channel
                            $NewAP.Encryption=$Encryption
                            $NewAP.Signal=$Signal
                            $NewAP.Radio=$Radio
                            $ListOfAPs+=$NewAP   
                            $lastLineisChannel=$false
                        }
                        $BSSID=$Matches[1]
                    }
                    if($nextline -match "^\s{9}Signal\s{1,24}\s:\s(.*)"){ $Signal=$Matches[1]}
                    if($nextline -match "^\s{9}Radio\stype\s{1,24}\s:\s(.*)"){ $Radio=$Matches[1]}
                    if($nextline -match "^\s{9}Channel\s{1,24}\s:\s(.*)"){ $Channel=$Matches[1]; $lastLineisChannel=$true}
                    
                    

                }
            }
        }   
    }
    if($profileNameWildCard -ne "")
    {
        $ListOfAPs = $ListOfAPs | Where-Object {$_.Name -like $profileNameWildCard}
    }
    if($BSSIDWildCard -ne "")
    {
        $ListOfAPs =$ListOfAPs | Where-Object {$_.BSSID -like $BSSIDWildCard}
    }
    return $ListOfAPs
    #process all AP to an object, and after filter them
}
Set-Alias -Name Scan-WifiAPs -Value Show-WifiAPs

Function Get-TCPConnectionsInfo()
{
<#
    
.DESCRIPTION
   This function will get back information about tcp connection.
        
    
 
.EXAMPLE
   Get-TCPConnectionsInfo |Format-Table
    
 
RemoteDNS RemoteIP RemotePort ProcessID ProcessName Company LocalIP LocalPort
--------- -------- ---------- --------- ----------- ------- ------- ---------
KriszLaptop fe80::f546:a6ce:fae0:37a7%4 445 4 System fe80::f546:a6ce:fae0:37a7%4 1796
KriszLaptop fe80::f546:a6ce:fae0:37a7%4 1796 4 System fe80::f546:a6ce:fae0:37a7%4 445
KriszLaptop 127.0.0.1 1266 12400 Duplicati.GUI.TrayIcon Duplicati Team 127.0.0.1 8200
wm-in-f189.1e100.net 64.233.166.189 443 6080 opera Opera Software 192.168.2.185 6164
server22809.teamviewer.com 188.172.204.19 5938 3772 TeamViewer_Service TeamViewer GmbH 192.168.2.185 6104
db5sch101110740.wns.windows.com 40.77.229.82 443 5884 svchost Microsoft Corporation 192.168.2.185 6096
KriszLaptop 127.0.0.1 1704 3772 TeamViewer_Service TeamViewer GmbH 127.0.0.1 5939
KriszLaptop 127.0.0.1 4537 3772 TeamViewer_Service TeamViewer GmbH 127.0.0.1 4538
KriszLaptop 127.0.0.1 4538 3772 TeamViewer_Service TeamViewer GmbH 127.0.0.1 4537
KriszLaptop 127.0.0.1 2263 7532 pycharm64 JetBrains s.r.o. 127.0.0.1 2264
KriszLaptop 127.0.0.1 2264 7532 pycharm64 JetBrains s.r.o. 127.0.0.1 2263
KriszLaptop 127.0.0.1 2261 7532 pycharm64 JetBrains s.r.o. 127.0.0.1 2262
KriszLaptop 127.0.0.1 2262 7532 pycharm64 JetBrains s.r.o. 127.0.0.1 2261
KriszLaptop 127.0.0.1 1706 7388 TeamViewer TeamViewer GmbH 127.0.0.1 1707
 
 
#>
Get-NetTCPConnection -State Established |  
ForEach-Object {
        if($lastItem -eq $null)
        {
            $lastItem=""
        }
        if($_.RemoteAddress -ne $lastItem)
        {
            $Name=Resolve-DnsName $_.RemoteAddress -ErrorAction SilentlyContinue;
            $lastItem=$_.RemoteAddress
        }
        
        $Process=Get-Process | Where-Object Id -eq $_.OwningProcess
        
        [pscustomobject]@{RemoteDNS=$Name.Server; RemoteIP=$_.RemoteAddress;RemotePort=$_.RemotePort;ProcessID=$_.OwningProcess;ProcessName=$Process.ProcessName;Company=$Process.Company; LocalIP=$_.LocalAddress; LocalPort=$_.LocalPort}
        
    
}  
}


function Debug-Connection()
{
<#
    
.DESCRIPTION
   This function will chechk connection to specified network, and it will attempt to re-connect in case of long disconnection.
    
        
.PARAMETER ProfileName
   You can specify the exact profile name, where you want to connect.
 
.EXAMPLE
   Stay-connected -ProfileName TP007
    
   Connection will be proceed only if profile exists.
 
.EXAMPLE
   Stay-connected -ProfileName TP007 -InterfaceName Wi-Fi
 
   Connection will be procced, if profile exists on the specified interface.
#>
    [CmdletBinding()]
    param()
    
    DynamicParam {
        $ParameterName="ProfileName"
        $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttribute.Mandatory = $true
        $ParameterAttribute.Position = 1
        $AttributeCollection.Add($ParameterAttribute)
        $arrSet = Get-WifiProfiles
        $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($arrSet)
        $AttributeCollection.Add($ValidateSetAttribute)
        $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterName, [string], $AttributeCollection)
        $RuntimeParameterDictionary.Add($ParameterName, $RuntimeParameter)


        $ParameterNameInterface="InterfaceName"
        $AttributeCollectionInterface = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
        $ParameterAttributeInterface = New-Object System.Management.Automation.ParameterAttribute
        $ParameterAttributeInterface.Mandatory = $false
        $ParameterAttributeInterface.Position = 2
        $AttributeCollectionInterface.Add($ParameterAttributeInterface)
        $arrSetInterface=get-netadapter | where-Object {$_.PhysicalMediaType -eq "Native 802.11"} | & {process{return $_.Name}}
        $ValidateSetAttributeInterface=New-Object System.Management.Automation.ValidateSetAttribute($arrSetInterface)
        $AttributeCollectionInterface.Add($ValidateSetAttributeInterface)
        $RuntimeParameterInterface = New-Object System.Management.Automation.RuntimeDefinedParameter($ParameterNameInterface, [string], $AttributeCollectionInterface)
        $RuntimeParameterDictionary.Add($ParameterNameInterface, $RuntimeParameterInterface)




        return $RuntimeParameterDictionary
    }
    begin{
        $ProfileName = $PsBoundParameters[$ParameterName]
        $SelectedInterface=$PsBoundParameters[$ParameterNameInterface]
    }
    process
    {
        $allProfiles=$(netsh wlan show profiles)
        $IsProfileExist=$false
        foreach($nextline in $allProfiles)
        {
            if($nextline -match "^.*Profile\s*:\s$ProfileName$")
            {
                $IsProfileExist=$true      
            }
        }
        if($IsProfileExist)
        {
            if($SelectedInterface -eq $null)
            {
                $SelectedInterface=get-netadapter  | where-Object {$_.PhysicalMediaType -eq "Native 802.11"}|Select-Object -First 1 | & {process{return $_.Name}}
            } 
            $SleepCounter=0
            while($true)
            {
                Start-Sleep 60
                $Status=Show-WifiInterface
                $Status=$Status.split("`n") | Where-Object {$_ -match "^\s{4}State"}
                if($Status -match ".*disconnected.*")
                {
                    $SleepCounter++
                    DateEcho "Network state: Disconnected"
                    if($SleepCounter -gt 10)
                    {
                        DateEcho "Connection attempt"
                        netsh wlan connect name=$ProfileName interface=$SelectedInterface       
                        
                    }
                }
                else
                {
                    $SleepCounter=0
                    if($Status -match ".*:\s(.*)")
                    {
                        DateEcho "Network state: $($Matches[1])"    
                    }
                    
                }

                
            }
        }
        else
        {
            Write-host "Network profile does not exists."
        }
    }
}
Set-Alias -Name Stay-Connected -Value Debug-Connection

function New-DateStamp($Var)
{
<#
    
.DESCRIPTION
   This function will add an extra time stamp for all input.
   Pipeline enabled command.
 
.EXAMPLE
   DateEcho "This message need a timesamp"
   26.01.2017-22:24:08> This message need a timesamp
 
.EXAMPLE
    ping 8.8.8.8 -t | DateEcho
 
    26.01.2017-22:24:48> Reply from 8.8.8.8: bytes=32 time=10ms TTL=57
    26.01.2017-22:24:49> Reply from 8.8.8.8: bytes=32 time=13ms TTL=57
    26.01.2017-22:24:50> Reply from 8.8.8.8: bytes=32 time=12ms TTL=57
    26.01.2017-22:24:51> Reply from 8.8.8.8: bytes=32 time=10ms TTL=57
    26.01.2017-22:24:52> Reply from 8.8.8.8: bytes=32 time=10ms TTL=57
#>
    
    process
    {
         $TimeStamp=Get-Date -Format "dd.MM.yyyy-HH:mm:ss> "
        "$TimeStamp$Var$_"
        
    }
    

}
Set-Alias -Name DateEcho -Value New-DateStamp
