# Install-Module -Name PSnmap
# Import-Module -Name PSnmap
# $x = PSnmap -Cn beleriand  -Port 22,3389,80,443 -Dns #10.114.187.1/24 #, synology, ubuntuvm, vista64esxi #-Verbose
# $x | Where { $_.Ping } | Format-Table -AutoSize
    $Global:InetDns = "DNS Provider Name,Primary DNS Server,Secondary DNS Server,Online,Trusted
    Google,8.8.8.8,8.8.4.4,,True
    OpenDNS Home,208.67.222.222,208.67.220.220,,True
    CloudFlare,1.1.1.1,1.0.0.1,,
    Quad9,9.9.9.9,149.112.112.112,,
    Level3,209.244.0.3,209.244.0.4,,
    Verisign,64.6.64.6,64.6.65.6,,True
    DNS.WATCH,84.200.69.80,84.200.70.40,,
    Comodo Secure DNS,8.26.56.26,8.20.247.20,,
    Norton ConnectSafe,199.85.126.10,199.85.127.10,,
    GreenTeamDNS,81.218.119.11,209.88.198.133,,
    SafeDNS,195.46.39.39,195.46.39.40,,
    OpenNIC,23.94.60.240,128.52.130.209,,
    SmartViper,208.76.50.50,208.76.51.51,,
    Dyn,216.146.35.35,216.146.36.36,,True
    FreeDNS,37.235.1.174,37.235.1.177,,
    Alternate DNS,198.101.242.72,23.253.163.53,,
    Yandex.DNS,77.88.8.8,77.88.8.1,,
    UncensoredDNS,91.239.100.100,89.233.43.71,,
    Hurricane Electric,74.82.42.42,,,
    puntCAT,109.69.8.51,,,
    Source,https://twitgoo.com/best-free-dns-servers/,,,
    Source,https://whatsabyte.com/internet/best-public-dns-servers/,,,
    " | ConvertFrom-CSV

Function Test-InetDnsServers
{
    $Global:inetdns | 
    ForEach-Object{
        If ($_.Trusted -eq $true){
            If ([Bool](Ping -n 2 $_.'Primary DNS Server') -and
                [Bool](Ping -n 2 $_.'Secondary DNS Server'))
                { $_.Online = $true }
            Else { $_.Online = $false }
            }
        Else { $_.Trusted = $false }
    }
    Return $inetdns
}

Function Get-ReverseIP ($ip)
{
    ([ipaddress]::Parse(([ipaddress]::Parse($ip)).address)).IPAddressToString
} # ReverseIP 10.114.187.34
Set-Alias -Name ReverseIP -Value Get-ReverseIP


function Get-NetworkAdapterStatus {
    <#
       .Synopsis
            Produces a listing of network adapters and status on a local or remote machine.
       .Description
            This script produces a listing of network adapters and status on a local or remote machine.
       .Example
            Get-NetworkAdapterStatus.ps1 -computer MunichServer
            Lists all the network adapters and status on a computer named MunichServer
       .Example
            Get-NetworkAdapterStatus.ps1
            Lists all the network adapters and status on local computer
       .Inputs
            [string]
       .OutPuts
            [string]
       .Notes
            NAME:  Get-NetworkAdapterStatus.ps1
            AUTHOR: Ed Wilson
            LASTEDIT: 1/10/2014
            KEYWORDS: Hardware, Network Adapter
       .Link
            Http://www.ScriptingGuys.com
    #Requires -Version 2.0
    #>
    Param(
        [string]$computer= $env:COMPUTERNAME
        )
        function Get-StatusFromValue
            {
            Param($SV)
            switch($SV)
            {
            0 { "Disconnected" }
            1 { "Connecting" }
            2 { "Connected" }
            3 { "Disconnecting" }
            4 { "Hardware not present" }
            5 { "Hardware disabled" }
            6 { "Hardware malfunction" }
            7 { "Media disconnected" }
            8 { "Authenticating" }
            9 { "Authentication succeeded" }
            10 { "Authentication failed" }
            11 { "Invalid Address" }
            12 { "Credentials Required" }
            Default { "Not connected" }
            }
            } #end Get-StatusFromValue function
        # Switch ($PSVersionTable){
        #     {$_.PSVersion.Major -lt 7} {
                Get-WmiObject -Class win32_networkadapter -computer $computer |
                    Select-Object Name, @{n="Status";e={Get-StatusFromValue $_.NetConnectionStatus}}
        #         }
        #     default {
        #         Get-CimInstance -Class win32_networkadapter -computer $computer | 
        #             Select Name, @{n="Status";e={Get-StatusFromValue $_.NetConnectionStatus}}
        #         }
        #     }
    }

Function Get-NICInfo
{
    #requires -modules NetAdapter
    $physicalNICs = [Ordered]@{} | Select-Object AllNICs,Physical,LoopBack1,LoopBack2,LB_Name,GatewayIndex,GatewayNIC,hyperVNIC
    $physicalNICs.AllNICs = Get-NetAdapter -IncludeHidden
    $physicalNICs.Physical = Get-NetAdapter -IncludeHidden -Physical
    $physicalNICs.LoopBack1 = Get-NetAdapter -IncludeHidden | Where-Object{ $_.InterfaceDescription -match 'Loopback'}
    $physicalNICs.LoopBack2 = (Get-WmiObject Win32_NetworkAdapter | Where-Object Name -match 'Loopback')
    $physicalNICs.LB_Name = ($physicalNICs.LoopBack1.Name,$physicalNICs.LoopBack2.Name -join ',')
    $physicalNICs.GatewayIndex = (Get-WmiObject -Class Win32_IP4RouteTable | Where-Object { $_.destination -eq '0.0.0.0' -and $_.mask -eq '0.0.0.0'} | Sort-Object -Property metric1).interfaceindex #| select nexthop, metric1, interfaceindex
    $physicalNICs.GatewayNIC = ($physicalNICs.AllNICs | Where-Object{ $_.ifIndex -eq $physicalNICs.GatewayIndex}).Name
    $physicalNICs.hyperVNIC = ($physicalNICs.AllNICs |  Where-Object{ $_.status -eq 'up'} | Where-Object{ $_.ifIndex -ne $physicalNICs.GatewayIndex} | Sort-Object -Property ifIndex | Select-Object -first 1).Name

    Return $physicalNICs
}

function Get-SubnetCalculator
{
    <#
        Created By: Matthew Sisson
            Created Date: 8/7/2019

        .PARAMETER IPAddress
            Enter the IP address with CIDR notation.

        .PARAMETER Big
            Doubles the size of the displayed form.

        .EXAMPLE
            Subnet-Calculator.ps1 -IPAddress 172.16.20.1/23
            or
            Subnet-Calculator.ps1 172.16.20.1/23
    #>
    [CmdletBinding()]
    param
    (
        [string]$IPAddress='172.16.0.1/16',
        [switch]$Big
    )

    #region  -  Get Favicon.ico
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $FavIcon = Test-Path -Path "favicon.ico" -PathType Leaf
        If ($FavIcon -eq $false) {Invoke-WebRequest "https://microsoft.com/favicon.ico" -OutFile "favicon.ico"}
    #endregion

    #region  -   Functions

        # Function to convert IP address string to binary
        function toBinary ($dottedDecimal)
        {
            $dottedDecimal.split(".") | ForEach-Object {$binary=$binary + $([convert]::toString($_,2).padleft(8,"0"))}
            return $binary
        }

        # Function to binary IP address to dotted decimal string
        function toDottedDecimal ($binary)
        {
            do {$dottedDecimal += "." + [string]$([convert]::toInt32($binary.substring($i,8),2)); $i+=8 } while ($i -le 24)
            return $dottedDecimal.substring(1)
        }

        # Function to convert CIDR format to binary
        function CidrToBin ($cidr)
        {
            if($cidr -le 32)
            {
                [Int[]]$array = (1..32)
                for($i=0;$i -lt $array.length;$i++)
                {
                    if($array[$i] -gt $cidr){$array[$i]="0"}else{$array[$i]="1"}
                }
                $cidr =$array -join ""
            }
            return $cidr
        }

        # Function to convert network mask to wildcard format
        function NetMasktoWildcard ($wildcard)
        {
            foreach ($bit in [char[]]$wildcard)
            {
                if ($bit -eq "1") { $wildcardmask += "0" }
                elseif ($bit -eq "0") { $wildcardmask += "1" }
            }
            return $wildcardmask
        }

        Function Subnet-Calc
        {
            # Check to see if the IP Address was entered in CIDR format.
            if ($IPAddress -like "*/*")
            {
                $CIDRIPAddress = $IPAddress
                $IPAddress = $CIDRIPAddress.Split("/")[0]
                $cidr = [convert]::ToInt32($CIDRIPAddress.Split("/")[1])
                if ($cidr -le 32 -and $cidr -ne 0)
                {
                    $ipBinary = toBinary $IPAddress
                    $smBinary = CidrToBin($cidr)
                    $Netmask = toDottedDecimal($smBinary)
                    $wildcardbinary = NetMasktoWildcard ($smBinary)
                }
                else
                {
                    Write-Warning "Subnet Mask is invalid!"
                    Exit
                }
            }
            else
            {    # Address was not entered in CIDR format.
                if (!$Netmask) { $Netmask = Read-Host "Netmask" }
                $ipBinary = toBinary $IPAddress
                if ($Netmask -eq "0.0.0.0")
                {
                    Write-Warning "Subnet Mask is invalid!"
                    Exit
                }
                else
                {
                    $smBinary = toBinary $Netmask
                    $wildcardbinary = NetMasktoWildcard ($smBinary)
                }
            }

            # First determine the location of the first zero in the subnet mask in binary (if any)
            $netBits=$smBinary.indexOf("0")

            # If there is a 0 found then the subnet mask is less than 32 (CIDR).
            if ($netBits -ne -1)
            {
                $cidr = $netBits
                #validate the subnet mask
                if (($smBinary.length -ne 32) -or 
                    ($smBinary.substring($netBits).contains("1") -eq $true))
                {
                    Write-Warning "Subnet Mask is invalid!"
                    Exit
                }

                # Validate the IP address
                if ($ipBinary.length -ne 32)
                {
                    Write-Warning "IP Address is invalid!"
                    Exit
                }

                #identify subnet boundaries
                $networkID = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"0"))
                $networkIDbinary = $ipBinary.substring(0,$netBits).padright(32,"0")
                $firstAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"0") + "1")
                $firstAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"0") + "1")
                $lastAddress = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(31,"1") + "0")
                $lastAddressBinary = $($ipBinary.substring(0,$netBits).padright(31,"1") + "0")
                $broadCast = toDottedDecimal $($ipBinary.substring(0,$netBits).padright(32,"1"))
                $broadCastbinary = $ipBinary.substring(0,$netBits).padright(32,"1")
                $wildcard = toDottedDecimal ($wildcardbinary)
                $Hostspernet = ([convert]::ToInt32($broadCastbinary,2) - [convert]::ToInt32($networkIDbinary,2)) - 1
            }
            else
            {    # Subnet mask is 32 (CIDR)
                # Validate the IP address
                if($ipBinary.length -ne 32)
                {
                    Write-Warning "IP Address is invalid!"
                    Exit
                }

                #identify subnet boundaries
                $networkID = toDottedDecimal $($ipBinary)
                $networkIDbinary = $ipBinary
                $firstAddress = toDottedDecimal $($ipBinary)
                $firstAddressBinary = $ipBinary
                $lastAddress = toDottedDecimal $($ipBinary)
                $lastAddressBinary = $ipBinary
                $broadCast = toDottedDecimal $($ipBinary)
                $broadCastbinary = $ipBinary
                $wildcard = toDottedDecimal ($wildcardbinary)
                $Hostspernet = 1
                $cidr = 32
            }

            $Global:IPAddress = $IPAddress
            $Global:Netmask = $Netmask
            $Global:Wildcard = $Wildcard
            $Global:NetworkID = $networkID
            $Global:CIDR = $cidr
            $Global:Broadcast = $broadCast
            $Global:FirstAddress = $firstAddress
            $Global:LastAddress = $lastAddress
            $Global:Hostspernet = $Hostspernet
            $Global:ipBinary = $ipBinary
            $Global:smBinary = $smBinary
            $Global:Wildcardbinary = $wildcardbinary
            $Global:networkIDbinary = $networkIDbinary
            $Global:firstAddressBinary = $firstAddressBinary
            $Global:lastAddressBinary = $lastAddressBinary
            $Global:broadCastbinary = $broadCastbinary

            return
        }
    #endregion

    #region  -   Base Form
        ### Form Colors ###
            $FormBackColor = "#222222"
            $FormForeColor = "#c5c9ca"
            $PanelBackColor = "#3b3f42"
            $TextboxBackColor = "#2b2b2b"
            $TextboxForeColor = "#c3803c"
            $ButtonBackColor = "#2e4058"

        ### Load Assembies ###
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Application]::EnableVisualStyles()
    #endregion

    #region  -   resize
        If ($Big.IsPresent -eq $false){ $xl = 0 }
        Else { $xl = -1 }
        
        $size = @{
            mainX = 480,(480*2)
            mainY = 585,(585*2)
            titleX = 466,(466*2)
            titleY = 86,(86*2)
            ipX = 466,(466*2)
            ipY = 86,(86*2)
            ipTxt = (125,20),((125*2),(20*2))
            ip2Txt = (125,25),((125*2),(25*2))
            hstTxt = (75,20),((75*2),(20*2))
            hst2Txt = (75,25),((75*2),(25*2))
            txtL = (466,125),((466*2),(125*2))
            rngTxt = (225,20),((225*2),(20*2))
            rng2Txt = (225,25),((225*2),(25*2))
            binXY = (466,215),((466*2),(215*2))
            binL = (50,20),((50*2),(20*2))
            binTlbl = (90,20),((90*2),(20*2))
            binTxt = (275,25),((275*2),(25*2))
            btnXY = (466,52),((466*2),(52*2))
            btnL = (130,20),((130*2),(20*2))
            ttlL = (466,40),((466*2),(40*2))
            }
        $locale = @{
            title = (4,0),((4*2),(0*2))    # Title Panel
            ttlLoc1 = (0,-5),((0*2),(-5*2))
            ttlLoc2 = (0,45),((0*2),(45*2))
            ipLoc1 = (50,92),((50*2),(92*2))   # IP Address
            ipLoc2 = (50,112),((50*2),(112*2))
            snLoc1 = (200,92),((200*2),(92*2))   # Subnet Mask
            snLoc2 = (200,112),((200*2),(112*2))
            cdrLoc1 = (350,92),((350*2),(92*2))   # CIDR
            cdrLoc2 = (350,112),((350*2),(112*2))
            txtPnlLoc = (4,150),((4*2),(150*2))   # Text Panel
            niLoc1 = (46,10),((46*2),(10*2))   # NetworkID
            niLoc2 = (46,30),((46*2),(30*2))
            wcLoc1 = (196,10),((196*2),(10*2))   # Wildcard Mask
            wcLoc2 = (196,30),((196*2),(30*2))
            hstLoc1 = (346,10),((346*2),(10*2))   # Hosts
            hstLoc2 = (346,30),((346*2),(30*2))
            bcLoc1 = (46,65),((46*2),(65*2))   # Broadcast
            bcLoc2 = (46,85),((46*2),(85*2))
            hstrLoc1 = (196,65),((196*2),(65*2))   # Host Range
            hstrLoc2 = (196,85),((196*2),(85*2))
            bPnlLoc1 = (4,280),((4*2),(280*2))   # Binary Panel
            bPnlLoc2 = (0,0),((0*2),(0*2))
            bin1Loc1 = (50,21),((50*2),(21*2))   # Binary IP Address
            bin1Loc2 = (146,20),((146*2),(20*2))
            bin2Loc1 = (50,51),((50*2),(51*2))   # Binary Netmask
            bin2Loc2 = (146,50),((146*2),(50*2))
            bin3Loc1 = (50,81),((50*2),(81*2))   # Binary Wildcard
            bin3Loc2 = (146,80),((146*2),(80*2))
            bin4Loc1 = (50,111),((50*2),(111*2))   # Binary HostMin
            bin4Loc2 = (146,110),((146*2),(110*2))
            bin5Loc1 = (50,141),((50*2),(141*2))   # Binary HostMax
            bin5Loc2 = (146,140),((146*2),(140*2))
            bin6Loc1 = (50,171),((50*2),(171*2))   # Binary Broadcast
            bin6Loc2 = (146,170),((146*2),(170*2))
            btnLoc1 = (4,500),((4*2),(500*2))   # Button Panel
            btnLoc2 = (330,30),((330*2),(30*2))
            cbtnLoc1 = (195,15),((195*2),(15*2))   # Close Button
            }
    #endregion

    #region  -   Form 
        $Form = New-Object system.Windows.Forms.Form
        $Form.Text = "Subnet Calculator"
        $Form.FormBorderStyle = "FixedDialog"
        $Form.TopMost  = $True
        $Form.MinimizeBox  = $False
        $Form.MaximizeBox  = $False
        $Form.StartPosition = "CenterScreen"
        $Font = New-Object System.Drawing.Font("Segoe UI Semibold",10)
        $BinaryFont = New-Object System.Drawing.Font("Consolas",10)
        $Form.Font = $Font
        $Form.Width = [int]$size.mainX[$xl]
        $Form.Height = [int]$size.mainY[$xl]
        $Form.AutoScroll = $True
        $Form.AutoSize = $true
        $Form.AutoSizeMode = "GrowOnly"
        $Form.TopMost = $True
        $Form.Opacity = 1 #0.95
        $Form.BackColor = $FormBackColor
        $Form.ForeColor = $FormForeColor
        $Form.ShowInTaskbar = $False
        #$Image = [system.drawing.image]::FromFile("bg.png")
        #$Form.BackgroundImage = $Image
        $Form.BackgroundImageLayout = "Center"
        $Icon = New-Object System.Drawing.Icon ("favicon.ico")
        $Form.Icon = $Icon
    #endregion

    #region  -   Title Panel
        $TitlePanel = New-Object Windows.Forms.Panel
        $TitlePanel.Location = '4,0'
        $TitlePanel.size = "$($size.titleX[$xl]),$($size.titleY[$xl])" 
        $TitlePanel.BackColor = $PanelBackColor
        $TitlePanel.ForeColor = "#fffff" #$FormForeColor
        $Form.Controls.Add($TitlePanel)
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 0,-5
        $label.Size = New-Object Drawing.Point $size.btnXY[$xl]
        $label.BackColor = "Transparent"
        $label.ForeColor = "#737373"
        $label.Text = "CONTOSO"
        $label.TextAlign = "TopCenter"
        $label.add_Click({[system.Diagnostics.Process]::start("https://microsoft.com")})
        $TitleFont = New-Object System.Drawing.Font("Segoe UI Semibold",32)
        $label.Font = $TitleFont
        $TitlePanel.Controls.Add($label)
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 0,45
        $label.Size = New-Object Drawing.Point $size.ttlL[$xl]
        $label.BackColor = "Transparent"
        $label.ForeColor = "#57b1fd"
        $label.Text = "Subnet Calculator"
        $label.TextAlign = "TopCenter"
        $label.add_Click({[system.Diagnostics.Process]::start("https://microsoft.com")})
        $TitleFont = New-Object System.Drawing.Font("Segoe UI Semibold",18)
        $label.Font = $TitleFont
        $TitlePanel.Controls.Add($label)
    #endregion

    #region  -   IP Address
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,92
        $label.Size = New-Object Drawing.Point $size.ipTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "IPv4 Address"
        $Form.Controls.Add($label)
        $FormIPAddress = New-Object System.Windows.Forms.TextBox
        $FormIPAddress.Location = New-Object System.Drawing.Point 50,112
        $FormIPAddress.Size = New-Object System.Drawing.Point $size.ipTxt[$xl]
        $FormIPAddress.text = $IPAddress
        $FormIPAddress.TabIndex = 1
        $FormIPAddress.BackColor = $TextboxBackColor
        $FormIPAddress.ForeColor = $TextboxForeColor
        $FormIPAddress.BorderStyle = "FixedSingle"
        $Form.Controls.Add($FormIPAddress)
        $FormIPAddress.Add_LostFocus({
            $IPAddress = $FormIPAddress.text
            $NetMask = $FormSubnet.text
            $CIDR = $FormCIDR.text

            Subnet-Calc

            $FormIPAddress.text = $Global:IPAddress
            $FormSubnet.text = $Global:NetMask
            $FormCIDR.text = $Global:CIDR
            $FormNetworkID.text = $Global:NetworkID
            $FormWildcard.text = $Global:Wildcard
            $FormHosts.text = $Global:Hostspernet
            $FormHostRange.text = "$Global:FirstAddress - $Global:LastAddress"
            $FormBroadcast.text = $Global:Broadcast
            $BinaryAddress.text = $Global:ipBinary
            $BinaryNetmask.text = $Global:smBinary
            $BinaryWildcard.text = $Global:wildcardbinary
            $BinaryHostMin.text = $Global:firstAddressBinary
            $BinaryHostMax.text = $Global:lastAddressBinary
            $BinaryBroadcast.text = $Global:broadCastbinary
        })
    #endregion

    #region  -   Subnet Mask
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 200,92
        $label.Size = New-Object Drawing.Point $size.ipTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Subnet Mask"
        $Form.Controls.Add($label)
        $FormSubnet = New-Object System.Windows.Forms.TextBox
        $FormSubnet.Location = New-Object System.Drawing.Point 200,112
        $FormSubnet.Size = New-Object System.Drawing.Point $size.ipTxt[$xl]
        $FormSubnet.text = $NetMask
        $FormSubnet.TabIndex = 2
        $FormSubnet.BackColor = $TextboxBackColor
        $FormSubnet.ForeColor = $TextboxForeColor
        $FormSubnet.BorderStyle = "FixedSingle"
        $Form.Controls.Add($FormSubnet)
        $FormSubnet.Add_LostFocus({
            $IPAddress = $FormIPAddress.text
            $NetMask = $FormSubnet.text
            $CIDR = $FormCIDR.text

            Subnet-Calc

            $FormIPAddress.text = $Global:IPAddress
            $FormSubnet.text = $Global:NetMask
            $FormCIDR.text = $Global:CIDR
            $FormNetworkID.text = $Global:NetworkID
            $FormWildcard.text = $Global:Wildcard
            $FormHosts.text = $Global:Hostspernet
            $FormHostRange.text = "$Global:FirstAddress - $Global:LastAddress"
            $FormBroadcast.text = $Global:Broadcast
            $BinaryAddress.text = $Global:ipBinary
            $BinaryNetmask.text = $Global:smBinary
            $BinaryWildcard.text = $Global:wildcardbinary
            $BinaryHostMin.text = $Global:firstAddressBinary
            $BinaryHostMax.text = $Global:lastAddressBinary
            $BinaryBroadcast.text = $Global:broadCastbinary
        })
    #endregion

    #region  -   CIDR
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 350,92
        $label.Size = New-Object Drawing.Point $size.hstTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Mask Bits"
        $Form.Controls.Add($label)
        $FormCIDR = New-Object System.Windows.Forms.TextBox
        $FormCIDR.Location = New-Object System.Drawing.Point 350,112
        $FormCIDR.Size = New-Object System.Drawing.Point $size.hstTxt[$xl]
        $FormCIDR.text = $CIDR
        $FormCIDR.TabIndex = 3
        $FormCIDR.BackColor = $TextboxBackColor
        $FormCIDR.ForeColor = $TextboxForeColor
        $FormCIDR.BorderStyle = "FixedSingle"
        $Form.Controls.Add($FormCIDR)
        $FormCIDR.Add_LostFocus({
            $IPAddress = $FormIPAddress.text
            $NetMask = $FormSubnet.text
            $CIDR = $FormCIDR.text

            $IPAddress = $IPAddress+"/"+$CIDR

            Subnet-Calc

            $FormIPAddress.text = $Global:IPAddress
            $FormSubnet.text = $Global:NetMask
            $FormCIDR.text = $Global:CIDR
            $FormNetworkID.text = $Global:NetworkID
            $FormWildcard.text = $Global:Wildcard
            $FormHosts.text = $Global:Hostspernet
            $FormHostRange.text = "$Global:FirstAddress - $Global:LastAddress"
            $FormBroadcast.text = $Global:Broadcast
            $BinaryAddress.text = $Global:ipBinary
            $BinaryNetmask.text = $Global:smBinary
            $BinaryWildcard.text = $Global:wildcardbinary
            $BinaryHostMin.text = $Global:firstAddressBinary
            $BinaryHostMax.text = $Global:lastAddressBinary
            $BinaryBroadcast.text = $Global:broadCastbinary
        })
    #endregion

    #region  -   Text Panel
        $TxtPanel = New-Object Windows.Forms.Panel
        $TxtPanel.Location = '4,150'
        $TxtPanel.size = "$($size.txtL[$xl] -join ',')"
        $TxtPanel.BackColor = $PanelBackColor
        $Form.Controls.Add($TxtPanel)
    #endregion

    #region  -   NetworkID
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 46,10
        $label.Size = New-Object Drawing.Point $size.ipTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Network"
        $TxtPanel.Controls.Add($label)
        $FormNetworkID = New-Object System.Windows.Forms.Label
        $FormNetworkID.Location = New-Object System.Drawing.Point 46,30
        $FormNetworkID.Size = New-Object System.Drawing.Point $size.ip2Txt[$xl]
        $FormNetworkID.BackColor = $TextboxBackColor
        $FormNetworkID.ForeColor = $FormForeColor
        $FormNetworkID.BorderStyle = "FixedSingle"
        $FormNetworkID.text = $NetworkID
        $FormNetworkID.TextAlign = "MiddleCenter"
        $TxtPanel.Controls.Add($FormNetworkID)
    #endregion

    #region  -   Wildcard Mask
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 196,10
        $label.Size = New-Object Drawing.Point $size.ipTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Wildcard Mask"
        $TxtPanel.Controls.Add($label)
        $FormWildcard = New-Object System.Windows.Forms.Label
        $FormWildcard.Location = New-Object System.Drawing.Point 196,30
        $FormWildcard.Size = New-Object System.Drawing.Point $size.ip2Txt[$xl]
        $FormWildcard.BackColor = $TextboxBackColor
        $FormWildcard.ForeColor = $FormForeColor
        $FormWildcard.BorderStyle = "FixedSingle"
        $FormWildcard.text = $Wildcard
        $FormWildcard.TextAlign = "MiddleCenter"
        $TxtPanel.Controls.Add($FormWildcard)
    #endregion

    #region  -   Hosts
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 346,10
        $label.Size = New-Object Drawing.Point $size.hstTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Hosts"
        $TxtPanel.Controls.Add($label)
        $FormHosts = New-Object System.Windows.Forms.Label
        $FormHosts.Location = New-Object System.Drawing.Point 346,30
        $FormHosts.Size = New-Object System.Drawing.Point $size.hst2Txt[$xl]
        $FormHosts.BackColor = $TextboxBackColor
        $FormHosts.ForeColor = $FormForeColor
        $FormHosts.BorderStyle = "FixedSingle"
        $FormHosts.text = $Hostspernet
        $FormHosts.TextAlign = "MiddleCenter"
        $TxtPanel.Controls.Add($FormHosts)
    #endregion

    #region  -   Broadcast
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 46,65
        $label.Size = New-Object Drawing.Point $size.ipTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Broadcast Address"
        $TxtPanel.Controls.Add($label)
        $FormBroadcast = New-Object System.Windows.Forms.Label
        $FormBroadcast.Location = New-Object System.Drawing.Point 46,85
        $FormBroadcast.Size = New-Object System.Drawing.Point $size.ip2Txt[$xl]
        $FormBroadcast.BackColor = $TextboxBackColor
        $FormBroadcast.ForeColor = $FormForeColor
        $FormBroadcast.BorderStyle = "FixedSingle"
        $FormBroadcast.text = $Broadcast
        $FormBroadcast.TextAlign = "MiddleCenter"
        $TxtPanel.Controls.Add($FormBroadcast)
    #endregion

    #region  -   Host Range
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 196,65
        $label.Size = New-Object Drawing.Point $size.rngTxt[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Host Address Range"
        $TxtPanel.Controls.Add($label)
        $FormHostRange = New-Object System.Windows.Forms.Label
        $FormHostRange.Location = New-Object System.Drawing.Point 196,85
        $FormHostRange.Size = New-Object System.Drawing.Point $size.rng2Txt[$xl]
        $FormHostRange.BackColor = $TextboxBackColor
        $FormHostRange.ForeColor = $FormForeColor
        $FormHostRange.BorderStyle = "FixedSingle"
        $FormHostRange.text = "$FirstAddress - $LastAddress"
        $FormHostRange.TextAlign = "MiddleCenter"
        $TxtPanel.Controls.Add($FormHostRange)
    #endregion

    #region  -   Binary Panel
        $BinaryPanel = New-Object Windows.Forms.Panel
        $BinaryPanel.Location = '4,280'
        $BinaryPanel.size = "$($size.binXY[$xl] -join ',')"
        $BinaryPanel.BackColor = $PanelBackColor
        $Form.Controls.Add($BinaryPanel)
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 0,0
        $label.Size = New-Object Drawing.Point $size.binL[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Binary"
        $BinaryPanel.Controls.Add($label)
    #endregion

    #region  -   Binary IP Address
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,21
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "IP Address"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryAddress = New-Object System.Windows.Forms.Label
        $BinaryAddress.Location = New-Object System.Drawing.Point 146,20
        $BinaryAddress.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryAddress.BackColor = $TextboxBackColor
        $BinaryAddress.ForeColor = $FormForeColor
        $BinaryAddress.BorderStyle = "FixedSingle"
        $BinaryAddress.text = $ipBinary
        $BinaryAddress.Font = $BinaryFont
        $BinaryAddress.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryAddress)
    #endregion

    #region  -   Binary Netmask
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,51
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Netmask"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryNetmask = New-Object System.Windows.Forms.Label
        $BinaryNetmask.Location = New-Object System.Drawing.Point 146,50
        $BinaryNetmask.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryNetmask.BackColor = $TextboxBackColor
        $BinaryNetmask.ForeColor = $FormForeColor
        $BinaryNetmask.BorderStyle = "FixedSingle"
        $BinaryNetmask.text = $smBinary
        $BinaryNetmask.Font = $BinaryFont
        $BinaryNetmask.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryNetmask)
    #endregion

    #region  -   Binary Wildcard
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,81
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Wildcard"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryWildcard = New-Object System.Windows.Forms.Label
        $BinaryWildcard.Location = New-Object System.Drawing.Point 146,80
        $BinaryWildcard.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryWildcard.BackColor = $TextboxBackColor
        $BinaryWildcard.ForeColor = $FormForeColor
        $BinaryWildcard.BorderStyle = "FixedSingle"
        $BinaryWildcard.text = $wildcardbinary
        $BinaryWildcard.Font = $BinaryFont
        $BinaryWildcard.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryWildcard)
    #endregion

    #region  -   Binary HostMin
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,111
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "First Address"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryHostMin = New-Object System.Windows.Forms.Label
        $BinaryHostMin.Location = New-Object System.Drawing.Point 146,110
        $BinaryHostMin.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryHostMin.BackColor = $TextboxBackColor
        $BinaryHostMin.ForeColor = $FormForeColor
        $BinaryHostMin.BorderStyle = "FixedSingle"
        $BinaryHostMin.text = $firstAddressBinary
        $BinaryHostMin.Font = $BinaryFont
        $BinaryHostMin.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryHostMin)
    #endregion

    #region  -   Binary HostMax
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,141
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Last Address"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryHostMax = New-Object System.Windows.Forms.Label
        $BinaryHostMax.Location = New-Object System.Drawing.Point 146,140
        $BinaryHostMax.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryHostMax.BackColor = $TextboxBackColor
        $BinaryHostMax.ForeColor = $FormForeColor
        $BinaryHostMax.BorderStyle = "FixedSingle"
        $BinaryHostMax.text = $lastAddressBinary
        $BinaryHostMax.Font = $BinaryFont
        $BinaryHostMax.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryHostMax)
    #endregion

    #region  -   Binary Broadcast
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 50,171
        $label.Size = New-Object Drawing.Point $size.binTlbl[$xl]
        $label.BackColor = "Transparent"
        $label.text = "Broadcast"
        $label.TextAlign = "MiddleRight"
        $BinaryPanel.Controls.Add($label)
        $BinaryBroadcast = New-Object System.Windows.Forms.Label
        $BinaryBroadcast.Location = New-Object System.Drawing.Point 146,170
        $BinaryBroadcast.Size = New-Object System.Drawing.Point $size.binTxt[$xl]
        $BinaryBroadcast.BackColor = $TextboxBackColor
        $BinaryBroadcast.ForeColor = $FormForeColor
        $BinaryBroadcast.BorderStyle = "FixedSingle"
        $BinaryBroadcast.text = $broadCastbinary
        $BinaryBroadcast.Font = $BinaryFont
        $BinaryBroadcast.TextAlign = "MiddleCenter"
        $BinaryPanel.Controls.Add($BinaryBroadcast)
    #endregion

    #region  -   Button Panel
        $ButtonPanel = New-Object Windows.Forms.Panel
        $ButtonPanel.Location = '4,500'
        $ButtonPanel.size = "$($size.btnXY[$xl] -join ',')"
        $ButtonPanel.TabIndex = 0
        $ButtonPanel.BackColor = $PanelBackColor
        $Form.Controls.Add($ButtonPanel)
        $label = New-Object Windows.Forms.Label
        $label.Location = New-Object Drawing.Point 330,30
        $label.Size = New-Object Drawing.Point $size.btnL[$xl]
        $label.BackColor = "Transparent"
        $label.ForeColor = "#57b1fd"
        $label.Text = "microsoft.com"
        $label.TextAlign = "MiddleRight"
        $label.add_Click({[system.Diagnostics.Process]::start("https://microsoft.com")})
        $ButtonPanel.Controls.Add($label)
    #endregion

    #region  -   Close Button
        $Closebutton = New-Object Windows.Forms.Button
        $Closebutton.text = "Close"
        $Closebutton.Location = New-Object Drawing.Point 195,15
        $Closebutton.TabIndex = 0
        $Closebutton.FlatStyle = "Flat"
        $Closebutton.BackColor = $ButtonBackColor
        $ButtonPanel.Controls.Add($Closebutton)
        $CloseButton.Add_Click({$Form.Close()})
    #endregion

    #region  -   Show Form
        Subnet-Calc
        $FormIPAddress.text = $Global:IPAddress
        $FormSubnet.text = $Global:NetMask
        $FormCIDR.text = $Global:CIDR
        $FormNetworkID.text = $Global:NetworkID
        $FormWildcard.text = $Global:Wildcard
        $FormHosts.text = $Global:Hostspernet
        $FormHostRange.text = "$Global:FirstAddress - $Global:LastAddress"
        $FormBroadcast.text = $Global:Broadcast
        $BinaryAddress.text = $Global:ipBinary
        $BinaryNetmask.text = $Global:smBinary
        $BinaryWildcard.text = $Global:wildcardbinary
        $BinaryHostMin.text = $Global:firstAddressBinary
        $BinaryHostMax.text = $Global:lastAddressBinary
        $BinaryBroadcast.text = $Global:broadCastbinary
        $Form.ShowDialog() | Out-Null
    #endregion
}
# Subnet-Calculator -IPAddress 10.114.187.1/23 -Big
Set-Alias -Name Subnet-Calculator -Value Get-SubnetCalculator

function Find-DHCPServer
{
    ipconfig /all | find /i "DHCP Server"
}

Function Get-WifiPassword
{
    (netsh wlan show profiles) | Select-String "\:(.+)$" |  
        ForEach-Object{$name=$_.Matches.Groups[1].Value.Trim(); $_} | 
        ForEach-Object{(netsh wlan show profile name="$name" key=clear)} | 
            Select-String "Key Content\W+\:(.+)$" | 
            ForEach-Object{$pass=$_.Matches.Groups[1].Value.Trim(); $_} | 
                ForEach-Object{[PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }} | 
                Format-Table -AutoSize
}


function Test-WlanMetered
{
    Param ([switch]$Legacy)
    Switch ($Legacy){
        $true  {
            $wlan = (netsh wlan show interfaces | select-string "SSID" | select-string -NotMatch "BSSID")
            if ($wlan) {
                $ssid = (($wlan) -split ":" )[1].Trim() -replace '"'
                $cost = ((netsh wlan show profiles $ssid | select-string "Cost|Kosten" ) -split ":")[2].Trim() -replace '"'
                return ($cost -ne "unrestricted" -and $cost -ne "Uneingeschr�nkt" -and $cost -ne 'Uneingeschr"nkt')
                }
            else { $false }
            }
        $False {
            [void][Windows.Networking.Connectivity.NetworkInformation, Windows, ContentType = WindowsRuntime]
            $cost = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile().GetConnectionCost()
            $cost.ApproachingDataLimit -or $cost.OverDataLimit -or $cost.Roaming -or $cost.BackgroundDataUsageRestricted -or ($cost.NetworkCostType -ne "Unrestricted")
            }
        }
}   

 Function Show-WifiProfiles
{
    Param ( [Switch]$Pwd )
    $profiles = netsh wlan show profiles | Select-String ":(.{1,})$" | ForEach-Object { ($_.Line -split ': ')[-1] } 
    If ($Pwd)
    {
        Foreach ($profile in $profiles)
        {
            $password = (@(netsh wlan show profile name="$profile" key=clear) -like '*Key Content*' -split ': ')[-1]
            [PSCustomObject]@{
                Profile = $profile
                Password = $password
            }
        }  
    }
    Else { $Profiles }
}

Function Get-CurrentRDPPort
{
    (get-item 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').GetValue('PortNumber')
}

function ConvertFrom-DecimalIPtoBinary ([string]$DecimalIPAddress){
    #Create an empty variable
    $Binary  = $null
 
    #Extract octets from IP Address
    $Octets = $DecimalIPAddress.Split('.')
 
    #Convert each octet to Binary and add to the variable $Binary
        # Here we use ToString with '2' as the base, 2 means binary
        # We are also using padleft to make sure each octet is 8 bits long with leading zeros if needed
    $Octets | ForEach-Object {$Binary += ([convert]::ToString($_,2)).PadLeft(8,"0")}
 
    return $Binary
}

Function Get-NicGuid
{
    # Display GUIDs for Network Card(s)
    Param ([switch]$useWMI)
    If ($useOld.IsPresent -eq $true)
    {
        Get-WmiObject  Win32_NetworkAdapterConfiguration -filter 'IPEnabled=True' | 
            ForEach-Object{$_.GetRelated('Win32_NetworkAdapter')}| Select-Object Description,GUID
    }
    Else
    {
        Get-NetAdapter | Select-Object InterfaceDescription, InterfaceGuid
    }
}

Function Repair-irpStackSize
{
    # Fix network speed (Windows)
    Param
    (
    $regPath = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
    $regValue = 32,
    $keyName = 'IRPStackSize',
    [switch]$usecmd
    )
    Switch ($usecmd.IsPresent){
        $true  { & reg add "HKEY_Local_Machine\$regPath\" /v $keyName /t REG_DWORD /d $regValue }
        $false { New-ItemProperty -Path "HKLM:\$regPath" -Name $keyName -Value $regValue -PropertyType 'DWORD' -Force }
        }
}
Set-Alias -Name Fix-irpStackSize -Value Repair-irpStackSize

Function Get-WanIpAddress
{
    (New-Object System.Net.WebClient).DownloadString('https://api.ipify.org')
}
