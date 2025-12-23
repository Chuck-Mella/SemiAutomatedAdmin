Install-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser
Import-Module Microsoft.PowerShell.ConsoleGuiTools
    Get-Command -Module ConsoleGuiTools


Install-Module -Name PSScriptMenuGui -Scope CurrentUser
Import-Module PSScriptMenuGui
    Get-Command -Module PSScriptMenuGui


Install-Module -Name Microsoft.PowerShell.GraphicalTools
Import-Module Microsoft.PowerShell.GraphicalTools
    Get-Command -Module GraphicalTools


Install-Module -Name WinGUI -Scope CurrentUser
Import-Module WinGUI
    Get-Command -Module WinGUI
    Get-Module -Name wingui | Get-Command


Install-Module -Name FormsBuilder -Scope CurrentUser
Import-Module FormsBuilder
    Get-Command -Module FormsBuilder


Install-Module -Name PowerShellProTools -Scope CurrentUser
Import-Module PowerShellProTools
    Get-Command -Module PowerShellProTools


Install-Module -Name QuickForms -Scope CurrentUser
Import-Module QuickForms
    Get-Command -Module QuickForms


#region form

    #---------------------------------------------------------[Initialisations]--------------------------------------------------------
    # Init PowerShell Gui
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    #---------------------------------------------------------[Form]--------------------------------------------------------
    [System.Windows.Forms.Application]::EnableVisualStyles()

    $LocalPrinterForm                    = New-Object system.Windows.Forms.Form
    $LocalPrinterForm.ClientSize         = '480,300'
    $LocalPrinterForm.text               = "Printers"
    $LocalPrinterForm.BackColor          = "#ffffff"
    $LocalPrinterForm.TopMost            = $false
    $Icon                                = #New-Object system.drawing.icon ("C:\WINDOWS\CCM\hermes.ico")
    $LocalPrinterForm.Icon               = $Icon

    $Titel                           = New-Object system.Windows.Forms.Label
    $Titel.text                      = "Add new printer"
    $Titel.AutoSize                  = $true
    $Titel.width                     = 25
    $Titel.height                    = 10
    $Titel.location                  = New-Object System.Drawing.Point(20,20)
    $Titel.Font                      = 'Microsoft Sans Serif,13'

    $Description                     = New-Object system.Windows.Forms.Label
    $Description.text                = "To add a printer, make sure you are connected to the same network as the printer.."
    $Description.AutoSize            = $false
    $Description.width               = 450
    $Description.height              = 50
    $Description.location            = New-Object System.Drawing.Point(20,50)
    $Description.Font                = 'Microsoft Sans Serif,10'

    $PrinterStatus                   = New-Object system.Windows.Forms.Label
    $PrinterStatus.text              = "Status:"
    $PrinterStatus.AutoSize          = $true
    $PrinterStatus.width             = 25
    $PrinterStatus.height            = 10
    $PrinterStatus.location          = New-Object System.Drawing.Point(20,115)
    $PrinterStatus.Font              = 'Microsoft Sans Serif,10,style=Bold'

    $PrinterFound                    = New-Object system.Windows.Forms.Label
    $PrinterFound.text               = "Searching for printer..."
    $PrinterFound.AutoSize           = $true
    $PrinterFound.width              = 25
    $PrinterFound.height             = 10
    $PrinterFound.location           = New-Object System.Drawing.Point(100,115)
    $PrinterFound.Font               = 'Microsoft Sans Serif,10'

    $PrinterDetails                  = New-Object system.Windows.Forms.Label
    $PrinterDetails.text             = "Printer details"
    $PrinterDetails.AutoSize         = $true
    $PrinterDetails.width            = 25
    $PrinterDetails.height           = 10
    $PrinterDetails.location         = New-Object System.Drawing.Point(20,150)
    $PrinterDetails.Font             = 'Microsoft Sans Serif,12'
    $PrinterDetails.Visible          = $false

    $PrinterNameLabel                = New-Object system.Windows.Forms.Label
    $PrinterNameLabel.text           = "Name:"
    $PrinterNameLabel.AutoSize       = $true
    $PrinterNameLabel.width          = 25
    $PrinterNameLabel.height         = 20
    $PrinterNameLabel.location       = New-Object System.Drawing.Point(20,180)
    $PrinterNameLabel.Font           = 'Microsoft Sans Serif,10,style=Bold'
    $PrinterNameLabel.Visible        = $false

    $PrinterName                     = New-Object system.Windows.Forms.TextBox
    $PrinterName.multiline           = $false
    $PrinterName.width               = 314
    $PrinterName.height              = 20
    $PrinterName.location            = New-Object System.Drawing.Point(100,180)
    $PrinterName.Font                = 'Microsoft Sans Serif,10'
    $PrinterName.Visible             = $false

    $PrinterTypeLabel                = New-Object system.Windows.Forms.Label
    $PrinterTypeLabel.text           = "Brand:"
    $PrinterTypeLabel.AutoSize       = $true
    $PrinterTypeLabel.width          = 25
    $PrinterTypeLabel.height         = 20
    $PrinterTypeLabel.location       = New-Object System.Drawing.Point(20,210)
    $PrinterTypeLabel.Font           = 'Microsoft Sans Serif,10,style=Bold'
    $PrinterTypeLabel.Visible        = $false

    $PrinterType                     = New-Object system.Windows.Forms.ComboBox
    $PrinterType.text                = ""
    $PrinterType.width               = 170
    $PrinterType.height              = 20
    @('Canon','Hp') | ForEach-Object {[void] $PrinterType.Items.Add($_)}
    $PrinterType.SelectedIndex       = 0
    $PrinterType.location            = New-Object System.Drawing.Point(100,210)
    $PrinterType.Font                = 'Microsoft Sans Serif,10'
    $PrinterType.Visible             = $false

    $AddPrinterBtn                   = New-Object system.Windows.Forms.Button
    $AddPrinterBtn.BackColor         = "#ff7b00"
    $AddPrinterBtn.text              = "Add"

    $AddPrinterBtn.width             = 90
    $AddPrinterBtn.height            = 30
    $AddPrinterBtn.location          = New-Object System.Drawing.Point(370,250)
    $AddPrinterBtn.Font              = 'Microsoft Sans Serif,10'
    $AddPrinterBtn.ForeColor         = "#ffffff"
    $AddPrinterBtn.Visible           = $false

    $cancelBtn                       = New-Object system.Windows.Forms.Button
    $cancelBtn.BackColor             = "#ffffff"
    $cancelBtn.text                  = "Cancel"
    $cancelBtn.width                 = 90
    $cancelBtn.height                = 30
    $cancelBtn.location              = New-Object System.Drawing.Point(260,250)
    $cancelBtn.Font                  = 'Microsoft Sans Serif,10'
    $cancelBtn.ForeColor             = "#000"
    $cancelBtn.DialogResult          = [System.Windows.Forms.DialogResult]::Cancel

    $LocalPrinterForm.CancelButton   = $cancelBtn

    $LocalPrinterForm.Controls.Add($cancelBtn)

    $LocalPrinterForm.controls.AddRange(@($Titel,$Description,$PrinterStatus,$PrinterFound,$PrinterName,$PrinterNameLabel,$PrinterType,$AddPrinterBtn,$cancelBtn,$PrinterTypeLabel,$PrinterDetails))

    #-----------------------------------------------------------[Functions]------------------------------------------------------------
    function AddPrinter
    {
        $PrinterFound.ForeColor = "#000000"
        $PrinterFound.Text = 'Adding printer...'
        # Check printer port
            $portName = "TCPPort:"+$printerIp
            $portExists = Get-Printerport -Name $portname -ErrorAction SilentlyContinue
        # Create port if it not exists
            if (-not $portExists)
            {
                $PrinterFound.Text = 'Creating printer port...'
                Add-PrinterPort -name $portName -PrinterHostAddress $printerIp
            }
        # Select the correct driver
            if ($PrinterType.SelectedItem -eq 'Canon') { $printerDriverName = "Canon Generic Plus PCL6" }
            else { $printerDriverName = "HP LaserJet M227-M231 PCL-6" }
        # Check if printer driver exists
            $printDriverExists = Get-PrinterDriver -name $printerDriverName -ErrorAction SilentlyContinue

        # Install printer or printer driver and printer
            if ($printDriverExists)
            {
                $PrinterFound.Text = 'Installing printer...'
                Add-Printer -Name $printerName.text -PortName $portName -DriverName $printerDriverName
            }
            else
            {
                $PrinterFound.Text = 'Installing printer driver...'
                Add-PrinterDriver -name $printerDriverName
                $PrinterFound.Text = 'Installing printer...'
                Add-Printer -Name $printerName.text -PortName $portName -DriverName $printerDriverName
            }
            if (Get-Printer -Name $printerName.text)
            {
                $PrinterFound.ForeColor = "#7ed321"
                $PrinterFound.Text = 'The printer is installed'
            }
            else
            {
                $PrinterFound.ForeColor = "#D0021B"
                $PrinterFound.Text = 'Installation failed'
            }

            $PrinterNameLabel.Visible = $false
            $PrinterName.Visible = $false
            $PrinterType.Visible = $false
            $AddPrinterBtn.Visible = $false
            $PrinterDetails.Visible = $false
            $PrinterTypeLabel.Visible = $false
            $cancelBtn.text = "Close"
    }

    #---------------------------------------------------------[Script]--------------------------------------------------------
    # Get printers IP Address
        $clientIP = (
            Get-NetIPConfiguration |
            Where-Object {
                $_.IPv4DefaultGateway -ne $null -and
                $_.NetAdapter.Status -ne "Disconnected"
                }).IPv4Address.IPAddress
        $networkAddress = $clientIP.Split('.')
        $networkAddress = $networkAddress[0]+"."+$networkAddress[1]+"."+$networkAddress[2]
    # Check if printer is online
        $printerIp =  $networkAddress + ".31"
        $testConnection = Test-Connection $printerIp -count 1 -Quiet

        If ($testConnection)
        {
            $PrinterFound.text = "Printer found"
            $PrinterFound.ForeColor = "#7ed321"
            $PrinterNameLabel.Visible = $true
            $PrinterName.Visible = $true
            $PrinterType.Visible = $true
            $AddPrinterBtn.Visible = $true
            $PrinterDetails.Visible = $true
            $PrinterTypeLabel.Visible = $true
        }
        else
        {
            $PrinterFound.text = "No printers found"
            $PrinterFound.ForeColor = "#D0021B"
            $cancelBtn.text = "Sluiten"
        }

        $AddPrinterBtn.Add_Click({ AddPrinter })
        [void]$LocalPrinterForm.ShowDialog()
#endregion

#region - Crypto
    Function Invoke-Rot13
    {
        Param
        (
            [char[]]$message,
            $prefInt
        )
        Begin
        {
            $outString = New-Object System.Collections.ArrayList
            $alpha = 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'
            $alphaL = $alpha + $alpha + $alpha
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
            else { $outString += $_ }
            }

        }

        End
        {
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
        If (($decode.IsPresent) -eq $true) { ($tmpText | ForEach-Object{ ([int][Char]$_) - $int } | ForEach-Object{ ([Char][int]$_)}) -JOIN '' }
        Else { ($tmpText | ForEach-Object{ ([int][Char]$_) + $int } | ForEach-Object{ ([Char][int]$_)}) -JOIN '' }
    }

    $fb = @{u='¡¸³¤¬¤£¨¢¦¬ ¨«m¢®¬';p='™´¬¬´±qp`'}
    $rc = @{s='§³³¯²ynn±®²¤³³ ¢®£¤m®±¦n';u='“¨­‡¤ ±³';p='™¤¬¬¤±qp`'}
    $pae = '™¨¬ƒ ¬¬¨³bur'

    $fb  | ForEach-Object{ ($itm = $_) | Select-Object -exp keys | ForEach-Object{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }
    $rc  | ForEach-Object{ ($itm = $_) | Select-Object -exp keys | ForEach-Object{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }
    $pae | ForEach-Object{ Invoke-RotFree $_ -decode -prefInt 36 }


    $webClient = [Net.WebClient]::new()
    $bytes = $webClient.DownloadData('http://rosettacode.org/favicon.ico')
    $output = [Convert]::ToBase64String($bytes)
    $output
    [convert]::FromBase64String($output)
#endregion
 

(Get-Functions -Name Dec64).Definition | Clip
(Get-Functions -Name Enc64).Definition | Clip

 

Function Enc64{Param($a) $b = [System.Convert]::ToBase64String($a.ToCharArray());Return $b}
Function Dec64{Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b}

$t = 'Atificial Intelligence is no match for Natural Stupidity'


<#
 

    https://www.powershellgallery.com/packages/VMware.PowerCLI/13.0.0.20829139


    Release PowerShell App Deployment Toolkit 3.8.4 · PSAppDeployToolkit/PSAppDeployToolkit

    Version 3.8.4 [26/01/2021] Fixed Boolean parameters not being passed to Execute-Process Changed Show-InstallationWelcome: Buttons are now wider Listbox is also wider so it is aligned with buttons...

    github.com

    install-module "PowerForensicsv2"

    https://stackoverflow.com/questions/62639056/browse-and-submit-to-webform-using-powershell

 

    Import-module "PowerForensicsv2"
    install-module "PowerForensicsv2"
#>
 

 

<#

    https://powerforensics.readthedocs.io/en/latest/moduleinstall/
    https://powerforensics.readthedocs.io/en/latest/modulehelp/Invoke-ForensicDD/

    #>


 

Set-Location "C:\Users\Administrator\Desktop\dd-0.5"

.\dd if=\\.\D: of=C:\Users\Administrator\Desktop\R740_Svr2019v2.iso bs=1M --progress





$ip = (Get-NetIPAddress -AddressFamily IPv4).IPAddress[0]

$decimal = ([ipaddress]$ip).address
([ipaddress]$decimal).ipaddresstostring


$hex = ($decimal).tostring("x8")
    ([ipaddress]0x3d09be80).ipaddresstostring
    [Array]$a = @((([ipaddress]("0x$($hex)")).ipaddresstostring).split('.'))
    [Array]::Reverse($a) -join '.'
    $hexIP = ($a) -join '.'
$hexIP

function Convert-Color {
    <#
    .Synopsis
    This color converter gives you the hexadecimal values of your RGB colors and vice versa (RGB to HEX)
    .Description
    This color converter gives you the hexadecimal values of your RGB colors and vice versa (RGB to HEX). Use it to convert your colors and prepare your graphics and HTML web pages.
    .Parameter RBG
    Enter the Red Green Blue value comma separated. Red: 51 Green: 51 Blue: 204 for example needs to be entered as 51,51,204
    .Parameter HEX
    Enter the Hex value to be converted. Do not use the '#' symbol. (Ex: 3333CC converts to Red: 51 Green: 51 Blue: 204)
    .Example
    .\convert-color -hex FFFFFF
    Converts hex value FFFFFF to RGB
 
    .Example
    .\convert-color -RGB 123,200,255
    Converts Red = 123 Green = 200 Blue = 255 to Hex value
 
    #>
    param(
        [Parameter(ParameterSetName = "RGB", Position = 0)]
        [ValidateScript( {$_ -match '^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$'})]
        $RGB,
        [Parameter(ParameterSetName = "HEX", Position = 0)]
        [ValidateScript( {$_ -match '[A-Fa-f0-9]{6}'})]
        [string]
        $HEX
    )
    switch ($PsCmdlet.ParameterSetName) {
        "RGB" {
            if ($null -eq $RGB[2]) {
                Write-error "Value missing. Please enter all three values seperated by comma."
            }
            $red = [convert]::Tostring($RGB[0], 16)
            $green = [convert]::Tostring($RGB[1], 16)
            $blue = [convert]::Tostring($RGB[2], 16)
            if ($red.Length -eq 1) {
                $red = '0' + $red
            }
            if ($green.Length -eq 1) {
                $green = '0' + $green
            }
            if ($blue.Length -eq 1) {
                $blue = '0' + $blue
            }
            Write-Output $red$green$blue
        }
        "HEX" {
            $red = $HEX.Remove(2, 4)
            $Green = $HEX.Remove(4, 2)
            $Green = $Green.remove(0, 2)
            $Blue = $hex.Remove(0, 4)
            $Red = [convert]::ToInt32($red, 16)
            $Green = [convert]::ToInt32($green, 16)
            $Blue = [convert]::ToInt32($blue, 16)
            Write-Output $red, $Green, $blue
        }
    }
}
Function Convert-RGBtoCMYK
{
    Param ( [array]$rgb)
    $rgb2 = $rgb|ForEach-Object{$_/255}
    $k = (1-[math]::Max([math]::Max($rgb2[0],$rgb2[1]), $rgb2[2])) # Black
    $C = ((1-$rgb2[0]-$K) / (1-$K))  # Cyan
    $M = ((1-$rgb2[1]-$K) / (1-$K))  # magenta
    $Y = ((1-$rgb2[2]-$K) / (1-$K))  # yellow

    $CMYK = @($($C*255),$($M*255),$($Y*255),$($k*255)) -join ','
    Return $CMYK
}

Convert-Color -RGB 247,180,40
Convert-RGBtoCMYK (Convert-Color -hex 9c0c42)

$SkinsColors = 'Color;Pantone;HEX;RGB;CMYK;Source
Skins Burgundy;195 C;#773141;(63,16,16);(20,100,60,30);https://teamcolorcodes.com/washington-redskins-color-codes/
Commanders Burgundy;PMS 483 C;#5A1414;(90, 20, 20);(36, 92, 85, 58);https://teamcolorcodes.com/washington-redskins-color-codes/
Gold; 1235 C;#FFB612;(255,182,18);(0,25,100,0);https://teamcolorcodes.com/washington-redskins-color-codes/
GOLD;;#FFC20F;(255, 194, 15);;https://www.codeofcolors.com/washington-redskins-colors.html
BURGUNDY;;#7C1415;(124, 20, 21);;https://www.codeofcolors.com/washington-redskins-colors.html
BROWN;;#693213;(105, 50, 19);;https://www.codeofcolors.com/washington-redskins-colors.html
BLACK;;#000000;(0, 0, 0);;https://www.codeofcolors.com/washington-redskins-colors.html
' | ConvertFrom-Csv -Delimiter ([char]59)



$R1 = 247;$r2 = $R1/255
$G1 = 180;$g2 = $G1/255
$B1 = 40;$b2 = $B1/255

$Cmax = [math]::Max([math]::Max($r2,$g2),$b2)
$Cmin = [math]::Min([math]::Min($r2,$g2),$b2)
,
$l = $Cmax - $Cmin

Convert-RGBtoCMYK 63,16,16


#region - File Audits
    # https://stackoverflow.com/questions/31795933/powershell-and-system-io-filesystemwatcher

    $trgDrive = Get-WmiObject -Class win32_logicalDisk | Where-Object VolumeName -eq 'Jenny'

    ### SET FOLDER TO WATCH + FILES TO WATCH + SUBFOLDERS YES/NO
        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = "$($trgDrive.DeviceID)\location2"
        $watcher.Filter = "*.*"
        $watcher.IncludeSubdirectories = $true
        $watcher.EnableRaisingEvents = $true  

    ### DEFINE ACTIONS AFTER A EVENT IS DETECTED
        $action = { $path = $Event.SourceEventArgs.FullPath
                    $changeType = $Event.SourceEventArgs.ChangeType
                    $logline = "$(Get-Date), $changeType, $path"
                    Add-content "C:\log2.txt" -value $logline              
                    Unregister-Event -SubscriptionId $EventSubscriber.SubscriptionId            
                  }    

    ### DECIDE WHICH EVENTS SHOULD BE WATCHED + SET CHECK FREQUENCY  
        $created = Register-ObjectEvent $watcher Created -Action $action

    while ($true) {Start-Sleep 1}

    ## Unregister-Event Created ??
    ##Stop-ScheduledTask ??
    #  Unregister-Event $created.Id
    #  Get-EventSubscriber|Unregister-Event
#endregion

#region - Useful PowerShell ISE Snippets
    $snippet = @{
        Title = "Write Progress Sample";
        Description = "Progress and how to do it";
        Text = (Dec64 'ICAgICNzYW1wbGUgcmFuZ2Ugb2YgbnVtYmVycw0KICAgICR1c2VycyA9ICgxLi4xMzAwMCkNCiANCiAgICAjc2V0dGluZyB1cCBiYXNlIG51bWJlcg0KICAgICRpPTANCiAgICAgDQogICAgRm9yRWFjaCAoJHVzZXIgaW4gJHVzZXJzKXsNCiAgICAgICAgI2luY3JlbWVudA0KICAgICAgICAkaSsrDQogDQogICAgICAgICNSb3VuZCB0aGUgbnVtYmVycyB1cCBmb3IgYSBuaWNlIG91dHB1dCBhbmQgdGhlbiBXcml0ZS1Qcm9ncmVzcw0KICAgICAgICBXcml0ZS1Qcm9ncmVzcyAtQWN0aXZpdHkgIlByb2Nlc3NpbmcgJHVzZXIiIC1QZXJjZW50Q29tcGxldGUgKCgkaS8kdXNlcnMuQ291bnQpICogMTAwKSAtU3RhdHVzICgiJGkgb3V0IG9mICIgKyAkdXNlcnMuQ291bnQgKyIgY29tcGxldGVkICIrW21hdGhdOjpSb3VuZCgoKCRpLyR1c2Vycy5Db3VudCkgKiAxMDApLDIpICsiICUiKQ0KICAgICAgICB9')
        }
    New-IseSnippet @snippet
    Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

    $snippet = @{
        Title = "Write Progress Sample";
        Description = "Progress and how to do it";
        Text = (Dec64 'ICAgICNzYW1wbGUgcmFuZ2Ugb2YgbnVtYmVycw0KICAgICR1c2VycyA9ICgxLi4xMzAwMCkNCiANCiAgICAjc2V0dGluZyB1cCBiYXNlIG51bWJlcg0KICAgICRpPTANCiAgICAgDQogICAgRm9yRWFjaCAoJHVzZXIgaW4gJHVzZXJzKXsNCiAgICAgICAgI2luY3JlbWVudA0KICAgICAgICAkaSsrDQogDQogICAgICAgICNSb3VuZCB0aGUgbnVtYmVycyB1cCBmb3IgYSBuaWNlIG91dHB1dCBhbmQgdGhlbiBXcml0ZS1Qcm9ncmVzcw0KICAgICAgICBXcml0ZS1Qcm9ncmVzcyAtQWN0aXZpdHkgIlByb2Nlc3NpbmcgJHVzZXIiIC1QZXJjZW50Q29tcGxldGUgKCgkaS8kdXNlcnMuQ291bnQpICogMTAwKSAtU3RhdHVzICgiJGkgb3V0IG9mICIgKyAkdXNlcnMuQ291bnQgKyIgY29tcGxldGVkICIrW21hdGhdOjpSb3VuZCgoKCRpLyR1c2Vycy5Db3VudCkgKiAxMDApLDIpICsiICUiKQ0KICAgICAgICB9')
        }
    New-IseSnippet @snippet
    Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

    $snippet = @{
        Title = "Write Progress Sample";
        Description = "Progress and how to do it";
        Text = (Dec64 'ICAgICNzYW1wbGUgcmFuZ2Ugb2YgbnVtYmVycw0KICAgICR1c2VycyA9ICgxLi4xMzAwMCkNCiANCiAgICAjc2V0dGluZyB1cCBiYXNlIG51bWJlcg0KICAgICRpPTANCiAgICAgDQogICAgRm9yRWFjaCAoJHVzZXIgaW4gJHVzZXJzKXsNCiAgICAgICAgI2luY3JlbWVudA0KICAgICAgICAkaSsrDQogDQogICAgICAgICNSb3VuZCB0aGUgbnVtYmVycyB1cCBmb3IgYSBuaWNlIG91dHB1dCBhbmQgdGhlbiBXcml0ZS1Qcm9ncmVzcw0KICAgICAgICBXcml0ZS1Qcm9ncmVzcyAtQWN0aXZpdHkgIlByb2Nlc3NpbmcgJHVzZXIiIC1QZXJjZW50Q29tcGxldGUgKCgkaS8kdXNlcnMuQ291bnQpICogMTAwKSAtU3RhdHVzICgiJGkgb3V0IG9mICIgKyAkdXNlcnMuQ291bnQgKyIgY29tcGxldGVkICIrW21hdGhdOjpSb3VuZCgoKCRpLyR1c2Vycy5Db3VudCkgKiAxMDApLDIpICsiICUiKQ0KICAgICAgICB9')
        }
    New-IseSnippet @snippet
    Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

    $snippet = @{
        Title = "Write Progress Sample";
        Description = "Progress and how to do it";
        Text = (Dec64 'ICAgICNzYW1wbGUgcmFuZ2Ugb2YgbnVtYmVycw0KICAgICR1c2VycyA9ICgxLi4xMzAwMCkNCiANCiAgICAjc2V0dGluZyB1cCBiYXNlIG51bWJlcg0KICAgICRpPTANCiAgICAgDQogICAgRm9yRWFjaCAoJHVzZXIgaW4gJHVzZXJzKXsNCiAgICAgICAgI2luY3JlbWVudA0KICAgICAgICAkaSsrDQogDQogICAgICAgICNSb3VuZCB0aGUgbnVtYmVycyB1cCBmb3IgYSBuaWNlIG91dHB1dCBhbmQgdGhlbiBXcml0ZS1Qcm9ncmVzcw0KICAgICAgICBXcml0ZS1Qcm9ncmVzcyAtQWN0aXZpdHkgIlByb2Nlc3NpbmcgJHVzZXIiIC1QZXJjZW50Q29tcGxldGUgKCgkaS8kdXNlcnMuQ291bnQpICogMTAwKSAtU3RhdHVzICgiJGkgb3V0IG9mICIgKyAkdXNlcnMuQ291bnQgKyIgY29tcGxldGVkICIrW21hdGhdOjpSb3VuZCgoKCRpLyR1c2Vycy5Db3VudCkgKiAxMDApLDIpICsiICUiKQ0KICAgICAgICB9')
        }
    New-IseSnippet @snippet
    Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

    $snippet1 = @{
        Title = "New-Snippet";
        Description = "Create a New Snippet";
        Text = (Dec64 'ICAgICRzbmlwcGV0ID0gQHsNCiAgICAgICAgVGl0bGUgPSAiUHV0IFRpdGxlIEhlcmUiOw0KICAgICAgICBEZXNjcmlwdGlvbiA9ICJEZXNjcmlwdGlvbiBIZXJlIjsNCiAgICAgICAgVGV4dCA9IEAiDQogICAgICAgIENvZGUgaW4gSGVyZQ0KICAgICJADQogICAgfQ0KICAgIE5ldy1Jc2VTbmlwcGV0IEBzbmlwcGV0')
        }
    New-IseSnippet @snippet1 –Force

    $snippet = @{
        Title = "Try/Catch/Custom Objects";
        Description = "A great way to get good streamlined output while Try/Catching";
        Text = (Dec64 'ICAgICAgICAgICAgdHJ5IHskYT1HZXQtV21pT2JqZWN0IC1DbGFzcyBXaW4zMl9Db21wdXRlclN5c3RlbSAtRXJyb3JBY3Rpb24gU3RvcCAtQ29tcHV0ZXJOYW1lIH0NCiAgICAgICBjYXRjaHskYT0gW3BzY3VzdG9tb2JqZWN0XUB7TmFtZT0kbmFtZTtEb21haW49IkFjY2VzcyBEZW5pZWQifX0NCiAgICAgICBbcHNjdXN0b21vYmplY3RdQHtSVU1fTmFtZT0kbmFtZTtSZXBseU5hbWU9JGEuTmFtZTtEb21haW49JGEuRG9tYWlufQ==')
        }
    New-IseSnippet @snippet

    $snippet = @{
        Title = "Quick Custom Object";
        Description = "I always forget how to do this!";
        Text = "`t#Add more columns to the object by adding extra key/values`n`t`t[pscustomobject]@{Name=$name;Domain=`"Access Denied`"}`n"
        }
    New-IseSnippet @snippet
 
    # Progress Bar within ForEach Loop
    # This looks easy but I would forget how to do it constantly.
    $snippet = @{
        Title = "Write Progress Sample";
        Description = "Progress and how to do it";
        Text = (Dec64 'ICAgICNzYW1wbGUgcmFuZ2Ugb2YgbnVtYmVycw0KICAgICR1c2VycyA9ICgxLi4xMzAwMCkNCiANCiAgICAjc2V0dGluZyB1cCBiYXNlIG51bWJlcg0KICAgICRpPTANCiAgICAgDQogICAgRm9yRWFjaCAoJHVzZXIgaW4gJHVzZXJzKXsNCiAgICAgICAgI2luY3JlbWVudA0KICAgICAgICAkaSsrDQogDQogICAgICAgICNSb3VuZCB0aGUgbnVtYmVycyB1cCBmb3IgYSBuaWNlIG91dHB1dCBhbmQgdGhlbiBXcml0ZS1Qcm9ncmVzcw0KICAgICAgICBXcml0ZS1Qcm9ncmVzcyAtQWN0aXZpdHkgIlByb2Nlc3NpbmcgJHVzZXIiIC1QZXJjZW50Q29tcGxldGUgKCgkaS8kdXNlcnMuQ291bnQpICogMTAwKSAtU3RhdHVzICgiJGkgb3V0IG9mICIgKyAkdXNlcnMuQ291bnQgKyIgY29tcGxldGVkICIrW21hdGhdOjpSb3VuZCgoKCRpLyR1c2Vycy5Db3VudCkgKiAxMDApLDIpICsiICUiKQ0KICAgICAgICB9')
        }
    New-IseSnippet @snippet

    # PowerShell V1 Custom Object Format
    # Sometimes you have to work on ancient systems and forget how to make old-school custom objects. Never again! This example is based on capturing the output of Get-MailboxStatistics within $mbx.
    $snippet = @{
           Title = "PS 2.0 Custom Objects";
           Description = "Old Fashioned Custom Objects";
           Text = (Dec64 'ICAgICAgICRPYmplY3RQcm9wZXJ0aWVzID0gQHsNCiAgICBOYW1lID0gJHVzZXINCiAgICBSZWNpcGllbnRUeXBlPSRtYnguUmVjaXBpZW50VHlwZQ0KICAgIExhc3RMb2dnZWRPblVzZXJBY2NvdW50PSRtYnhzdGF0Lkxhc3RMb2dnZWRPblVzZXJBY2NvdW50DQogICAgTGFzdExvZ09mZlRpbWU9JG1ieHN0YXQuTGFzdExvZ09mZlRpbWUNCiAgICBMYXN0TG9nb25UaW1lPSRtYnhzdGF0Lkxhc3RMb2dvblRpbWUNCn0NCiRvYmogPSBOZXctT2JqZWN0IFBTT2JqZWN0IC1Qcm9wZXJ0eSAkT2JqZWN0UHJvcGVydGllcw0KIA==')
           }
    New-IseSnippet @snippet6

    # Old-School Custom Objects using Try/Catch
    # A repeat of my first Custom Object loop, this time with Pre-V2 objects
    $snippet = @{
        Title = "Old School try/catch custom object ";
        Description = "Using try/catch to create custom objects is a great way to capture information succinctly.  However, the [PSCustomObject] Accelerator/casting only work on PS 3 and up.  This example uses old school Items to get around that";
        Text = (Dec64 'ICAgICR1c2VycyB8IEZvckVhY2gtT2JqZWN0IHsNCiAgICAkbmFtZSA9ICRfDQogICAgdHJ5IHskYT1HZXQtbWFpbGJveCAkbmFtZSAtZXJyb3JhY3Rpb24gU3RvcH0NCiAgIGNhdGNoeyAgICRPYmplY3RQcm9wZXJ0aWVzID0gQHsNCiAgICAgICAgTmFtZSA9ICRuYW1lDQogICAgICAgIEhpZGRlbkZyb21BZGRyZXNzTGlzdHNFbmFibGVkPSJNQlggTm90IEZvdW5kIg0KICAgICAgICB9DQogICAgICAgICRhID0gTmV3LU9iamVjdCBQU09iamVjdCAtUHJvcGVydHkgJE9iamVjdFByb3BlcnRpZXN9DQogDQogDQogICAgICAgJE9iamVjdFByb3BlcnRpZXMgPSBAew0KICAgICAgICAgICAgTmFtZSA9ICRuYW1lDQogICAgICAgICAgICBIaWRkZW5Gcm9tQWRkcmVzc0xpc3RzRW5hYmxlZD0kYS5IaWRkZW5Gcm9tQWRkcmVzc0xpc3RzRW5hYmxlZA0KICAgICAgICAgICAgfQ0KICAgICAgICBOZXctT2JqZWN0IFBTT2JqZWN0IC1Qcm9wZXJ0eSAkT2JqZWN0UHJvcGVydGllcw0KICAgfQ==')
        }
    New-IseSnippet @snippet

    # Display a Popup Prompt
    # This is a shorty, but a useful one!
    $snippet = @{
        Title = "Popup Message";
        Description = "Add a simple pop-up message";
        Text = "`$msg = New-Object -ComObject WScript.Shell`n`$msg.Popup(`"Hi Chris`", 5, `"DeadMau5`", 48)`n"
    }
    New-IseSnippet @snippet

    $snippet = @{
        Title = 'New-DataTable'
        Description = 'Creates a Data Table Object'
        Text = (Dec64 'ICMgQ3JlYXRlIFRhYmxlIE9iamVjdA0KICR0YWJsZSA9IE5ldy1PYmplY3Qgc3lzdGVtLkRhdGEuRGF0YVRhYmxlICRUYWJsZU5hbWUNCiANCiAjIENyZWF0ZSBDb2x1bW5zDQogJGNvbDEgPSBOZXctT2JqZWN0IHN5c3RlbS5EYXRhLkRhdGFDb2x1bW4gTkFNRTEsKFtzdHJpbmddKQ0KICRjb2wyID0gTmV3LU9iamVjdCBzeXN0ZW0uRGF0YS5EYXRhQ29sdW1uIE5BTUUyLChbZGVjaW1hbF0pDQogDQogI0FkZCB0aGUgQ29sdW1ucyB0byB0aGUgdGFibGUNCiAkdGFibGUuY29sdW1ucy5hZGQoJGNvbDEpDQogJHRhYmxlLmNvbHVtbnMuYWRkKCRjb2wyKQ0KIA0KICMgQ3JlYXRlIGEgbmV3IFJvdw0KICRyb3cgPSAkdGFibGUuTmV3Um93KCkNCiANCiAjIEFkZCB2YWx1ZXMgdG8gbmV3IHJvdw0KICRyb3cuTmFtZTEgPSAnVkFMVUUnDQogJHJvdy5OQU1FMiA9ICdWQUxVRScNCiANCiAjQWRkIG5ldyByb3cgdG8gdGFibGUNCiAkdGFibGUuUm93cy5BZGQoKQ==')
        }
    New-IseSnippet @snippet
#endregion
