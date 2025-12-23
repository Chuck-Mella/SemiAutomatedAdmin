
#region - Select-Network
    #Requires -RunAsAdministrator
        Function Open-Menu($netList)
        {
            Add-Type -AssemblyName PresentationFramework

            ($NICOption = New-Object System.Windows.Window).Title = "Select Desired Network"
            ($NICOption | %{ $_.Width = 400; $_.Height = 150; $_.WindowStartupLocation = "CenterScreen"; $_.Topmost = $true })

            ($stackPanel = New-Object System.Windows.Controls.StackPanel).Orientation = "Vertical"
            ($stackPanel | %{ $_.HorizontalAlignment = "Center"; $_.VerticalAlignment = "Center" })

            ($label = New-Object System.Windows.Controls.Label).Content = "Please select an option:"

            $comboBox = New-Object System.Windows.Controls.ComboBox
            ($comboBox | %{ $_.Width = 200; $_.Height = 25 })
            ForEach ($Net in $netList.Desc){ [VOID] $comboBox.Items.Add($Net) }

            ($button = New-Object System.Windows.Controls.Button).Content = "OK"
            ($button | %{ $_.Width = 75; $_.Height = 25; $_.Margin = "10"; $_.Add_Click({ $NICOption.DialogResult = $true }) })

            $label,$comboBox,$button | %{ [VOID] $stackPanel.Children.Add($_) }

            $NICOption.Content = $stackPanel

            $null = $NICOption.ShowDialog()

            Switch ($NICOption.DialogResult)
            {
                $true  { Return $comboBox.SelectedItem }
                $false { Write-Warning "Selection Window closed! EXITING!"; Pause; EXIT }
            }
            If ($comboBox.SelectedItem -eq $null){ Write-Warning "No Network Selected! EXITING!"; Pause; EXIT }
        }
        $netList = "
            Net1,CallManager,10.10.20.100,24,10.10.20.1,10.10.20.1,$false
            Net2,TACLANE,172.16.0.100,24,172.16.0.1,172.16.0.1,$false
            Net3,DirtyNet,,,,,$true
            Net4,Fabcon,192.168.0.150,24,192.168.0.1,$('192.168.0.1','192.168.0.2'),$false
            " | ConvertFrom-Csv -Delimiter ',' -Header Network,Desc,IP,SNM,DfltGwy,DNS,DHCP
        #Get-NetAdapter | ft ifIndex, Name, Status -Auto
        $nic = Get-NetAdapter -Physical | ? {$_.Status -eq "Up"}

        # $trgNet = $netList | Where Desc -eq ($netList.Desc | OGV -Title 'Select Network Config to Use' -PassThru)
        $trgNet = $netList | Where Desc -eq (Open-Menu $netList)


        # Set Interface Name
            $nic | Rename-NetAdapter -NewName $trgNet

        # Enable/Disable DHCP
            Switch ($trgNet.DHCP)
            {
            $true
            {
                If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Enabled'){}
                Else { Set-NetIPInterface -ifIndex $nic.InterfaceIndex -Dhcp Enabled }
            }
            $false
            {
                If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Disabled'){}
                Else { Set-NetIPInterface -ifIndex $nic.InterfaceIndex -Dhcp Disabled }
            }
        }

        # Set IP if req'd
            If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Disabled')
            {
                # Set IP
                    New-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -IPAddress $trgNet.IP -DefaultGateway $trgNet.DfltGwy -PrefixLength $trgNet.SNM

                # Set DNS
                    Set-DNSClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $trgNet.DNS
            }
    <#
        #John's Idea to quickly mod NIC to network connected to

         Get-Command -Module NetTCPIP
         Get-Command -Noun NetAdapter

        # View Physical and Active Network Interfaces only
           Get-NetAdapter -Physical | ? {$_.Status -eq "Up"}

        # Disable/Enable the Network Interface
           Get-NetAdapter -InterfaceIndex $nic.InterfaceIndex | Disable-NetAdapter
           Get-NetAdapter -InterfaceIndex $nic.InterfaceIndex | Enable-NetAdapter

        # Show TCP/IP Configuration of Network Interface
           Get-NetIPConfiguration -InterfaceAlias Ethernet

        # View IPv4 Address only
           (Get-NetAdapter -ifIndex $nic.InterfaceIndex | Get-NetIPAddress).IPv4Address

        # Managing the Routing Table
           Get-NetRoute -InterfaceAlias Ethernet

            # To add a new default route for interface with index "6", use the following command.
            New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop "192.168.0.1" -InterfaceIndex 6
            # This command sets a default route with a next-hop 192.168.0.1. Please replace 192.168.0.1 with your own gateway router.
            # By default, the New-NetRoute command adds the route to the "Active Store" and "Persistent Store".
            # The "Active Store" is not persistent across reboots. If you want to add a temporary route which goes away after reboot,
            # you can add -PolicyStore "ActiveStore" at the end of above command.
    #>

<#
#Requires -RunAsAdministrator
$cmd = (@'
Function Open-Menu($netList)
{
  Add-Type -AssemblyName PresentationFramework
  ($NICOption = New-Object System.Windows.Window).Title = "Select Desired Network"
  ($NICOption | %{ $_.Width = 400; $_.Height = 150; $_.WindowStartupLocation = "CenterScreen"; $_.Topmost = $true })
  ($stackPanel = New-Object System.Windows.Controls.StackPanel).Orientation = "Vertical"
  ($stackPanel | %{ $_.HorizontalAlignment = "Center"; $_.VerticalAlignment = "Center" })
  ($label = New-Object System.Windows.Controls.Label).Content = "Please select an option:"
  $comboBox = New-Object System.Windows.Controls.ComboBox
  ($comboBox | %{ $_.Width = 200; $_.Height = 25 })
  ForEach ($Net in $netList.Desc){ [VOID] $comboBox.Items.Add($Net) }
  ($button = New-Object System.Windows.Controls.Button).Content = "OK"
  ($button | %{ $_.Width = 75; $_.Height = 25; $_.Margin = "10"; $_.Add_Click({ $NICOption.DialogResult = $true }) })
  $label,$comboBox,$button | %{ [VOID] $stackPanel.Children.Add($_) }
  $NICOption.Content = $stackPanel
  $null = $NICOption.ShowDialog()
  Switch ($NICOption.DialogResult)
  {
    $true  { Return $comboBox.SelectedItem }
    $false { Write-Warning "Selection Window closed! EXITING!"; Pause; EXIT }
  }
  If ($comboBox.SelectedItem -eq $null){ Write-Warning "No Network Selected! EXITING!"; Pause; EXIT }
}
$netList = "
Net1,CallManager,10.10.20.100,24,10.10.20.1,10.10.20.1,$false
Net2,TACLANE,172.16.0.100,24,172.16.0.1,172.16.0.1,$false
Net3,DirtyNet,,,,,$true
Net4,Fabcon,192.168.0.150,24,192.168.0.1,$('192.168.0.1','192.168.0.2'),$false
" | ConvertFrom-Csv -Delimiter ',' -Header Network,Desc,IP,SNM,DfltGwy,DNS,DHCP
#Get-NetAdapter | ft ifIndex, Name, Status -Auto
  $nic = Get-NetAdapter -Physical | ? {$_.Status -eq "Up"}
# $trgNet = $netList | Where Desc -eq ($netList.Desc | OGV -Title 'Select Network Config to Use' -PassThru)
  $trgNet = $netList | Where Desc -eq (Open-Menu $netList)
# Set Interface Name
  $nic | Rename-NetAdapter -NewName $trgNet.Desc
# Enable/Disable DHCP
  Switch ($trgNet.DHCP)
  {
    $true
    {
      If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Enabled'){}
      Else { Set-NetIPInterface -ifIndex $nic.InterfaceIndex -Dhcp Enabled }
    }
    $false
    {
      If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Disabled'){}
      Else { Set-NetIPInterface -ifIndex $nic.InterfaceIndex -Dhcp Disabled }
    }
}
# Set IP if req'd
  If ((Get-NetIPInterface -InterfaceIndex $nic.InterfaceIndex)[0].Dhcp -match 'Disabled')
  {
    # Set IP
      New-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -IPAddress $trgNet.IP -DefaultGateway $trgNet.DfltGwy -PrefixLength $trgNet.SNM
    # Set DNS
      Set-DNSClientServerAddress -InterfaceIndex $nic.InterfaceIndex -ServerAddresses $trgNet.DNS
  }
'@)#.Length
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encCmd = [Convert]::ToBase64String($bytes)
$decBytes = [Convert]::FromBase64String($encCmd)
$decCmd = [System.Text.Encoding]::Unicode.GetString($decBytes)

$netList = Import-Csv ".\NetList.csv" -Delimiter ';' -Header Network,Desc,IP,SNM,DfltGwy,DNS,DHCP

powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ('RgB1AG4AYwB0AGkAbwBuACAATwBwAGUAbgAtAE0AZQBuAHUAKAAkAG4AZQB0AEwAaQBzAHQAKQAKAHsACgAgACAAQQBkAGQALQBUAHkAcABlACAALQBBAHMAcwBlAG0AYgBsAHkATgBhAG0AZQAgAFAAcgBlAHMAZQBuAHQAYQB0AGkAbwBuAEYAcgBhAG0AZQB3AG8AcgBrAAoAIAAgACgAJABOAEkAQwBPAHAAdABpAG8AbgAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4AVwBpAG4AZABvAHcAKQAuAFQAaQB0AGwAZQAgAD0AIAAiAFMAZQBsAGUAYwB0ACAARABlAHMAaQByAGUAZAAgAE4AZQB0AHcAbwByAGsAIgAKACAAIAAoACQATgBJAEMATwBwAHQAaQBvAG4AIAB8ACAAJQB7ACAAJABfAC4AVwBpAGQAdABoACAAPQAgADQAMAAwADsAIAAkAF8ALgBIAGUAaQBnAGgAdAAgAD0AIAAxADUAMAA7ACAAJABfAC4AVwBpAG4AZABvAHcAUwB0AGEAcgB0AHUAcABMAG8AYwBhAHQAaQBvAG4AIAA9ACAAIgBDAGUAbgB0AGUAcgBTAGMAcgBlAGUAbgAiADsAIAAkAF8ALgBUAG8AcABtAG8AcwB0ACAAPQAgACQAdAByAHUAZQAgAH0AKQAKACAAIAAoACQAcwB0AGEAYwBrAFAAYQBuAGUAbAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4AQwBvAG4AdAByAG8AbABzAC4AUwB0AGEAYwBrAFAAYQBuAGUAbAApAC4ATwByAGkAZQBuAHQAYQB0AGkAbwBuACAAPQAgACIAVgBlAHIAdABpAGMAYQBsACIACgAgACAAKAAkAHMAdABhAGMAawBQAGEAbgBlAGwAIAB8ACAAJQB7ACAAJABfAC4ASABvAHIAaQB6AG8AbgB0AGEAbABBAGwAaQBnAG4AbQBlAG4AdAAgAD0AIAAiAEMAZQBuAHQAZQByACIAOwAgACQAXwAuAFYAZQByAHQAaQBjAGEAbABBAGwAaQBnAG4AbQBlAG4AdAAgAD0AIAAiAEMAZQBuAHQAZQByACIAIAB9ACkACgAgACAAKAAkAGwAYQBiAGUAbAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4AQwBvAG4AdAByAG8AbABzAC4ATABhAGIAZQBsACkALgBDAG8AbgB0AGUAbgB0ACAAPQAgACIAUABsAGUAYQBzAGUAIABzAGUAbABlAGMAdAAgAGEAbgAgAG8AcAB0AGkAbwBuADoAIgAKACAAIAAkAGMAbwBtAGIAbwBCAG8AeAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBXAGkAbgBkAG8AdwBzAC4AQwBvAG4AdAByAG8AbABzAC4AQwBvAG0AYgBvAEIAbwB4AAoAIAAgACgAJABjAG8AbQBiAG8AQgBvAHgAIAB8ACAAJQB7ACAAJABfAC4AVwBpAGQAdABoACAAPQAgADIAMAAwADsAIAAkAF8ALgBIAGUAaQBnAGgAdAAgAD0AIAAyADUAIAB9ACkACgAgACAARgBvAHIARQBhAGMAaAAgACgAJABOAGUAdAAgAGkAbgAgACQAbgBlAHQATABpAHMAdAAuAEQAZQBzAGMAKQB7ACAAWwBWAE8ASQBEAF0AIAAkAGMAbwBtAGIAbwBCAG8AeAAuAEkAdABlAG0AcwAuAEEAZABkACgAJABOAGUAdAApACAAfQAKACAAIAAoACQAYgB1AHQAdABvAG4AIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4AVwBpAG4AZABvAHcAcwAuAEMAbwBuAHQAcgBvAGwAcwAuAEIAdQB0AHQAbwBuACkALgBDAG8AbgB0AGUAbgB0ACAAPQAgACIATwBLACIACgAgACAAKAAkAGIAdQB0AHQAbwBuACAAfAAgACUAewAgACQAXwAuAFcAaQBkAHQAaAAgAD0AIAA3ADUAOwAgACQAXwAuAEgAZQBpAGcAaAB0ACAAPQAgADIANQA7ACAAJABfAC4ATQBhAHIAZwBpAG4AIAA9ACAAIgAxADAAIgA7ACAAJABfAC4AQQBkAGQAXwBDAGwAaQBjAGsAKAB7ACAAJABOAEkAQwBPAHAAdABpAG8AbgAuAEQAaQBhAGwAbwBnAFIAZQBzAHUAbAB0ACAAPQAgACQAdAByAHUAZQAgAH0AKQAgAH0AKQAKACAAIAAkAGwAYQBiAGUAbAAsACQAYwBvAG0AYgBvAEIAbwB4ACwAJABiAHUAdAB0AG8AbgAgAHwAIAAlAHsAIABbAFYATwBJAEQAXQAgACQAcwB0AGEAYwBrAFAAYQBuAGUAbAAuAEMAaABpAGwAZAByAGUAbgAuAEEAZABkACgAJABfACkAIAB9AAoAIAAgACQATgBJAEMATwBwAHQAaQBvAG4ALgBDAG8AbgB0AGUAbgB0ACAAPQAgACQAcwB0AGEAYwBrAFAAYQBuAGUAbAAKACAAIAAkAG4AdQBsAGwAIAA9ACAAJABOAEkAQwBPAHAAdABpAG8AbgAuAFMAaABvAHcARABpAGEAbABvAGcAKAApAAoAIAAgAFMAdwBpAHQAYwBoACAAKAAkAE4ASQBDAE8AcAB0AGkAbwBuAC4ARABpAGEAbABvAGcAUgBlAHMAdQBsAHQAKQAKACAAIAB7AAoAIAAgACAAIAAkAHQAcgB1AGUAIAAgAHsAIABSAGUAdAB1AHIAbgAgACQAYwBvAG0AYgBvAEIAbwB4AC4AUwBlAGwAZQBjAHQAZQBkAEkAdABlAG0AIAB9AAoAIAAgACAAIAAkAGYAYQBsAHMAZQAgAHsAIABXAHIAaQB0AGUALQBXAGEAcgBuAGkAbgBnACAAIgBTAGUAbABlAGMAdABpAG8AbgAgAFcAaQBuAGQAbwB3ACAAYwBsAG8AcwBlAGQAIQAgAEUAWABJAFQASQBOAEcAIQAiADsAIABQAGEAdQBzAGUAOwAgAEUAWABJAFQAIAB9AAoAIAAgAH0ACgAgACAASQBmACAAKAAkAGMAbwBtAGIAbwBCAG8AeAAuAFMAZQBsAGUAYwB0AGUAZABJAHQAZQBtACAALQBlAHEAIAAkAG4AdQBsAGwAKQB7ACAAVwByAGkAdABlAC0AVwBhAHIAbgBpAG4AZwAgACIATgBvACAATgBlAHQAdwBvAHIAawAgAFMAZQBsAGUAYwB0AGUAZAAhACAARQBYAEkAVABJAE4ARwAhACIAOwAgAFAAYQB1AHMAZQA7ACAARQBYAEkAVAAgAH0ACgB9AAoAJABuAGUAdABMAGkAcwB0ACAAPQAgACIACgBOAGUAdAAxACwAQwBhAGwAbABNAGEAbgBhAGcAZQByACwAMQAwAC4AMQAwAC4AMgAwAC4AMQAwADAALAAyADQALAAxADAALgAxADAALgAyADAALgAxACwAMQAwAC4AMQAwAC4AMgAwAC4AMQAsACQAZgBhAGwAcwBlAAoATgBlAHQAMgAsAFQAQQBDAEwAQQBOAEUALAAxADcAMgAuADEANgAuADAALgAxADAAMAAsADIANAAsADEANwAyAC4AMQA2AC4AMAAuADEALAAxADcAMgAuADEANgAuADAALgAxACwAJABmAGEAbABzAGUACgBOAGUAdAAzACwARABpAHIAdAB5AE4AZQB0ACwALAAsACwALAAkAHQAcgB1AGUACgBOAGUAdAA0ACwARgBhAGIAYwBvAG4ALAAxADkAMgAuADEANgA4AC4AMAAuADEANQAwACwAMgA0ACwAMQA5ADIALgAxADYAOAAuADAALgAxACwAJAAoACcAMQA5ADIALgAxADYAOAAuADAALgAxACcALAAnADEAOQAyAC4AMQA2ADgALgAwAC4AMgAnACkALAAkAGYAYQBsAHMAZQAKACIAIAB8ACAAQwBvAG4AdgBlAHIAdABGAHIAbwBtAC0AQwBzAHYAIAAtAEQAZQBsAGkAbQBpAHQAZQByACAAJwAsACcAIAAtAEgAZQBhAGQAZQByACAATgBlAHQAdwBvAHIAawAsAEQAZQBzAGMALABJAFAALABTAE4ATQAsAEQAZgBsAHQARwB3AHkALABEAE4AUwAsAEQASABDAFAACgAjAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgAgAHwAIABmAHQAIABpAGYASQBuAGQAZQB4ACwAIABOAGEAbQBlACwAIABTAHQAYQB0AHUAcwAgAC0AQQB1AHQAbwAKACAAIAAkAG4AaQBjACAAPQAgAEcAZQB0AC0ATgBlAHQAQQBkAGEAcAB0AGUAcgAgAC0AUABoAHkAcwBpAGMAYQBsACAAfAAgAD8AIAB7ACQAXwAuAFMAdABhAHQAdQBzACAALQBlAHEAIAAiAFUAcAAiAH0ACgAjACAAJAB0AHIAZwBOAGUAdAAgAD0AIAAkAG4AZQB0AEwAaQBzAHQAIAB8ACAAVwBoAGUAcgBlACAARABlAHMAYwAgAC0AZQBxACAAKAAkAG4AZQB0AEwAaQBzAHQALgBEAGUAcwBjACAAfAAgAE8ARwBWACAALQBUAGkAdABsAGUAIAAnAFMAZQBsAGUAYwB0ACAATgBlAHQAdwBvAHIAawAgAEMAbwBuAGYAaQBnACAAdABvACAAVQBzAGUAJwAgAC0AUABhAHMAcwBUAGgAcgB1ACkACgAgACAAJAB0AHIAZwBOAGUAdAAgAD0AIAAkAG4AZQB0AEwAaQBzAHQAIAB8ACAAVwBoAGUAcgBlACAARABlAHMAYwAgAC0AZQBxACAAKABPAHAAZQBuAC0ATQBlAG4AdQAgACQAbgBlAHQATABpAHMAdAApAAoAIwAgAFMAZQB0ACAASQBuAHQAZQByAGYAYQBjAGUAIABOAGEAbQBlAAoAIAAgACQAbgBpAGMAIAB8ACAAUgBlAG4AYQBtAGUALQBOAGUAdABBAGQAYQBwAHQAZQByACAALQBOAGUAdwBOAGEAbQBlACAAJAB0AHIAZwBOAGUAdAAuAEQAZQBzAGMACgAjACAARQBuAGEAYgBsAGUALwBEAGkAcwBhAGIAbABlACAARABIAEMAUAAKACAAIABTAHcAaQB0AGMAaAAgACgAJAB0AHIAZwBOAGUAdAAuAEQASABDAFAAKQAKACAAIAB7AAoAIAAgACAAIAAkAHQAcgB1AGUACgAgACAAIAAgAHsACgAgACAAIAAgACAAIABJAGYAIAAoACgARwBlAHQALQBOAGUAdABJAFAASQBuAHQAZQByAGYAYQBjAGUAIAAtAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAAgACQAbgBpAGMALgBJAG4AdABlAHIAZgBhAGMAZQBJAG4AZABlAHgAKQBbADAAXQAuAEQAaABjAHAAIAAtAG0AYQB0AGMAaAAgACcARQBuAGEAYgBsAGUAZAAnACkAewB9AAoAIAAgACAAIAAgACAARQBsAHMAZQAgAHsAIABTAGUAdAAtAE4AZQB0AEkAUABJAG4AdABlAHIAZgBhAGMAZQAgAC0AaQBmAEkAbgBkAGUAeAAgACQAbgBpAGMALgBJAG4AdABlAHIAZgBhAGMAZQBJAG4AZABlAHgAIAAtAEQAaABjAHAAIABFAG4AYQBiAGwAZQBkACAAfQAKACAAIAAgACAAfQAKACAAIAAgACAAJABmAGEAbABzAGUACgAgACAAIAAgAHsACgAgACAAIAAgACAAIABJAGYAIAAoACgARwBlAHQALQBOAGUAdABJAFAASQBuAHQAZQByAGYAYQBjAGUAIAAtAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAAgACQAbgBpAGMALgBJAG4AdABlAHIAZgBhAGMAZQBJAG4AZABlAHgAKQBbADAAXQAuAEQAaABjAHAAIAAtAG0AYQB0AGMAaAAgACcARABpAHMAYQBiAGwAZQBkACcAKQB7AH0ACgAgACAAIAAgACAAIABFAGwAcwBlACAAewAgAFMAZQB0AC0ATgBlAHQASQBQAEkAbgB0AGUAcgBmAGEAYwBlACAALQBpAGYASQBuAGQAZQB4ACAAJABuAGkAYwAuAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAAgAC0ARABoAGMAcAAgAEQAaQBzAGEAYgBsAGUAZAAgAH0ACgAgACAAIAAgAH0ACgB9AAoAIwAgAFMAZQB0ACAASQBQACAAaQBmACAAcgBlAHEAJwBkAAoAIAAgAEkAZgAgACgAKABHAGUAdAAtAE4AZQB0AEkAUABJAG4AdABlAHIAZgBhAGMAZQAgAC0ASQBuAHQAZQByAGYAYQBjAGUASQBuAGQAZQB4ACAAJABuAGkAYwAuAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAApAFsAMABdAC4ARABoAGMAcAAgAC0AbQBhAHQAYwBoACAAJwBEAGkAcwBhAGIAbABlAGQAJwApAAoAIAAgAHsACgAgACAAIAAgACMAIABTAGUAdAAgAEkAUAAKACAAIAAgACAAIAAgAE4AZQB3AC0ATgBlAHQASQBQAEEAZABkAHIAZQBzAHMAIAAtAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAAgACQAbgBpAGMALgBJAG4AdABlAHIAZgBhAGMAZQBJAG4AZABlAHgAIAAtAEkAUABBAGQAZAByAGUAcwBzACAAJAB0AHIAZwBOAGUAdAAuAEkAUAAgAC0ARABlAGYAYQB1AGwAdABHAGEAdABlAHcAYQB5ACAAJAB0AHIAZwBOAGUAdAAuAEQAZgBsAHQARwB3AHkAIAAtAFAAcgBlAGYAaQB4AEwAZQBuAGcAdABoACAAJAB0AHIAZwBOAGUAdAAuAFMATgBNAAoAIAAgACAAIAAjACAAUwBlAHQAIABEAE4AUwAKACAAIAAgACAAIAAgAFMAZQB0AC0ARABOAFMAQwBsAGkAZQBuAHQAUwBlAHIAdgBlAHIAQQBkAGQAcgBlAHMAcwAgAC0ASQBuAHQAZQByAGYAYQBjAGUASQBuAGQAZQB4ACAAJABuAGkAYwAuAEkAbgB0AGUAcgBmAGEAYwBlAEkAbgBkAGUAeAAgAC0AUwBlAHIAdgBlAHIAQQBkAGQAcgBlAHMAcwBlAHMAIAAkAHQAcgBnAE4AZQB0AC4ARABOAFMACgAgACAAfQA=')
#>

#endregion

