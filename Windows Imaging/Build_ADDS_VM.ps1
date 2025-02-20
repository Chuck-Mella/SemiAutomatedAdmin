#region _ ADDS VM
    $Dom = 'EastLab.Net' # 'Contoso.com'
    $dcName = "mecm-dc1"
    $admCreds = $($aesKey = (137,51,63,190,205,150,20,73,189,108,202,22,97,208,88,80,93,170,21,52,98,105,188,51,73,111,119,92,72,154,19,81)
                $encText = '76492d1116743f0423413b16050a5345MgB8AHUAdgBBAHIAYgBvAFUANABTAG4AWAA3AGIAeQBQAGkAMABRAHEARwArAFEAPQA9AHwAOAA3AGEANQA4ADYAZAAzADUAOQA1ADMAMgBmADUAMwBlADIANwBmAGQAMgBhAGQAZQAwAGIAYgAzADkAZQAzADAAYQAxAGYAMABiADUANQAzADEAOAAwAGEAZAA2ADUANwAzADAAMAAxADAAYwA3AGMAOQBkADQANwBiADQAYQA0AGEAYgAyAGQAMwA4AGEAMgAyAGUANwA3ADYAYQA3AGUAYgAzADcAYgA5ADAAZABmADMANABkADMAYgA3ADMA' | convertTo-securestring -Key $aesKey
                New-object system.Management.Automation.Pscredential ('~\Administrator',$encText)
                )
    $ts = New-PSSession -VMName MECM-DC1 -Credential $admCreds
    Invoke-Command -Session $ts -ScriptBlock {
        # Turn off IPv6 Random & Temporary IP Assignments
        Set-NetIPv6Protocol -RandomizeIdentifiers Disabled
        Set-NetIPv6Protocol -UseTemporaryAddresses Disabled

        # Turn off IPv6 Transition Technologies
        Set-Net6to4Configuration -State Disabled
        Set-NetIsatapConfiguration -State Disabled
        Set-NetTeredoConfiguration -Type Disabled
    }
    Invoke-Command -Session $ts -ScriptBlock {
        # Install the ADDS Bits and Promote
        $domainName  = $using:Dom
        $netBIOSname = $domainName.Split('.')[0].ToUpper()
        $mode  = "Win2012R2"

        Install-WindowsFeature AD-Domain-Services -IncludeAllSubFeature -IncludeManagementTools

        Import-Module ADDSDeployment

        $forestProperties = @{

            DomainName           = $domainName
            DomainNetbiosName    = $netBIOSname
            ForestMode           = $mode
            DomainMode           = $mode
            CreateDnsDelegation  = $false
            InstallDns           = $true
            DatabasePath         = "C:\Windows\NTDS"
            LogPath              = "C:\Windows\NTDS"
            SysvolPath           = "C:\Windows\SYSVOL"
            NoRebootOnCompletion = $false
            Force                = $true

        }

        Install-ADDSForest @forestProperties
        # Note: When prompted, enter a Safe Mode Administrator password.
    }
    <#Setting up the NIC, Renaming the Computer, and Rebooting
    # Define the Computer Name

    # Define the IPv4 Addressing
    $IPv4Address = "10.10.100.25"
    $IPv4Prefix = "24"
    $IPv4GW = "10.10.100.1"
    $IPv4DNS = "8.8.8.8"

    # Get the Network Adapter's Prefix
    $ipIF = (Get-NetAdapter).ifIndex


    # Add IPv4 Address, Gateway, and DNS
    New-NetIPAddress -InterfaceIndex $ipIF -IPAddress $IPv4Address -PrefixLength $IPv4Prefix -DefaultGateway $IPv4GW
    Set-DNSClientServerAddress -interfaceIndex $ipIF -ServerAddresses $IPv4DNS#>
    # Add Test Site 1
        $ts = New-PSSession -VMName MECM-DC1 -Credential (Get-Credential "$Dom\Administrator")
        Invoke-Command -Session $ts -ScriptBlock {
            ## DNS, Sites & Services, and Time Keeping
            # Define DNS and Sites & Services Settings
            $IPv4netID = "172.16.11.0/24"
            $siteName = "SUSLAB"
            $location = "Springfield"
 
            # Add DNS Reverse Lookup Zones
            Add-DNSServerPrimaryZone -NetworkID $IPv4netID -ReplicationScope 'Forest' -DynamicUpdate 'Secure'

            # Make Changes to Sites & Services
            $defaultSite = Get-ADReplicationSite | Select DistinguishedName
            Rename-ADObject $defaultSite.DistinguishedName -NewName $siteName
            New-ADReplicationSubnet -Name $IPv4netID -site $siteName -Location $location

            # Re-Register DC's DNS Records
            Register-DnsClient

        }
    # Add Test Site 2
        Invoke-Command -Session $ts -ScriptBlock {
            ## DNS, Sites & Services, and Time Keeping
            # Define DNS and Sites & Services Settings
            $IPv4netID = "172.16.12.0/24"
            $siteName = "MDTLAB"
            $location = "Springfield"

            # Add DNS Reverse Lookup Zones
            Add-DNSServerPrimaryZone -NetworkID $IPv4netID -ReplicationScope 'Forest' -DynamicUpdate 'Secure'

            # Make Changes to Sites & Services
            $defaultSite = Get-ADReplicationSite | Select DistinguishedName
            Rename-ADObject $defaultSite.DistinguishedName -NewName $siteName
            New-ADReplicationSubnet -Name $IPv4netID -site $siteName -Location $location

            # Re-Register DC's DNS Records
            Register-DnsClient
        }
    # Add Test Site 3
        Invoke-Command -Session $ts -ScriptBlock {
            ## DNS, Sites & Services, and Time Keeping
            # Define DNS and Sites & Services Settings
            $IPv4netID = "172.16.13.0/24"
            $siteName = "SDCLAB"
            $location = "Springfield"

            # Add DNS Reverse Lookup Zones
            Add-DNSServerPrimaryZone -NetworkID $IPv4netID -ReplicationScope 'Forest' -DynamicUpdate 'Secure'

            # Make Changes to Sites & Services
            $defaultSite = Get-ADReplicationSite | Select DistinguishedName
            Rename-ADObject $defaultSite.DistinguishedName -NewName $siteName
            New-ADReplicationSubnet -Name $IPv4netID -site $siteName -Location $location

            # Re-Register DC's DNS Records
            Register-DnsClient

        }
    # NTP
    Invoke-Command -Session $ts -ScriptBlock {
 
        # Define Authoritative Internet Time Servers
        $timePeerList = "0.us.pool.ntp.org 1.us.pool.ntp.org"
        # Set Time Configuration
        w32tm /config /manualpeerlist:$timePeerList /syncfromflags:manual /reliable:yes /update

    }
    # DNS Cleanup
        Invoke-Command -Session $ts -ScriptBlock {
            # Enable Default Aging/Scavenging Settings for All Zones and this DNS Server
            Set-DnsServerScavenging -ScavengingState $True -ScavengingInterval 7:00:00:00 -ApplyOnAllZones
            $Zones = Get-DnsServerZone | Where-Object {$_.IsAutoCreated -eq $False -and $_.ZoneName -ne 'TrustAnchors'}
            $Zones | Set-DnsServerZoneAging -Aging $True
        }
    # Domain Build Out
        Invoke-Command -Session $ts -ScriptBlock { 
            #Build an OU Structure
            $domn = $using:Dom
            $baseDN = ("DC={0},DC={1}" -f $domn.Split('.')[0],$domn.Split('.')[1])
            $resourcesDN = "OU=Resources," + $baseDN

            New-ADOrganizationalUnit "Resources" -path $baseDN
            New-ADOrganizationalUnit "Admin Users" -path $resourcesDN
            New-ADOrganizationalUnit "Groups Security" -path $resourcesDN
            New-ADOrganizationalUnit "Service Accounts" -path $resourcesDN
            New-ADOrganizationalUnit "Workstations" -path $resourcesDN
            New-ADOrganizationalUnit "Servers" -path $resourcesDN
            New-ADOrganizationalUnit "Users" -path $resourcesDN

            # Enable the Recycle Bin
            $ForestFQDN = $domn
            $SchemaDC   = "$using:dcName.$domn"
            Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' `
                                     -Scope ForestOrConfigurationSet `
                                     -Target $ForestFQDN -Server $SchemaDC -confirm:$false

        }
    # Create User Accounts
        $usrDB = "Chuck,Mella,Y`nEd,Mella,Y`nGaby,Mella,N" | ConvertFrom-Csv -Delim ',' -Header First,Last,Admin
        $Password = Read-Host -assecurestring "Default User Password"
        Invoke-Command -Session $ts -ScriptBlock {
            $domn = $using:Dom
            $baseDN = ("DC={0},DC={1}" -f $domn.Split('.')[0],$domn.Split('.')[1])
            $resourcesDN = "OU=Resources," + $baseDN
            $usrList = $using:usrDB
            $dfltPwd = $using:Password

            ForEach ($usr in $usrList)
            {
                If ($usr.Admin -eq 'Y')
                {
                    # Create a Privileged Account
                        $userProperties = @{

                            Name                 = "$($usr.First) $($usr.last) EA"
                            GivenName            = $usr.First
                            Surname              = "$($usr.last)"
                            DisplayName          = "$($usr.last),$($usr.First)  EA"
                            Path                 = "OU=Admin Users,$resourcesDN"
                            SamAccountName       = "EAdmin$($usr.First[0])$($usr.last[0])"
                            UserPrincipalName    = "EAdmin$($usr.First[0])$($usr.last[0])@$domn"
                            AccountPassword      = $dfltPwd
                            PasswordNeverExpires = $True
                            Enabled              = $True
                            Description          = "$($Dom.Split('.')[0]) Enterprise Admin"
                        }

                        New-ADUser @userProperties -PassThru | Set-ADUser -ChangePasswordAtLogon:$True

                    # Add Privileged Account to EA, DA, & SA Groups
                        Add-ADGroupMember "Domain Admins" $userProperties.SamAccountName
                        Add-ADGroupMember "Enterprise Admins" $userProperties.SamAccountName
                        Add-ADGroupMember "Schema Admins" $userProperties.SamAccountName
                }

                # Create a Non-Privileged User Account
                    $userProperties = @{

                        Name                 = "$($usr.First) $($usr.last)"
                        GivenName            = $usr.First
                        Surname              = $usr.last 
                        DisplayName          = "$($usr.First) $($usr.last)"
                        Path                 = "OU=Users,$resourcesDN"
                        SamAccountName       = "$($usr.First).$($usr.last)"
                        UserPrincipalName    = "$($usr.First).$($usr.last)@$domn"
                        AccountPassword      = $dfltPwd
                        PasswordNeverExpires = $True
                        Enabled              = $True
                        Description          = "$($domn.Split('.')[0]) User"

                    }

                    New-ADUser @userProperties | Set-ADUser -ChangePasswordAtLogon:$True
            }
            }
    # Cleanup ADDS        
        Invoke-Command -Session $ts -ScriptBlock {
            # Secure & Disable the Administrator Account
                Set-ADUser Administrator -AccountNotDelegated:$true -SmartcardLogonRequired:$true -Enabled:$false
 
            # Create an Active Directory Snapshot
                C:\Windows\system32\ntdsutil.exe snapshot "activate instance ntds" create quit quit
            }
#endregion
