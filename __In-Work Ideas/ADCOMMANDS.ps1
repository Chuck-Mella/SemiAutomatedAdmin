
#region AD Command
# OS Test
    Switch (Get-WmiObject Win32_OperatingSystem | Select-Object -Exp ProductType)
    {
        1 { 'Workstation'; $adsi = $true }
        2 { 'DC'; $adsi = $false }
        3 { 'Member Server'; $adsi = $true }
    }
# Get all computers
    If ($adsi -eq $false)
    {
        $all_Systems = Get-ADComputer -Filter * 
        $all_Systems | Add-Member -MemberType NoteProperty -Name 'tesa' -Value ''
        $all_Systems | Measure-Object | Select-Object Count
        $all_Systems | Out-GridView
    }
    Else 
    {
        $adsi = (New-Object System.DirectoryServices.DirectorySearcher)
        $adsi.SearchRoot = "LDAP://$(([ADSI]'').DistinguishedName)"
        $adsi.Filter = '(&(objectCategory=computer))'
        $all_Systems = ($adsi).FindAll() | Select-Object @{n='Name';e={$_.Path.Split(',')[0] -replace 'LDAP://CN='}}, @{n='DistinguishedName';e={$_.Path -replace 'LDAP://' }}
        $all_Systems | Measure-Object | Select-Object Count
    }

# Get ONLY Servers
    $all_Servers = $all_Systems | Where-Object { $_.DistinguishedName -Match '(Server|Domain Controller)'}
    $all_Servers | Measure-Object | Select-Object Count
    $all_Servers | Out-GridView

# Get ONLY Workstations
    $all_wks = $all_Systems | Where-Object { $_.DistinguishedName -NotMatch '(Server|Domain Controller)'}
    $all_wks | Measure-Object | Select-Object Count
    $all_wks | Out-GridView

# Get ONLY East Coast Servers
    $E_Servers = $all_Servers | Where-Object { $_.DistinguishedName -NotMatch 'AD-W'}
    $E_Servers | Measure-Object | Select-Object Count
    $E_Servers | Out-GridView

# Get ONLY West Coast Servers
    $W_Servers = $all_Servers | Where-Object { $_.DistinguishedName -Match 'AD-W'}
    $W_Servers | Measure-Object | Select-Object Count
    $W_Servers | Out-GridView



# Get Computer by type
      If ($adsi -eq $false)
    {
        $all_Systems = Get-ADComputer -Filter * -Properties  Name,OperatingSystem,OperatingSystemVersion,IPv4Address
        $all_Systems | Measure-Object | Select-Object Count
    }
    Else 
    {
    }
    
    $ALL =  $all_Systems| Select-Object Name,OperatingSystem,OperatingSystemVersion,IPv4Address,DistinguishedName
    ($Servers = Get-ADComputer -Filter { operatingsystem -like "*Server*" -and enabled -eq "true" } `
        -Properties Name,OperatingSystem,OperatingSystemVersion,IPv4Address | 
        Sort-Object -Property OperatingSystem | 
        Select-Object Name,OperatingSystem,OperatingSystemVersion,IPv4Address,DistinguishedName).Count
    ($Clients = Get-ADComputer -Filter { operatingsystem -notlike "*Server*" -and enabled -eq "true" } `
        -Properties Name,OperatingSystem,OperatingSystemVersion,IPv4Address | 
        Sort-Object -Property OperatingSystem | 
        Select-Object Name,OperatingSystem,OperatingSystemVersion,IPv4Address,DistinguishedName).Count
    $Clients | Where-Object distinguishedName -Match '(west|cn\=wa|template)' | Out-GridView
    $Servers | Where-Object distinguishedName -NotMatch '(west|cn\=wa|template)' | Out-GridView

($ALL = Get-ADComputer -Filter * | Where-Object { $_.operatingsystem -eq $null }).Count
$ALL 
($eastServers = Get-ADComputer -Filter * |
    Where-Object {
            $_.DistinguishedName -Match 'Server' -and 
            $_.DistinguishedName -NotMatch 'west'
          }) | Select-Object Name,DistinguishedName | Out-GridView -Title 'East Coast Servers'#Measure | Select Count

($westServers = Get-ADComputer -Filter * |
    Where-Object {
            $_.DistinguishedName -Match 'Server' -and 
            $_.DistinguishedName -Match 'west'
          }) | Select-Object Name,DistinguishedName | Out-GridView #Measure | Select Count
$EastServers | Out-GridView -Title 'East Servers'
$westServers | Out-GridView -Title 'West Servers'

$System = $env:ComputerName
Get-ADComputer -Filter { Name -like $System } | Select-Object *



<#
    $a = ( $b = ( ( 'CN=WAVJSTP04,CN=Computers,DC=olad,DC=edu' -split ',') | Where-Object {$_ -notmatch 'DC='} ) -Replace 'CN=' ).count
    $c = $a -1
    $d = $(For ($c; $c -ge 0; $c--){$b[$c]}) -join '\'
    $all_Systems.Add($d)
#>
# NET USERS $env:USERNAME /DOMAIN | findstr /c:'AD-East Admins'==''
# Get-ADGroupMember 'it users' | Select samaccountname
