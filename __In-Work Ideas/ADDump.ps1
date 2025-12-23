
# Get-ADObject -LDAPFilter "objectClass=Contact"  -Properties mail| select Name, PrimarySMTPAddress,mail |  Export-Clixml "$wrkPath\contact.xml"

$wrkPath = 'C:\Users\adminCM\Desktop\FABCON Data'
Get-ADUser -Filter * -Properties * | export-clixml -path "$wrkPath\userexport_new.xml"
# Get-ADUser -Filter * -Properties * | export-clixml -path "$wrkPath\userexport.xml"
$h = Import-CliXml "$wrkPath\userexport_new.xml"
$i = Import-CliXml "$wrkPath\userexport.xml"
$h | Out-GridView
$i | Out-GridView
Compare-Object $h $i
$h | Select-Object Name,SCriptpath | Out-GridView
$i | Select-Object Name,SCriptpath | Out-GridView


# Get-ADGroup -filter {Name -like "Domain A*"} -Properties Members | Export-Clixml .\groupmembers.xml
$i = ForEach ($Grp in (Get-ADGroup -Filter *))
{
    $Grp | Get-ADGroupMember |  Select-Object distinguishedName,name,objectClass,objectGUID,SamAccountName,SID,@{n='Group';e={$Grp.Name}}
}
$i | Export-CliXml -path "$wrkPath\groupexport.xml"
$GrpInfo = Import-CliXml "$wrkPath\groupexport.xml"
$GrpInfo | Select-Object Name,Group | Group-Object name | Out-GridView


$j = ForEach ($fs in (Get-FileShare))
{
    $y = (Get-SmbShare -Name $FS.Name)#.
    $x = [PSCustomObject]@{
            Name = $FS.Name
            Owner = $y.PresetPathAcl.Owner
            Access = $y.PresetPathAcl.AccessToString
        }
    $x
}
$j | Export-CliXml -path "$wrkPath\shareexport.xml"
$fsInfo = Import-CliXml "$wrkPath\shareexport.xml"
$fsInfo

Get-ADOrganizationalUnit -Filter * | 
    Select-Object name,DistinguishedName,@{n=’OUPath’;e={$_.distinguishedName -replace '^.+?,',''}}, `
    # select name,DistinguishedName,@{n=’OUPath’;e={$_.distinguishedName -replace '^.+?,(CN|OU|DC.+)','$1'}}, `
        @{n=’OUNum’;e={([regex]::Matches($_.distinguishedName, “OU=” )).count}} | 
    Sort-Object OUNum | Export-CliXml "$wrkPath\OUTree.xml" # | export-csv "$wrkPath\OUTree.csv" -NoTypeInformation
$OUs = Import-CliXml "$wrkPath\OUTree.xml"
# ForEach ($OU in $OUs) { New-ADOrganizationalUnit -Name $OU.Name -Path $OU.OUPath }




Get-Printer | Export-CliXml "$wrkPath\Printers.xml"
    $prt = Import-CliXml "$wrkPath\Printers.xml"
    $prt | Select-Object Name,Location,PrinterStatus | Out-GridView
Get-WmiObject -class win32_printer -ComputerName . | Export-CliXml "$wrkPath\PrintersWMI.xml"
    $prt2 = Import-CliXml "$wrkPath\PrintersWMI.xml"
    $prt2 | Select-Object Caption,Location,PortName,DriverName,PrinterStatus | Out-GridView
Get-PrinterPort | Export-CliXml "$wrkPath\PrintersPorts.xml"
    $prt3 = Import-CliXml "$wrkPath\PrintersPorts.xml"
    $prt3 | Out-GridView
Get-PrinterDriver | Export-CliXml "$wrkPath\PrintersDriver.xml"
    $prt4 = Import-CliXml "$wrkPath\PrintersDriver.xml"
    $prt4 | Out-GridView
    $prt4 | Format-List
    ($prt4 | Get-Member | Where-Object{$_.Membertype -match 'property'}) | Select-Object @{n='Property Fields';e={$_.Name}}

Get-PrintConfiguration -PrinterObject 

($f = Foreach ($Printer in (Get-Printer *))
{
     Get-PrintConfiguration –PrinterName $Printer.name # –DuplexingMode "TwoSidedLongEdge"
}) | Export-CliXml "$wrkPath\PrintersCfg.xml"
$Printers = Import-CliXml "$wrkPath\PrintersCfg.xml"
($Printers | Get-Member | Where-Object{$_.Membertype -match 'property'}) | Select-Object @{n='Property Fields';e={$_.Name}}
$Printers | Out-GridView
$f | Out-GridView

#region - ADSI
    Function Convert-LastLogonTimeStamp
    {
        Param
        (
            [int64]$LastOn=0
        )
        [datetime]$utc="1/1/1601"
        if ($LastOn -eq 0) { $utc } 
        else
        {
            [datetime]$utc="1/1/1601"
            $i=$LastOn/864000000000
            [datetime]$utcdate = $utc.AddDays($i)
            #adjust for time zone
            $offset = Get-WmiObject -class Win32_TimeZone
            $utcdate.AddMinutes($offset.bias)
        }
    }

    $search = New-Object System.DirectoryServices.DirectorySearcher
    $search.SearchRoot = "LDAP://$(([ADSI]'').DistinguishedName)"
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
    $search.Filter = $filter
    $search.FindAll()

    $r = $search.findone().Properties.GetEnumerator() | ForEach-Object -begin {$hash=@{}} -process { $hash.add($_.key,$($_.Value)) } -end {[pscustomobject]$Hash}
    $r | Select-Object Name,Title,Department,DistinguishedName,WhenChanged,LastLogonTimeStamp
    $r | Select-Object Name,Title,Department,DistinguishedName,WhenChanged,@{Name="LastLogon";Expression={Convert-LastLogonTimeStamp $_.lastLogonTimeStamp}}

    $all = $search.FindAll()
    $all.Count
    $all | Select-Object Path | Out-GridView

    $disabled = Foreach ($user in $all)
    {
        $user.Properties.GetEnumerator() |
            ForEach-Object -begin {$hash=@{}} -process {
                $hash.add($_.key,$($_.Value))
            } -end {[pscustomobject]$Hash}
    }

    $disabled | Sort-Object Department | Format-Table -GroupBy Department -Property Name, `
    Title,@{Name="LastLogon";Expression={Convert-LastLogonTimeStamp $_.lastLogonTimeStamp}}, `
    Distinguishedname


    ([adsi]"LDAP://RootDSE").dnsHostName
    ([adsi]"LDAP://RootDSE").defaultNamingContext
    ([adsi]"LDAP://RootDSE").serverName
    ([adsi]"LDAP://RootDSE")
    ([adsi]"LDAP://RootDSE")
    ([adsi]"LDAP://RootDSE")
    ([adsi]"LDAP://RootDSE")
    ([ADSI]'')


    [adsisearcher]$Searcher = $filter
    # $searcher.SearchRoot = [ADSI]"LDAP://CHI-DC04/OU=Employees,DC=Globomantics,DC=Local"
    $today = Get-Date
    [datetime]$utc = "1/1/1601"
    $ticks = ($today - $utc).ticks
    $searcher.filter = "(&(objectCategory=person)(objectClass=user)(!accountexpires=0)(accountexpires<=$ticks))"

    $days = 120
    $cutoff = (Get-Date).AddDays(-120)
    $ticks = ($cutoff - $utc).ticks
    $searcher.filter = "(&(objectCategory=person)(objectClass=user)(lastlogontimestamp<=$ticks))"
    $all = $searcher.FindAll()

    $inactive = Foreach ($user in $all)
    {
        $user.Properties.GetEnumerator() |
            ForEach-Object -begin {$hash=@{}} -process {
            $hash.add($_.key,$($_.Value))
            } -end {[pscustomobject]$Hash}
    }
    $inactive | Select-Object Name,Title,Department,DistinguishedName,WhenChanged,
    @{Name="LastLogon";Expression={Convert-LastLogonTimeStamp $_.lastLogonTimeStamp}} |
    Out-Gridview -title "Last Logon"
#endregion

Get-GPInheritance -Target 'fab.net'

Function Get-AllGPO
{
	Get-GPOReport -all -ReportType xml | ForEach-Object{
		([xml]$_).gpo | Select-Object name,@{n="SOMName";e={$_.LinksTo | ForEach-Object {$_.SOMName}}},@{n="SOMPath";e={$_.LinksTo | ForEach-Object{$_.SOMPath}}}
	}
}

#Get Gpo with name Turn* and display what OU is linked.
Get-AllGPO | Where-Object {$_.Name -match "Turn*"} | ForEach-Object{$_.SomName}
Get-AllGPO | ForEach-Object{$_.SomName}



# For those who cannot use the GPO module, get linked GPOs:

$gpm = New-Object -ComObject GPMgmt.GPM
$constants = $gpm.GetConstants()
$GPODomain = $gpm.GetDomain($env:USERDOMAIN,$null,$contants.UseAnyDC)
$GPOs = $GPODomain.SearchGPOs($gpm.CreateSearchCriteria())

$GPOs | Foreach-Object{
 $gpmSearchCriteria = $gpm.CreateSearchCriteria()
 $gpmSearchCriteria.Add($constants.SearchPropertySomLinks,$constants.SearchOpContains,$_)
 $somList = $GPODomain.SearchSoms($gpmSearchCriteria)
 if($somList.Count -gt 0) {$somList.DisplayName}
}
