#region - AD Dump
    # Get-ADObject -LDAPFilter "objectClass=Contact"  -Properties mail| select Name, PrimarySMTPAddress,mail |  Export-Clixml "$wrkPath\contact.xml"

    $wrkPath = 'C:\Users\adminCM\Desktop\FABCON Data'
    Get-ADUser -Filter * -Properties * | export-clixml -path "$wrkPath\userexport_new.xml"
    # Get-ADUser -Filter * -Properties * | export-clixml -path "$wrkPath\userexport.xml"
    $h = Import-CliXml "$wrkPath\userexport_new.xml"
    $i = Import-CliXml "$wrkPath\userexport.xml"
    $h | ogv
    $i | ogv
    Compare-Object $h $i
    $h | Select Name,SCriptpath | ogv
    $i | Select Name,SCriptpath | ogv

    # Get-ADGroup -filter {Name -like "Domain A*"} -Properties Members | Export-Clixml .\groupmembers.xml
    $i = ForEach ($Grp in (Get-ADGroup -Filter *))
    {
        $Grp | Get-ADGroupMember |  Select distinguishedName,name,objectClass,objectGUID,SamAccountName,SID,@{n='Group';e={$Grp.Name}}
    }
    $i | Export-CliXml -path "$wrkPath\groupexport.xml"
    $GrpInfo = Import-CliXml "$wrkPath\groupexport.xml"
    $GrpInfo | Select Name,Group | Group-Object name | ogv

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
    $j | Export-CliXml -path "$wrkPath\shareexport_$(& HostName).xml"
    $fsInfo = Import-CliXml "$wrkPath\shareexport_$(& HostName).xml"
    $fsInfo

    Get-ADOrganizationalUnit -Filter * | 
        select name,DistinguishedName,@{n='OUPath';e={$_.distinguishedName -replace '^.+?,',''}}, `
        # select name,DistinguishedName,@{n='OUPath';e={$_.distinguishedName -replace '^.+?,(CN|OU|DC.+)','$1'}}, `
            @{n='OUNum';e={([regex]::Matches($_.distinguishedName, "OU=" )).count}} | 
        Sort OUNum | Export-CliXml "$wrkPath\OUTree.xml" # | export-csv "$wrkPath\OUTree.csv" -NoTypeInformation
    $OUs = Import-CliXml "$wrkPath\OUTree.xml"
    # ForEach ($OU in $OUs) { New-ADOrganizationalUnit -Name $OU.Name -Path $OU.OUPath }


    Get-Printer | Export-CliXml "$wrkPath\Printers.xml"
        $prt = Import-CliXml "$wrkPath\Printers.xml"
        $prt | Select Name,Location,PrinterStatus | Out-GridView
    Get-WmiObject -class win32_printer -ComputerName . | Export-CliXml "$wrkPath\PrintersWMI.xml"
        $prt2 = Import-CliXml "$wrkPath\PrintersWMI.xml"
        $prt2 | Select Caption,Location,PortName,DriverName,PrinterStatus | Out-GridView
    Get-PrinterPort | Export-CliXml "$wrkPath\PrintersPorts.xml"
        $prt3 = Import-CliXml "$wrkPath\PrintersPorts.xml"
        $prt3 | Out-GridView
    Get-PrinterDriver | Export-CliXml "$wrkPath\PrintersDriver.xml"
        $prt4 = Import-CliXml "$wrkPath\PrintersDriver.xml"
        $prt4 | Out-GridView
        $prt4 | fl
        ($prt4 | gm | ?{$_.Membertype -match 'property'}) | select @{n='Property Fields';e={$_.Name}}
    Get-PrintConfiguration -PrinterObject 
    ($f = Foreach ($Printer in (Get-Printer *))
    {
            Get-PrintConfiguration -PrinterName $Printer.name # -DuplexingMode "TwoSidedLongEdge"
    }) | Export-CliXml "$wrkPath\PrintersCfg.xml"
    $Printers = Import-CliXml "$wrkPath\PrintersCfg.xml"
    ($Printers | gm | ?{$_.Membertype -match 'property'}) | select @{n='Property Fields';e={$_.Name}}
    $Printers | OGV
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

        $r = $search.findone().Properties.GetEnumerator() | foreach -begin {$hash=@{}} -process { $hash.add($_.key,$($_.Value)) } -end {[pscustomobject]$Hash}
        $r | Select Name,Title,Department,DistinguishedName,WhenChanged,LastLogonTimeStamp
        $r | Select Name,Title,Department,DistinguishedName,WhenChanged,@{Name="LastLogon";Expression={Convert-LastLogonTimeStamp $_.lastLogonTimeStamp}}

        $all = $search.FindAll()
        $all.Count
        $all | Select Path | Out-GridView

        $disabled = Foreach ($user in $all)
        {
            $user.Properties.GetEnumerator() |
                foreach -begin {$hash=@{}} -process {
                    $hash.add($_.key,$($_.Value))
                } -end {[pscustomobject]$Hash}
        }

        $disabled | sort Department | Format-Table -GroupBy Department -Property Name, `
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
                foreach -begin {$hash=@{}} -process {
                $hash.add($_.key,$($_.Value))
                } -end {[pscustomobject]$Hash}
        }
        $inactive | Select Name,Title,Department,DistinguishedName,WhenChanged,
        @{Name="LastLogon";Expression={Convert-LastLogonTimeStamp $_.lastLogonTimeStamp}} |
        Out-Gridview -title "Last Logon"
    #endregion


    Get-GPInheritance -Target '$curDomain'

    Function Get-AllGPO
    {
        Get-GPOReport -all -ReportType xml | %{
        ([xml]$_).gpo | select name,@{n="SOMName";e={$_.LinksTo | % {$_.SOMName}}},@{n="SOMPath";e={$_.LinksTo | %{$_.SOMPath}}}
        }
    }

    #Get Gpo with name Turn* and display what OU is linked.
    Get-AllGPO | ? {$_.Name -match "Turn*"} | %{$_.SomName}
    Get-AllGPO | %{$_.SomName}



    # For those who cannot use the GPO module, get linked GPOs:

    $gpm = New-Object -ComObject GPMgmt.GPM
    $constants = $gpm.GetConstants()
    $GPODomain = $gpm.GetDomain($env:USERDOMAIN,$null,$contants.UseAnyDC)
    $GPOs = $GPODomain.SearchGPOs($gpm.CreateSearchCriteria())

    $GPOs | Foreach-Object
    {
        $gpmSearchCriteria = $gpm.CreateSearchCriteria()
        $gpmSearchCriteria.Add($constants.SearchPropertySomLinks,$constants.SearchOpContains,$_)
        $somList = $GPODomain.SearchSoms($gpmSearchCriteria)
        if($somList.Count -gt 0) {$somList.DisplayName}
    }

#endregion
#region - AD account Profile/ScriptPath Mods
    $profPath = "\\FILESVR\RoamingProfiles$\%UserName%"
    $usrsADE = Get-ADUser -Filter * -searchBase "OU=Users\, AD-East,dc=olad,dc=mil" -Properties scriptPath
    $usrsADE | where surname -eq 'bartram' | %{ set-ADUser $_ -ProfilePath $profPath -verbose }
    $profPath = "\\FILESVR_C\RoamingProfiles·$\$($_.samAccountName -replace '$' ) "


    $usrsADE = Get-ADUser -Filter * -searchBase "OU=Users,AD-East,dc=olad,dc=mil" -Properties scriptPath
    $usrsADE | sort | select Name,scriptpath | OGV -Title 'AD East user scripts'
    $usrsADE | where scriptPath -eq $null | sort | select samAccountName,Name ,scriptpath | OGV -Title 'AD East user Scripts' -PassThru | Clip
    $usrsADE | where scriptPath -ne $null | %{ Set-ADUser $_ -Scri ptPath $null -verbose }
    $usrsADE = Get-ADUser -Filter * -searchBase "OU=Users\, AD-East,dc=olad,dc=mil" -Properties scriptPath
    $usrsADE | Select samAccountName,Name ,scriptpath | sort | OGV -Title 'AD East user scripts' -PassThru | clip
    $usrsADE = Get-ADUser -Filter * -searchBase "OU=Users\, AD-East,dc=olad,dc=mil" -Properties scriptPath
    $usrsADE | %{ set-ADUser $_ -scriptPath 'KillMapped.bat' -verbose }
    $usrsADE | select samAccountName,Name,scriptpath | sort | OGV -Title 'AD East user scripts'
#endregion
#region - create AD groups
    $usrsADE = Get-ADUser -Filter * -searchBase "OU=Users\, AD-East,dc=olad,dc=mil"
    New-ADGroup -Name "gp_ADE-Users" -samAccountName gpADEUsers `
                -Groupcategory security -Groupscope Global `
                -DisplayName "AD-East Group Policy users" `
                -Path "OU=Domain Groups,DC=olad,DC=mil" `
                -Description "Members of this group run AD East affiliated Group Policies"
    Get-ADGroup -searchBase "OU=Domain Groups,DC=olad,DC=mil" -filter { name -like "gp_ADE-Users" } | Add-ADGroupMember -Members $usrsADE
    $usrsADW = Get-ADUser -Filter * -searchBase "OU=Users\, AD-West,dc=olad,dc=mil"
    New-ADGroup -Name "gp_.ADW-Users" `
                -samAccountName gpAowusers -Groupcategory security `
                -Groupscope Global -DisplayName "AD-West Group Policy users" `
                -Path "OU=Domain Groups,DC=olad,DC=mil" `
                -Description "Members of this group run AD west affiliated Group Policies"
    Get-ADGroup -searchBase "OU=Domain Groups,DC=olad,DC=mil" -filter { name -like "gp_.ADW-Users" } | Add-ADGroupMember -Members $usrsADW
#endregion
#region - AD DB Permission check (SCAP)
    # Get AD DB Info
    $DBs = Get-ItemProperty HKLM:\SYSTEM\Currentcontrolset\Services\NTDS\Parameters | select 'Database log files path','DSA working Directory','DSA Database file'
    sl $oss.'Database log files path'
    icacls *.*
    $a = '(NT AUTHORITY\SYSTEMIBUILTIN\Administrators)'
    'NT AUTHORITY\SYSTEM:(I)(F)
    BUILTIN\Administrators:(I)(F)'
    sl $oss.'DSA Database file'
    (icacls $DBS.'DSA Database file') -match 'NT AUTHORITY\SYSTEM:(I)(F)`nBUILTIN\Administrators:(I)(F)'
    Get-Acl $oss.'DSA Database file' | select -Exp Access
    Get-Acl $DBs.'Database log files path' | select -Exp Access
    Get-Acl $DBs.'DSA working Directory' | where IdentityReference -NotMatch $a | Select -Exp Access
#endregion
#region _ ADSI Searches
    (([adsisearcher]"objectCategory=Computer").FindAll()| ?{$_.Properties.OperatingSystem -match 'Server'}).Count
    (([adsisearcher]"objectCategory=Computer").FindAll()| ?{$_.Properties.OperatingSystem -notmatch 'Server'}).Count
    (([adsisearcher]"objectCategory=User").FindAll()| ?{$_.Properties.Enabled -eq $true}).Count
#endregion
