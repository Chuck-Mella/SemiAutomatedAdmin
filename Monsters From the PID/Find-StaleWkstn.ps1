Param
(
    $DaysInactive = 10,
    [Switch]$AD
)
$sr = 'LDAP://OU=ASD,OU=MISCELLANEOUS,OU=Belvoir,OU=National Capital Region,OU=Installations,'+([adsi]'').distinguishedname
$time = (Get-Date).Adddays(-($DaysInactive))
$deadline = $time.ToFileTime()
$outFile = “$([Environment]::GetFolderPath('Desktop'))\Stale-Computers.CSV”
Switch ($AD.IsPresent)
{
    $false 
    {   # ADSI
        ($all = [adsisearcher]"(&(objectclass=computer))").SearchRoot = $sr
        $tmp = $all.FindAll()
        $rslt = ($tmp | Where { $_.Properties.lastlogontimestamp -le $deadline }).Properties |
            Select @{n='Name';e={$_.cn}},
                   @{n='OS';e={$_.operatingsystem}},
                   @{n='SaM';e={$_.samaccountname}},
                   @{n='Fqdn';e={$_.distinguishedname}},
                   @{n='LastLogon';e={$_.lastlogontimestamp}} | Sort LastLogon
        $rslt | %{ $_.LastLogon = [DateTime]::FromFileTime($_.LastLogon) }
        $rslt | Export-CSV $outFile –NoTypeInformation -Force
        If ((Get-Host).Name -match 'ISE'){ $rslt | OGV -Title "$($rslt.Count) Stale Workstations found" }
    }
    $true
    {   #  AD Cmdlets
        Import-Module ActiveDirectory
        ($rslt = Get-ADComputer -Filter {LastLogonTimeStamp -lt $time} -Properties Name, OperatingSystem, SamAccountName, DistinguishedName) | Export-CSV $outFile –NoTypeInformation
        If ((Get-Host).Name -match 'ISE'){ $rslt | OGV -Title "$($rslt.Count) Stale Workstations found" }
    }
}
