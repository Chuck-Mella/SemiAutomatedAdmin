$Module = 'fn_EvtLogs' 
$Module = 'fn_ADTools' 
$trgFunctions = ($Global:codeLib).SelectNodes("//Function") | Where Module -eq $Module #Name -eq 'Convert-Evt2XL'
$trgFilters = ($Global:codeLib).SelectNodes("//Filter") | Where Module -eq $Module
$search = $trgFunctions | select name,code | sort name
$search | select Module -Unique | Measure | Select -ExpandProperty Count
Dec64 (($search | Select Name,Code,psVer | sort name)[0]).Code.'#cdata-section'
Module      : fn_ADTools
Alias       : 
AliasCmt    : 
Tags        : IDA Functions
Date        : 2016-09
Information : Information
Code        : Code



$InitForm = "Function <FUNCNAME>`n{`n`t[GAZZLE]`n}`n`n" | Out-String
$buildForm = $null
ForEach ($srch in $search)
{
    $tmpForm = $InitForm
        $tmpForm = $tmpForm -replace '<FUNCNAME>',$($srch.Name)
        $r = "$(Dec64 ($srch.Code.'#cdata-section') | Out-String)"
        $tmpForm = $tmpForm -replace '[GAZZLE]', $R
    $buildForm = $buildForm + $tmpForm | Out-String
}
$buildForm | Clip

$srch.Information

Dec64 $trgFunctions[0].Code.'#cdata-section'
#-------------------------------------------------------------------------------------------------------------
dec64 $rgx.Help




















$search = New-Object System.DirectoryServices.DirectorySearcher
$search
$srchroot = ([adsi]"").distinguishedname -replace 'DC=nae','CN=Users'
$search.SearchRoot = [ADSI]"LDAP://$srchroot"
# Users
    $search.Filter = "(&(objectCategory=person)(objectClass=user))"
# Disabled Users
    $search.Filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"

$search.FindAll() | Select Path | where $_ -match 'brandow'


(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
(Get-WmiObject -Class Win32_ComputerSystem).Workgroup


$search | Select Name