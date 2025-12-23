Param
(
    $curDomain = ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain())
)
$InstallationsDN = @(@{domain=$curDomain.Name;server=$curDomain.PdcRoleOwner;groups=@();})
Import-Module ActiveDirectory

$excel = New-Object -ComObject Excel.Application
$excel.Visible = $true
$workbook = $excel.Workbooks.Add()
$workbook.Worksheets.Add()
$sheet = $workbook.Worksheets.Item(2)
$sheet.name = "Log"
$workbook.Worksheets.Item("Log").cells.Item(1,1) = "GPO"
$workbook.Worksheets.Item("Log").cells.Item(1,2) = "Error"
$countRow=2
$sheet = $workbook.Worksheets.Item(1)
$sheet.name = "Installations"
$workbook.Worksheets.Item("Installations").cells.Item(1,1) = "Installation"
$workbook.Worksheets.Item("Installations").cells.Item(1,2) = "Brigade"
$workbook.Worksheets.Item("Installations").cells.Item(1,3) = "RNEC"
$workbook.Worksheets.Item("Installations").cells.Item(1,4) = "Count"
$workbook.Worksheets.Item("Installations").cells.Item(1,5) = "User # No Encryption"
$workbook.Worksheets.Item("Installations").cells.Item(1,6) = "User # AES 256"
$workbook.Worksheets.Item("Installations").cells.Item(1,7) = "User # AES 128"
$workbook.Worksheets.Item("Installations").cells.Item(1,8) = "User # All Encryption"
$workbook.Worksheets.Item("Installations").cells.Item(1,9) = "User # Unknown Encryption"
$sheet.columns.item("A").columnWidth = 20
$sheet.columns.item("B").columnWidth = 15
$sheet.columns.item("C").columnWidth = 20
$sheet.columns.item("D").columnWidth = 15
$sheet.columns.item("E").columnWidth = 18.86
$sheet.columns.item("F").columnWidth = 13
$sheet.columns.item("G").columnWidth = 13
$sheet.columns.item("H").columnWidth = 18.71
$sheet.columns.item("I").columnWidth = 25

function Get-CustomADObject($SearchBase,$Filter,$SearchScope)
{
	try
	{
		$objDomain = New-Object System.DirectoryServices.DirectoryEntry
		$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		$objSearcher.SearchRoot = [adsi]"LDAP://$SearchBase"
        If ($Filter -eq "(&(objectCategory=Person)(objectClass=User))") {
            $ADPropertiesToLoad = '"name"'
            #$ADPropertiesToLoad = '"name","msDS-SupportedEncryptionTypes"'
        }
        Elseif ($Filter -eq "(objectCategory=OrganizationalUnit)") {
            $ADPropertiesToLoad = '"Name"'
        }
		$objSearcher.PageSize = 1000
		$catch = $objSearcher.PropertiesToLoad.Add($ADPropertiesToLoad)
        #$catch = $objSearcher.PropertiesToLoad.Add("Name")

		$objSearcher.Filter = $Filter

		$objSearcher.SearchScope = $SearchScope
	return $objSearcher.FindAll()
	}
	catch [System.Exception]
	{
        Write-Error "Unable to find object with filter: $Filter" 
		return

	}
}

function Get-ADSIObject
{
    param(
        $SearchBase = $((New-Object System.DirectoryServices.DirectoryEntry).DistinguishedName),
        $Filter,
        [ValidateSet("Base","OneLevel","Subtree")]
        $SearchScope,
        $Properties,
        [ValidateRange(1,1000)]
        $PageSize=100,
        $ResultSetSize=0
    )
    try
    {
        $adSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $adSearcher.SearchRoot = [adsi]"LDAP://$SearchBase"
        $adSearcher.PageSize = $PageSize
        $adSearcher.Filter = $Filter
        $adSearcher.SearchScope = $SearchScope
        $adSearcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All
        if($ResultSetSize -gt 0)
        {
            $adSearcher.SizeLimit = $ResultSetSize
        }
        #foreach($property in $Properties)
        #{
        #    $adSearcher.PropertiesToLoad.Add($property) | Out-Null
        #}
        $adObjects = $adSearcher.FindAll()
        #return $adSearcher.FindAll()
        $returnObjects = @()
        foreach($adobj in $adObjects)
        {
        $adobj
            $obj = New-Object -TypeName PSObject
            foreach($key in $adobj.Properties.PropertyNames)
            {
                $obj | Add-Member -MemberType NoteProperty -Name $key -Value $($adobj.Properties[$key])
            }
            $returnObjects += $obj
        }
        return $returnObjects
    }
    catch [System.Exception]
    {
        return $_.Exception.Message
    }
}

foreach ($Domain in $InstallationsDN)
{
	$Filter = "(objectCategory=OrganizationalUnit)"
	#$InstallationOUs = Get-CustomADObject -Filter $Filter -SearchBase "OU=Installations,dc=$DomainName,dc=ds,dc=army,dc=mil" -SearchScope OneLevel -Properties
    $OUs = Get-ADSIObject -filter $Filter -Server $Domain.server -SearchBase ("OU=Installations,DC=" + $domain.domain + ",DC=ds,DC=army,DC=mil") -SearchScope OneLevel
	foreach ($OU in $OUs)
	{
        $OU
		$OUName = $OU.properties.name.trim()
		If ($OUName -eq "_DisabledUsers"){ }
		Elseif ($OUName -eq "_DoDVisitor"){ }
		Elseif ($OUName -eq "_Inprocessing"){ }
		Elseif ($OUName -eq "_Outprocessing"){ }
		Elseif ($OUName -eq "SKIPOU"){ }
		Elseif ($OUName -eq "ETC"){ }
		Else
		{
			If ($OUName -eq "Buchanan" -or $OUName -eq "Devens" -or $OUName -eq "Dix" -or $OUName -eq "Drum" -or $OUName -eq "Hamilton" -or $OUName -eq "Natick R&D Center" -or $OUName -eq "Picatinny Arsenal" -or $OUName -eq "Watervliet Arsenal"){
				$RNEC = "NorthEast"
				$BDE = "93SB"
			}
			If ($OUName -eq "Campbell" -or $OUName -eq "Knox" -or $OUName -eq "Blue Grass AD" -or $OUName -eq "Crane AAA"){
				$RNEC = "Bluegrass"
				$BDE = "93SB"
			}
			If ($OUName -eq "Bragg"){
				$RNEC = "Fort Bragg"
				$BDE = "93SB"
			}
			If ($OUName -eq "Aberdeen PG" -or $OUName -eq "Carlisle Barracks" -or $OUName -eq "Detrick" -or $OUName -eq "Adelphi Lab Center" -or $OUName -eq "Letterkenny AD" -or $OUName -eq "Tobyhanna AD"){
				$RNEC = "MidAtlantic"
				$BDE = "93SB"
			}
			If ($OUName -eq "NCR" -or $OUName -eq "Meade"){
				$RNEC = "National Capital Region"
				$BDE = "93SB"
			}
			If ($OUName -eq "Eustis" -or $OUName -eq "Lee"){
				$RNEC = "SouthAtlantic"
				$BDE = "93SB"
			}
			If ($OUName -eq "Benning" -or $OUName -eq "Gordon" -or $OUName -eq "Jackson" -or $OUName -eq "Stewart" -or $OUName -eq "Goose Creek CEG-A"){
				$RNEC = "SouthEast"
				$BDE = "93SB"
			}
			If ($OUName -eq "Garrison-Michigan" -or $OUName -eq "Rucker" -or $OUName -eq "Redstone Arsenal" -or $OUName -eq "Rock Island Arsenal" -or $OUName -eq "Pine Bluff Arsenal"){
				$RNEC = "Central"
				$BDE = "106SB"
			}
			If ($OUName -eq "Bliss"){
				$RNEC = "Fort Bliss"
				$BDE = "106SB"
			}
			If ($OUName -eq "Hood"){
				$RNEC = "Fort Hood"
				$BDE = "106SB"
			}
			If ($OUName -eq "Lewis1"){
				$RNEC = "Lewis-McChord"
				$BDE = "106SB"
			}
			If ($OUName -eq "Leonard Wood" -or $OUName -eq "Leonard Wood" -or $OUName -eq "Riley" -or $OUName -eq "McCoy"){
				$RNEC = "Midwest"
				$BDE = "106SB"
			}
			If ($OUName -eq "Huachuca" -or $OUName -eq "Sill" -or $OUName -eq "Sam Houston" -or $OUName -eq "Polk" -or $OUName -eq "Yuma PG" -or $OUName -eq "Corpus Christi AD" -or $OUName -eq "Red River AD" -or $OUName -eq "McAlester AAP" -or $OUName -eq "White Sands"){
				$RNEC = "SouthWest"
				$BDE = "106SB"
			}
			If ($OUName -eq "Irwin" -or $OUName -eq "Carson" -or $OUName -eq "Monterey" -or $OUName -eq "Dugway PG" -or $OUName -eq "Tooele AD" -or $OUName -eq "Hunter Liggett" -or $OUName -eq "Sierra AD" -or $OUName -eq "Hawthorne AD" -or $OUName -eq "Tooele AD" -or $OUName -eq "Camp Roberts"){
				$RNEC = "West"
				$BDE = "106SB"
			}
			$UserCount=0
            $UserCountAES256=0
            $UserCountAES128=0
            $UserCountNoEncryption=0
            $UserCountAllEncryption=0
            $UserCountNotKnownEncryption=0
			$OUPath = $OU.distinguishedName
			$Filter = "(&(objectCategory=Person)(objectClass=User))"
			#$Users = Get-CustomADObject -Filter $Filter -SearchBase $OUPath -SearchScope Subtree -Properties
            $OUPath
            $Users = Get-ADSIObject -filter $Filter -Server $Domain.server -SearchBase $OUPath -SearchScope Subtree
			foreach ($User in $Users)
			{
                $User
                $UserEncryption = $($user.'msDS-SupportedEncryptionTypes')
				$UserCount=$UserCount+1
                If ($UserEncryption -eq 0){
                    $UserCountNoEncryption=$UserCountNoEncryption+1
                }
                elseIf ($UserEncryption -eq 16){
                    $UserCountAES256=$UserCountAES256+1
                }
                elseIf ($UserEncryption -eq 8){
                    $UserCountAES128=$UserCountAES128+1
                }
                elseIf ($UserEncryption -eq 24){
                    $UserCountAllEncryption=$UserCountAllEncryption+1
                }
                else {
                    $UserCountNotKnownEncryption=$UserCountNotKnownEncryption+1
                }
			}
			#$computers = (get-adcomputer -filter * -searchbase $ou.distinguishedname -Server $DC).count
            #$sheet.cells.item($countRow,1).FormulaLocal = $OUName
			$workbook.Worksheets.Item("Installations").cells.Item($countRow,1) = $OUName
			$workbook.Worksheets.Item("Installations").cells.Item($countRow,2) = $BDE
			$workbook.Worksheets.Item("Installations").cells.Item($countRow,3) = $RNEC
			$workbook.Worksheets.Item("Installations").cells.Item($countRow,4) = $UserCount
            $workbook.Worksheets.Item("Installations").cells.Item($countRow,5) = $UserCountNoEncryption
            $workbook.Worksheets.Item("Installations").cells.Item($countRow,6) = $UserCountAES256
            $workbook.Worksheets.Item("Installations").cells.Item($countRow,7) = $UserCountAES128
            $workbook.Worksheets.Item("Installations").cells.Item($countRow,8) = $UserCountAllEncryption
            $workbook.Worksheets.Item("Installations").cells.Item($countRow,9) = $UserCountNotKnownEncryption
			$countRow=$countRow+1
		}
		$BDE=""
		$RNEC=""
	}
}

$workbook.SaveAs("$([Environment]::GetFolderPath('Desktop'))\GetUserCounts.xlsx")
$workbook.Close
$excel.Quit()
