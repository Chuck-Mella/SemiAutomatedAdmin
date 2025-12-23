# The Function of this script is to gather data on Stale User and Computer Objects. 
#
# Granted to : Maj Thomas Styles // US Army // 7th Signal Command on 11/4/2017.
#
# Author: Jake Dean // Microsoft Premier Field Engineer // On behalf of 7th Signal Command, US Army 
#
# Microsoft Corporation. All rights reserved. This sample script is not supported under   
# Microsoft standard support program or service. The sample scripts are provided AS IS without 
# warranty of any kind. Microsoft disclaims all implied warranties including, without limitation, 
# any implied warranties of merchantability or of fitness for a particular purpose. The entire risk 
# arising out of the use or performance of the sample scripts and documentation remains with you. 
# In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or 
# delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages
# for loss of business profits, business interruption, loss of business information, or other pecuniary 
# loss) arising out of the use of or inability to use the sample scripts or documentation, even if 
# Microsoft has been advised of the possibility of such damages.
#
# Version 1.0
#

[CmdletBinding]

Function Get-StaleObjects {
    
    [CmdletBinding()]
    Param(
    $filePath = "$($env:userprofile)\Desktop\StaleObjectData",
    $Stale_Date = 45
    )
    
    #format date
    $stale_date = [DateTime]::Today.AddDays(-$staledate)
    #delete results if already exist
    If ($(Try { Test-Path $filePath} Catch { $false })){Remove-Item $filePath -force}
    
    $filepath = "$env:userprofile\desktop\Stale Objects Data"
    $ChildDomains = @("DAHQ.DS.ARMY.MIL","NANW.DS.ARMY.MIL","NAE.DS.ARMY.MIL","NASE.DS.ARMY.MIL","NASW.DS.ARMY.MIL")
    [int]$TotalStaleComputers = 0
    [int]$TotalStaleUsers = 0
        
    #these hashtables are used to populate a calculated property to determine if the account is stale
    $hash_isComputerStale = @{Name="StaleComputer";
    Expression={if(($_.LastLogonTimeStamp -lt $stale_date.ToFileTimeUTC() -or $_.LastLogonTimeStamp -notlike "*") `
        -and ($_.pwdlastset -lt $stale_date.ToFileTimeUTC() -or $_.pwdlastset -eq 0) `
        -and ($_.enabled -eq $true) -and ($_.whencreated -lt $stale_date) `
        -and ($_.IPv4Address -eq $null) -and ($_.OperatingSystem -like "Windows*") `
        -and (!($_.serviceprincipalnames -like "*MSClusterVirtualServer*"))){$True}else{$False}}}
     
    $hash_isUserStale = @{Name="StaleUser";
    Expression={if(($_.LastLogonTimeStamp -lt $stale_date.ToFileTimeUTC() -or $_.LastLogonTimeStamp -notlike "*") `
        -and ($_.pwdlastset -lt $stale_date.ToFileTimeUTC() -or $_.pwdlastset -eq 0) `
        -and ($_.enabled -eq $true) -and ($_.whencreated -lt $stale_date) `
        -and ($_.rank -notlike "*Col*,*Gen*,*GS15*" )){$true}else{$false}}}
    
    
    #this hashtable is used to create a calculated property that converts pwdlastset
    $hash_pwdLastSet = @{Name="pwdLastSet";
    Expression={([datetime]::FromFileTime($_.pwdLastSet))}}
     
    #this hashtable is used to create a calculated property that converts lastlogontimestamp
    $hash_lastLogonTimestamp = @{Name="LastLogonTimeStamp";
    Expression={([datetime]::FromFileTime($_.LastLogonTimeStamp))}}
     
    #this hashtable is used to create a calculated property to display domain of the computer
    $hash_domain = @{Name="Domain";
    Expression={$childdomain}}
    
    function Get-CustomADObject($SearchBase,$Filter,$SearchScope) {
	    try {
		        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
		        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
		        $objSearcher.SearchRoot = [adsi]"LDAP://$SearchBase"
		        $objSearcher.PageSize = 1000
		        $catch = $objSearcher.PropertiesToLoad.Add("name")
		        $objSearcher.Filter = $Filter
		        $objSearcher.SearchScope = $SearchScope
	        return $objSearcher.FindAll()
	        }
    	    catch [System.Exception] {                Write-Error "Unable to find object with filter: $Filter" 
	        	return
	        }
        }

    Function Get-StaleComputers {
        $datatype = "StaleComputers"
        
        Write-Verbose "Retrieiving Computer Objects at $Installation that have not been logged into for more than 45 days" 
    
        get-adcomputer -filter {isCriticalSystemObject -eq $False} `
            -properties PwdLastSet,whencreated,SamAccountName,LastLogonTimeStamp,Enabled,IPv4Address,operatingsystem,serviceprincipalnames `
            -server $childdomain |
            Select-Object $hash_domain,SamAccountName,enabled,operatingsystem,IPv4Address,`
                    $hash_isComputerStale,$hash_pwdLastSet,$hash_lastLogonTimestamp | `
            Export-Csv -path "$filePath\$ChildDomain\$DataType.csv" -notypeinformation -Append
        
        $staleComputerCount = @((get-content "$filepath\$Childdomain\$datatype.csv").count -1 )
        [int]$TotalStaleComputers = $TotalStaleComputers + $staleComputerCount 
        Write-Verbose -Verbose "Stale User Query of $childdomain completed successfully." 
        Write-Verbose "$stalecomputercountCount accounts from $Installation were placed in $filepath\$Domain\$Installation - $datatype.csv" 
        Write-Verbose "Total Stale User Accounts Found is now $TotalStaleComputers" 
        }
    
    Function get-StaleUsers {
    
        $datatype = "StaleUsers"
    
        Write-Verbose "Retrieiving User Objects in $Installation OU.  that have not been logged into for more than 45 days" 
        
        Get-ADSIObject -filter {&(objectCategory=Person)(objectClass=User)`
            (LastLogonTimeStamp -lt $stale_date) -or (LastLogonTimeStamp -notlike "*")`
            -and ((pwdlastset -lt $stale_date -or pwdlastset -eq 0) -and `
            (enabled -eq $true)) -and (ServicePrincipalName -notlike "*")}
            -Searchbase "OU=Installations,OU=NASE,OU=DS,OU=ARMY,OU=MIL"
            -Seachscope Subtree
            #-properties PwdLastSet,whencreated,SamAccountName,name,LastLogonTimeStamp,Enabled,serviceprincipalname
            -server $dc
            Select-Object $hash_domain,name,enabled,operatingsystem,IPv4Address,whencreated,$hash_isUserStale,$hash_pwdLastSet,$hash_lastLogonTimestamp | `
            Export-Csv -path "$filePath\$ChildDomain\$DataType.csv" -notypeinformation -Append
        
        $StaleUserCount = @(get-content "$filepath\Childdomain\$datatype.csv").count
        [int]$TotalStaleComputers = $TotalStaleComputers + $StaleUserCount 
        Write-Verbose "Stale User Query of $childdomain completed successfully." 
        Write-Verbose "$StaleUsercountCount accounts from $Installation were placed in $filepath\$Installation $datatype" 
        Write-Verbose "Total Stale User Accounts Found is now $TotalStaleComputers" 
        }
    
        Function Merge-CSVFiles { 
            [cmdletbinding()] 
            param() 
            
            Write-Verbose "Creating Final Reports in $FilePath"
            Import-CSV (Get-ChildItem -Path "$filepath\*\StaleUsers.csv") | Export-CSV "$filepath\Final Computer Report.csv" 
            Import-CSV (Get-ChildItem -Path "$filepath\*\StaleComputers.csv") | Export-CSV "$filepath\Final User Report.csv"
            Write-Verbose "Final Reports created Successfully."
        
        }

    #Create directory for stale objects reports
    Write-Verbose "Creating File Repository for Stale Objects Data at $filepath" 
    New-Item -itemtype directory -path $filepath -Force
    Write-Verbose "File directory $filepath created successfully." 
     
    #Create Child Domain Variables and test connection
    
    Foreach ($Childdomain in $Childdomains) {

	If ($ChildDomain -eq "NAE.DS.ARMY.MIL") {
		$DC = "BRAGA1NEVXD0001.nae.ds.army.mil"
        $Base = "OU=Installations,DC=nae,dc=ds,dc=army,dc=mil"
	}
	Elseif ($ChildDomain -eq "NASE.DS.ARMY.MIL") {
		$DC = "BRAGA1SEVXD0001.nase.ds.army.mil"
        $Base = "OU=Installations,DC=nase,dc=ds,dc=army,dc=mil"
	}
	Elseif ($ChildDomain -eq "NANW.DS.ARMY.MIL") {
		$DC = "BRAGA1NWVXD0001.nanw.ds.army.mil"
        $Base = "OU=Installations,DC=nanw,dc=ds,dc=army,dc=mil"
	}
	Elseif ($ChildDomain -eq "NASW.DS.ARMY.MIL") {
		$DC = "BRAGA1SWVXD0001.nasw.ds.army.mil"
        $Base = "OU=Installations,DC=nasw,dc=ds,dc=army,dc=mil"
	}
	Elseif ($ChildDomain -eq "DAHQ.DS.ARMY.MIL") {
		$DC = "BRAGA1HQVXD0001.dahq.ds.army.mil"
        $Base = "OU=Installations,DC=dahq,dc=ds,dc=army,dc=mil"
	}

    #$DomainDistinguishedName = (get-addomain $childdomain).distinguishedname
    #$DC = ((Get-ADDomainController -Discover -Domain "$childdomain" ).name + "." +"$childdomain" )
    #$InstallationName = ("OU=Installations," + "$DomainDistinguishedName") 
    $Filter = "(objectCategory=OrganizationalUnit)"
    $Installations = Get-CustomADObject -Filter $Filter -SearchBase $Base -SearchScope OneLevel -Properties
    $ConnectionTest = Test-connection -computername $DC -BufferSize 16 -Count 1 -Quiet 


    If ( $Connectiontest = $True) {

        Write-Verbose "Testconnection to $childdomain successful!" 
        Write-Verbose "Creating File Repository for $Childdomain Stale Objects Data at $filepath\$Childdomain" 
        New-Item -itemtype directory -path $filepath\$ChildDomain -force
        Write-Verbose "File directory $filepath\$childdomain created successfully." 

#Create Installation Variables and begin query

        Foreach ( $Installation in $Installations ) {
            $InstallationName = $Installation.properties.name
            $Searchbase = "OU=$InstallationName,$Base"
            $UserFilter = "(objectCategory=User)"
            $Computerfilter = "(ObjectCategory=Computer)"

            Write-Verbose "Retrieiving Total User and Computer Objects $Installation." 
            $usercount = ( Get-ADSIObject -filter $userfilter -Server $DC -SearchBase $Seachbase -SearchScope Subtree).count 
            $computercount = (Get-ADSIObject -filter $Computerfilter -SearchBase $Searchbase -SearchScope Subtree).count 
            [int]$TotalComputerAccounts = $TotalComputerAccounts += $TotalStaleComputers
            #Retrieve Stale User Accounts From each Installation
            
            If ($Usercount -eq "0") { Write-Verbose "No User Objects in $Installation." }
            Else { Get-StaleUsers -Verbose }

            If( $ComputerCount -eq "0" ) { Write-Verbose "No Computer Objects in $Installation." }
            Else { Get-StaleComputers -Verbose } 
        }
    
    }
            
        Else { 
            Write-Verbose "Connection to $Childdomain Failed. Moving to next Domain." 
        }

    }

    Merge-CSVFiles -Verbose

}    

Function Merge-CSVFiles { 
    [cmdletbinding()] 
    param() 
    
    Write-Verbose "Creating Final Reports in $FilePath"
    Import-CSV (Get-ChildItem -Path "$filepath\*\StaleUsers.csv") | Export-CSV "$filepath\Final Computer Report.csv" 
    Import-CSV (Get-ChildItem -Path "$filepath\*\StaleComputers.csv") | Export-CSV "$filepath\Final User Report.csv"
    Write-Verbose "Final Reports created Successfully."

}

Get-Staleobjects -verbose

Write-Host "Inactive Object Search Completed. Total of $TotalStaleUsers stale users and $TotalStaleComputers stale  computers found." 
