# set target path
    Param ($logSvr, [Switch]$noADSI = $false)
    $pthLog = '\\$logSvr\log_ADinventory$'
    # collect AD Data
    # use PS cmdlets
        $all_AD = Get-ADObject -Filter * -Properties Name,DistinguishedName,objectclass,objectGUID
    # Use ASDSI
        If ($noADSI.IsPresent -eq $false)
        {
          $all_ADSI = $(
              $adsi = (New-object system.Directoryservices.Directorysearcher)
              $adsi.searchRoot = "LDAP://$(([ADSI]'' ).DistinguishedName) "
              $adsi.Pagesize = 3000
              ($adsi ).FindAll()
              )
        }

    <# collect AD objclass
        # use PS cmdlets
          $objclassl = $all-AD | select -Exp objectclass -unique | sort
        # Use ASDSI
          If ($noADSI.IsPresent -eq $false){  $objclass2 = $all_ADSI | %{$_.Properties.objectclass} | select -unique | sort }
        # compare-object $objclassl $objclass2
        # compare object counts
          ($all-AD | Measure | select count).count -eq ($all_ADSI | Measure | selectcount).count
        # Review AD Data (searchable)
          $all_AD | select Name,oistinguishedName,objectclass,objectGUID | OGV
          If ($noADSI.IsPresent -eq $false){ $all_ADSI | OGV }
    #>
    # save Reports
        $all_AD | Export-clixml -Path "$pthlog\AD-Dump_$(Get-Date -f yyyy-MM-dd_HHmm).xml"
        If ($noADSI.IsPresent -eq $false){ $all_ADSI | Export-clixml -Path "$pthLog\ADSI-Dump_$(Get-Date -f yyyy-MMdd_HHmm).xml" }
