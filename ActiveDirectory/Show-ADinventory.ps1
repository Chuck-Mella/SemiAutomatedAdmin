Param ($logSvr, [Switch]$noADSI = $false)
# set target path
    $pthLog = '\\$logSvr\log_ADinventory$'
# collect AD Data
# use PS cmdlets
    $all_AD = Get-ADObject -Filter * -Properties Name, DistinguishedName ,objectclass ,objectGUID
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
    <#
        # collect AD objclass
        # use PS cmdlets
            $objclassl = $all-AD | select -Exp objectclass -unique 1 sort
        # Use ASDSI
            If ($noADSI.IsPresent -eq $false){ $objclass2 = $all_ADSI | %{$_.Properties.objectclass} | select -unique | sort }
            If ($noADSI.IsPresent -eq $false){  compare-object $objclassl $objclass2 }
        # compare object counts
            ($all_AD | Measure Select count).Count -eq (Sall_ADSI | Measure | select count).count
        # Review AD Data (searchable)
            $all_AD | select Name,DistinguishedName,Objectclass,objectGUID | OGV
            If ($noADSI.IsPresent -eq $false){ $all_ADSI | OGV }
    #>
# save Reports
    $all_AD | Export-clixml -Path "$P,thLog\AD-Dump_$(Get-Date -f yyyy-MM-dd_HHmm).xml"
    If ($noADSI.IsPresent -eq $false){ $all_ADSI | Export-Clixml -Path "$pthLog\ADSI-Dump_$(Get-Date -f yyyy-MMdd_HHmm).xml" }
# set target path
    $pthLog = '\\LOGSERVER\log_ADinventory$ '
#collect AD Data
    # Import most recent data
    $all_AD = Import-clixml -Path (GCI $pthLog -Filter AD-*.xml | sort -Desc | Select -First 1 ).FullName
    If ($noADSI.IsPresent -eq $false){ $all_ADSI = Import-clixml -Path (GCI $pthLog -Filter ADSI-*. xml | sort -Desc |select -First 1 ).FullName }
# Review AD Data (Searchable)
    switch (GWMI win32_operatingsystem | select -Exp ProductType)
    {
        2
        {
            # 2-DC
            $Test = $all_AD | OGV -Title "All AD objects ( $($all_AD.count) objects)" -
            PassThru
            ($t2 = Get-aduser $Test.objectGUID) | OGV -Title "object Properties ( $( $t2.samaccountname) )" -PassThru | clip
        }
        default
        {
            # 1-workstation, 3-MemberServer
            If ($noADSI.IsPresent -eq $false){ 
                $Test = ($all_ADSI) | OGV -Titl e "All ADSI Objects ( $($all_ADSI. Count) objects)" -PassThru
                $Test | select -Exp Properties | OGV -Title "object Properties ( $($Test.properties.samaccountname) )" -PassThru | clip
                }
        }
    }
