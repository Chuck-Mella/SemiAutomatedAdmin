function Test-FQDN([string]$FQDN)
{
    $regex = '^(?=.{1,253}\.?$)(?:(?!-|[^a-zA-Z0-9-]{2,})[a-zA-Z0-9-]{1,63}(?<!-)\.)+(?:[a-zA-Z]{2,63}|\d{1,3})$'
    if ($FQDN -match $regex) { return $true } else { return $false }
}
function Test-IPv4([string]$IP)
{
    $regex = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
    if ($IP -match $regex) { return $true } else { return $false }
}

# Example usage
$fqdn1 = "example.com"
$fqdn2 = "subdomain.example.co.uk"
$fqdn3 = "invalid_fqdn"
$IP1 = "192.168.1.1"
$IP2 = "2001:db8:3333:4444:5555:6666:7777:8888"
$IP3 = "::1"

Test-FQDN -FQDN $fqdn1 # Returns True
Test-FQDN -FQDN $fqdn2 # Returns True
Test-FQDN -FQDN $fqdn3 # Returns False
Test-FQDN -FQDN one.2.3.4.5.6.seven.com
Test-IPv4 -IP $IP1
Test-IPv4 -IP $IP2
Test-IPv4 -IP $IP3
Test-IPv4 -IP 1.2.3.4

[ValidateSet('BLACKNET','FBINET','SCINET','TACNET','UDMZ','UNET')]$Enclave
[ValidateSet('A','AAAA','CNAME','NS','MX','SRV')]$RecType
[ValidateSet('ADD','DEL')]$RecType
[ValidateSet($True,$False)]$Cre8Ptr
[ValidateSet($True,$False)]$AllwAuthUsrUpd
[ValidatePattern(REGEX"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")]$FLookup = 1.2.3.4




# \\fbi.gov\public\Software\Server Team\DNS\Scripts\DNSBackup
#region - HA Cluster
    # Replace the values of these variables
        $HyperVClusterName = "Compute01"
        $HyperVObjectADGroupSamName = "Hyper-VServerComputerAccounts" <#No spaces#>
        $ScriptFolder = "C:\Scripts\SetupSMBSharesWithHyperV"

    # Start of script itself
        CD $ScriptFolder
        .\ADGroupSetup.ps1 -HyperVObjectADGroupSamName $HyperVObjectADGroupSamName -HyperVClusterName $HyperVClusterName



    # Replace the values of these variables
        $StorageClusterName = "StorageSpacesDirect1"
        $HyperVObjectADGroupSamName = "Hyper-VServerComputerAccounts" <#No spaces#>
        $SOFSName = "SOFS"
        $SharePrefix = "Share"
        $ScriptFolder = "C:\Scripts\SetupSMBSharesWithHyperV"

    # Start of the script itself
        CD $ScriptFolder
        Get-ClusterSharedVolume -Cluster $StorageClusterName | ForEach-Object {
            $ShareName = $SharePrefix + $_.SharedVolumeInfo.friendlyvolumename.trimstart("C:\ClusterStorage\Volume")
            Write-host "Creating share $ShareName on "$_.name "on Volume: " $_.SharedVolumeInfo.friendlyvolumename
            .\FileShareSetup.ps1 -HyperVClusterName $StorageClusterName -CSVVolumeNumber $_.SharedVolumeInfo.friendlyvolumename.trimstart("C:\ClusterStorage\Volume") -ScaleOutFSName $SOFSName -ShareName $ShareName -HyperVObjectADGroupSamName $HyperVObjectADGroupSamName
        }
#endregion
#region - Test-DNSServerV2
    # Define the OU to search
    $OU = "OU=Domain Controllers,DC=FBI,DC=GOV"

    #Output File
    $outputFile = "C:\temp\DNS_Results.txt"

    # Initialize the output file
    "" | Out-File -FilePath $outputFile

    # Write the header for the output
    "Computer Name: IPAddress: Result: RoundTripTime: TcpTried: UdpTried:" | Out-File -FilePath $outputFile -Append

    # Define the service name to restart
    $serviceName = "DNS Server"

    # Get all computer objects in the specified OU
    $computers = Get-ADComputer -Filter * -SearchBase $OU -Property Name, IPV4Address

    #Iterate through each computer object and add its IPv4 address to the array
    foreach ($computer in $computers) {
        $ipAddress = $computer.IPv4Address

        #Run the DNS test
        $dnsTestResult = Test-DnsServer -IPAddress $ipAddress

        #Format the results
        $resultLine = "$($computer.Name),$ipAddress,$($dnsTestResult.Result),$($dnsTestResult.RoundTripTime),$($dnsTestResult.TcpTried),$($dnsTestResult.UdpTried)"

        #Write the result line to the output file
        $resultLine | Out-File -FilePath $outputFile -Append

    # Check the result and prompt for confirmation to restart the service if not Success
    if ($dnsTestResult.Result -ne "Success") {
        Write-Host "DNS test failed for $($computer.Name) with IP $ipAddress."
        
        # Prompt for confirmation
        $confirmation = Read-Host "Do you want to restart the 'DNS Server' service on $($computer.Name)? (Y/N)"

        if ($confirmation -eq 'Y') {
            try {
                # Restart the DNS Server service on the remote computer
                 Invoke-command -ComputerName $computer.Name -ScriptBlock {
                    param($serviceName)
                    Restart-Service -Name $ServiceName
                } -ArgumentList $serviceName

                Write-Host "Service '$serviceName' restarted on $($computer.Name)"
            } catch {
                write-Host "Failed to restart service $serviceName on $($computer.Name). Error: $_"
            }
        } else {
            Write-Host "Skipped restarting service on $($computer.Name)"
        }
      }
    }

    Write-Host "Results have been saved to $outputFile"

    #Ignore AzureADKerberos in the results

#endregion
#region - Create DNS Records from a CSV -A and CNames
    #-----------DNS Record Creation------------
    #        Created: 8/15/2024 - Andrew Carter
    #       Modified: 8/21/2024 - Andrew Carter
    # Current Verion: 1.01 - updated notes and domc
    #        Version: 1.00 - first draft
    #
    #
    #     This script should add various types of DNS records if 
    #     the file if formated correctly.
    #    Columns = ZoneName | RecordName | RecordType(A/Cname) | RecordData (example: IPAddress)
    #-------------------------------------------

    # The CSV will need the following columns:
    # zonename | recordname | recordtype | record data
    # Grab the information from the CSV
    $csv = Import-Csv -Path "C:\Users\You\Downloads\dnscsvtest.csv"
    # Import CSV ALREADY ASSUMES THERE IS A HEADER AND USES IT TO CREATE THE PROPERTIES FOR EACH COLUMN!!!!!
    $dnsserver = "hqd2-udomc-201"

    # Loop through each record in the CSV
    foreach ($record in $csv) {
        $zonename = $record.ZoneName
        $recordname = $record.RecordName
        $recordtype = $record.RecordType
        $recordData = $record.RecordData

    # Check if the DNS zone exists, if not create
        $zone = Get-DnsServerZone -ComputerName $dnsserver -Name $zonename -ErrorAction SilentlyContinue
            if (-not $zone) {
            Add-DnsServerPrimaryZone -ComputerName $dnsserver -Name $zonename -ReplicationScope Domain
            Write-Host "Created DNS zone: $zonename" -ForegroundColor Green
            }
    # Check if the record exists, if not create
        $dnsrecord = Get-DnsServerResourceRecord -ComputerName $dnsserver -ZoneName $zonename -Name $recordname -ErrorAction SilentlyContinue
            if (-not $dnsrecord) { # Looks for Recordtype
                switch ($recordtype) {
                "A" { 
                    Add-DnsServerResourceRecordA -ComputerName $dnsserver -ZoneName $zonename -Name $recordname -IPv4Address $recorddata
                    Write-host "Added A record: $recordname in zone: $zonename"
                    }
                "CNAME" {
                    Add-DnsServerResourceRecordCName -ComputerName $dnsserver -ZoneName $zonename -Name $recordname -HostNameAlias $recordData
                    Write-Host "Added CNAME record: $recordname in zone: $zonename"
                    }
                }
            } else {
            Write-Host "DNS record $recordname already exists in zone: $zonename" -ForegroundColor Yellow
            }
        }
#endregion
#region - DNSBackup
    # Pre Requisites of script are that this needs to be run as administrator, you must create your folder structure that you wish to back up DNS files to and replace C:\Path\to\folder within script accordingly.
    # Version 1.0 1/10/2022 Created by HQ-T3-Windows Server Operating System Team | contact jldaines@fbi.gov for questions/assistance

    $date= Get-Date -Format yyyyMMdd

    $a= { 
    
        $ZoneList = Get-DNSServerZone | Where-Object{$_.ZoneType -eq "Primary"} | Select ZoneName

        # Creates Directory needed for local server backup, must match up with Line 31
        New-Item -ItemType Directory -Path "C:\Windows\System32\dns\domainDNSBackup"

        # Variables for Year, Month, Day, Time
        $Year = Get-date -Format yyyy
        $Month = Get-Date -Format MM
        $Day = Get-Date -Format dd

        ForEach ($line in $ZoneList) {
        
            # Creates dns backup files.
            Export-DNSServerZone -Name $line.zonename -FileName "$($line.zonename)_$Year-$Month-$Day.txt"

            # Creates csv with DNS records
            Get-DnsServerResourceRecord -ZoneName $line.zonename | select HostName,RecordType,@{n='IP';E={$_.RecordData.IPV4Address}},@{n='CName';E={$_.RecordData.HostNameAlias}} | Export-Csv C:\Windows\System32\dns\$($line.zonename)DNSWorksheet_$Year-$Month-$Day.csv

            # Moves DNS backup files from the default DNS folder to defined backup location. Change C:\Path\to\folder to location you are backing up your DNS files to.
            Move-Item "C:\Windows\System32\dns\$($line.zonename)_$Year-$Month-$Day.txt" "C:\Windows\System32\dns\domainDNSBackup\$($line.zonename)_$Year-$Month-$Day.txt" -Force
            Move-Item "C:\Windows\System32\dns\$($line.zonename)DNSWorksheet_$Year-$Month-$Day.csv" "C:\Windows\System32\dns\domainDNSBackup\$($line.zonename)DNSWorksheet_$Year-$Month-$Day.csv" -Force
        }
    } 

    # Replace computername to the DNS server you are running this to.
    Invoke-Command -ComputerName hqd1-udomc-101 -ScriptBlock $a 

    # Moves DNS backup files from the local server onto share location, replace computer name and share path as needed. Share folder and permissions must be set prior to running this script.
    Move-Item "\\hqd1-udomc-101\c$\Windows\System32\dns\domainDNSBackup" "\\fbi.gov\public\Software\Server Team\DNS\DNS Backups\" -Force
    Rename-Item "\\fbi.gov\public\Software\Server Team\DNS\DNS Backups\domainDNSBackup" "\\fbi.gov\public\Software\Server Team\DNS\DNS Backups\domainDNSBackup_$date"

    # Deletes any DNS backup files older than 90 days.
    Get-ChildItem –Path "\\fbi.gov\public\Software\Server Team\DNS\DNS Backups\" -Recurse | Where-Object {($_.LastWriteTime -lt (Get-Date).AddDays(-90))} | Remove-Item -Recurse -Force   
#endregion
#region - DHCP Control
    # Examples
    $svrDHCP = "dhcpserver.contoso.com"
    $OptStore = [Ordered]@{
        DnsServer = "192.168.1.2"
        WinsServer = "192.168.1.3"
        DnsDomain = "contoso.com"
        Router = "192.168.1.1"
        Wpad = "http://proxy.contoso.com/wpad.dat"
    }

    # Example 1: Set server level option values
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP @OptStore
    # This example sets the server level option values for DNS server, WINS server, DNS domain, router, and WPAD.

    # Example 2: Set option values for a scope
    Set-DhcpServerv4OptionValue -ComputerName -ScopeId 10.10.10.0 $svrDHCP @OptStore
    # This example sets the option values for DNS server, WINS server, DNS domain, router, and WPAD for scope 10.10.10.0.

    # Example 3: Set option values for an address
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ReservedIP 10.10.10.5 @OptStore
    # This example sets the option values for DNS server, WINS server, DNS domain, router, and WPAD for reserved IP address 10.10.10.5.

    # Example 4: Set option values for a policy
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ScopeId 10.10.10.0 -PolicyName "LabComputers" @optStore
    # This example sets the option values for DNS server, WINS server, DNS domain, router, and WPAD for policy named LabComputers in the scope 10.10.10.0.

    # Example 5: Set service-wide option value for DNS server
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -OptionId 6 -Value $optStore.Router
    # This example sets the server-wide DHCPv4 option value for option ID 6, or DNS server.

    # Example 6: Set option value for DNS server for a scope
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ScopeId 10.10.10.0 -OptionId 6 -Value $optStore.DnsServer
    # This example sets the DHCPv4 option value for option ID 6, or DNS server, for the scope 10.10.10.0.

    # Example 7: Set option value for DNS server for a reservation
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ReservedIP 10.10.10.5 -OptionId 6 -Value $optStore.DnsServer
    # This example sets the DHCPv4 option value for option ID 6, or DNS server, for the specified reservation.

    # Example 8: Set a vendor class specific option value
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ScopeId 10.10.10.0 -VendorClass "MSUCClient" -OptionId 5 -Value ([System.Text.Encoding]::ASCII.GetBytes("/CertProv/CertProvisioningService.svc"))
    # This example sets the vendor class specific DHCPv4 option value for option ID 5 on the specified scope for the specified vendor class named MSUCClient.

    # Example 9: Set option value for DNS server for a policy
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ScopeId 10.10.10.0 -PolicyName "PrinterPolicy" -OptionId 6 -Value "192.168.1.10"
    # This example sets the DHCPv4 option value for option ID 6, or DNS server, on the specified scope for the specified policy.

    # Example 10: Set a user class specific option value for DNS server
    Set-DhcpServerv4OptionValue -ComputerName $svrDHCP -ScopeId 10.10.10.0 -UserClass "LabComputer" -OptionId 6 -Value "192.168.1.10"
    # This example sets the user class specific DHCPv4 option value for option ID 6, or DNS server, on the specified scope for the specified user class.

    # Example 11: Set a vendor class specific option value for a scope
    Set-DhcpServerv4OptionValue -ScopeId 10.10.10.0 -OptionId 43 -Value "241","08","33","255","132","10","33","255","133"
    # This example sets the vendor class specific DHCPv4 option value for option ID 43, or embedded vendor-specific options, on the specified scope.


    $svrs = Get-DhcpServerInDC
    $trgServer = ($svrs | ? DNSName -Match 'hqd1').DNSName
    $srcDHCP = Get-DhcpServerv4OptionValue -ComputerName $trgServer
    Help Get-DhcpServerv4OptionValue -Online


    Get-DhcpServerv4OptionVAlue -ComputerName $trgServer
    Get-DhcpServerv4OptionDefinition -ComputerName $trgServer
#endregion
#region - ClusteAwareUpdating
    #get version of the module (selects the first if there are more versions installed)
    $version = (Get-Module -ListAvailable ClusteAwareUpdating) | Sort-Object Version -Descending  | Select-Object Version -First 1
    #convert version to string and create a new object ModuleVersion
    $stringver = $version | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
    $ver = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
    #count the dots 
    $charCount = ($ver.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
    "--"
    $stringver
    "--"
    $ver
    "--"
    $charCount


    switch($charCount){
        {$charCount -eq 1}{ 
          if ([version]('{0}.{1}' -f $ver.split('.')) -ge [version]('{0}.{1}' -f $exampver.split('.'))) {
            Write-Host "Installed $ver is greater than or equal $exampver"
          }
          else {
            Write-Host "Installed Module:$ver is lower version than available $exampver"
          }  
        }

    $update = "ClusteAwareUpdating"
    foreach($checkmodule in $update){
      #getting version of installed module
      $version = (Get-Module -ListAvailable $checkmodule) | Sort-Object Version -Descending  | Select-Object Version -First 1
      #converting version to string
      $stringver = $version | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
      $a = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
      #getting latest module version from ps gallery 
      $psgalleryversion = Find-Module -Name $checkmodule | Sort-Object Version -Descending | Select-Object Version -First 1
      #converting version to string
      $onlinever = $psgalleryversion | select @{n='OnlineVersion'; e={$_.Version -as [string]}}
      $b = $onlinever | Select-Object OnlineVersion -ExpandProperty OnlineVersion
      #check version format 0.0.0 or 0.0 ...
      $charCount = ($a.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
      switch($charCount){
        {$charCount -eq 1}{
          ##version format 1.1 
          if ([version]('{0}.{1}' -f $a.split('.')) -ge [version]('{0}.{1}' -f $b.split('.'))) {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed $a is equal or greater than $b"
          }
          else {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed Module:$a is lower version than $b"
          }  
        }
        {$charCount -eq 2}{
          ##version format 1.1.1  
          if ([version]('{0}.{1}.{2}' -f $a.split('.')) -ge [version]('{0}.{1}.{2}' -f $b.split('.'))) {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed $a is equal or greater than $b"
          }
          else {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed Module:$a is lower version than $b"
          }  
        }
        {$charCount -eq 3}{ 
          ##version format 1.1.1.1
          if ([version]('{0}.{1}.{2}.{3}' -f $a.split('.')) -ge [version]('{0}.{1}.{2}.{3}' -f $b.split('.'))) {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed $a is equal or greater than $b"
          }
          else {
            Write-Host "Module: $checkmodule"
            Write-Host "Installed Module:$a is lower version than $b"
          }  
        }
       }
    }
#endregion
#region - OneNote
    # get a table of all notebooks

    $OneNote = New-Object -ComObject OneNote.Application
    [xml]$Hierarchy = ""
    $OneNote.GetHierarchy("", [Microsoft.Office.InterOp.OneNote.HierarchyScope]::hsPages, [ref]$Hierarchy)

    $Hierarchy.Notebooks.Notebook | Format-Table Name, path, isUnread, isCurrentlyViewed




    # list all notebooks with their sectiongroups and sections in the first level
    $OneNote = New-Object -ComObject OneNote.Application
    [xml]$Hierarchy = ""
    $OneNote.GetHierarchy("", [Microsoft.Office.InterOp.OneNote.HierarchyScope]::hsPages, [ref]$Hierarchy)

    foreach ($notebook in $Hierarchy.Notebooks.Notebook ) {
        " "
        $notebook.Name
        "=============="

        foreach ($sectiongroup in $notebook.SectionGroup) {
            if ($sectiongroup.isRecycleBin -ne 'true') {
            "## "+$sectiongroup.Name
            }
        }
        "## #"
        foreach ($section in $notebook.Section) {
            #    $section |fl *
            "### "+$section.Name
        }
    }



    # write content from HTML-File to a new Notebook
    # (keeping heading levels and defining custom styles for headers, images not handled in this script)

    $OneNote = New-Object -ComObject OneNote.Application

    $NotebookPath = "C:\Temp\onenoteimport\"
    $source = Get-Content -Encoding UTF8 -Path 'C:\Temp\test.html' -Raw;
    $NotebookName = "import"
    $SiteName = 'Test' 

    # create new notebook
    $OneNote = New-Object -ComObject OneNote.Application
    $Scope = [Microsoft.Office.Interop.OneNote.HierarchyScope]::hsNotebooks
    [ref]$xml = ""
    $OneNote.OpenHierarchy($NotebookPath, "", $xml, "cftNotebook")

    $SectionPath = $NotebookPath + $NotebookName + '.one'
  
    # create new section
    [ref]$xmlSection = ""
    $OneNote.OpenHierarchy($SectionPath, "", $xmlSection, "cftSection")

    [ref]$newpageID = ''
    $OneNote.CreateNewPage($xmlSection.Value,[ref]$newpageID,[Microsoft.Office.Interop.OneNote.NewPageStyle]::npsBlankPageWithTitle)
      
    [ref]$NewPageXML = ''
    $OneNote.GetPageContent($newpageID.Value,[ref]$NewPageXML,[Microsoft.Office.Interop.OneNote.PageInfo]::piAll)
      
    $null = [Reflection.Assembly]::LoadWithPartialName('System.Xml.Linq')
    $xDoc = [System.Xml.Linq.XDocument]::Parse($NewPageXML.Value)
 
    # Get OneNote XML namespace
    $ns = $xDoc.Root.Name.Namespace

    # first quickstyle = pagetitle
    $quickstyledef = $xDoc.Descendants() | Where-Object -Property Name -Like -Value '*}QuickStyleDef'
    $quickstyledef.SetAttributeValue('font','Source Sans Pro Black')
    $quickstyledef.SetAttributeValue('fontColor','#80be6a')

    # define other styles
    $QuickStyleNode2 = New-Object System.Xml.Linq.XElement( $ns + "QuickStyleDef")
    $QuickStyleNode2.SetAttributeValue('index','2')
    $QuickStyleNode2.SetAttributeValue('name','p')
    $QuickStyleNode2.SetAttributeValue('font','Source Sans Pro Light')
    $QuickStyleNode2.SetAttributeValue('fontColor','automatic')
    $QuickStyleNode2.SetAttributeValue('fontSize','11.0')
    $QuickStyleNode2.SetAttributeValue('spaceBefore','0.3')
    $QuickStyleNode2.SetAttributeValue('spaceAfter','0.3')
    $quickstyledef.AddAfterSelf($QuickStyleNode2)
    $QuickStyleNode3 = New-Object System.Xml.Linq.XElement( $ns + "QuickStyleDef")
    $QuickStyleNode3.SetAttributeValue('index','3')
    $QuickStyleNode3.SetAttributeValue('name','h1')
    $QuickStyleNode3.SetAttributeValue('font','Source Sans Pro Black')
    $QuickStyleNode3.SetAttributeValue('fontColor','#be806a')
    $QuickStyleNode3.SetAttributeValue('fontSize','16.0')
    $QuickStyleNode3.SetAttributeValue('spaceBefore','1.0')
    $QuickStyleNode3.SetAttributeValue('spaceAfter','0.5')
    $quickstyledef.AddAfterSelf($QuickStyleNode3)
    $QuickStyleNode4 = New-Object System.Xml.Linq.XElement( $ns + "QuickStyleDef")
    $QuickStyleNode4.SetAttributeValue('index','4')
    $QuickStyleNode4.SetAttributeValue('name','h2')
    $QuickStyleNode4.SetAttributeValue('font','Source Sans Pro Black')
    $QuickStyleNode4.SetAttributeValue('fontColor','#be806a')
    $QuickStyleNode4.SetAttributeValue('fontSize','14.0')
    $QuickStyleNode4.SetAttributeValue('spaceBefore','0.8')
    $QuickStyleNode4.SetAttributeValue('spaceAfter','0.3')
    $quickstyledef.AddAfterSelf($QuickStyleNode4)
    $QuickStyleNode5 = New-Object System.Xml.Linq.XElement( $ns + "QuickStyleDef")
    $QuickStyleNode5.SetAttributeValue('index','5')
    $QuickStyleNode5.SetAttributeValue('name','h3')
    $QuickStyleNode5.SetAttributeValue('font','Source Sans Pro Black')
    $QuickStyleNode5.SetAttributeValue('fontColor','#555555')
    $QuickStyleNode5.SetAttributeValue('fontSize','12.0')
    $QuickStyleNode5.SetAttributeValue('spaceBefore','0.5')
    $QuickStyleNode5.SetAttributeValue('spaceAfter','0.3')
    $quickstyledef.AddAfterSelf($QuickStyleNode5)

    $title = $xDoc.Descendants() | Where-Object -Property Name -Like -Value '*}T'
    if (-not $title)
    {throw 'Error: can not find title element'}

    # set site title
    $title.Value = "$SiteName"

    $x = $xDoc.Descendants() | Where-Object -Property Name -Like -Value '*}Title'


    $OutlineNode = New-Object System.Xml.Linq.XElement( $ns + "Outline")
    $OEChildrenNode = New-Object System.Xml.Linq.XElement( $ns + "OEChildren")


    $html = New-Object -ComObject "HTMLFile";
    $html.IHTMLDocument2_write($source);
    $html.childNodes[1].childNodes[1].childNodes | ? { $_.id -eq 'content' } | % { $_.childnodes } | % {

        $node = $_

        switch ($_.nodeName) {

        'H1' {
            $OENode = New-Object System.Xml.Linq.XElement( $ns + "OE")
            $TNode = New-Object System.Xml.Linq.XElement( $ns + "T")
            $CdataNode = New-Object System.Xml.Linq.XCData($node.innerText)

            $TNode.Add($CdataNode)
            $OENode.Add($TNode)
            $OENode.SetAttributeValue('quickStyleIndex','3')
            $OEChildrenNode.Add($OENode)
        }
        'H2' {
            $OENode = New-Object System.Xml.Linq.XElement( $ns + "OE")
            $TNode = New-Object System.Xml.Linq.XElement( $ns + "T")
            $CdataNode = New-Object System.Xml.Linq.XCData($node.innerText)

            $TNode.Add($CdataNode)
            $OENode.Add($TNode)
            $OENode.SetAttributeValue('quickStyleIndex','4')
            $OEChildrenNode.Add($OENode)
        }
        'H3' {
            $OENode = New-Object System.Xml.Linq.XElement( $ns + "OE")
            $TNode = New-Object System.Xml.Linq.XElement( $ns + "T")
            $CdataNode = New-Object System.Xml.Linq.XCData($node.innerText)

            $TNode.Add($CdataNode)
            $OENode.Add($TNode)
            $OENode.SetAttributeValue('quickStyleIndex','5')
            $OEChildrenNode.Add($OENode)
        }
        'P' {
            $HTMLBlock = New-Object System.Xml.Linq.XElement( $ns + "HTMLBlock")
            $HTMLData = New-Object System.Xml.Linq.XElement( $ns + "Data")
            $CdataNode = New-Object System.Xml.Linq.XCData($node.innerHTML)


            $HTMLData.Add($CdataNode)
            $HTMLBlock.Add($HTMLData)
            $OEChildrenNode.Add($HTMLBlock)
        }
        '#text' {
            $OENode = New-Object System.Xml.Linq.XElement( $ns + "OE")
            $TNode = New-Object System.Xml.Linq.XElement( $ns + "T")
            $CdataNode = New-Object System.Xml.Linq.XCData($node.nodeValue)

            $TNode.Add($CdataNode)
            $OENode.Add($TNode)
            $OENode.SetAttributeValue('quickStyleIndex','2')
            $OEChildrenNode.Add($OENode)
        }
        default {
            $HTMLBlock = New-Object System.Xml.Linq.XElement( $ns + "HTMLBlock")
            $HTMLData = New-Object System.Xml.Linq.XElement( $ns + "Data")
            $CdataNode = New-Object System.Xml.Linq.XCData("$($node.outerHTML)")


            $HTMLData.Add($CdataNode)
            $HTMLBlock.Add($HTMLData)
            $OEChildrenNode.Add($HTMLBlock)
        }
        }
    }

    $OutlineNode.Add($OEChildrenNode)

    $x.AddAfterSelf( $OutlineNode )

    $onenote.UpdatePageContent($xDoc.ToString())
#endregion
