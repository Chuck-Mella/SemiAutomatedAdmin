#region - Installed Applications Report
$S = @"
Name,Version,InstallDate,Scope,Architecture,Server
DS License Server,6.223.00570,20220128,All Users,64-Bit,FABCONDC01
EMET 5.0,5.0,20170303,All Users,32-Bit,FABCONDC01
"@| ConvertFrom-Csv | OGV
#endregion
#region - Group Policy
    #region - GPCmds
        $curDomain = ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
        $gpPath = (gci "\\localhost\SYSVOL\$curDomain\Policies")
        $trgGPOs = (Get-GPO -All) | Where DisplayName -Match '_MSFT Microsoft 365 Apps v2206'
        ($trgGPOs.id.guid | % { $gpPath | Where Name -Match $_ } | Select -ExpandProperty FullName) | clip
        ($trgGPOs) | Select DisplayName,Id | Sort DisplayName | OGV
        ii "\\localhost\SYSVOL\$curDomain\Policies"

        $addedTemplates = Compare-Object (gci 'C:\Windows\PolicyDefinitions' -r) (gci '\\fabcondc02\C$\Windows\PolicyDefinitions' -r)
        $addedTemplates | Export-Clixml -Path C:\users\adminCM\Desktop\admImports.xml

        $admImported = Import-Clixml -Path C:\users\adminCM\Desktop\admImports.xml 
        $admImported.inputobject.name |sort



        1..4 | %{ New-GPO -name "_NGPO-$_" }
        ################################################
        sl \\$curDomain\SYSVOL\$curDomain\Policies
        new-item PolicyDefinitions -ItemType Container
        ii \\$curDomain\SYSVOL\$curDomain\Policies\PolicyDefinitions

        cd .\PolicyDefinitions
        copy-item C:\Windows\PolicyDefinitions\* -recurse -force
        remove-item activecli*.* -Recurse
        ##################################################


        (Get-GPO -All) | Select DisplayName,Id | Sort DisplayName
 
        $filePath = [Environment]::GetFolderPath("Desktop") + '\' + 'FABCON Data'
        ($aclShares = ($shares = Get-SmbShare) | Get-SmbShareAccess) | Out-Null
        $Shares | Export-Clixml -Path "$filePath\ShareData.xml"
        $aclShares | Export-Clixml -Path "$filePath\ShareAclData.xml"
        $shrTest = Import-Clixml "$filePath\ShareData.xml"
        $shrAclTest = Import-Clixml "$filePath\ShareAclData.xml"

        fsutil behavior query disable8dot3
        ipmo -Name PoshWSuS
        $ws = Connect-PSWSUSServer -WsusServer 'fabconwsus01' -Port 8530
        $ws.GetConfiguration()

        install-module

        #region - Search-GPOText
            $SiD = $rgx.sid
            $StiGFix = "ADD YOUR [D|E|P]" # Replacing 'Domain Admins' and 'Enterprise Admins'
            $SiDx = "sha256" # Remove residual service account sids
            Function Search-GPOText
            {
                Param
                (
                    $String ,
                    $Domain = "$curDomain"
                )
                $NearestDC = (Get-ADDomainController -Discover -NextClosestSite).Name

                #Get a list of GPOs from the domain
                    $GPOs = Get-GPO -All -Domain $Domain -Server $NearestDC | sort DisplayName

                #Go through each Object and check its XML against $String
                Foreach ($GPO in $GPOs)
                {
                    Write-Host "Working on $($GPO.DisplayName)"
  
                    #Get Current GPO Report (XML)
                    $CurrentGPOReport = Get-GPOReport -Guid $GPO.Id -ReportType Xml -Domain $Domain -Server $NearestDC
  
                    If ($CurrentGPOReport -match $String)
                    {
	                    Write-Host "A Group Policy matching ""$($String)"" has been found:" -Foregroundcolor Green
	                    Write-Host "-  GPO Name: $($GPO.DisplayName)" -Foregroundcolor Green
	                    Write-Host "-  GPO Id: $($GPO.Id)" -Foregroundcolor Green
	                    Write-Host "-  GPO Status: $($GPO.GpoStatus)" -Foregroundcolor Green
                    }
                }
            }
            Search-GPOText -String 'Do not show the "local access only" network icon'

            $svr = $($allGPOs.DisplayName -match '2016' -notmatch 'server')
            $guids = ($svr | %{ (Get-Gpo -Name $_) | Select DisplayName,ID })
            $guids | ogv
        #endregion
        #region - Search-GPOsForSetting
            Function Search-GPOsForSetting
            {
                <#
                    http://blogs.technet.com/b/grouppolicy/archive/2009/04/14/tool-images.aspx
                    http://blogs.technet.com/b/grouppolicy/archive/2009/04/17/find-settings-in-every-gpo.aspx
        
                    Powershell script that does the following:
                    Search-GPOsForSetting  [–IsComputerConfiguration] <boolean>
                                           [-Extension] <string>
                                           [-Where] </string><string> 
                                           [-Is] </string><string>
                                           [[-Return] </string><string>]
                                           [[-DomainName] </string><string>]

                    Example: Search-GPOsForSetting -IsComputerConfiguration $true -Extension Security -Where Name -Is LockoutDuration -Return SettingNumber
                    Example: Search-GPOsForSetting -IsComputerConfiguration $true -Extension Registry -Where Name -Is ACSettingIndex -Return SettingNumber
                    Example: Search-GPOsForSetting -IsComputerConfiguration $true -Extension SoftwareInstallation -where AutoInstall -is true -Return Path
                    Example: Search-GPOsForSetting -IsComputerConfiguration $true -Extension Registry -where Name -is "Run these programs at user logon" -Return State
                #>
                param
                (
                    [Parameter(Mandatory=$true)]  
                    [Boolean] $IsComputerConfiguration,
                    [Parameter(Mandatory=$true)]  
                    [string] $Extension,  
                    [Parameter(Mandatory=$true)]  
                    [string] $Where,
                    [Parameter(Mandatory=$true)]
                    [string] $Is,
                    [Parameter(Mandatory=$false)] 
                    [string] $Return,
                    [Parameter(Mandatory=$false)]  
                    [string] $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                )
 
 
                function print
                {    
                    param
                    (
                        $displayName,
                        $value
                    )
    
                    $host.UI.WriteLine();
    
                    $stringToPrint = "The Gpo '" + $displayName + "' has a " + $Extension + " setting where '" + $Where + "' is equal to '" + $Is + "'";
    
                    if ($Return -ne $null)
                    {
                        $stringToPrint += " and the value of its '" + $Return + "' property is: '" + $value + "'";
                    }
    
                    $host.UI.Write([ConsoleColor]::Magenta, [ConsoleColor]::Black,    $stringToPrint);
                    $host.UI.WriteLine();
                }
 
                function processNodes
                {
                    param
                    (
                        $nodes,
                        $foundWhere
                    )
    
                    $thePropertyWeWant = $Where;
    
                    # If we already found the $Where then we are looking for our $Return value now.
                    if ($foundWhere)
                    {
                        $thePropertyWeWant = $Return;
                    }
            
                    foreach($node in $nodes)
                    {
                        $valueWeFound = $null;
    
                        #Here we are checking siblings                                        
                        $lookingFor = Get-Member -InputObject $node -Name $thePropertyWeWant;                
 
                        if ($lookingFor -ne $null)
                        {
                            $valueWeFound = $node.($lookingFor.Name);
                        }
                        else #Here we are checking attributes.
                        {
                            if ($node.Attributes -ne $null) 
                            {                
                                $lookingFor = $node.Attributes.GetNamedItem($thePropertyWeWant);
 
                                if( $lookingFor -ne $null)
                                {                
                                    $valueWeFound = $lookingFor;
                                }
                            }
                        }    
        
                        if( $lookingFor -ne $null)
                        {         
                            #If we haven't found the $Where yet, then we may have found it now.       
                            if (! $foundWhere)
                            {                                                                         
                                # We have found the $Where if it has the value we want.
                                if ( [String]::Compare($valueWeFound, $Is, $true) -eq 0 )
                                {                                
                                    # Ok it has the value we want too.  Now, are we looking for a specific
                                    # sibling or child of this node or are we done here?
                                    if ($Return -eq $null)
                                    {
                                        #we are done, there is no $Return to look for
                                        print -displayName $Gpo.DisplayName -value $null;
                                        return;              
                                    }
                                    else
                                    {
                                        # Now lets look for $Return in the siblings and then if no go, the children.                                                                                        
                                       processNodes -nodes $node -foundWhere $true;                                                               
                                    }
                                }
                           
                            }        
                            else
                            {
                                #we are done.  We already found the $Where, and now we have found the $Return.
                                print -displayName $Gpo.DisplayName -value $valueWeFound;
                                return;   
                            }
                        }                                      
                
        
                        if (! [String]::IsNullOrEmpty($node.InnerXml))
                        {                    
                            processNodes -nodes $node.ChildNodes -foundWhere $foundWhere;
                        }            
                    }
                }
 
                #Import our module for the call to the Get-GPO cmdlet
                Import-Module GroupPolicy;
 
                $allGposInDomain = Get-GPO -All -Domain $DomainName;
 
                $xmlnsGpSettings = "http://www.microsoft.com/GroupPolicy/Settings";
                $xmlnsSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";
                $xmlnsSchema = "http://www.w3.org/2001/XMLSchema";
 
                $QueryString = "gp:";
 
                if($IsComputerConfiguration){ $QueryString += "Computer/gp:ExtensionData/gp:Extension"; }
                else{ $QueryString += "User/gp:ExtensionData/gp:Extension"; }
 
                foreach ($Gpo in $allGposInDomain)
                {                
                    $xmlDoc = [xml] (Get-GPOReport -Guid $Gpo.Id -ReportType xml -Domain $Gpo.DomainName);        
                    $xmlNameSpaceMgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable);
 
                    $xmlNameSpaceMgr.AddNamespace("", $xmlnsGpSettings);
                    $xmlNameSpaceMgr.AddNamespace("gp", $xmlnsGpSettings);
                    $xmlNameSpaceMgr.AddNamespace("xsi", $xmlnsSchemaInstance);
                    $xmlNameSpaceMgr.AddNamespace("xsd", $xmlnsSchema);
 
                    $extensionNodes = $xmlDoc.DocumentElement.SelectNodes($QueryString, $XmlNameSpaceMgr);
 
                    foreach ($extensionNode in $extensionNodes)
                    {                
                        if ([String]::Compare(($extensionNode.Attributes.Item(0)).Value, 
                            "http://www.microsoft.com/GroupPolicy/Settings/" + $Extension, $true) -eq 0)
                        {
                            # We have found the Extension we are looking for now recursively search
                            # for $Where (the property we are looking for a specific value of).
                                                                
                            processNodes -nodes $extensionNode.ChildNodes -foundWhere $false;        
                        }
                    }        
                }
            }

            Search-GPOsForSetting -IsComputerConfiguration $true -Extension Security -where Name -is "ADD *" -Return State

            $svr = $($allGPOs.DisplayName -match '2012 R2 Member Server STIG Computer')
            Get-GPPermissions -Name $svr -TargetName "Enterprise Admins" -TargetType Group  -All
        #endregion
        #region - Export-GptWmiFilter
            function Export-GptWmiFilter {
                <#
                .SYNOPSIS
                    Export WMI Filters.
     
                .DESCRIPTION
                    Export WMI Filters.
                    By default, all filters are exported.
 
                    Use -ConstrainExport parameter to switch this behavior to:
                    WMI Filters to export are picked up by the GPO they are assigned to.
                    Unassigned filters are ignored.
     
                .PARAMETER Path
                    The path where to create the export.
                    Must be an existing folder.
 
                .PARAMETER ConstrainExport
                    Don't export all WMI filters, instead:
                    WMI Filters to export are picked up by the GPO they are assigned to.
                    Unassigned filters are ignored.
     
                .PARAMETER Name
                    Filter GPOs to process by name.
     
                .PARAMETER GpoObject
                    Specify GPOs to process by object.
     
                .PARAMETER Domain
                    The domain to export from.
     
                .EXAMPLE
                    PS C:\> Export-GptWmiFilter -Path 'C:\temp\Test'
     
                    Export all WMI Filters of all GPOs into the current folder.
            #>
                [CmdletBinding()]
                param (
                    [ValidateScript( { Test-Path -Path $_ })]
                    [Parameter(Mandatory = $true)]
                    [string]
                    $Path,

                    [switch]
                    $ConstrainExport,
        
                    [string]
                    $Name = '*',
        
                    [Parameter(ValueFromPipeline = $true)]
                    $GpoObject,
        
                    [string]
                    $Domain = $env:USERDNSDOMAIN
                )
    
                begin {
                    $wmiPath = "CN=SOM,CN=WMIPolicy,$((Get-ADDomain -Server $Domain).SystemsContainer)"
                    $allFilterHash = @{ }
                    $foundFilterHash = @{ }
        
                    Get-ADObject -Server $Domain -SearchBase $wmiPath -Filter { objectClass -eq 'msWMI-Som' } -Properties msWMI-Author, msWMI-Name, msWMI-Parm1, msWMI-Parm2 | ForEach-Object {
                        $allFilterHash[$_.'msWMI-Name'] = [pscustomobject]@{
                            Author      = $_.'msWMI-Author'
                            Name        = $_.'msWMI-Name'
                            Description = $_.'msWMI-Parm1'
                            Filter      = $_.'msWMI-Parm2'
                        }
                    }
                }
                process {
                    if (-not $ConstrainExport) { return }

                    $gpoObjects = $GpoObject
                    if (-not $GpoObject) {
                        $gpoObjects = Get-GPO -All -Domain $Domain | Where-Object DisplayName -Like $Name
                    }
                    foreach ($filterName in $gpoObjects.WmiFilter.Name) {
                        $foundFilterHash[$filterName] = $allFilterHash[$filterName]
                    }
                }
                end {
                    if ($ConstrainExport) {
                        $foundFilterHash.Values | Where-Object { $_ } | Export-Csv -Path (Join-Path -Path $Path -ChildPath "gp_wmifilters_$($Domain).csv") -Encoding UTF8 -NoTypeInformation
                    }
                    else {
                        $allFilterHash.Values | Where-Object { $_ } | Export-Csv -Path (Join-Path -Path $Path -ChildPath "gp_wmifilters_$($Domain).csv") -Encoding UTF8 -NoTypeInformation
                    }
                }
            }
        #endregion
        #region - GP - WmiFilters Dump
            # Dump wmiFilter Links
                $allGPOs = Get-GPO -All
                $allGPOs |
                    Select-Object @{n='GPO';e={$_.DisplayName}},@{n='Filter';e={$_.WmiFilter.Name}} |
                    Convertto-Csv -NoTypeInformation |
                    Out-File ([Environment]::GetFolderPath("Desktop") + '\' + 'wmiFltr-Map.csv')
                Import-Csv  ([Environment]::GetFolderPath("Desktop") + '\' + 'wmiFltr-Map.csv')

                # OR

                $wmiFltrLinkData = New-Object System.Data.Datatable
                # Adding columns
                    "GPO","Guid","wmi Filter" | %{ [void]$wmiFltrLinkData.Columns.Add("$_") }

                # Add row data
                ForEach ($link in $allGPOs)
                {
                    [void]$wmiFltrLinkData.Rows.Add( `
                            $($link.DisplayName), `
                            $($link.Id), `
                            $($link.WmiFilter.Name))
                }    
                $wmiFltrLinkData |
                    Out-File ([Environment]::GetFolderPath("Desktop") + '\' + 'wmiFltr-Map.csv')

            # Dump WmiFilter Config Data [ADSI]
                $search = New-Object System.DirectoryServices.DirectorySearcher
                $search.SearchRoot = "LDAP://$(([ADSI]'').DistinguishedName)"
                $adsiFilter = "(&(objectclass=msWMI-Som))" # (msWMI-Name=*)
                $search.Filter = $adsiFilter
                $wmiFilters = $search.FindAll()
                # $wmiFilters | Where {($_.Properties.'mswmi-name' -match '2019')}
                # $test = $wmiFilters | Where {($_.Properties.'mswmi-name' -match '2019') -and ($_.Properties.'mswmi-name' -match 'Domain Controller')}
                # $test.Properties.'mswmi-parm2'
                $r = $wmiFilters |
                    Select  @{n='Filter';e={$_.Properties.'mswmi-name'}}, `
                            @{n='Description';e={$_.Properties.'mswmi-parm1'}}, `
                            @{n='Namespace';e={$_.Properties.'mswmi-parm2'.Split(';')[5]}}, `
                            @{n='Query';e={$_.Properties.'mswmi-parm2'.Split(';')[6]}} 
                $r | Export-Csv -NoTypeInformation ([Environment]::GetFolderPath("Desktop") + '\' + 'wmiFltr-Info.csv') 

                # OR

                $wmiFltrData = New-Object System.Data.Datatable
                # Adding columns
                    "Filter","Description","Namespace","Query","Author","Cre8Date","ChangeDate" | %{ [void]$wmiFltrData.Columns.Add("$_") }

                # Add row data
                ForEach ($filter in $wmiFilters)
                {
                    [void]$wmiFltrData.Rows.Add( `
                            $($filter.Properties.'mswmi-name'), `
                            $($filter.Properties.'mswmi-parm1'), `
                            $($filter.Properties.'mswmi-parm2'.Split(';')[5]), `
                            $($filter.Properties.'mswmi-parm2'.Split(';')[6]), `
                            $($filter.Properties.'mswmi-author'), `
                            $($filter.Properties.'whencreated'), `
                            $($filter.Properties.'whenchanged'))
                }    
                $wmiFltrData |
                    Out-File ([Environment]::GetFolderPath("Desktop") + '\' + 'wmiFltr-Info.csv')
     
        #endregion

        Import-Module ActiveDirectory
        Import-Module GroupPolicy
        $dc = Get-ADDomainController -Discover -Service PrimaryDC
        Get-GPOReport -All -ReportType HTML -Domain '$curDomain' -Path 'C:\Temp\GPOReportsAll.html' -Server $dc
    #endregion
    #region - Get-GPLinks
        #requires -version 5.1
        #requires -module GroupPolicy,ActiveDirectory

        $fileContent = (Dec64 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjwhLS0NCkZvcm1hdCB0eXBlIGRhdGEgZ2VuZXJhdGVkIDAxLzExLzIwMjEgMTQ6MzA6NTUgYnkgQ09NUEFOWVxBcnREDQpUaGlzIGZpbGUgd2FzIGNyZWF0ZWQgdXNpbmcgdGhlIE5ldy1QU0Zvcm1hdFhNTCBjb21tYW5kIHRoYXQgaXMgcGFydA0Kb2YgdGhlIFBTU2NyaXB0VG9vbHMgbW9kdWxlLg0KaHR0cHM6Ly9naXRodWIuY29tL2pkaGl0c29sdXRpb25zL1BTU2NyaXB0VG9vbHMNCi0tPg0KPENvbmZpZ3VyYXRpb24+DQogIDxWaWV3RGVmaW5pdGlvbnM+DQogICAgPFZpZXc+DQogICAgICA8IS0tQ3JlYXRlZCAwMS8xMS8yMDIxIDE0OjMwOjU1IGJ5IENPTVBBTllcQXJ0RC0tPg0KICAgICAgPE5hbWU+ZGVmYXVsdDwvTmFtZT4NCiAgICAgIDxWaWV3U2VsZWN0ZWRCeT4NCiAgICAgICAgPFR5cGVOYW1lPm15R1BPTGluazwvVHlwZU5hbWU+DQogICAgICA8L1ZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgPFRhYmxlQ29udHJvbD4NCiAgICAgICAgPCEtLURlbGV0ZSB0aGUgQXV0b1NpemUgbm9kZSBpZiB5b3Ugd2FudCB0byB1c2UgdGhlIGRlZmluZWQgd2lkdGhzLi0tPg0KICAgICAgICA8QXV0b1NpemUgLz4NCiAgICAgICAgPFRhYmxlSGVhZGVycz4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+VGFyZ2V0PC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD4yMDwvV2lkdGg+DQogICAgICAgICAgICA8QWxpZ25tZW50PmxlZnQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgIDxUYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICAgIDxMYWJlbD5EaXNwbGF5TmFtZTwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MjQ8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5hYmxlZDwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MTA8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5mb3JjZWQ8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjExPC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPk9yZGVyPC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD42PC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+cmlnaHQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICA8L1RhYmxlSGVhZGVycz4NCiAgICAgICAgPFRhYmxlUm93RW50cmllcz4NCiAgICAgICAgICA8VGFibGVSb3dFbnRyeT4NCiAgICAgICAgICAgIDxXcmFwIC8+DQogICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtcz4NCiAgICAgICAgICAgICAgPCEtLQ0KICAgICAgICAgICAgQnkgZGVmYXVsdCB0aGUgZW50cmllcyB1c2UgcHJvcGVydHkgbmFtZXMsIGJ1dCB5b3UgY2FuIHJlcGxhY2UgdGhlbSB3aXRoIHNjcmlwdGJsb2Nrcy4NCiAgICAgICAgICAgIDxTY3JpcHRCbG9jaz4uZm9vIC8xbWIgLWFzIFtpbnRdPC9TY3JpcHRCbG9jaz4NCi0tPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+VGFyZ2V0PC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+RGlzcGxheU5hbWU8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFNjcmlwdEJsb2NrPg0KICAgICAgICAgICAgICAgIDwhLS0gdXNlIEFOU0kgZm9ybWF0dGluZyBpZiB1c2luZyB0aGUgY29uc29sZSBob3N0LS0+DQogICAgICAgICAgICAgICAgaWYgKFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSW50ZXJuYWwuSG9zdC5JbnRlcm5hbEhvc3QubmFtZSAtZXEgJ0NvbnNvbGVIb3N0Jykgew0KICAgICAgICAgICAgICAgICBpZiAoLkVuYWJsZWQpIHsNCiAgICAgICAgICAgICAgICAgICAuRW5hYmxlZA0KICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgICAgICAgICIbWzE7OTFtG1swbSINCiAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlIHsNCiAgICAgICAgICAgICAgICAgIC5FbmFibGVkDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIDwvU2NyaXB0QmxvY2s+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxTY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgICA8IS0tIHVzZSBBTlNJIGZvcm1hdHRpbmcgaWYgdXNpbmcgdGhlIGNvbnNvbGUgaG9zdC0tPg0KICAgICAgICAgICAgICAgIGlmIChTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkludGVybmFsLkhvc3QuSW50ZXJuYWxIb3N0Lm5hbWUgLWVxICdDb25zb2xlSG9zdCcpIHsNCiAgICAgICAgICAgICAgICAgaWYgKC5FbmZvcmNlZCkgew0KICAgICAgICAgICAgICAgICAgICIbWzE7OTJtG1swbSINCiAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICBlbHNlIHsNCiAgICAgICAgICAgICAgICAgICAuRW5mb3JjZWQNCiAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICBlbHNlIHsNCiAgICAgICAgICAgICAgICAgIC5FbmZvcmNlZA0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICA8L1NjcmlwdEJsb2NrPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPk9yZGVyPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW1zPg0KICAgICAgICAgIDwvVGFibGVSb3dFbnRyeT4NCiAgICAgICAgPC9UYWJsZVJvd0VudHJpZXM+DQogICAgICA8L1RhYmxlQ29udHJvbD4NCiAgICA8L1ZpZXc+DQogICAgPFZpZXc+DQogICAgICA8IS0tQ3JlYXRlZCAwMS8xMS8yMDIxIDE0OjMxOjA3IGJ5IENPTVBBTllcQXJ0RC0tPg0KICAgICAgPE5hbWU+bGluazwvTmFtZT4NCiAgICAgIDxWaWV3U2VsZWN0ZWRCeT4NCiAgICAgICAgPFR5cGVOYW1lPm15R1BPTGluazwvVHlwZU5hbWU+DQogICAgICA8L1ZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgPEdyb3VwQnk+DQogICAgICAgIDwhLS0NCiAgICAgICAgICAgIFlvdSBjYW4gYWxzbyB1c2UgYSBzY3JpcHRibG9jayB0byBkZWZpbmUgYSBjdXN0b20gcHJvcGVydHkgbmFtZS4NCiAgICAgICAgICAgIFlvdSBtdXN0IGhhdmUgYSBMYWJlbCB0YWcuDQogICAgICAgICAgICA8U2NyaXB0QmxvY2s+Lm1hY2hpbmVuYW1lLnRvVXBwZXIoKTwvU2NyaXB0QmxvY2s+DQogICAgICAgICAgICA8TGFiZWw+Q29tcHV0ZXJuYW1lPC9MYWJlbD4NCiAgICAgICAgICAgIFVzZSA8TGFiZWw+IHRvIHNldCB0aGUgZGlzcGxheWVkIHZhbHVlLg0KLS0+DQogICAgICAgIDxQcm9wZXJ0eU5hbWU+VGFyZ2V0PC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgIDxMYWJlbD5UYXJnZXQ8L0xhYmVsPg0KICAgICAgPC9Hcm91cEJ5Pg0KICAgICAgPFRhYmxlQ29udHJvbD4NCiAgICAgICAgPFRhYmxlSGVhZGVycz4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RGlzcGxheU5hbWU8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjM1PC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPkVuYWJsZWQ8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjEwPC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPkVuZm9yY2VkPC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD4xMTwvV2lkdGg+DQogICAgICAgICAgICA8QWxpZ25tZW50PmxlZnQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgIDxUYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICAgIDxMYWJlbD5PcmRlcjwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+NjwvV2lkdGg+DQogICAgICAgICAgICA8QWxpZ25tZW50PnJpZ2h0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgPC9UYWJsZUhlYWRlcnM+DQogICAgICAgIDxUYWJsZVJvd0VudHJpZXM+DQogICAgICAgICAgPFRhYmxlUm93RW50cnk+DQogICAgICAgICAgICA8V3JhcCAvPg0KICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbXM+DQogICAgICAgICAgICAgIDwhLS0NCiAgICAgICAgICAgIEJ5IGRlZmF1bHQgdGhlIGVudHJpZXMgdXNlIHByb3BlcnR5IG5hbWVzLCBidXQgeW91IGNhbiByZXBsYWNlIHRoZW0gd2l0aCBzY3JpcHRibG9ja3MuDQogICAgICAgICAgICA8U2NyaXB0QmxvY2s+LmZvbyAvMW1iIC1hcyBbaW50XTwvU2NyaXB0QmxvY2s+DQotLT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8UHJvcGVydHlOYW1lPkRpc3BsYXlOYW1lPC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxTY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgICA8IS0tIHVzZSBBTlNJIGZvcm1hdHRpbmcgaWYgdXNpbmcgdGhlIGNvbnNvbGUgaG9zdC0tPg0KICAgICAgICAgICAgICAgIGlmIChTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkludGVybmFsLkhvc3QuSW50ZXJuYWxIb3N0Lm5hbWUgLWVxICdDb25zb2xlSG9zdCcpIHsNCiAgICAgICAgICAgICAgICAgaWYgKC5FbmFibGVkKSB7DQogICAgICAgICAgICAgICAgICAgLkVuYWJsZWQNCiAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICBlbHNlIHsNCiAgICAgICAgICAgICAgICAgICAiG1sxOzkxbRtbMG0iDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAuRW5hYmxlZA0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICA8L1NjcmlwdEJsb2NrPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8U2NyaXB0QmxvY2s+DQogICAgICAgICAgICAgICAgPCEtLSB1c2UgQU5TSSBmb3JtYXR0aW5nIGlmIHVzaW5nIHRoZSBjb25zb2xlIGhvc3QtLT4NCiAgICAgICAgICAgICAgICBpZiAoU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5JbnRlcm5hbC5Ib3N0LkludGVybmFsSG9zdC5uYW1lIC1lcSAnQ29uc29sZUhvc3QnKSB7DQogICAgICAgICAgICAgICAgIGlmICguRW5mb3JjZWQpIHsNCiAgICAgICAgICAgICAgICAgICAiG1sxOzkybRtbMG0iDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAgLkVuZm9yY2VkDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAuRW5mb3JjZWQNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgPC9TY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5PcmRlcjwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtcz4NCiAgICAgICAgICA8L1RhYmxlUm93RW50cnk+DQogICAgICAgIDwvVGFibGVSb3dFbnRyaWVzPg0KICAgICAgPC9UYWJsZUNvbnRyb2w+DQogICAgPC9WaWV3Pg0KICAgIDxWaWV3Pg0KICAgICAgPCEtLUNyZWF0ZWQgMDEvMTEvMjAyMSAxNDozMToxOSBieSBDT01QQU5ZXEFydEQtLT4NCiAgICAgIDxOYW1lPmdwbzwvTmFtZT4NCiAgICAgIDxWaWV3U2VsZWN0ZWRCeT4NCiAgICAgICAgPFR5cGVOYW1lPm15R1BPTGluazwvVHlwZU5hbWU+DQogICAgICA8L1ZpZXdTZWxlY3RlZEJ5Pg0KICAgICAgPEdyb3VwQnk+DQogICAgICAgIDwhLS0NCiAgICAgICAgICAgIFlvdSBjYW4gYWxzbyB1c2UgYSBzY3JpcHRibG9jayB0byBkZWZpbmUgYSBjdXN0b20gcHJvcGVydHkgbmFtZS4NCiAgICAgICAgICAgIFlvdSBtdXN0IGhhdmUgYSBMYWJlbCB0YWcuDQogICAgICAgICAgICA8U2NyaXB0QmxvY2s+Lm1hY2hpbmVuYW1lLnRvVXBwZXIoKTwvU2NyaXB0QmxvY2s+DQogICAgICAgICAgICA8TGFiZWw+Q29tcHV0ZXJuYW1lPC9MYWJlbD4NCiAgICAgICAgICAgIFVzZSA8TGFiZWw+IHRvIHNldCB0aGUgZGlzcGxheWVkIHZhbHVlLg0KLS0+DQogICAgICAgIDxQcm9wZXJ0eU5hbWU+RGlzcGxheU5hbWU8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgPExhYmVsPkRpc3BsYXlOYW1lPC9MYWJlbD4NCiAgICAgIDwvR3JvdXBCeT4NCiAgICAgIDxUYWJsZUNvbnRyb2w+DQogICAgICAgIDxUYWJsZUhlYWRlcnM+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPlRhcmdldDwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+NDU8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5hYmxlZDwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MTA8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5mb3JjZWQ8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjExPC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPk9yZGVyPC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD42PC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+cmlnaHQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICA8L1RhYmxlSGVhZGVycz4NCiAgICAgICAgPFRhYmxlUm93RW50cmllcz4NCiAgICAgICAgICA8VGFibGVSb3dFbnRyeT4NCiAgICAgICAgICAgIDxXcmFwIC8+DQogICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtcz4NCiAgICAgICAgICAgICAgPCEtLQ0KICAgICAgICAgICAgQnkgZGVmYXVsdCB0aGUgZW50cmllcyB1c2UgcHJvcGVydHkgbmFtZXMsIGJ1dCB5b3UgY2FuIHJlcGxhY2UgdGhlbSB3aXRoIHNjcmlwdGJsb2Nrcy4NCiAgICAgICAgICAgIDxTY3JpcHRCbG9jaz4uZm9vIC8xbWIgLWFzIFtpbnRdPC9TY3JpcHRCbG9jaz4NCi0tPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+VGFyZ2V0PC9Qcm9wZXJ0eU5hbWU+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxTY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgICA8IS0tIHVzZSBBTlNJIGZvcm1hdHRpbmcgaWYgdXNpbmcgdGhlIGNvbnNvbGUgaG9zdC0tPg0KICAgICAgICAgICAgICAgIGlmIChTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkludGVybmFsLkhvc3QuSW50ZXJuYWxIb3N0Lm5hbWUgLWVxICdDb25zb2xlSG9zdCcpIHsNCiAgICAgICAgICAgICAgICAgaWYgKC5FbmFibGVkKSB7DQogICAgICAgICAgICAgICAgICAgLkVuYWJsZWQNCiAgICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgICBlbHNlIHsNCiAgICAgICAgICAgICAgICAgICAiG1sxOzkxbRtbMG0iDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAuRW5hYmxlZA0KICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICA8L1NjcmlwdEJsb2NrPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8U2NyaXB0QmxvY2s+DQogICAgICAgICAgICAgICAgPCEtLSB1c2UgQU5TSSBmb3JtYXR0aW5nIGlmIHVzaW5nIHRoZSBjb25zb2xlIGhvc3QtLT4NCiAgICAgICAgICAgICAgICBpZiAoU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5JbnRlcm5hbC5Ib3N0LkludGVybmFsSG9zdC5uYW1lIC1lcSAnQ29uc29sZUhvc3QnKSB7DQogICAgICAgICAgICAgICAgIGlmICguRW5mb3JjZWQpIHsNCiAgICAgICAgICAgICAgICAgICAiG1sxOzkybRtbMG0iDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAgLkVuZm9yY2VkDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAuRW5mb3JjZWQNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgPC9TY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5PcmRlcjwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtcz4NCiAgICAgICAgICA8L1RhYmxlUm93RW50cnk+DQogICAgICAgIDwvVGFibGVSb3dFbnRyaWVzPg0KICAgICAgPC9UYWJsZUNvbnRyb2w+DQogICAgPC9WaWV3Pg0KICAgIDxWaWV3Pg0KICAgICAgPCEtLUNyZWF0ZWQgMDEvMTUvMjAyMSAxMDozNzo0MSBieSBDT01QQU5ZXGFydGQtLT4NCiAgICAgIDxOYW1lPnRhcmdldHR5cGU8L05hbWU+DQogICAgICA8Vmlld1NlbGVjdGVkQnk+DQogICAgICAgIDxUeXBlTmFtZT5teUdQT0xpbms8L1R5cGVOYW1lPg0KICAgICAgPC9WaWV3U2VsZWN0ZWRCeT4NCiAgICAgIDxHcm91cEJ5Pg0KICAgICAgICA8IS0tDQogICAgICAgICAgICBZb3UgY2FuIGFsc28gdXNlIGEgc2NyaXB0YmxvY2sgdG8gZGVmaW5lIGEgY3VzdG9tIHByb3BlcnR5IG5hbWUuDQogICAgICAgICAgICBZb3UgbXVzdCBoYXZlIGEgTGFiZWwgdGFnLg0KICAgICAgICAgICAgPFNjcmlwdEJsb2NrPi5tYWNoaW5lbmFtZS50b1VwcGVyKCk8L1NjcmlwdEJsb2NrPg0KICAgICAgICAgICAgPExhYmVsPkNvbXB1dGVybmFtZTwvTGFiZWw+DQogICAgICAgICAgICBVc2UgPExhYmVsPiB0byBzZXQgdGhlIGRpc3BsYXllZCB2YWx1ZS4NCi0tPg0KICAgICAgICA8UHJvcGVydHlOYW1lPlRhcmdldFR5cGU8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgPExhYmVsPlRhcmdldFR5cGU8L0xhYmVsPg0KICAgICAgPC9Hcm91cEJ5Pg0KICAgICAgPFRhYmxlQ29udHJvbD4NCiAgICAgICAgPCEtLURlbGV0ZSB0aGUgQXV0b1NpemUgbm9kZSBpZiB5b3Ugd2FudCB0byB1c2UgdGhlIGRlZmluZWQgd2lkdGhzLg0KICAgICAgICA8QXV0b1NpemUgLz4tLT4NCiAgICAgICAgPFRhYmxlSGVhZGVycz4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+VGFyZ2V0PC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD41MDwvV2lkdGg+DQogICAgICAgICAgICA8QWxpZ25tZW50PmxlZnQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgIDxUYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICAgIDxMYWJlbD5EaXNwbGF5TmFtZTwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MzU8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5hYmxlZDwvTGFiZWw+DQogICAgICAgICAgICA8V2lkdGg+MTA8L1dpZHRoPg0KICAgICAgICAgICAgPEFsaWdubWVudD5sZWZ0PC9BbGlnbm1lbnQ+DQogICAgICAgICAgPC9UYWJsZUNvbHVtbkhlYWRlcj4NCiAgICAgICAgICA8VGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgICA8TGFiZWw+RW5mb3JjZWQ8L0xhYmVsPg0KICAgICAgICAgICAgPFdpZHRoPjExPC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+bGVmdDwvQWxpZ25tZW50Pg0KICAgICAgICAgIDwvVGFibGVDb2x1bW5IZWFkZXI+DQogICAgICAgICAgPFRhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICAgICAgPExhYmVsPk9yZGVyPC9MYWJlbD4NCiAgICAgICAgICAgIDxXaWR0aD42PC9XaWR0aD4NCiAgICAgICAgICAgIDxBbGlnbm1lbnQ+cmlnaHQ8L0FsaWdubWVudD4NCiAgICAgICAgICA8L1RhYmxlQ29sdW1uSGVhZGVyPg0KICAgICAgICA8L1RhYmxlSGVhZGVycz4NCiAgICAgICAgPFRhYmxlUm93RW50cmllcz4NCiAgICAgICAgICA8VGFibGVSb3dFbnRyeT4NCiAgICAgICAgICAgIDxXcmFwLz4NCiAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW1zPg0KICAgICAgICAgICAgICA8IS0tDQogICAgICAgICAgICBCeSBkZWZhdWx0IHRoZSBlbnRyaWVzIHVzZSBwcm9wZXJ0eSBuYW1lcywgYnV0IHlvdSBjYW4gcmVwbGFjZSB0aGVtIHdpdGggc2NyaXB0YmxvY2tzLg0KICAgICAgICAgICAgPFNjcmlwdEJsb2NrPi5mb28gLzFtYiAtYXMgW2ludF08L1NjcmlwdEJsb2NrPg0KLS0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5UYXJnZXQ8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFByb3BlcnR5TmFtZT5EaXNwbGF5TmFtZTwvUHJvcGVydHlOYW1lPg0KICAgICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgPFRhYmxlQ29sdW1uSXRlbT4NCiAgICAgICAgICAgICAgICA8U2NyaXB0QmxvY2s+DQogICAgICAgICAgICAgICAgPCEtLSB1c2UgQU5TSSBmb3JtYXR0aW5nIGlmIHVzaW5nIHRoZSBjb25zb2xlIGhvc3QtLT4NCiAgICAgICAgICAgICAgICBpZiAoU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5JbnRlcm5hbC5Ib3N0LkludGVybmFsSG9zdC5uYW1lIC1lcSAnQ29uc29sZUhvc3QnKSB7DQogICAgICAgICAgICAgICAgIGlmICguRW5hYmxlZCkgew0KICAgICAgICAgICAgICAgICAgIC5FbmFibGVkDQogICAgICAgICAgICAgICAgIH0NCiAgICAgICAgICAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAgICAgICAgIhtbMTs5MW0bWzBtIg0KICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgICAgICAgLkVuYWJsZWQNCiAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgPC9TY3JpcHRCbG9jaz4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgIDxUYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICAgICAgPFNjcmlwdEJsb2NrPg0KICAgICAgICAgICAgICAgIDwhLS0gdXNlIEFOU0kgZm9ybWF0dGluZyBpZiB1c2luZyB0aGUgY29uc29sZSBob3N0LS0+DQogICAgICAgICAgICAgICAgaWYgKFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb24uSW50ZXJuYWwuSG9zdC5JbnRlcm5hbEhvc3QubmFtZSAtZXEgJ0NvbnNvbGVIb3N0Jykgew0KICAgICAgICAgICAgICAgICBpZiAoLkVuZm9yY2VkKSB7DQogICAgICAgICAgICAgICAgICAgIhtbMTs5Mm0bWzBtIg0KICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgICAgICAgIC5FbmZvcmNlZA0KICAgICAgICAgICAgICAgICB9DQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIGVsc2Ugew0KICAgICAgICAgICAgICAgICAgLkVuZm9yY2VkDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgICAgIDwvU2NyaXB0QmxvY2s+DQogICAgICAgICAgICAgIDwvVGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICA8VGFibGVDb2x1bW5JdGVtPg0KICAgICAgICAgICAgICAgIDxQcm9wZXJ0eU5hbWU+T3JkZXI8L1Byb3BlcnR5TmFtZT4NCiAgICAgICAgICAgICAgPC9UYWJsZUNvbHVtbkl0ZW0+DQogICAgICAgICAgICA8L1RhYmxlQ29sdW1uSXRlbXM+DQogICAgICAgICAgPC9UYWJsZVJvd0VudHJ5Pg0KICAgICAgICA8L1RhYmxlUm93RW50cmllcz4NCiAgICAgIDwvVGFibGVDb250cm9sPg0KICAgIDwvVmlldz4NCiAgPC9WaWV3RGVmaW5pdGlvbnM+DQo8L0NvbmZpZ3VyYXRpb24+')
        $fileName = 'myGPOlink.format.ps1xml'
        $fileContent | SC -Path $fileName
        GC -Path $fileName

        Function Get-GPLink
        {
            <#
                .Synopsis
                    Get Group Policy Object links

                .Description
                    This command will display the links to existing Group Policy objects. You can filter for enabled
                    or disabled links. The default user domain is queried although you can specify an alternate domain
                    and/or a specific domain controller. There is no provision for alternate credentials. The command
                    writes a custom object to the pipeline. There are associated custom table views you can use. See examples.

                .Parameter Name
                    Enter a GPO name. Wildcards are allowed. This parameter has an alias of gpo.

                .Parameter Server
                    Specify the name of a specific domain controller to query.

                .Parameter Domain
                    Enter the name of an Active Directory domain. The default is the current user domain. 
                    Your credentials must have permission to query the domain. Specify the DNS domain name, i.e. company.com

                .Parameter Enabled
                    Only show links that are enabled.

                .Parameter Disabled
                    Only show links that are Disabled.

                .Example 1
                    PS C:\> Get-GPLink
                    Target                                  DisplayName                       Enabled Enforced Order
                    ------                                  -----------                       ------- -------- -----
                    dc=company,dc=pri                       Default Domain Policy             True    True         1
                    dc=company,dc=pri                       PKI AutoEnroll                    True    False        2
                    ou=domain controllers,dc=company,dc=pri Default Domain Controllers Policy True    False        1
                    ou=it,dc=company,dc=pri                 Demo 2                            True    False        1
                    ou=dev,dc=company,dc=pri                Demo 1                            True    False        1
                    ou=dev,dc=company,dc=pri                Demo 2                            False   False        2
                    ou=sales,dc=company,dc=pri              Demo 1                            True    False        1
                    ...
                    If you are running in the console, False values under Enabled will be displayed in red. Enforced values 
                    that are True will be displayed in Green.

                .Example 2
                    PS C:\> Get-GPLink -Disabled
                    Target                             DisplayName Enabled Enforced Order
                    ------                             ----------- ------- -------- -----
                    ou=dev,dc=company,dc=pri           Demo 2      False   False        2
                    ou=foo\,bar demo,dc=company,dc=pri Gladys      False   False        1
                    Get disabled Group Policy links.
                    .Example
                    PS C:\> Get-GPLink gladys | get-gpo
                    DisplayName      : Gladys
                    DomainName       : Company.Pri
                    Owner            : COMPANY\Domain Admins
                    Id               : 7551c3d8-99fa-4bc6-85a2-bd650124f11a
                    GpoStatus        : AllSettingsEnabled
                    Description      :
                    CreationTime     : 1/11/2021 2:34:37 PM
                    ModificationTime : 1/11/2021 2:34:38 PM
                    UserVersion      : AD Version: 0, SysVol Version: 0
                    ComputerVersion  : AD Version: 0, SysVol Version: 0
                    WmiFilter        :

                .Example 3
                    PS C:\>  Get-GPLink | Where TargetType -eq "domain"
                    Target            DisplayName           Enabled Enforced Order
                    ------            -----------           ------- -------- -----
                    dc=company,dc=pri Default Domain Policy True    True         1
                    dc=company,dc=pri PKI AutoEnroll        True    True         2
                    Other possible TargetType values are OU and Site.
                    .Example
                    PS C:\>  Get-GPLink | sort Target | Format-Table -view link
                       Target: dc=company,dc=pri
                    DisplayName                         Enabled    Enforced    Order
                    -----------                         -------    --------    -----
                    PKI AutoEnroll                      True       False           2
                    Default Domain Policy               True       True            1
                       Target: ou=dev,dc=company,dc=pri
                    DisplayName                         Enabled    Enforced    Order
                    -----------                         -------    --------    -----
                    Demo 1                              True       False           1
                    Demo 2                              False      False           2
                    ...

                .Example 4
                    PS C:\> Get-GPLink | Sort TargetType | Format-Table -view targetType
                       TargetType: Domain
                    Target                          DisplayName                  Enabled    Enforced     Order
                    ------                          -----------                  -------    --------     -----
                    dc=company,dc=pri               PKI AutoEnroll               True       True             2
                    dc=company,dc=pri               Default Domain Policy        True       True             1
                       TargetType: OU
                    Target                            DisplayName                Enabled    Enforced     Order
                    ------                            -----------                -------    --------     -----
                    ou=accounting,dc=company,dc=pri   Accounting-dev-test-foo    True       False            1
                    ou=sales,dc=company,dc=pri        Demo 1                     True       False            1
                    ...

                .Example 5
                    PS C:\> Get-GPLink | Sort Name | Format-Table -view gpo
                       DisplayName: Default Domain Controllers Policy
                    Target                                        Enabled    Enforced    Order
                    ------                                        -------    --------    -----
                    ou=domain controllers,dc=company,dc=pri       True       False           1
                       DisplayName: Default Domain Policy
                    Target                                        Enabled    Enforced    Order
                    ------                                        -------    --------    -----
                    dc=company,dc=pri                             True       True            1
                       DisplayName: Demo 1
                    Target                                        Enabled    Enforced    Order
                    ------                                        -------    --------    -----
                    ou=dev,dc=company,dc=pri                      True       False           1
                    CN=Default-First-Site-Name,cn=Sites,CN=Config True       True            2
                    uration,DC=Company,DC=Pri
                    ...

                .Example 6
                    PS C:\> Get-GPLink | Format-Table -GroupBy Domain -Property Link,GPO,Enabled,Enforced
                       Domain: Company.Pri
                    Link                                    GPO                               Enabled Enforced
                    ----                                    ---                               ------- --------
                    dc=company,dc=pri                       Default Domain Policy                True     True
                    dc=company,dc=pri                       PKI AutoEnroll                       True    False
                    ou=domain controllers,dc=company,dc=pri Default Domain Controllers Policy    True    False
                    ou=it,dc=company,dc=pri                 Demo 2                               True    False
                    ou=dev,dc=company,dc=pri                Demo 1                               True    False
                    ou=dev,dc=company,dc=pri                Demo 2                              False    False
                    ou=sales,dc=company,dc=pri              Demo 1                               True    False
                    ou=foo\,bar demo,dc=company,dc=pri      Gladys                              False    False
                    ou=foo\,bar demo,dc=company,dc=pri      Demo 2                               True    False

                .Link
                    Get-GPO

                .Link
                    Set-GPLink

                .Inputs
                    System.String

                .Notes
                    Learn more about PowerShell: http://jdhitsolutions.com/blog/essential-powershell-resources/
                #>
            [cmdletbinding(DefaultParameterSetName = "All")]
            [outputtype("myGPOLink")]
            Param
            (
                [parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName, HelpMessage = "Enter a GPO name. Wildcards are allowed")]
                [alias("gpo")]
                [ValidateNotNullOrEmpty()]
                [string]$Name,
                [Parameter(HelpMessage = "Specify the name of a specific domain controller to query.")]
                [ValidateNotNullOrEmpty()]
                [string]$Server,
                [Parameter(ValueFromPipelineByPropertyName)]
                [ValidateNotNullOrEmpty()]
                [string]$Domain,
                [Parameter(ParameterSetName = "enabled")]
                [switch]$Enabled,
                [Parameter(ParameterSetName = "disabled")]
                [switch]$Disabled
            )
            Begin
            {
                Write-Verbose "Starting $($myinvocation.mycommand)"
                #display some metadata information in the verbose output
                Write-Verbose "Running as $($env:USERDOMAIN)\$($env:USERNAME) on $($env:Computername)"
                Write-Verbose "Using PowerShell version $($psversiontable.PSVersion)"
                Write-Verbose "Using ActiveDirectory module $((Get-Module ActiveDirectory).version)"
                Write-Verbose "Using GroupPolicy module $((Get-Module GroupPolicy).version)"

                #define a helper function to get site level GPOs
                #It is easier for this task to use the Group Policy Management COM objects.
                Function Get-GPSiteLink
                {
                    [cmdletbinding()]
                    Param
                    (
                        [Parameter(Position = 0,ValueFromPipelineByPropertyName,ValueFromPipeline)]
                        [alias("Name")]
                        [string[]]$SiteName = "Default-First-Site-Name",
                        [Parameter(Position = 1)]
                        [string]$Domain,
                        [string]$Server
                    )

                    Begin
                    {
                        Write-Verbose "Starting $($myinvocation.mycommand)"

                        #define the GPMC COM Objects
                        $gpm = New-Object -ComObject "GPMGMT.GPM"
                        $gpmConstants = $gpm.GetConstants()

                    }

                    Process
                    {
                        $getParams = @{Current = "LoggedonUser"; ErrorAction = "Stop" }
                        if ($Server) {
                            $getParams.Add("Server", $Server)
                        }
                        if ( -Not $PSBoundParameters.ContainsKey("Domain"))
                        {
                            Write-Verbose "Querying domain"
                            Try
                            {
                                $Domain = (Get-ADDomain @getParams).DNSRoot
                            }
                            Catch
                            {
                                Write-Warning "Failed to query the domain. $($_.exception.message)"
                                #Bail out of the function since we need this information
                                return
                            }
                        }

                        Try
                        {
                            $Forest = (Get-ADForest @getParams).Name
                        }
                        Catch
                        {
                            Write-Warning "Failed to query the forest. $($_.exception.message)"
                            #Bail out of the function since we need this information
                            return
                        }

                        $gpmDomain = $gpm.GetDomain($domain, $server, $gpmConstants.UseAnyDC)
                        foreach ($item in $siteName)
                        {
                            #connect to site container
                            $SiteContainer = $gpm.GetSitesContainer($forest, $domain, $null, $gpmConstants.UseAnyDC)
                            Write-Verbose "Connected to site container on $($SiteContainer.domainController)"
                            #get sites
                            Write-Verbose "Getting $item"
                            $site = $SiteContainer.GetSite($item)
                            Write-Verbose "Found $($sites.count) site(s)"
                            if ($site)
                            {
                                Write-Verbose "Getting site GPO links"
                                $links = $Site.GetGPOLinks()
                                if ($links)
                                {
                                    #add the GPO name
                                    Write-Verbose "Found $($links.count) GPO link(s)"
                                    foreach ($link in $links)
                                    {
                                        [pscustomobject]@{
                                            GpoId       = $link.GPOId -replace ("{|}", "")
                                            DisplayName = ($gpmDomain.GetGPO($link.GPOID)).DisplayName
                                            Enabled     = $link.Enabled
                                            Enforced    = $link.Enforced
                                            Target      = $link.som.path
                                            Order       = $link.somlinkorder
                                            } #custom object
                                    }
                                } 
                            } 
                        } 
                    } 

                    End
                    {
                        Write-Verbose "Ending $($myinvocation.MyCommand)"
                    } 
                }
            }
            Process {
                Write-Verbose "Using these bound parameters"
                $PSBoundParameters | Out-String | Write-Verbose

                #use a generic list instead of an array for better performance
                $targets = [System.Collections.Generic.list[string]]::new()

                #use an internal $PSDefaultParameterValues instead of trying to
                #create parameter hashtables for splatting
                if ($Server)
                {
                    $script:PSDefaultParameterValues["Get-AD*:Server"] = $server
                    $script:PSDefaultParameterValues["Get-GP*:Server"] = $Server
                }

                if ($domain)
                {
                    $script:PSDefaultParameterValues["Get-AD*:Domain"] = $domain
                    $script:PSDefaultParameterValues["Get-ADDomain:Identity"] = $domain
                    $script:PSDefaultParameterValues["Get-GP*:Domain"] = $domain
                }

                Try
                {
                    Write-Verbose "Querying the domain"
                    $mydomain = Get-ADDomain -ErrorAction Stop
                    #add the DN to the list
                    $targets.Add($mydomain.distinguishedname)
                }
                Catch
                {
                    Write-Warning "Failed to get domain information. $($_.exception.message)"
                    #bail out if the domain can't be queried
                    Return
                }

                if ($targets)
                {
                    #get OUs
                    Write-Verbose "Querying organizational units"
                    Get-ADOrganizationalUnit -Filter * |
                    ForEach-Object { $targets.add($_.Distinguishedname) }

                    #get all the links
                    Write-Verbose "Getting GPO links from $($targets.count) targets"
                    $links = [System.Collections.Generic.list[object]]::New()
                    Try
                    {
                        ($Targets | Get-GPInheritance -ErrorAction Stop).gpolinks | ForEach-Object { $links.Add($_) }
                    }
                    Catch
                    {
                        Write-Warning "Failed to get GPO inheritance. If specifying a domain, be sure to use the DNS name. $($_.exception.message)"
                        #bail out
                        return
                    }

                    Write-Verbose "Querying sites"
                    $getADO = @{
                        LDAPFilter = "(Objectclass=site)"
                        properties = "Name"
                        SearchBase = (Get-ADRootDSE).ConfigurationNamingContext
                        }
                    $sites = (Get-ADObject @getADO).name
                    if ($sites)
                    {
                        Write-Verbose "Processing $($sites.count) site(s)"
                        #call the private helper function
                        $sites | Get-GPSiteLink | ForEach-Object { $links.add($_) }
                    }

                    #filter for Enabled or Disabled
                    if ($enabled)
                    {
                        Write-Verbose "Filtering for Enabled policies"
                        $links = $links.where( { $_.enabled })
                    }
                    elseif ($Disabled)
                    {
                        Write-Verbose "Filtering for Disabled policies"
                        $links = $links.where( { -Not $_.enabled })
                    }

                    if ($Name)
                    {
                        Write-Verbose "Filtering for GPO name like $name"
                        #filter by GPO name using v4 filtering feature for performance
                        $results = $links.where({ $_.displayname -like "$name" })
                    }
                    else
                    {
                        #write all the links
                        Write-Verbose "Displaying ALL GPO Links"
                        $results = $links
                    }
                    if ($results)
                    {
                        #insert a custom type name so that formatting can be applied
                        $results.GetEnumerator().ForEach( { $_.psobject.TypeNames.insert(0, "myGPOLink") })
                        $results
                    }
                    else
                    {
                        Write-Warning "Failed to find any GPO using a name like $Name"
                    }
                }
            }
            End
            {
                Write-Verbose "Ending $($myinvocation.mycommand)"
            }
        }

        #define custom type extensions
        Update-TypeData -MemberType AliasProperty -MemberName GUID -Value GPOId -TypeName myGPOLink -Force
        Update-TypeData -MemberType AliasProperty -MemberName Name -Value DisplayName -TypeName myGPOLink -Force
        Update-TypeData -MemberType AliasProperty -MemberName GPO -Value DisplayName -TypeName myGPOLink -Force
        Update-TypeData -MemberType AliasProperty -MemberName Link -Value Target -TypeName myGPOLink -Force
        Update-TypeData -MemberType AliasProperty -MemberName Domain -Value GpoDomainName -TypeName myGPOLink -Force
        Update-TypeData -MemberType ScriptProperty -MemberName TargetType -Value {
            switch -regex ($this.target) {
                "^((ou)|(OU)=)" { "OU" }
                "^((dc)|(DC)=)" { "Domain" }
                "^((cn)|(CN)=)" { "Site" }
                Default { "Unknown"}
            }
        } -TypeName myGPOLink -Force

        #define custom formatting
        Update-FormatData $PSScriptRoot\mygpolink.format.ps1xml
    #endregion
    #region - GPLink&Copy
        <#
            Ashley McGlone
            Microsoft Premier Field Engineer
            http://aka.ms/GoateePFE
            May 2015
            This script includes the following functions:
                Get-GPLink
                Get-GPUnlinked
                Copy-GPRegistryValue

                All code has been tested on Windows Server 2008 R2 with PowerShell v2.0.
            Requires:
                -PowerShell v2 or above
                -RSAT
                -ActiveDirectory module
                -GroupPolicy module
        #>


        Function Get-GPLink
        {
            <#
                .SYNOPSIS
                    This function creates a report of all group policy links, their locations, and
                    their configurations in the current domain.  Output is a CSV file.

                .DESCRIPTION
                    Long description

                .PARAMETER Path
                    Optional parameter.  If specified, it will return GPLinks for a specific OU or 
                    domain root rather than all GPLinks.

                .EXAMPLE
                    Get-GPLink | Out-GridView

                .EXAMPLE
                    Get-GPLink -Path 'OU=Users,OU=IT,DC=wingtiptoys,DC=local' | Out-GridView

                .EXAMPLE
                    Get-GPLink -Path 'DC=wingtiptoys,DC=local' | Out-GridView

                .EXAMPLE
                    Get-GPLink -Path 'DC=wingtiptoys,DC=local' | ForEach-Object {$_.DisplayName}

                .NOTES
                    For more information on gPLink, gPOptions, and gPLinkOptions see:
                     [MS-GPOL]: Group Policy: Core Protocol
                      http://msdn.microsoft.com/en-us/library/cc232478.aspx
                     2.2.2 Domain SOM Search
                      http://msdn.microsoft.com/en-us/library/cc232505.aspx
                     2.3 Directory Service Schema Elements
                      http://msdn.microsoft.com/en-us/library/cc422909.aspx
                     3.2.5.1.5 GPO Search
                      http://msdn.microsoft.com/en-us/library/cc232537.aspx

                    SOM is an acronym for Scope of Management, referring to any location where
                    a group policy could be linked: domain, OU, site.
                    This GPO report does not list GPO filtering by permissions.
                    Helpful commands when inspecting GPO links:
                    Get-ADOrganizationalUnit -Filter {Name -eq 'Production'} | Select-Object -ExpandProperty LinkedGroupPolicyObjects
                    Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName, LinkedGroupPolicyObjects
                    Get-ADObject -Identity 'OU=HR,DC=wingtiptoys,DC=local' -Property gPLink
            #>
            Param
            (
                [Parameter()]
                [string]
                $Path
            )

            # Requires RSAT installed and features enabled
            Import-Module GroupPolicy
            Import-Module ActiveDirectory

            # Pick a DC to target
            $Server = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName

            # Grab a list of all GPOs
            $GPOs = Get-GPO -All -Server $Server | Select-Object ID, Path, DisplayName, GPOStatus, WMIFilter, CreationTime, ModificationTime, User, Computer

            # Create a hash table for fast GPO lookups later in the report.
            # Hash table key is the policy path which will match the gPLink attribute later.
            # Hash table value is the GPO object with properties for reporting.
            $GPOsHash = @{}
            ForEach ($GPO in $GPOs)
            {
                $GPOsHash.Add($GPO.Path,$GPO)
            }

            # Empty array to hold all possible GPO link SOMs
            $gPLinks = @()

            If ($PSBoundParameters.ContainsKey('Path'))
            {
                $gPLinks += `
                 Get-ADObject -Server $Server -Identity $Path -Properties name, distinguishedName, gPLink, gPOptions |
                 Select-Object name, distinguishedName, gPLink, gPOptions
            }
            Else
            {
                # GPOs linked to the root of the domain
                #  !!! Get-ADDomain does not return the gPLink attribute
                $gPLinks += `
                 Get-ADObject -Server $Server -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions |
                 Select-Object name, distinguishedName, gPLink, gPOptions

                # GPOs linked to OUs
                #  !!! Get-GPO does not return the gPLink attribute
                $gPLinks += `
                 Get-ADOrganizationalUnit -Server $Server -Filter * -Properties name, distinguishedName, gPLink, gPOptions |
                 Select-Object name, distinguishedName, gPLink, gPOptions

                # GPOs linked to sites
                $gPLinks += `
                 Get-ADObject -Server $Server -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
                 Select-Object name, distinguishedName, gPLink, gPOptions
            }

            # Empty report array
            $report = @()

            # Loop through all possible GPO link SOMs collected
            ForEach ($SOM in $gPLinks)
            {
                # Filter out policy SOMs that have a policy linked
                If ($SOM.gPLink)
                {

                    # If an OU has 'Block Inheritance' set (gPOptions=1) and no GPOs linked,
                    # then the gPLink attribute is no longer null but a single space.
                    # There will be no gPLinks to parse, but we need to list it with BlockInheritance.
                    If ($SOM.gPLink.length -gt 1)
                    {
                        <#
                            Use @() for force an array in case only one object is returned (limitation in PS v2)
                            Example gPLink value:
                                [LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2][LDAP://cn={046584E4-F1CD-457E-8366-F48B7492FBA2},cn=policies,cn=system,DC=wingtiptoys,DC=local;0][LDAP://cn={12845926-AE1B-49C4-A33A-756FF72DCC6B},cn=policies,cn=system,DC=wingtiptoys,DC=local;1]
                            Split out the links enclosed in square brackets, then filter out
                            the null result between the closing and opening brackets ][
                        #>
                        $links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})
                        # Use a for loop with a counter so that we can calculate the precedence value
                        For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- )
                        {
                            <#
                                Example gPLink individual value (note the end of the string):
                                    LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2
                                Splitting on '/' and ';' gives us an array every time like this:
                                    0: LDAP:
                                    1: (null value between the two //)
                                    2: distinguishedName of policy
                                    3: numeric value representing gPLinkOptions (LinkEnabled and Enforced)
                            #>
                            $GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
                            # Add a new report row for each GPO link
                            $report += New-Object -TypeName PSCustomObject -Property @{
                                Name              = $SOM.Name;
                                OUDN              = $SOM.distinguishedName;
                                PolicyDN          = $GPOData[2];
                                Precedence        = $links.count - $i
                                GUID              = "{$($GPOsHash[$($GPOData[2])].ID)}";
                                DisplayName       = $GPOsHash[$GPOData[2]].DisplayName;
                                GPOStatus         = $GPOsHash[$GPOData[2]].GPOStatus;
                                WMIFilter         = $GPOsHash[$GPOData[2]].WMIFilter.Name;
                                GPOCreated        = $GPOsHash[$GPOData[2]].CreationTime;
                                GPOModified       = $GPOsHash[$GPOData[2]].ModificationTime;
                                UserVersionDS     = $GPOsHash[$GPOData[2]].User.DSVersion;
                                UserVersionSysvol = $GPOsHash[$GPOData[2]].User.SysvolVersion;
                                ComputerVersionDS = $GPOsHash[$GPOData[2]].Computer.DSVersion;
                                ComputerVersionSysvol = $GPOsHash[$GPOData[2]].Computer.SysvolVersion;
                                Config            = $GPOData[3];
                                LinkEnabled       = [bool](!([int]$GPOData[3] -band 1));
                                Enforced          = [bool]([int]$GPOData[3] -band 2);
                                BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                            } # End Property hash table
                        } # End For
                    }
                }
            } # End ForEach

            # Output the results to CSV file for viewing in Excel
            $report |
             Select-Object OUDN, BlockInheritance, LinkEnabled, Enforced,  `
                           Precedence,DisplayName, GPOStatus, WMIFilter, GUID,  `
                           GPOCreated, GPOModified, UserVersionDS, UserVersionSysvol, `
                           ComputerVersionDS, ComputerVersionSysvol, PolicyDN
        }

        Function Get-GPUnlinked
        {
            <#
                .SYNOPSIS
                    Used to discover GPOs that are not linked anywhere in the domain.

                .DESCRIPTION
                    All GPOs in the domain are returned. The Linked property indicates true if any links exist.  The property is blank if no links exist.

                .EXAMPLE
                    Get-GPUnlinked | Out-GridView

                .EXAMPLE
                    Get-GPUnlinked | Where-Object {!$_.Linked} | Out-GridView

                .NOTES
                    This function does not look for GPOs linked to sites.
                    Use the Get-GPLink function to view those.
            #>
            Import-Module GroupPolicy
            Import-Module ActiveDirectory

            # BUILD LIST OF ALL POLICIES IN A HASH TABLE FOR QUICK LOOKUP
            $AllPolicies = Get-ADObject -Filter * -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).Distinguishedname)" -SearchScope OneLevel -Property DisplayName, whenCreated, whenChanged
            $GPHash = @{}

            ForEach ($Policy in $AllPolicies)
            {
                $GPHash.Add($Policy.DistinguishedName,$Policy)
            }

            # BUILD LIST OF ALL LINKED POLICIES
            $AllLinkedPolicies = Get-ADOrganizationalUnit -Filter * | Select-Object -ExpandProperty LinkedGroupPolicyObjects -Unique
            $AllLinkedPolicies += Get-ADDomain | Select-Object -ExpandProperty LinkedGroupPolicyObjects -Unique

            # FLAG EACH ONE WITH A LINKED PROPERTY
            ForEach ($Policy in $AllLinkedPolicies)
            {
                $GPHash[$Policy].Linked = $true
            }

            # POLICY LINKED STATUS
            $GPHash.Values | Select-Object whenCreated, whenChanged, Linked, DisplayName, Name, DistinguishedName

            ### NOTE THAT whenChanged IS NOT A REPLICATED VALUE
        }

        Function DownTheRabbitHole
        {
            # HELPER FUNCTION FOR Copy-GPRegistryValue
            [CmdletBinding()]
            Param
            (
                [Parameter()]
                [String[]]
                $rootPaths,
                [Parameter()]
                [String]
                $SourceGPO,
                [Parameter()]
                [String]
                $DestinationGPO
            )

            $ErrorActionPreference = 'Continue'

            ForEach ($rootPath in $rootPaths)
            {
                Write-Verbose "SEARCHING PATH [$SourceGPO] [$rootPath]"
                Try
                {
                    $children = Get-GPRegistryValue -Name $SourceGPO -Key $rootPath -Verbose -ErrorAction Stop
                }
                Catch
                {
                    Write-Warning "REGISTRY PATH NOT FOUND [$SourceGPO] [$rootPath]"
                    $children = $null
                }

                $Values = $children | Where-Object {-not [string]::IsNullOrEmpty($_.PolicyState)}
                If ($Values)
                {
                    ForEach ($Value in $Values)
                    {
                        If ($Value.PolicyState -eq "Delete")
                        {
                            Write-Verbose "SETTING DELETE [$SourceGPO] [$($Value.FullKeyPath):$($Value.Valuename)]"
                            If ([string]::IsNullOrEmpty($_.Valuename))
                            {
                                Write-Warning "EMPTY VALUENAME, POTENTIAL SETTING FAILURE, CHECK MANUALLY [$SourceGPO] [$($Value.FullKeyPath):$($Value.Valuename)]"
                                Set-GPRegistryValue -Disable -Name $DestinationGPO -Key $Value.FullKeyPath -Verbose | Out-Null
                            }
                            Else
                            {

                                # Warn if overwriting an existing value in the DestinationGPO.
                                # This usually does not get triggered for DELETE settings.
                                Try
                                {
                                    $OverWrite = $true
                                    $AlreadyThere = Get-GPRegistryValue -Name $DestinationGPO -Key $rootPath -ValueName $Value.Valuename -Verbose -ErrorAction Stop
                                }
                                Catch
                                {
                                    $OverWrite = $false
                                }
                                Finally
                                {
                                    If ($OverWrite)
                                    {
                                        Write-Warning "OVERWRITING PREVIOUS VALUE [$SourceGPO] [$($Value.FullKeyPath):$($Value.Valuename)] [$($AlreadyThere.Value -join ';')]"
                                    }
                                }

                                Set-GPRegistryValue -Disable -Name $DestinationGPO -Key $Value.FullKeyPath -ValueName $Value.Valuename -Verbose | Out-Null
                            }
                        }
                        Else
                        {
                            # PolicyState = "Set"
                            Write-Verbose "SETTING SET [$SourceGPO] [$($Value.FullKeyPath):$($Value.Valuename)]"

                            # Warn if overwriting an existing value in the DestinationGPO.
                            # This can occur when consolidating multiple GPOs that may define the same setting, or when re-running a copy.
                            # We do not check to see if the values match.
                            Try
                            {
                                $OverWrite = $true
                                $AlreadyThere = Get-GPRegistryValue -Name $DestinationGPO -Key $rootPath -ValueName $Value.Valuename -Verbose -ErrorAction Stop
                            }
                            Catch
                            {
                                $OverWrite = $false
                            }
                            Finally
                            {
                                If ($OverWrite)
                                {
                                    Write-Warning "OVERWRITING PREVIOUS VALUE [$SourceGPO] [$($Value.FullKeyPath):$($Value.Valuename)] [$($AlreadyThere.Value -join ';')]"
                                }
                            }

                            $Value | Set-GPRegistryValue -Name $DestinationGPO -Verbose | Out-Null
                        }
                    }
                }

                $subKeys = $children | Where-Object {[string]::IsNullOrEmpty($_.PolicyState)} | 
                    Select-Object -ExpandProperty FullKeyPath
                if ($subKeys)
                {
                    DownTheRabbitHole -rootPaths $subKeys -SourceGPO $SourceGPOSingle -DestinationGPO $DestinationGPO -Verbose
                }
                
            }
        }

        Function Copy-GPRegistryValue
        {
            <#
                .SYNOPSIS
                    Copies GPO registry settings from one or more policies to another.

                .DESCRIPTION
                    Long description

                .PARAMETER Mode
                    Indicates which half of the GPO settings to copy.  Three possible values: All, User, Computer.

                .PARAMETER SourceGPO
                    Display name of one or more GPOs from which to copy settings.

                .PARAMETER DestinationGPO
                    Display name of destination GPO to receive the settings.
                    If the destination GPO does not exist, then it creates it.

                .EXAMPLE
                    Copy-GPRegistryValue -Mode All -SourceGPO "IE Test" -DestinationGPO "NewMergedGPO" -Verbose

                .EXAMPLE
                    Copy-GPRegistryValue -Mode All -SourceGPO "foo", "Starter User", "Starter Computer" -DestinationGPO "NewMergedGPO" -Verbose

                .EXAMPLE
                    Copy-GPRegistryValue -Mode User -SourceGPO 'User Settings' -DestinationGPO 'New Merged GPO' -Verbose

                .EXAMPLE
                    Copy-GPRegistryValue -Mode Computer -SourceGPO 'Computer Settings' -DestinationGPO 'New Merged GPO' -Verbose

                .NOTES
                    Helpful commands when inspecting GPO links:
                    Get-ADOrganizationalUnit -Filter {Name -eq 'Production'} | Select-Object -ExpandProperty LinkedGroupPolicyObjects
                    Get-ADOrganizationalUnit -Filter * | Select-Object DistinguishedName, LinkedGroupPolicyObjects
                    Get-ADObject -Identity 'OU=HR,DC=wingtiptoys,DC=local' -Property gPLink
            #>
            [CmdletBinding()]
            Param
            (
                [Parameter()]
                [ValidateSet('All','User','Computer')]
                [String]
                $Mode = 'All',
                [Parameter()]
                [String[]]
                $SourceGPO,
                [Parameter()]
                [String]
                $DestinationGPO
            )
            Import-Module GroupPolicy -Verbose:$false

            $ErrorActionPreference = 'Continue'

            Switch ($Mode)
            {
                'All'      {$rootPaths = "HKCU\Software","HKLM\System","HKLM\Software"; break}
                'User'     {$rootPaths = "HKCU\Software"                              ; break}
                'Computer' {$rootPaths = "HKLM\System","HKLM\Software"                ; break}
            }
    
            If (Get-GPO -Name $DestinationGPO -ErrorAction SilentlyContinue)
            # If ((Get-GPO -All) | Where DisplayName -match $SourceGPOSingle -ErrorAction SilentlyContinue)
            {
                Write-Verbose "DESTINATION GPO EXISTS [$DestinationGPO]"
            }
            Else
            {
                Write-Verbose "CREATING DESTINATION GPO [$DestinationGPO]"
                New-GPO -Name $DestinationGPO -Verbose | Out-Null
            }

            $ProgressCounter = 0
            $ProgressTotal   = @($SourceGPO).Count   # Syntax for PSv2 compatibility
            ForEach ($SourceGPOSingle in $SourceGPO)
            {
                Write-Progress -PercentComplete ($ProgressCounter / $ProgressTotal * 100) -Activity "Copying GPO settings to: $DestinationGPO" -Status "From: $SourceGPOSingle"
                If (Get-GPO -Name $SourceGPOSingle -ErrorAction SilentlyContinue)
                # If ((Get-GPO -All) | Where DisplayName -match $SourceGPOSingle -ErrorAction SilentlyContinue)
                {
                    Write-Verbose "SOURCE GPO EXISTS [$SourceGPOSingle]"

                    DownTheRabbitHole -rootPaths $rootPaths -SourceGPO $SourceGPOSingle -DestinationGPO $DestinationGPO -Verbose

                    Get-GPOReport -Name $SourceGPOSingle -ReportType Xml -Path "$pwd\report_$($SourceGPOSingle).xml"
                    $nonRegistry = Select-String -Path "$pwd\report_$($SourceGPOSingle).xml" -Pattern "<Extension " -SimpleMatch | Where-Object {$_ -notlike "*RegistrySettings*"}

                    If (($nonRegistry | Measure-Object).Count -gt 0)
                    {
                        Write-Warning "SOURCE GPO CONTAINS NON-REGISTRY SETTINGS FOR MANUAL COPY [$SourceGPOSingle]"
                        Write-Warning ($nonRegistry -join "`r`n")
                    }
                }
                Else
                {
                    Write-Warning "SOURCE GPO DOES NOT EXIST [$SourceGPOSingle]"
                }
                $ProgressCounter++
            }

            Write-Progress -Activity "Copying GPO settings to: $DestinationGPO" -Completed -Status "Complete"
        }


        <#########################################################################sdg#>
        BREAK

        # Help
        Help Get-GPLink -Full
        Help Get-GPUnlinked -Full
        Help Copy-GPRegistryValue -Full

        # Copy one GPO registry settings into another
        Copy-GPRegistryValue -Mode Computer -SourceGPO "MS-B" `
            -DestinationGPO 'Microsoft 365 Apps v2206 - Computer' -Verbose

        # Copy one GPO registry settings into another, just user settings
        Copy-GPRegistryValue -Mode User -SourceGPO '_Microsoft 365 Apps v2206 - DDE Block - User' `
            -DestinationGPO '_Microsoft 365 Apps - User' -Verbose

        # Copy one GPO registry settings into another, just computer settings
        Copy-GPRegistryValue -Mode Computer -SourceGPO 'Client Settings' `
            -DestinationGPO 'New Merged GPO' -Verbose

        # Copy multiple GPO registry settings into another
        Copy-GPRegistryValue -Mode All  -DestinationGPO "NewMergedGPO" `
            -SourceGPO "Firewall Policy", "Starter User", "Starter Computer" -Verbose

        # Copy all GPOs linked to one OU registry settings into another
        # Sort in reverse precedence order so that the highest precedence settings overwrite
        # any potential settings conflicts in lower precedence policies.
        $SourceGPOs = Get-GPLink -Path 'OU=SubTest,OU=Testing,DC=CohoVineyard,DC=com' |
            Sort-Object Precedence -Descending |
            Select-Object -ExpandProperty DisplayName
        Copy-GPRegistryValue -Mode All -SourceGPO $SourceGPOs `
            -DestinationGPO "NewMergedGPO" -Verbose

        # Log all GPO copy output (including verbose and warning)
        # Requires PowerShell v3.0+
        Copy-GPRegistryValue -Mode All -SourceGPO 'IE Test' `
            -DestinationGPO 'New Merged GPO' -Verbose *> GPOCopyLog.txt

        # Disable all GPOs linked to an OU
        Get-GPLink -Path 'OU=SubTest,OU=Testing,DC=CohoVineyard,DC=com' |
            ForEach-Object {
                Set-GPLink -Target $_.OUDN -GUID $_.GUID -LinkEnabled No -Confirm
            }

        # Enable all GPOs linked to an OU
        Get-GPLink -Path 'OU=SubTest,OU=Testing,DC=CohoVineyard,DC=com' |
            ForEach-Object {
                Set-GPLink -Target $_.OUDN -GUID $_.GUID -LinkEnabled Yes -Confirm
            }

        # Quick link status of all GPOs
        Get-GPUnlinked | Out-Gridview

        # Just the unlinked GPOs
        Get-GPUnlinked | Where-Object {!$_.Linked} | Out-GridView

        # Detailed GP link status for all GPO with links
        Get-GPLink | Out-GridView

        # List of GPOs linked to a specific OU (or domain root)
        Get-GPLink -Path 'OU=SubTest,OU=Testing,DC=CohoVineyard,DC=com' |
            Select-Object -ExpandProperty DisplayName

        # List of OUs (or domain root) where a specific GPO is linked
        Get-GPLink |
            Where-Object {$_.DisplayName -eq 'Script And Delegation Test'} |
            Select-Object -ExpandProperty OUDN
    #endregion
    #region - Purge/Merge Admin Templates (PolDefFixes)
        $pthA = "\\$curDomain\SYSVOL\$curDomain\Policies\PolicyDefinitions"
        $pthB = "\\$curDomain\SYSVOL\$curDomain\Policies\PolicyDefinitions\en-us"
        $pthC = "C:\Windows\PolicyDefinitions"
        $pthD = "C:\Windows\PolicyDefinitions\en-US"
        $pthE = "C:\Program Files (x86)\Microsoft Group Policy\Windows 10 October 2020 Update V2 (20H2)\PolicyDefinitions"
        $pthF = "C:\Program Files (x86)\Microsoft Group Policy\Windows 10 October 2020 Update V2 (20H2)\PolicyDefinitions\en-US"

        # Create Tables and add Rows
            ForEach ($itm in ('diff1Data','diff2Data','diff3Data'))
            {
                IEX "`$$itm = New-Object System.Data.Datatable"
                IEX "'Template Name','Path1','Side','Path2' | %{ [Void]`$$itm.Columns.Add(`$_) }"
            }
        # Capture Comparisons
            1..3 | %{
                $itm = "$_"
                $cmd = "`$diff$itm = Compare-Object (gci `$pth<P1>\* -File | Select -Exp Basename) (gci `$pth<P2>\* -File | Select -Exp Basename)"
                Switch ($itm)
                {
                    1 { IEX ($cmd -replace '<P1>','A' -replace '<P2>','B') }
                    2 { IEX ($cmd -replace '<P1>','C' -replace '<P2>','D') }
                    3 { IEX ($cmd -replace '<P1>','C' -replace '<P2>','A') }
                }
            }
        # Populate Table Rows
            $diff1 | %{ # ADML/ADMX Mismatch
                [void]$diff1Data.Rows.Add( $($_.InputObject),$($pthA),$($_.SideIndicator),$($pthB) )
                }
            $diff2 | %{ # ADML/ADMX Mismatch
                [void]$diff2Data.Rows.Add( $($_.InputObject),$($pthC),$($_.SideIndicator),$($pthD) )
                }
            $diff3 | %{
                [void]$diff3Data.Rows.Add( $($_.InputObject),$($pthC),$($_.SideIndicator),$($pthD) )
                }
            $diff1Data
            $diff2Data
            $diff3Data

                robocopy $pthE $pthC /MIR /COPYALL /XO /TEE /LOG:C:\Robo2.log
                $R = Compare-Object (gci $pthF\* -File) (gci $pthD\* -File)
                $R[0].InputObject.LastWriteTime

        Remove-Item $pthA -Force # -Recurse
        New-Item $pthA -ItemType Directory
        New-Item $pthB -ItemType Directory
 
        SL $pthA
        Copy-Item -Path $pthC\*.admx -Verbose
        SL $pthB
        Copy-Item -Path $pthD\*.adml -Verbose
        # Copy-Item -Path "$pthE\ActiveXInstallService.adml" -Verbose -Confirm
    #endregion

    Function Test-GroupPolicy
    {
        <#
            .SYNOPSIS
                PowerShell Wrapper for Get-GPResultantSetOfPolicy and gpresult.exe that adds a layer of abstraction to choosing
                which one to use and implements a few fixes to the HTML output of gpresult.

            .DESCRIPTION
                This script generates Resultant Set of Policy (RSoP) reports across Windows OSs with and without native PowerShell
                support for such.  When the native Get-GPResultantSetOfPolicy is available, that is used to generate an HTML/XML
                report.  When it is not, or the user wishes to output the results to console, the script relies on the older gpresult.exe.
                To further improve usability, the headers of gpresult-generated HTML reports are tweaked (see bullets below for specifics).
                These modifications help ensure the report is properly rendered in modern IE or Microsoft Edge IE Mode.

                Tweaks:
                - IE is instructed to render the report in IE5 Quirks Mode.
                - A mark-of-the-web meta tag is added to eliminate the need to unblock the VBScript responsible for Expand/Collapse, 
                  Tooltips, Printing, LTR/RTL adjustments, and keypress support.

                To save time, the user is also prompted about whether or not they want to open newly generated HTML reports in Microsoft Edge.
                Edge instances launched this way run with restricted permissions regardless of the elevation of the PowerShell Console.

            .COMPONENT
                GroupPolicy

            .NOTES
                This script requires elevation because both gpresult.exe and Get-GPResultantSetOfPolicy return errors or produce incomplete
                results when run without elevation.

                IE/IE Mode requirements stem from VBScript use.  VBScript support is enabled for the Local Intranet security zone by default,
                however if it does not work, you'll need to edit the following Group Policy (either local or global) to enable it:
                    "\\Computer\Administrative Templates\Windows Components\Internet Explorer\Internet Control Panel\ Security Page\Intranet Zone\Allow VBScript to run in Internet Explorer."

                Some Anti-Malware software considers the unmodified Microsoft VBScript included in the generated reports to be an exploit and blocks it.
                Software known to have this issue includes:
                    - Malwarebytes Anti-Malware: Will prevent IE VBScript from running if the Real-Time Protection >> Exploit Protection >> Advanced Settings >> 
                      Disable Internet Explorer VB Scripting option is enabled.

            .EXAMPLE
                Test-GroupPolicy
                Runs gpresult and outputs to the console.

            .EXAMPLE
                Test-GroupPolicy "C:\test\gpresult.html"
                Generates an HTML RSoP report using Get-GPResultantSetOfPolicy (or gpresult + fixes as a fallback) and prompts if you want to open it in Microsoft Edge.

            .EXAMPLE
                Test-GroupPolicy "C:\test\gpresult.html" -Server Test-01 -Scope Computer -Force -Quiet
                Generates an HTML RSoP report for Computer settings applied to the Test-01 computer and silently overwrites any existing report.
                The current user must have administrative privileges on the remote server.  Does not prompt to open in Microsoft Edge.

            .EXAMPLE
                Test-GroupPolicy "C:\test\gpresult.xml"
                Generates an XML RSoP report using Get-GPResultantSetOfPolicy or gpresult if the former is unavailable.
        #>
        [CmdletBinding(PositionalBinding=$false)]
        Param
        (
            # File Path of the exported report.  HTML file types export HTML reports and xml file types export XML reports.
            # This is the only parameter that can be implicitly passed.
            [Parameter(Position=0)]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
            # (S) Specifies the remote system to connect to. Do not use backslashes. The default is the local computer.
            [Alias("s")]
            [ValidateNotNullOrEmpty()]
            [string]$Server,
            # Specifies whether the user or the computer settings need to be displayed.
            [ValidateSet("USER","COMPUTER")]
            [string]$Scope,
            # Specifies the user name for which RSoP data is to be displayed.
            [ValidateNotNullOrEmpty()]
            [string]$User,
            # (F) Forces gpresult to overwrite the file path specified.
            [Alias("F")]
            [switch]$Force,
            # Do not prompt to open report in IE.
            [switch]$Quiet
        )

        [bool]$OutFile = $false

        if(Test-Path variable:As){Remove-Variable As}
        if(![String]::IsNullOrEmpty($Path)) {
            $OutFile = $true
            [char]$As = if([System.IO.Path]::GetExtension($Path) -imatch ".htm[l]?$"){"H"}
                        elseif([System.IO.Path]::GetExtension($Path) -ieq ".xml"){"X"}
                        else{throw "Test-GroupPolicy only supports exporting to HTML and XML files.  Please check the file extention of the supplied Path."}
        }

        # The Get-GPResultantSetOfPolicy cmdlet is superior when available, but only supports outputting to file.
        if($OutFile -and (Get-Command Get-GPResultantSetOfPolicy -ErrorAction SilentlyContinue))
        {
            $ReportType = switch($As){ "H"{"Html"; break}; "X"{"Xml"; break}}

            try
            {
                if(![String]::IsNullOrEmpty($Server) -and ![String]::IsNullOrEmpty($User))
                { Get-GPResultantSetOfPolicy -Path $Path -ReportType $ReportType -Computer $Server -User $User }
                elseif(![String]::IsNullOrEmpty($Server) -and [String]::IsNullOrEmpty($User))
                { Get-GPResultantSetOfPolicy -Path $Path -ReportType $ReportType -Computer $Server }
                elseif([String]::IsNullOrEmpty($Server) -and ![String]::IsNullOrEmpty($User))
                { Get-GPResultantSetOfPolicy -Path $Path -ReportType $ReportType -User $User }
                else
                { Get-GPResultantSetOfPolicy -Path $Path -ReportType $ReportType }

                Write-Output "Report Generation Complete"

                if($As -eq "H" -and (Test-Path $Path -PathType Leaf))
                {
                    # The runas command is used to run Edge with restricted, non-admin privileges.
                    if(!$Quiet.IsPresent -and (Read-Host -Prompt "Open the report in Microsoft Edge now? (Y/N)") -ieq "y")
                    { 
                        $msEdge = if(Test-Path "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe") 
                            {"${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"} 
                        else
                            {"${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"}
                        runas /trustlevel:0x20000 "\`"$msEdge\`" \`"$Path\`""
                    }
                }
            }
            catch{ throw $_.Exception }
        }
        else
        {
            # Construct gpresult invocation string
            $arguments = @()
            if(![String]::IsNullOrEmpty($Server)) {$arguments += "/S","`"$Server`""}
            if(![String]::IsNullOrEmpty($Scope)) {$arguments += "/SCOPE",$Scope}
            if(![String]::IsNullOrEmpty($User)) {$arguments += "/USER","`"$User`""}
            if([System.Management.Automation.ActionPreference]::SilentlyContinue -ne $VerbosePreference) {$arguments += "/Z"}
            elseif(!$OutFile) {$arguments += "/R"}

            if($OutFile)
            {
                if($Force.IsPresent) {$arguments += "/F"}

                $arguments += "/$As","`"$Path`""
            }

            # Generate GPRESULT Report
            try
            {
                # Run gpresult and Stop on any errors.
                Invoke-Command {gpresult $args} -ArgumentList $arguments -NoNewScope | Tee-Object -Variable p
                if($LASTEXITCODE -gt 0 -or $p -ilike "*The user*does not have RSoP data."){break}

                if($As -eq "H" -and (Test-Path $Path -PathType Leaf))
                {
                    # Edits the report to include both the mark-of-the-web meta tag and the IE Render Mode meta tag.
                    # For details on Mark-of-the-web meta tags, see: https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/compatibility/ms537628(v=vs.85)
                    # This ensures the report will always offer full functionality when opened in IE Mode.
                    (Get-Content $Path) -replace '<meta http-equiv="Content-Type" content="text/html; charset=UTF-16" />',
        '<!-- saved from url=(0016)https://localhost -->
        <meta http-equiv="X-UA-Compatible" content="IE=5" />
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-16" />' -replace '<tr><td colspan="2" class="rsopheader">Group Policy Results</td></tr>',
        '<tr><td colspan="2" class="rsopheader">Group Policy Results (Requires IE Mode)</td></tr>' | Set-Content $Path -Encoding Unicode

                    Write-Output "Report Generation Complete"
                    Write-Warning "This report requires IE or Microsoft Edge IE Mode with VBScript support enabled for full functionality.`r`nIf using Microsoft Edge you will need to either `"Switch to Internet Explorer Mode`" or configure the browser to open the file in IE Mode through some other means."

                    # The runas command is used to run Edge with restricted, non-admin privileges.
                    if(!$Quiet.IsPresent -and (Read-Host -Prompt "Open the report in Microsoft Edge now? (Y/N)") -ieq "y")
                    { 
                        $msEdge = if(Test-Path "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe") 
                            {"${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"} 
                        else
                            {"${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"}
                        runas /trustlevel:0x20000 "\`"$msEdge\`" \`"$Path\`""
                    }
                }
                else {Write-Output "Report Generation Complete"}
            }
            catch{ throw $_.Exception }
        }
    }
#endregion
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
        select name,DistinguishedName,@{n=’OUPath’;e={$_.distinguishedName -replace '^.+?,',''}}, `
        # select name,DistinguishedName,@{n=’OUPath’;e={$_.distinguishedName -replace '^.+?,(CN|OU|DC.+)','$1'}}, `
            @{n=’OUNum’;e={([regex]::Matches($_.distinguishedName, “OU=” )).count}} | 
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
         Get-PrintConfiguration –PrinterName $Printer.name # –DuplexingMode "TwoSidedLongEdge"
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
#region - DHCP
#region - DHCP Scope Statistics Report
Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b  }
$htmlfile = [Environment]::GetFolderPath("Desktop") + '\' + "DHCPData-$(Get-Date -f yyyyMMdd).html" ### The full path to the final HTML file
$htmlfile_temp = [Environment]::GetFolderPath("Desktop") + '\' + "DHCPData-$(Get-Date -f yyyyMMdd)_temp.html" ### The full path to the temporary HTML file
 
### Checking to see if the temp file exists, if it does it will remove it
If (Test-Path $htmlfile_temp) { Remove-Item $htmlfile_temp -Force }

$html_header = (Dec64 'DQo8aHRtbD4NCjxoZWFkPg0KPG1ldGEgaHR0cC1lcXVpdj0nQ29udGVudC1UeXBlJyBjb250ZW50PSd0ZXh0L2h0bWw7IGNoYXJzZXQ9aXNvLTg4NTktMSc+DQo8dGl0bGU+REhDUCBSZXBvcnQ8L3RpdGxlPg0KPFNUWUxFIFRZUEU9J3RleHQvY3NzJz4NCjwvc3R5bGU+DQo8L2hlYWQ+DQo8Ym9keT4NCjx0YWJsZS1sYXlvdXQ6IGZpeGVkPg0KPHRhYmxlIHdpZHRoPScxMDAlJz4NCjx0ciBiZ2NvbG9yPScjMDBCNjI0Jz4NCjx0ZCBjb2xzcGFuPSc3JyBoZWlnaHQ9JzI1JyBhbGlnbj0nY2VudGVyJz48c3Ryb25nPjxmb250IGNvbG9yPScjMDAwMDAwJyBzaXplPSc0JyBmYWNlPSd0YWhvbWEnPkRIQ1AgU2NvcGUgU3RhdGlzdGljcyBSZXBvcnQ8L2ZvbnQ+PGZvbnQgY29sb3I9JyMwMDAwMDAnIHNpemU9JzQnIGZhY2U9J3RhaG9tYSc+ICgwOS8wOS8yMDIyIDEzOjE3OjIzKTwvZm9udD48Zm9udCBjb2xvcj0nIzAwMDAwMCcgc2l6ZT0nMicgZmFjZT0ndGFob21hJz4gPEJSPiBEYXRhIFVwZGF0ZXMgRXZlcnkgRGF5PC9mb250Pg0KPC90cj4NCjwvdGFibGU+DQo8dGFibGUgd2lkdGg9JzEwMCUnPg0KPHRyIGJnY29sb3I9JyNDQ0NDQ0MnPg0KPHRkIGNvbHNwYW49JzcnIGhlaWdodD0nMjAnIGFsaWduPSdjZW50ZXInPjxzdHJvbmc+PGZvbnQgY29sb3I9JyMwMDAwMDAnIHNpemU9JzInIGZhY2U9J3RhaG9tYSc+PHNwYW4gc3R5bGU9YmFja2dyb3VuZC1jb2xvcjojRkZGMjg0PldBUk5JTkc8L3NwYW4+IGF0IDgwJSBJbiBVc2UgICAgICA8c3BhbiBzdHlsZT1iYWNrZ3JvdW5kLWNvbG9yOiNGRjAwMDA+PGZvbnQgY29sb3I9d2hpdGU+Q1JJVElDQUw8L2ZvbnQ+PC9zcGFuPiBhdCA5NSUgSW4gVXNlPC9mb250Pg0KPC90cj4NCjwvdGFibGU+DQo8dGFibGUgd2lkdGg9JzEwMCUnPjx0Ym9keT4NCiAgICA8dHIgYmdjb2xvcj1ibGFjaz4NCiAgICA8dGQgd2lkdGg9JzEwJScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+REhDUCBTZXJ2ZXI8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5TY29wZSBJRDwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDx0ZCB3aWR0aD0nMTAlJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5TY29wZSBuYW1lPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+U2NvcGUgU3RhdGU8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5JbiBVc2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5GcmVlPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+JSBJbiBVc2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5SZXNlcnZlZDwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDx0ZCB3aWR0aD0nOCUnIGhlaWdodD0nMTUnIGFsaWduPSdjZW50ZXInPiA8c3Ryb25nPiA8Zm9udCBjb2xvcj0nd2hpdGUnIHNpemU9JzInIGZhY2U9J3RhaG9tYScgPlN1Ym5ldCBNYXNrPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+U3RhcnQgb2YgUmFuZ2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5FbmQgb2YgUmFuZ2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5MZWFzZSBEdXJhdGlvbjwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDwvdHI+DQo8L3RhYmxlPg0K')
$html_header | Out-File $htmlfile_temp ### Writing the HTML header to the temporary file

$DHCP_Servers = Get-DhcpServerInDC | ForEach-Object {$_.DnsName} | Sort-Object -Property DnsName ### Dynamically pulling the DHCP servers in a Active Directory domain
Foreach ($DHCP_Server in $DHCP_Servers)
{
    ### Going through the DHCP servers that were returned one at a time to pull statistics
    $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server | Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, LeaseDuration, State ### Getting all the dhcp scopes for the given server
    Foreach ($DHCP_Scope in $DHCP_Scopes)
    { ### Going through the scopes returned in a given server
        $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server -ScopeId $DHCP_Scope.ScopeId | Select-Object Free, InUse, Reserved, PercentageInUse, ScopeId ### Gathering the scope stats
        $percentinuserounded = ([math]::Round($DHCP_Scope_Stats.PercentageInUse,0)) ### Rounding the percent in use to have no decimals
        ### Color formatting based on how much a scope is in use
        If ($percentinuserounded -ge 95){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#FF0000"> <font color="white">' + $percentinuserounded + '</font></td>'}
        If ($percentinuserounded -ge 80 -and $percentinuserounded -lt 95){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#FFF284"> <font color="black">' + $percentinuserounded + '</font></td>'}
        If ($percentinuserounded -lt 80){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#A6CAA9"> <font color="black">' + $percentinuserounded + '</font></td>'}
        ### Changing the cell color if the scope is inactive / active
        If ($DHCP_Scope.State -eq "Inactive"){$htmlScopeState = '<td width="8%" align="center" td bgcolor="#AAAAB2"> <font color="black">' + $DHCP_Scope.State  + '</font></td>'}
        If ($DHCP_Scope.State -eq "Active"){$htmlScopeState = '<td width="8%" align="center">' + $DHCP_Scope.State + '</td>'}
        ### Changing the background color on every other scope so the html is easy to read
        $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 0 ) {$htmlbgcolor = '<tr bgcolor=#F5F5F5>'} } ## Even Number (off-white)
        $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 1 ) {$htmlbgcolor = '<tr bgcolor=#CCCCCC>'} } ## Odd Number (gray)
        #### Creating the HTML row for the given DHCP scope with the detailed stats and information
        $current = "
                <table width='100%'><tbody>
                    $htmlbgcolor
                    <td width='10%' align='center'>$($DHCP_Server.TrimEnd(".local.domain"))</td>
                    <td width='8%' align='center'>$($DHCP_Scope.ScopeId)</td>
                    <td width='10%' align='center'>$($DHCP_Scope.Name)</td>
                    $htmlScopeState
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.InUse)</td>
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.Free)</td>
                    $htmlpercentinuse
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.Reserved)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.SubnetMask)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.StartRange)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.EndRange)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.LeaseDuration)</td>
                    </tr>
                </table>
                "
        $current  | Out-File $htmlfile_temp -Append ### Appending the HTML row to the tempory file
 
        $htmlwrite_count++ ### Incrementing the count by 1 so that the next HTML row is a different color
        Clear-Variable htmlScopeState, htmlpercentinuse, percentinuserounded, DHCP_Scope_Stats -ErrorAction SilentlyContinue
    }
}
Clear-Variable htmlwrite_count



If (Test-Path $htmlfile) { Remove-Item $htmlfile -Force } ### Removing the final html file if it exists
Rename-Item $htmlfile_temp $htmlfile -Force ### Renaming the temp file to the final file
#endregion
    #region - DHCP Reports
    # https://evotec.xyz/active-directory-dhcp-report-to-html-or-email-with-zero-html-knowledge/
    # Dynamically pulling the DHCP servers in a Active Directory domain
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId.IPAddressToString
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }

    Install-Module PSWriteHTML -Force
    Import-Module PSWriteHTML

    $Output | Out-HtmlView

    $Output | Out-HtmlView -FilePath $Env:USERPROFILE\Desktop\MyReport.html -Title 'DHCP Servers' -HideFooter -PreventShowHTML


    $Output | Out-HtmlView {
        New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
        New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType number
    } -HideFooter -Title 'DHCP Servers'


    $Output | Out-HtmlView {
        New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
        New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
        New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
        New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
        New-TableHeader -Names 'Subnet Mask','Start Range','End Range','Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
    } -HideFooter -Title 'DHCP Servers'


    # Dynamically pulling the DHCP servers in a Active Directory domain
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId.IPAddressToString
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }
    $Output | Out-HtmlView {
        New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
        New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
        New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
        New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
        New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
        New-TableHeader -Names 'Subnet Mask','Start Range','End Range','Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
    } -HideFooter -Title 'DHCP Servers' -FilePath $env:USERPROFILE\Desktop\MyDHCPReport.html



    Email -AttachSelf -AttachSelfName 'DHCP Report' {
        EmailHeader {
            EmailFrom -Address 'MyEmail@evotec.pl'
            EmailTo -Addresses "MyOtherEmail@evotec.pl"
            EmailServer -Server 'smtp.office365.com' -UserName 'login@evotec.pl' -Password "$ENV:UserProfile\Desktop\Password-Evotec.txt" -PasswordAsSecure -PasswordFromFile -Port 587 -SSL
            EmailOptions -Priority High -DeliveryNotifications Never
            EmailSubject -Subject 'DHCP Report - Scope Utilization'
        }
        EmailBody {
            EmailTextBox -FontFamily 'Calibri' -Size 17 -TextDecoration underline -Color DarkSalmon -Alignment center {
                'Demonstration'
            }
            EmailText -LineBreak
            EmailTable -DataTable $Output {
                New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackGroundColor Red -Color White -Inline -ComparisonType number
                New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackGroundColor Yellow -Color Black -Inline -ComparisonType number
                New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackGroundColor Green -Color White -Inline -ComparisonType number
                New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackGroundColor Gray -Color White -Inline -ComparisonType string
                New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
                New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
                New-TableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
            } -HideFooter
        }
    } -Supress $false




    Import-Module PSWriteHTML
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId.IPAddressToString
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }
    Email -AttachSelf -AttachSelfName 'DHCP Report' {
        EmailHeader {
            EmailFrom -Address 'przemyslaw.klys@evotec.pl'
            EmailTo -Addresses "przemyslaw.klys@euvic.pl"
            EmailServer -Server 'smtp.office365.com' -UserName 'przemyslaw.klys@evotec.pl' -Password "$ENV:UserProfile\Desktop\Password-Evotec.txt" -PasswordAsSecure -PasswordFromFile -Port 587 -SSL
            EmailOptions -Priority High -DeliveryNotifications Never
            EmailSubject -Subject 'DHCP Report - Scope Utilization'
        }
        EmailBody {
            EmailTextBox -FontFamily 'Calibri' -Size 17 -TextDecoration underline -Color DarkSalmon -Alignment center {
                'Demonstration'
            }
            EmailText -LineBreak
            EmailTable -DataTable $Output {
                New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackGroundColor Red -Color White -Inline -ComparisonType number
                New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackGroundColor Yellow -Color Black -Inline -ComparisonType number
                New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackGroundColor Green -Color White -Inline -ComparisonType number
                New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackGroundColor Gray -Color White -Inline -ComparisonType string
                New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
                New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
                New-TableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
            } -HideFooter
        }
    } -Supress $false







    Import-Module PSWriteHTML
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }
    Email -AttachSelf -AttachSelfName 'DHCP Report' {
        EmailHeader {
            EmailFrom -Address 'przemyslaw.klys@evotec.pl'
            EmailTo -Addresses "przemyslaw.klys@euvic.pl"
            EmailServer -Server 'smtp.office365.com' -Username 'przemyslaw.klys@evotec.pl' -Password "$ENV:UserProfile\Desktop\Password-Evotec.txt" -PasswordAsSecure -PasswordFromFile -Port 587 -SSL
            EmailOptions -Priority High -DeliveryNotifications Never
            EmailSubject -Subject 'DHCP Report - Scope Utilization'
        }
        EmailBody {
            EmailTextBox -FontFamily 'Calibri' -Size 17 -TextDecoration underline -Color DarkSalmon -Alignment center {
                'Demonstration'
            }
            EmailText -LineBreak
            EmailTable -DataTable $Output {
                EmailTableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
                EmailTableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
                EmailTableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
                EmailTableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
                EmailTableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
                EmailTableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
                EmailTableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
            } -HideFooter
        }
    } -Supress $false






    New-HTML {
        New-HTMLSection -Invisible {
            New-HTMLSection -HeaderText 'DHCP Report' {
                New-HTMLTable -DataTable $Output {
                    New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
                    New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
                    New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
                    New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
                    New-TableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
                }
            }
            New-HTMLSection -HeaderText 'Some Processes' {
                New-HTMLTable -DataTable (Get-Process | Select-Object -First 15) {
                }
            }
        }
    } -FilePath ii $Env:UserProfile\Desktop\DHCPReport.html -Online #-ShowHTML



    # Dynamically pulling the DHCP servers in a Active Directory domain
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId.IPAddressToString
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }
    New-HTML {
        New-HTMLSection -Invisible {
            New-HTMLSection -HeaderText 'DHCP Report' {
                New-HTMLTable -DataTable $Output {
                    New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
                    New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
                    New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackGroundColor BuddhaGold -Color White -FontWeight bold
                    New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackGroundColor Gray
                    New-TableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackGroundColor Gray
                }
            }
            New-HTMLSection -HeaderText 'Some Processes' {
                New-HTMLTable -DataTable (Get-Process | Select-Object -First 15) {
                }
            }
        }
    } -FilePath $Env:UserProfile\Desktop\DHCPReport.html -Online -ShowHTML




    # Dynamically pulling the DHCP servers in a Active Directory domain
    $DHCP_Servers = Get-DhcpServerInDC | Sort-Object -Property DnsName
    $Output = Foreach ($DHCP_Server in $DHCP_Servers) {
        # Going through the DHCP servers that were returned one at a time to pull statistics
        try {
            $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server.DNSName -ErrorAction Stop
        } catch {
            Write-Warning "Couldn't reach server $($DHCP_Server.DNSName)"
            $DHCP_Scopes = $Null
        }
        Foreach ($DHCP_Scope in $DHCP_Scopes) {
            # Going through the scopes returned in a given server
            $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server.DNSName -ScopeId $DHCP_Scope.ScopeId
            [PSCustomObject] @{
                'DHCP Server'    = $DHCP_Server.DNSName
                'DHCP IP'        = $DHCP_Server.IPAddress
                'Scope ID'       = $DHCP_Scope.ScopeId.IPAddressToString
                'Scope Name'     = $DHCP_Scope.Name
                'Scope State'    = $DHCP_Scope.State
                'In Use'         = $DHCP_Scope_Stats.InUse
                'Free'           = $DHCP_Scope_Stats.Free
                '% In Use'       = ([math]::Round($DHCP_Scope_Stats.PercentageInUse, 0))
                'Reserved'       = $DHCP_Scope_Stats.Reserved
                'Subnet Mask'    = $DHCP_Scope.SubnetMask
                'Start Range'    = $DHCP_Scope.StartRange
                'End Range'      = $DHCP_Scope.EndRange
                'Lease Duration' = $DHCP_Scope.LeaseDuration
            }
        }
    }
    New-HTML {
        New-HTMLTab -Name 'Summary' {
            New-HTMLSection -HeaderText 'All servers' {
                New-HTMLTable -DataTable $DHCP_Servers
            }
            foreach ($Server in $DHCP_Servers) {
                New-HTMLSection -Invisible {
                    try {
                        $Database = Get-DhcpServerDatabase -ComputerName $Server.DnsName
                    } catch {
                        continue
                    }
                    New-HTMLSection -HeaderText "Server $($Server.DnsName) - Database Information" {
                        New-HTMLTable -DataTable $Database
                    }
                    try {
                        $AuditLog = Get-DhcpServerAuditLog -ComputerName $Server.DnsName
                    } catch {
                        continue
                    }
                    New-HTMLSection -HeaderText "Server $($Server.DnsName) - Audit Log" {
                        New-HTMLTable -DataTable $AuditLog
                    }
                }
            }
        }
        New-HTMLTab -Name 'All DHCP Scopes' {
            New-HTMLSection -HeaderText 'DHCP Report' {
                New-HTMLTable -DataTable $Output {
                    New-TableCondition -Name '% In Use' -Operator ge -Value 95 -BackgroundColor Red -Color White -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator ge -Value 80 -BackgroundColor Yellow -Color Black -Inline -ComparisonType number
                    New-TableCondition -Name '% In Use' -Operator lt -Value 80 -BackgroundColor Green -Color White -Inline -ComparisonType number
                    New-TableCondition -Name 'Scope State' -Operator eq -Value 'Inactive' -BackgroundColor Gray -Color White -Inline -ComparisonType string
                    New-TableHeader -Title "DHCP Scope Statistics Report ($(Get-Date))" -Alignment center -BackgroundColor BuddhaGold -Color White -FontWeight bold
                    New-TableHeader -Names 'DHCP Server', 'DHCP IP' -Title 'Server Information' -Color White -Alignment center -BackgroundColor Gray
                    New-TableHeader -Names 'Subnet Mask', 'Start Range', 'End Range', 'Lease Duration' -Title 'Scope Configuration' -Color White -Alignment center -BackgroundColor Gray
                }
            }
        }
    } -FilePath $Env:UserProfile\Desktop\DHCPReport.html -Online -ShowHTML


    #endregion


    $htmlReportPath = [Environment]::GetFolderPath("Desktop") + '\' + "DHCPReport.html"


    function Get-DHCPServersSettings
    {
        $allDHCP = Get-DhcpServerInDC
        $allDHCP | Foreach-Object {
            $DHCPServerDB = Get-DhcpServerDatabase -ComputerName $_.Dnsname
            $DHCPServerAuditLog = Get-DhcpServerAuditLog -ComputerName $_.Dnsname
            [PSCustomObject]@{
                Name = $_.DnsName
                DBPath =  $DHCPServerDB.FileName
                BackupPath = $DHCPServerDB.BackupPath
                Logging = $DHCPServerDB.LoggingEnabled
                AuditState = $DHCPServerAuditLog.Enable
                AuditPath = $DHCPServerAuditLog.path
            }
        }
    }
      
    $DHCPServersSettings = Get-DHCPServersSettings
    Compress-Archive -Path $DHCPServersSettings.BackupPath -DestinationPath ($htmlReportPath -replace "Report.html","BU_$(Get-Date -f yyyyMMdd).zip")

    #region HTML
        $tmplt = (Dec64 'PCFET0NUWVBFIGh0bWw+DQo8aHRtbD4NCiAgICA8aGVhZD4NCiAgICA8L2hlYWQ+DQogICAgPGJ
                         vZHk+DQogICAgICAgIDxoMT5ESENQIFJlcG9ydDwvaDE+DQogICAgDQogICAgICAgIDxoMz5ESE
                         NQIFNlcnZlcnMgU2V0dGluZ3M8L2gzPg0KICAgICAgICA8REhDUERBVEE+DQogICAgPC9ib2R5P
                         g0KPC9odG1sPg==')
        $data = $($DHCPServersSettings | ConvertTo-Html -Fragment) | Out-String
        $tmplt = $tmplt -replace '<DHCPDATA>',$data
        $tmplt | Out-File -Encoding utf8 $htmlReportPath
        $($DHCPServersSettings | ConvertTo-Html -Fragment)    
    
    
        Invoke-Item $htmlReportPath
    #endregion
#endregion
#region - HTML data collect 
    #  https://petri.com/?s=ConvertTo-HTML 
    function ConvertFrom_HtmlTable {
        # adapted from: https://www.leeholmes.com/blog/2015/01/05/extracting-tables-from-powershells-invoke-webrequest/
        [CmdletBinding(DefaultParameterSetName = 'ByIndex')]
        param(
            [Parameter(Mandatory = $true, Position = 0)]
            [Microsoft.PowerShell.Commands.HtmlWebResponseObject]$WebRequest,

            [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'ByIndex')]
            [int]$TableIndex = 0,

            [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'ById')]
            [string]$TableId,

            [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'ByName')]
            [string]$TableName,

            [Parameter(Mandatory = $false, Position = 1, ParameterSetName = 'ByClass')]
            [string]$TableClassName
        )

        # Extract the table out of the web request
        switch ($PSCmdlet.ParameterSetName) {
            'ById'    { $table = $WebRequest.ParsedHtml.getElementByID($TableId) }
            'ByIndex' { $table = @($WebRequest.ParsedHtml.getElementsByTagName('table'))[$TableIndex]}
            'ByName'  { $table = @($WebRequest.ParsedHtml.getElementsByName($TableName))[0] }
            'ByClass' { $table = @($WebRequest.ParsedHtml.getElementsByClassName($TableClassName))[0] }
        }
        if (!$table) {
            Write-Warning "Could not find the given table."
            return $null
        }

        # load the System.Web assembly to be able to decode HTML entities
        Add-Type -AssemblyName System.Web

        $headers = @()
        # Go through all of the rows in the table
        foreach ($row in $table.Rows) {
            $cells = @($row.Cells)
            # If there is a table header, remember its titles
            if($cells[0].tagName -eq "TH") {
                $i = 0
                $headers = @($cells | ForEach-Object {
                    $i++
                    # decode HTML entities and double-up quotes that the value may contain
                    $th = ([System.Web.HttpUtility]::HtmlDecode($_.InnerText) -replace '"', '""').Trim()
                    # if the table header is empty, create it
                    if ([string]::IsNullOrEmpty($th)) { "H$i" } else { $th }
                })
                # proceed with the next row
                continue
            }
            # if we haven't found any table headers, make up names "H1", "H2", etc.
            if(-not $headers) {
                $headers = @(1..($cells.Count + 2) | ForEach-Object { "H$_" })
            }

            # Now go through the cells in the the row. For each, try to find the
            # title that represents that column and create a hashtable mapping those
            # titles to content
            $hash = [Ordered]@{}
            for ($i = 0; $i -lt $cells.Count; $i++) {
                # decode HTML entities and double-up quotes that the value may contain
                $value = ([System.Web.HttpUtility]::HtmlDecode($cells[$i].InnerText) -replace '"', '""').Trim()
                $th = $headers[$i]
                $hash[$th] = $value.Trim()
            }
            # And finally cast that hashtable to a PSCustomObject
            [PSCustomObject]$hash
        }
    }
    function Get-WebRequestTable
    {
        param(
            [Parameter(Mandatory = $true)]
            [Microsoft.PowerShell.Commands.HtmlWebResponseObject] $WebRequest,
  
            [Parameter(Mandatory = $true)]
            [int] $TableNumber
        )

        ## Extract the tables out of the web request
        $tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
        $table = $tables[$TableNumber]
        $titles = @()
        $rows = @($table.Rows)

        ## Go through all of the rows in the table
        foreach($row in $rows)
        {
            $cells = @($row.Cells)
   
            ## If we've found a table header, remember its titles
            if($cells[0].tagName -eq "TH")
            {
                $titles = @($cells | % { ("" + $_.InnerText).Trim() })
                continue
            }

            ## If we haven't found any table headers, make up names "P1", "P2", etc.
            if(-not $titles)
            {
                $titles = @(1..($cells.Count + 2) | % { "P$_" })
            }

            ## Now go through the cells in the the row. For each, try to find the
            ## title that represents that column and create a hashtable mapping those
            ## titles to content
            $resultObject = [Ordered] @{}
            for($counter = 0; $counter -lt $cells.Count; $counter++)
            {
                $title = $titles[$counter]
                if(-not $title) { continue }  

                $resultObject[$title] = ("" + $cells[$counter].InnerText).Trim()
            }

            ## And finally cast that hashtable to a PSCustomObject
            [PSCustomObject] $resultObject
        }
    }
    $savedFile = 'file:///C:/Users/adminCM/Desktop/FABCON%20Data/SystemReports/SystemReport_FABCONLOGO1_20220617-1346.html'
    $savedFile = "C:\Users\adminCM\Desktop\FABCON Data\SystemReports\SystemReport_FABCONLOGO1_20220617-1346.html"
    $request = Invoke-WebRequest $savedFile
    $table = ConvertFrom_HtmlTable -WebRequest $request -byindex -1 | Format-Table -Auto
    $table = Get-WebRequestTable -WebRequest $request -TableNumber -1 | Format-Table -Auto

    $S | ConvertTo-Html -Title 'Apps Table' -InputObject $s 
    $S | ConvertTo-Html -Fragment -As Table -PreContent "TABLENAME"

    Install-Module PowerHTML
    Import-Module PowerHTML
    function Get-WebRequestTable
    {
        Param
        (
            <#[Parameter(Mandatory = $true)]#>[uri] $URL = $savedFile,
            [Parameter(Mandatory = $true)] [int] $TableNumber
        )

        $WebRequest = Invoke-WebRequest $Url -UseBasicParsing
        $Html = ConvertFrom-Html -Content $WebRequest
        $Tables = $Html.SelectNodes('//table')
        $Table = $Tables[$TableNumber]
        foreach ($TableRow in $Table.Descendants('tr'))
        {
            if ($TableRow.ChildNodes.Name -eq 'th')
            {
                $TableHeaders = ($TableRow.ChildNodes | ?{$_.Name -eq 'th'} | ForEach-Object{$_.InnerText.trim()})
            }

        if (-not $TableHeaders)
        {
            $TableHeaders = @(1..(($TableRow.ChildNodes.Elements() | Measure-Object).Count) | % { "Column$_" })
        }

        $RowCells = $TableRow.ChildNodes | ?{$_.Name -eq 'td'}
        $resultObject = [Ordered] @{}

        for($counter = 0; $counter -lt $RowCells.Count; $counter++)
        {
            $resultObject.Add($TableHeaders[$counter],($RowCells[$counter].InnerText).Trim())
        }

        ## And finally cast that hashtable to a PSCustomObject
        [PSCustomObject] $resultObject
        }
    }
    $table = Get-WebRequestTable -Url $savedFile -TableNumber 0 | Format-Table -Auto

    (gpresult /h ($file = [Environment]::GetFolderPath("Desktop") + '\' + "GPResult_$(& Hostname)_$(Get-Date -f yyyy-MM-dd_HHmm).html")); ii $file

    Get-WebRequestTable -URL 'https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/licensing-service-plan-reference' -TableNumber 0
#endregion
#region - Get remote MAC Addresses
    Function Get-MACAdress
    {
        Param
        (
            $Computer
        )
        Try
        {
            Try
            {
                Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -ComputerName $Computer -EA Stop | 
                    Select-Object -Property MACAddress, Description
            }
            Catch
            {
                Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled='True'" -ComputerName $Computer -EA Stop | 
                    Select-Object -Property MACAddress, Description
            }
        }
        Catch
        {
            getmac.exe /s $Computer /fo table /nh /v
        }
        # Solution 3
    }
 
    ((Get-MACAdress 'fabconhv01' | Select -Exp MACAddress) -replace ':','').ToLower() | Clip
#endregion
#region - WSUS Client fixes
    Function Invoke-WSUSClientFix
    {
        <#  
        .SYNOPSIS  
            Performs a WSUS client reset on local or remote system.
        
        .DESCRIPTION
            Performs a WSUS client reset on local or remote system.
        
        .PARAMETER Computername
            Name of the remote or local system.
                   
        .NOTES  
            Name: Invoke-WSUSClientFix
            Author: Boe Prox
            DateCreated: 18JAN2012
            DateModified: 28Mar2014  
              
        .EXAMPLE  
            Invoke-WSUSClientFix -Computername 'Server' -Verbose
        
            VERBOSE: Server: Testing network connection
            VERBOSE: Server: Stopping wuauserv service
            VERBOSE: Server: Making remote registry connection to LocalMachine hive
            VERBOSE: Server: Connection to WSUS Client registry keys
            VERBOSE: Server: Removing Software Distribution folder and subfolders
            VERBOSE: Server: Starting wuauserv service
            VERBOSE: Server: Sending wuauclt /resetauthorization /detectnow command
    
            Description
            -----------
            This command resets the WSUS client information on Server.
        #> 
        [cmdletbinding(SupportsShouldProcess=$True)]
        Param (
            [parameter(ValueFromPipeLine=$True,ValueFromPipeLineByPropertyName=$True)]
            [Alias('__Server','Server','CN')]
            [string[]]$Computername = $Env:Computername
        )
        Begin { $reghive = [microsoft.win32.registryhive]::LocalMachine }
        Process {
            ForEach ($Computer in $Computername) {
                Write-Verbose ("{0}: Testing network connection" -f $Computer)
                If (Test-Connection -ComputerName $Computer -Count 1 -Quiet) {
                    Write-Verbose ("{0}: Stopping wuauserv service" -f $Computer)
                    $wuauserv = Get-Service -ComputerName $Computer -Name wuauserv 
                    Stop-Service -InputObject $wuauserv
                
                    Write-Verbose ("{0}: Making remote registry connection to {1} hive" -f $Computer, $reghive)
                    $remotereg = [microsoft.win32.registrykey]::OpenRemoteBaseKey($reghive,$Computer)
                    Write-Verbose ("{0}: Connection to WSUS Client registry keys" -f $Computer)
                    $wsusreg1 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate',$True)
                    $wsusreg2 = $remotereg.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',$True)
                
                    #Begin deletion of registry values for WSUS Client
                    If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientId'))) {
                        If ($PScmdlet.ShouldProcess("SusClientId","Delete Registry Value")) {
                            $wsusreg1.DeleteValue('SusClientId')
                        }
                    }
                    If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('SusClientIdValidation'))) {
                        If ($PScmdlet.ShouldProcess("SusClientIdValidation","Delete Registry Value")) {
                            $wsusreg1.DeleteValue('SusClientIdValidation')
                        }
                    }                
                    If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('PingID'))) {
                        If ($PScmdlet.ShouldProcess("PingID","Delete Registry Value")) {
                            $wsusreg1.DeleteValue('PingID')
                        }
                    }
                    If (-Not [string]::IsNullOrEmpty($wsusreg1.GetValue('AccountDomainSid'))) {
                        If ($PScmdlet.ShouldProcess("AccountDomainSid","Delete Registry Value")) {
                            $wsusreg1.DeleteValue('AccountDomainSid')
                        }
                    }   
                    If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('LastWaitTimeout'))) {
                        If ($PScmdlet.ShouldProcess("LastWaitTimeout","Delete Registry Value")) {
                            $wsusreg2.DeleteValue('LastWaitTimeout')
                        }
                    }
                    If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('DetectionStartTimeout'))) {
                        If ($PScmdlet.ShouldProcess("DetectionStartTimeout","Delete Registry Value")) {
                            $wsusreg2.DeleteValue('DetectionStartTimeout')
                        }
                    }
                    If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('NextDetectionTime'))) {
                        If ($PScmdlet.ShouldProcess("NextDetectionTime","Delete Registry Value")) {
                            $wsusreg2.DeleteValue('NextDetectionTime')
                        }
                    }
                    If (-Not [string]::IsNullOrEmpty($wsusreg2.GetValue('AUState'))) {
                        If ($PScmdlet.ShouldProcess("AUState","Delete Registry Value")) {
                            $wsusreg2.DeleteValue('AUState')
                        }
                    }
                
                    Write-Verbose ("{0}: Removing Software Distribution folder and subfolders" -f $Computer)
                    Try {
                        Remove-Item "\\$Computer\c$\Windows\SoftwareDistribution" -Recurse -Force -Confirm:$False -ErrorAction Stop                                                                                         
                    } Catch {
                        Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                    }
                
                    Write-Verbose ("{0}: Starting wuauserv service" -f $Computer)
                    Start-Service -InputObject $wuauserv
                
                    Write-Verbose ("{0}: Sending wuauclt /resetauthorization /detectnow command" -f $Computer)
                    Try {
                        Invoke-WmiMethod -Path Win32_Process -ComputerName $Computer -Name Create `
                        -ArgumentList "wuauclt /resetauthorization /detectnow" -ErrorAction Stop | Out-Null
                    } Catch {
                        Write-Warning ("{0}: {1}" -f $Computer,$_.Exception.Message)
                    }
                }
            }
        }
    }



    <#
        1. Create a batch file named ResetSUSClientID.bat using the text below:

        :: Batch script to delete duplicate SusClientIDs
        :: Implement this script as a "Startup" or "Logon"  script
        :: Script creates an output file called %Systemdrive%\SUSClientID.log
        :: If the %Systemdrive%\SUSClientID.log is already present, then the script simply exits

        @Echo off
        # if exist %systemdrive%\SUSClientID.log goto end
        If ((Test-Path "$env:systemdrive\SUSClientID.log" -PathType Leaf) -eq $true) { Break }
        # net stop bits
        Get-Service wuauserv | Stop-Service
        # net stop bits
        Get-Service bits | Stop-Service
        # reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f  > %systemdrive%\SUSClientID.log 2>&1
        reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v PingID /f  > $env:systemdrive\SUSClientID.log 2>&1
        reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v AccountDomainSid /f  >> %systemdrive%\SUSClientID.log 2>&1
        reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" /v SusClientId /f  >> %systemdrive%\SUSClientID.log 2>&1
        # net start wuauserv
        Get-Service wuauserv | Start-Service
        wuauclt.exe /resetauthorization /detectnow         
        # :end
        # exit
    #>
#endregion
#region - Duplicate Files
    Function Find-DuplicateFiles
    {
        <#
            .SYNOPSIS
                find_ducplicate_files.ps1 finds duplicate files based on hash values.
 
            .DESCRIPTION
                Prompts for entering file path. Shows duplicate files for selection.
                Selected files will be moved to new folder C:\Duplicates_Date for further review.
 
            .EXAMPLE
                Find-DuplicateFiles -filepath c:\temp 
                Search C:\Temp for ANY duplicaste files
             
            .EXAMPLE
                Find-DuplicateFiles -filepath c:\temp -exts ('Doc','Xls','Ppt','Vsd')
                Search C:\Temp for any files with extensions matching 'Doc','Xls','Ppt' or 'Vsd'
 
            .NOTES
                Author: Chuck Mella [2022] - Fuctionalized and re-tweaked version of Patrick
                Gruenauer's original script (Web: https://sid-500.com)
        #>
        Param
        (
            $filepath,
            [array]$exts
        )
        $params = @{
            Path = $filepath
            File = $true
            Recurse = $true
            Include = $( IF ($exts -ne $null){ ($exts | %{ "*.$_"}) -Join (', ') } Else { '*.*' })
            EA = 'SilentlyContinue'
            }
        ''
        If (Test-Path $filepath)
        {
            ''
            Write-Warning 'Searching for duplicates ... Please wait ...'
 
            $duplicates = Get-ChildItem @params | Get-FileHash | Group-Object -Property Hash | Where-Object Count -GT 1
 
            If ($duplicates.count -lt 1)
            {
                Write-Warning 'No duplicates found.'
                Break ''
            }
            else
            {
                Write-Warning "Duplicates found."
                $result = foreach ($d in $duplicates)
                {
                    $d.Group | Select-Object -Property Path, Hash
                }
 
                $date = Get-Date -F yyyy-MM-dd
                $itemstomove = $result |
                Out-GridView -Title `
                    "Select files (CTRL for multiple) and press OK. Selected files will be moved to C:\Duplicates_$date" `
                    -PassThru
 
                If ($itemstomove)
                {
                    New-Item -ItemType Directory -Path $env:SystemDrive\Duplicates_$date -Force
                    Move-Item $itemstomove.Path -Destination $env:SystemDrive\Duplicates_$date -Force
                    ''
                    Write-Warning "Mission accomplished. Selected files moved to C:\Duplicates_$date"
 
                    Start-Process "C:\Duplicates_$date"
                }
                else
                {
                    Write-Warning "Operation aborted. No files selected."
                }
            }
        }
        else
        {
            Write-Warning `
            "Folder not found. Use full path to directory e.g. C:\photos\patrick"
        }
    }
#endregion



