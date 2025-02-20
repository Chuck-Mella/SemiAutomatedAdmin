Function Get-GPLink
{
    <#
        .SYNOPSIS
            This function creates a report of all group policy links, their locations, and
            their configurations in the current domain.  Output is a CSV file.
        .DESCRIPTION
            Long description
        .PARAMETER Path
            Optional parameter.  If specified, it will return GPLinks for a specific OU or domain root rather than all GPLinks.
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
        ForEach ($GPO in $GPOs) { $GPOsHash.Add($GPO.Path,$GPO) }

    # Empty array to hold all possible GPO link SOMs
        $gPLinks = @()

    If ($PSBoundParameters.ContainsKey('Path'))
    {

        $gPLinks += `
            Get-ADObject -Server $Server -Identity $Path `
                -Properties name, distinguishedName, gPLink, gPOptions |
                    Select-Object name, distinguishedName, gPLink, gPOptions

    }
    Else
    {
        # GPOs linked to the root of the domain
        #  !!! Get-ADDomain does not return the gPLink attribute
            $gPLinks += `
                Get-ADObject -Server $Server -Identity (Get-ADDomain).distinguishedName `
                    -Properties name, distinguishedName, gPLink, gPOptions |
                        Select-Object name, distinguishedName, gPLink, gPOptions

        # GPOs linked to OUs
        #  !!! Get-GPO does not return the gPLink attribute
            $gPLinks += `
                Get-ADOrganizationalUnit -Server $Server -Filter * `
                    -Properties name, distinguishedName, gPLink, gPOptions |
                        Select-Object name, distinguishedName, gPLink, gPOptions

        # GPOs linked to sites
        $gPLinks += `
            Get-ADObject -Server $Server -LDAPFilter '(objectClass=site)' `
                -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" `
                -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
                    Select-Object name, distinguishedName, gPLink, gPOptions
    }

    # Empty report array
        $report = @()

    # Loop through all possible GPO link SOMs collected
    ForEach ($SOM in $gPLinks)
    {
        # Filter out policy SOMs that have a policy linked
        If ($SOM.gPLink) {

            # If an OU has 'Block Inheritance' set (gPOptions=1) and no GPOs linked,
            # then the gPLink attribute is no longer null but a single space.
            # There will be no gPLinks to parse, but we need to list it with BlockInheritance.
            If ($SOM.gPLink.length -gt 1) {
                # Use @() for force an array in case only one object is returned (limitation in PS v2)
                # Example gPLink value:
                #   [LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2][LDAP://cn={046584E4-F1CD-457E-8366-F48B7492FBA2},cn=policies,cn=system,DC=wingtiptoys,DC=local;0][LDAP://cn={12845926-AE1B-49C4-A33A-756FF72DCC6B},cn=policies,cn=system,DC=wingtiptoys,DC=local;1]
                # Split out the links enclosed in square brackets, then filter out
                # the null result between the closing and opening brackets ][
                $links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})
                # Use a for loop with a counter so that we can calculate the precedence value
                For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
                    # Example gPLink individual value (note the end of the string):
                    #   LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2
                    # Splitting on '/' and ';' gives us an array every time like this:
                    #   0: LDAP:
                    #   1: (null value between the two //)
                    #   2: distinguishedName of policy
                    #   3: numeric value representing gPLinkOptions (LinkEnabled and Enforced)
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
            Select-Object OUDN, BlockInheritance, LinkEnabled, Enforced, Precedence, `
                            DisplayName, GPOStatus, WMIFilter, GUID, GPOCreated, GPOModified, `
                            UserVersionDS, UserVersionSysvol, ComputerVersionDS, ComputerVersionSysvol, PolicyDN
    } # Help Help Get-GPLink -Full

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
        $AllPolicies = Get-ADObject -Filter * `
                                    -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).Distinguishedname)" `
                                    -SearchScope OneLevel `
                                    -Property DisplayName, whenCreated, whenChanged
        $GPHash = @{}
        ForEach ($Policy in $AllPolicies) { $GPHash.Add($Policy.DistinguishedName,$Policy) }

    # BUILD LIST OF ALL LINKED POLICIES
        $AllLinkedPolicies = Get-ADOrganizationalUnit -Filter * | 
                                Select-Object -ExpandProperty LinkedGroupPolicyObjects -Unique
        $AllLinkedPolicies += Get-ADDomain | Select-Object -ExpandProperty LinkedGroupPolicyObjects -Unique

    # FLAG EACH ONE WITH A LINKED PROPERTY
        ForEach ($Policy in $AllLinkedPolicies) { $GPHash[$Policy].Linked = $true }

    # POLICY LINKED STATUS
        $GPHash.Values | Select-Object whenCreated, whenChanged, Linked, DisplayName, Name, DistinguishedName

    ### NOTE THAT whenChanged IS NOT A REPLICATED VALUE
} # Help Get-GPUnlinked -Full

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
        [Parameter()][ValidateSet('All','User','Computer')]
        [String]$Mode = 'All',
        [Parameter()][String[]]$SourceGPO,
        [Parameter()][String]$DestinationGPO
    )
    Import-Module GroupPolicy -Verbose:$false
    $ErrorActionPreference = 'Continue'
    Switch ($Mode) {
        'All'      {$rootPaths = "HKCU\Software","HKLM\System","HKLM\Software"; break}
        'User'     {$rootPaths = "HKCU\Software"                              ; break}
        'Computer' {$rootPaths = "HKLM\System","HKLM\Software"                ; break}
        }
    If (Get-GPO -Name $DestinationGPO -ErrorAction SilentlyContinue)
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
        Else { Write-Warning "SOURCE GPO DOES NOT EXIST [$SourceGPOSingle]" }
        $ProgressCounter++
    }
    Write-Progress -Activity "Copying GPO settings to: $DestinationGPO" -Completed -Status "Complete"
    } # Help Copy-GPRegistryValue -Full

Function DownTheRabbitHole
{
    # HELPER FUNCTION FOR Copy-GPRegistryValue
    [CmdletBinding()]
    Param
    (
        [Parameter()][String[]]$rootPaths,
        [Parameter()][String]$SourceGPO,
        [Parameter()][String]$DestinationGPO
    )

    $ErrorActionPreference = 'Continue'

    ForEach ($rootPath in $rootPaths)
    {
        Write-Verbose "SEARCHING PATH [$SourceGPO] [$rootPath]"
        Try { $children = Get-GPRegistryValue -Name $SourceGPO -Key $rootPath -Verbose -ErrorAction Stop }
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
                        Catch { $OverWrite = $false }
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
                    Catch { $OverWrite = $false }
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
        $subKeys = $children | Where-Object {[string]::IsNullOrEmpty($_.PolicyState)} | Select-Object -ExpandProperty FullKeyPath
        If ($subKeys)
        {
            DownTheRabbitHole -rootPaths $subKeys -SourceGPO $SourceGPOSingle -DestinationGPO $DestinationGPO -Verbose
        }
    }
} # Help DownTheRabbitHole -Full

Function Get-GPOInfo
{
    <#
        .SYNOPSIS
            This function retrieves some informations about all the GPO's in a given domain.

        .DESCRIPTION
            This function uses the GroupPolicy module to generate an XML report, parse it, analyse it, and put all the useful informations in a custom object.

        .PARAMETER DomainName
            You can choose the domain to analyse.
            Defaulted to current domain.

        .EXAMPLE
            Get-GPOInfo -Verbose | Out-GridView -Title "GPO Report"

            Display a nice table with all GPO's and their informations.

        .EXAMPLE
            Get-GPOInfo | ? {$_.HasComputerSettings -and $_.HasUserSettings}

            GPO with both settings.

        .EXAMPLE
            Get-GPOInfo | ? {$_.HasComputerSettings -and ($_.ComputerEnabled -eq $false)}

            GPO with computer settings configured, but disabled.

        .EXAMPLE
            Get-GPOInfo | ? {$_.HasUserSettings -and ($_.UserEnabled -eq $false)}

            GPO with user settings configured, but disabled.

        .EXAMPLE
            Get-GPOInfo | ? {$_.ComputerSettings -eq 'NeverModified' -and $_.UserSettings -eq 'NeverModified'}

            Never modified GPO.

        .EXAMPLE
            Get-GPOInfo | ? {$_.LinksTO -eq $null}

            Unlinked GPO.
    
        .EXAMPLE
            Get-GPOInfo -DomainName Contoso.com
        
            Query an other domain.
    
        .EXAMPLE
            Get-GPOInfo | Select-Object Name -ExpandProperty ACLs | Out-GridView
    
            Export the GPO's ACL's.

        .INPUTS

        .OUTPUTS

        .NOTES

        .LINK
            Http://ItForDummies.net
    #>
    [cmdletbinding()]
    Param
    (
        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Connection $_ -Count 1 -Quiet})]
        [String]$DomainName=$env:USERDNSDOMAIN
    )
    Begin
    {
        Write-Verbose -Message "Importing Group Policy module..."
        Try { Import-Module -Name GroupPolicy -Verbose:$false -ErrorAction Stop }
        Catch { Write-Warning -Message "Failed to import GroupPolicy module"; Continue }
    }
    Process
    {
        ForEach($GPO in (Get-GPO -All -Domain $DomainName ))
        {
            Write-Verbose -Message "Processing $($GPO.DisplayName)..."
            [xml]$XmlGPReport = $GPO.generatereport('xml')
            #GPO version
            If ($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0){$ComputerSettings="NeverModified"}else{$ComputerSettings="Modified"}
            If ($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0){$UserSettings="NeverModified"}else{$UserSettings="Modified"}
            #GPO content
            If ($XmlGPReport.GPO.User.ExtensionData -eq $null){$UserSettingsConfigured=$false}else{$UserSettingsConfigured=$true}
            If ($XmlGPReport.GPO.Computer.ExtensionData -eq $null){$ComputerSettingsConfigured=$false}else{$ComputerSettingsConfigured=$true}
            #Output
            New-Object -TypeName PSObject -Property @{
                'LinksTO'            = $XmlGPReport.GPO.LinksTo | Select-Object -ExpandProperty SOMPath
                'Name'               = $XmlGPReport.GPO.Name
                'ComputerSettings'   = $ComputerSettings
                'UserSettings'       = $UserSettings
                'UserEnabled'        = $XmlGPReport.GPO.User.Enabled
                'ComputerEnabled'    = $XmlGPReport.GPO.Computer.Enabled
                'SDDL'               = $XmlGPReport.GPO.SecurityDescriptor.SDDL.'#text'
                'HasComputerSettings'= $ComputerSettingsConfigured
                'HasUserSettings'    = $UserSettingsConfigured
                'CreationTime'       = $GPO.CreationTime
                'ModificationTime'   = $GPO.ModificationTime
                'GpoStatus'          = $GPO.GpoStatus
                'GUID'               = $GPO.Id
                'WMIFilter'          = $GPO.WmiFilter.name,$GPO.WmiFilter.Description
                'Path'               = $GPO.Path
                'Id'                 = $GPO.Id
                'ACLs'               = $XmlGPReport.gpo.SecurityDescriptor.Permissions.TrusteePermissions | 
                ForEach-Object -Process `
                {
                    New-Object -TypeName PSObject -Property @{
                        'User'           = $_.trustee.name.'#Text'
                        'PermissionType' = $_.type.PermissionType
                        'Inherited'      = $_.Inherited
                        'Permissions'    = $_.Standard.GPOGroupedAccessEnum
                        }
                }
            } #NO
        } #FE GPO
    }
    End {  }
} # Get-GPOInfo -Verbose | Out-GridView -Title "GPO Report" 

filter Get-CGPOReportExtensionData
{
    <#
        .SYNOPSIS 
            Queries XML Reports generated by Get-GPOReport for specific Extension information

        .DESCRIPTION
            Finds the extension specified by the parameter ExtensionName in the Report or Reports
            (i.e. Files, Registry, Software Installation). Tacks on the namespace information
            necessary to query the extension onto the report as a custom PSObject and writes that 
            information to output.

        .PARAMETER gpoReport
            A report generated by Get-GPOReport -reportType XML.

        .PARAMETER namespaceMgr
            If no namespace manager is assigned to this value, the default namespaces for group 
            policy XML reports are used.

        .PARAMETER extensionName
            The name of the group policy extension that you wish to find in the reports.
            Valid names I am currently aware of:
            Security,Public Key,Registry,Remote Installation,Internet Explorer Maintenance,
            Software Installation,Scripts,Folder Redirection,Printers,Windows Firewall,
            Software Restriction,Drive Maps,Shortcuts,Folders,Files,Windows Registry,
            Environment Variables,WLanSvc Networks,Folder Options,Start Menu,
            Deployed Printer Connections Policy,Ini Files

        .EXAMPLE
            Get-GPOReport -All -ReportType XML | Get-CGPOReportExtension Data -ExtensionName "Drive Maps"

        .INPUTS
            [System.XML.XMLDocument]

        .OUTPUTS
            [System.Management.Automation.PSCustomObject]

        .NOTES
            Todo.

        .FUNCTIONALITY
            Todo.

    #>
    [CmdletBinding()]
    Param
    (
        [parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Xml.XmlDocument] $gpoReport,
        [parameter(Mandatory=$false)][Xml.XmlNamespaceManager] $namespaceMgr,
        [parameter(Mandatory=$true)]
        [String] $extensionName
    )
    Process
    {
        # Build a namespace manager if we don't have one
        if (-not $namespaceMgr)
        {
            # Create a namespace manager from our navigator object's nametable
            $namespaceMgr = New-Object System.Xml.XmlNamespaceManager $gpoReport.CreateNavigator().NameTable
            $namespaceMgr.AddNamespace( "e", "http://www.microsoft.com/GroupPolicy/Settings" )
        }
        # We're going to cheat and use Posh's dotted notation to get the GPO name
        # there is only one GPO node (it's the root), and only one Name element
        $GPOName = $gpoReport.GPO.Name

        # Gather the Extensions that match the our queryCSE
        $extensions = $gpoReport.selectnodes("/e:GPO//e:ExtensionData[e:Name = '$extensionName']/e:Extension", $namespaceMgr)
        foreach ($extension in $extensions)
        {
            # Init the extension specific namespace variable
            $extensionNamespaceName = $null
            $extensionNamespaceURI  = $null
            # We need the Extension child element of this ExtensionData element
            # and have to extract the specific namespaces assigned for Extension
            # by the 'Get-GPOReport' cmdlet
            $eNavigator = $extension.CreateNavigator()
            $eNamespace = $eNavigator.GetNamespacesInScope('All')
            foreach ($key in $eNamespace.keys)
            {
                # The namespace assignments we're looking for are always named 'q1', 'q2', ... 'q99'
                # If there's more than a hundred, someone needs to start splitting up their GPOs, :)
                if ($key -match '^q\d{1,2}$')
                {
                    # Now we have the namespace assignment that is valid to query this element
                        $gpoExtInfo = New-Object PSObject -Property @{
                        GPOName = $GPOName
                        fullReport = $gpoReport
                        extensionData  = $extension
                        extensionNamespaceName  = $key
                        extensionNamespaceURI   = $eNamespace.$key
                }
                    }
            }
            Write-Output $gpoExtInfo
        }
    }
}  # $xml | Get-CGPOReportExtensionData -ExtensionName "Drive Maps"

Function SearchGPOsForSetting
{
    <#
        Shamelessly stolen from this page (after fixing 1 bug):
        http://blogs.technet.com/b/grouppolicy/archive/2009/04/14/tool-images.aspx
        http://blogs.technet.com/b/grouppolicy/archive/2009/04/17/find-settings-in-every-gpo.aspx

        Powershell script that does the following:
        SearchGPOsForSetting.ps1  [-IsComputerConfiguration] <boolean> [-Extension] <string>
        [-Where] </string><string> [-Is] </string><string> [[-Return] </string><string>] [[-DomainName] </string><string>]
        [-Verbose] [-Debug] [-ErrorAction <actionpreference>] [-WarningAction </actionpreference><actionpreference>]
        [-ErrorVariable <string>] [-WarningVariable </string><string>] [-OutVariable </string><string>] [-OutBuffer <int32>]

        Example: .\SearchGPOsForSetting.ps1 -IsComputerConfiguration $true -Extension Security -Where Name -Is LockoutDuration -Return SettingNumber
        Example: .\SearchGPOsForSetting.ps1 -IsComputerConfiguration $true -Extension Registry -Where Name -Is ACSettingIndex -Return SettingNumber
    #>
    Param
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
    Function print
    {	
        Param ( $displayName, $value )
        $host.UI.WriteLine();
        $stringToPrint = "The Gpo '" + $displayName + "' has a " + $Extension + " setting where '" + $Where + "' is equal to '" + $Is + "'";
        If ($Return -ne $null) { $stringToPrint += " and the value of its '" + $Return + "' property is: '" + $value + "'"; }
        $host.UI.Write([ConsoleColor]::Magenta, [ConsoleColor]::Black,	$stringToPrint);
        $host.UI.WriteLine();
    }
    Function processNodes
    {
        Param ( $nodes, $foundWhere )
        $thePropertyWeWant = $Where;
        # If we already found the $Where then we are looking for our $Return value now.
        If ($foundWhere) { $thePropertyWeWant = $Return; }
        ForEach ($node in $nodes)
        {
        $valueWeFound = $null;
        #Here we are checking siblings
        $lookingFor = Get-Member -InputObject $node -Name $thePropertyWeWant;
        if ($lookingFor -ne $null) { $valueWeFound = $node.($lookingFor.Name); }
        else
            {
                #Here we are checking attributes.
            if ($node.Attributes -ne $null)
                {
            $lookingFor = $node.Attributes.GetNamedItem($thePropertyWeWant);
            if ( $lookingFor -ne $null) { $valueWeFound = $lookingFor; }
            }
        }
        if ( $lookingFor -ne $null)
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
        } #FE node
    }
    #Import our module for the call to the Get-GPO cmdlet
    Import-Module GroupPolicy;
 
    $allGposInDomain = Get-GPO -All -Domain $DomainName;
 
    $xmlnsGpSettings = "http://www.microsoft.com/GroupPolicy/Settings";
    $xmlnsSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";
    $xmlnsSchema = "http://www.w3.org/2001/XMLSchema";

    $QueryString = "gp:";
 
    if ($IsComputerConfiguration){ $QueryString += "Computer/gp:ExtensionData/gp:Extension"; }
    Else { $QueryString += "User/gp:ExtensionData/gp:Extension"; }
    ForEach ($Gpo in $allGposInDomain)
    {				
        $xmlDoc = [xml] (Get-GPOReport -Guid $Gpo.Id -ReportType xml -Domain $Gpo.DomainName);		
        $xmlNameSpaceMgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable);
 
        $xmlNameSpaceMgr.AddNamespace("", $xmlnsGpSettings);
        $xmlNameSpaceMgr.AddNamespace("gp", $xmlnsGpSettings);
        $xmlNameSpaceMgr.AddNamespace("xsi", $xmlnsSchemaInstance);
        $xmlNameSpaceMgr.AddNamespace("xsd", $xmlnsSchema);
 
        $extensionNodes = $xmlDoc.DocumentElement.SelectNodes($QueryString, $XmlNameSpaceMgr);
        ForEach ($extensionNode in $extensionNodes)
        {
        if ([String]::Compare(($extensionNode.Attributes.Item(0)).Value, 
            "http://www.microsoft.com/GroupPolicy/Settings/" + $Extension, $true) -eq 0)
            {
            # We have found the Extension we are looking for now recursively search
            # for $Where (the property we are looking for a specific value of).
                processNodes -nodes $extensionNode.ChildNodes -foundWhere $false;
            } #If
        } #FE extensionNode
    } #FE Gpo
} # help SearchGPOsForSetting -full

Function Find-OrphanedGPOs
{
    <#
        This script will find and print all orphaned Group Policy Objects (GPOs).

        Group Policy Objects (GPOs) are stored in two parts:

        1) GPC (Group Policy Container). The GPC is where the GPO stores all the AD-related configuration under the
            CN=Policies,CN=System,DC=... container, which is replicated via AD replication.
        2) GPT (Group Policy Templates). The GPT is where the GPO stores the actual settings located within SYSVOL
            area under the Policies folder, which is replicated by either File Replication Services (FRS) or
            Distributed File System (DFS).

        This script will help find GPOs that are missing one of the parts, which therefore makes it an orphaned GPO.

        A GPO typically becomes orphaned in one of two different ways:

        1) If the GPO is deleted directly through Active Directory Users and Computers or ADSI edit.
        2) If the GPO was deleted by someone that had permissions to do so in AD, but not in SYSVOL. In this case,
            the AD portion of the GPO would be deleted but the SYSVOL portion of the GPO would be left behind.

        Although orphaned GPT folders do no harm they do take up disk space and should be removed as a cleanup task.

        Lack of permissions to the corresponding objects in AD could cause a false positive. Therefore, verify GPT
        folders are truly orphaned before moving or deleting them.

        Original script written by Sean Metcalf
        http://blogs.metcorpconsulting.com/tech/?p=1076

        Release 1.1
        Modified by Jeremy@jhouseconsulting.com 29th August 2012
    #>

    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    # Get AD Domain Name
        $DomainDNS = $Domain.Name
    # Get AD Distinguished Name
        $DomainDistinguishedName = $Domain.GetDirectoryEntry() | Select-Object -ExpandProperty DistinguishedName  

    $GPOPoliciesDN = "CN=Policies,CN=System,$DomainDistinguishedName"
    $GPOPoliciesSYSVOLUNC = "\\$DomainDNS\SYSVOL\$DomainDNS\Policies"

    Write-Host -ForegroundColor Green "Finding all orphaned Group Policy Objects (GPOs)...`n"

    Write-Host -ForegroundColor Green "Reading GPO information from Active Directory ($GPOPoliciesDN)..."
    $GPOPoliciesADSI = [ADSI]"LDAP://$GPOPoliciesDN"
    [array]$GPOPolicies = $GPOPoliciesADSI.psbase.children
    ForEach ($GPO in $GPOPolicies) { [array]$DomainGPOList += $GPO.Name }
    #$DomainGPOList = $DomainGPOList -replace("{","") ; $DomainGPOList = $DomainGPOList -replace("}","")
    $DomainGPOList = $DomainGPOList | sort-object 
    [int]$DomainGPOListCount = $DomainGPOList.Count
    Write-Host -ForegroundColor Green "Discovered $DomainGPOListCount GPCs (Group Policy Containers) in Active Directory ($GPOPoliciesDN)`n"

    Write-Host -ForegroundColor Green "Reading GPO information from SYSVOL ($GPOPoliciesSYSVOLUNC)..."
    [array]$GPOPoliciesSYSVOL = Get-ChildItem $GPOPoliciesSYSVOLUNC
    ForEach ($GPO in $GPOPoliciesSYSVOL) {If ($GPO.Name -ne "PolicyDefinitions") {[array]$SYSVOLGPOList += $GPO.Name }}
    #$SYSVOLGPOList = $SYSVOLGPOList -replace("{","") ; $SYSVOLGPOList = $SYSVOLGPOList -replace("}","")
    $SYSVOLGPOList = $SYSVOLGPOList | sort-object 
    [int]$SYSVOLGPOListCount = $SYSVOLGPOList.Count
    Write-Host -ForegroundColor Green "Discovered $SYSVOLGPOListCount GPTs (Group Policy Templates) in SYSVOL ($GPOPoliciesSYSVOLUNC)`n"

    ## COMPARE-OBJECT cmdlet note:
        ## The => sign indicates that the item in question was found in the property set of the second object but not found in the property set for the first object. 
        ## The <= sign indicates that the item in question was found in the property set of the first object but not found in the property set for the second object.

    # Check for GPTs in SYSVOL that don't exist in AD
        [array]$MissingADGPOs = Compare-Object $SYSVOLGPOList $DomainGPOList -passThru | Where-Object { $_.SideIndicator -eq '<=' }
        [int]$MissingADGPOsCount = $MissingADGPOs.Count
        $MissingADGPOsPCTofTotal = $MissingADGPOsCount / $DomainGPOListCount
        $MissingADGPOsPCTofTotal = "{0:p2}" -f $MissingADGPOsPCTofTotal  
        Write-Host -ForegroundColor Yellow "There are $MissingADGPOsCount GPTs in SYSVOL that don't exist in Active Directory ($MissingADGPOsPCTofTotal of the total)"
        If ($MissingADGPOsCount -gt 0 )
        {
            Write-Host "These are:"
            $MissingADGPOs
        }
        Write-Host "`n"

    # Check for GPCs in AD that don't exist in SYSVOL
        [array]$MissingSYSVOLGPOs = Compare-Object $DomainGPOList $SYSVOLGPOList -passThru | Where-Object { $_.SideIndicator -eq '<=' }
        [int]$MissingSYSVOLGPOsCount = $MissingSYSVOLGPOs.Count
        $MissingSYSVOLGPOsPCTofTotal = $MissingSYSVOLGPOsCount / $DomainGPOListCount
        $MissingSYSVOLGPOsPCTofTotal = "{0:p2}" -f $MissingSYSVOLGPOsPCTofTotal  
        Write-Host -ForegroundColor Yellow "There are $MissingSYSVOLGPOsCount GPCs in Active Directory that don't exist in SYSVOL ($MissingSYSVOLGPOsPCTofTotal of the total)"
        If ($MissingSYSVOLGPOsCount -gt 0 )
        {
            Write-Host "These are:"
            $MissingSYSVOLGPOs
        }
        Write-Host "`n"

    # Pasted from <http://www.jhouseconsulting.com/jhouseconsulting/wp-content/uploads/2012/09/FindOrphanedGPOs.ps1_.txt> 

}


    <#
            $srcPolicy = 'CMP - Server 2008-R2 Safe Settings'
            $trgPolicy = 'TEST - CMP - Windows 7 Safe Settings'
            $fqdn = ([adsi]'').distinguishedName


            # Copy one GPO registry settings into another
            Copy-GPRegistryValue -Mode All -SourceGPO $srcPolicy `
                -DestinationGPO $trgPolicy -Verbose

            # Copy one GPO registry settings into another, just user settings
            Copy-GPRegistryValue -Mode User -SourceGPO $srcPolicy `
                -DestinationGPO $trgPolicy -Verbose

            # Copy one GPO registry settings into another, just computer settings
            Copy-GPRegistryValue -Mode Computer -SourceGPO $srcPolicy `
                -DestinationGPO $trgPolicy -Verbose

            # Copy multiple GPO registry settings into another
            Copy-GPRegistryValue -Mode All  -DestinationGPO $trgPolicy `
                -SourceGPO "Firewall Policy", "Starter User", "Starter Computer" -Verbose

            # Copy all GPOs linked to one OU registry settings into another
            # Sort in reverse precedence order so that the highest precedence settings overwrite
            # any potential settings conflicts in lower precedence policies.
            $SourceGPOs = Get-GPLink -Path "OU=SubTest,OU=Testing,$fqdn" |
                Sort-Object Precedence -Descending |
                Select-Object -ExpandProperty DisplayName
            Copy-GPRegistryValue -Mode All -SourceGPO $SourceGPOs `
                -DestinationGPO $trgPolicy -Verbose

            # Log all GPO copy output (including verbose and warning)
            # Requires PowerShell v3.0+
            Copy-GPRegistryValue -Mode All -SourceGPO $srcPolicy `
                -DestinationGPO $trgPolicy -Verbose *> GPOCopyLog.txt

            # Disable all GPOs linked to an OU
            Get-GPLink -Path "OU=SubTest,OU=Testing,$fqdn" |
                %{ Set-GPLink -Target $_.OUDN -GUID $_.GUID -LinkEnabled No -Confirm }

            # Enable all GPOs linked to an OU
            Get-GPLink -Path "OU=SubTest,OU=Testing,$fqdn" |
                %{ Set-GPLink -Target $_.OUDN -GUID $_.GUID -LinkEnabled Yes -Confirm }

            # Quick link status of all GPOs
            Get-GPUnlinked | Out-Gridview

            # Just the unlinked GPOs
            Get-GPUnlinked | ?{!$_.Linked} | Out-GridView

            # Detailed GP link status for all GPO with links
            Get-GPLink | Out-GridView

            # List of GPOs linked to a specific OU (or domain root)
            Get-GPLink -Path "OU=SubTest,OU=Testing,$fqdn" | Select -ExpandProperty DisplayName

            # List of OUs (or domain root) where a specific GPO is linked
            Get-GPLink | ?{$_.DisplayName -eq $srcPolicy} | Select -ExpandProperty OUDN

            $gpB4AftCmds = (Dec64 'U2V0IEZ5bD1jOlx0ZW1wXERmbHREb21Pbmx5DQpncHJlc3VsdCAteCAlZnlsJS54bWwNCmdwcmVzdWx0IC1oIC
                VmeWwlLmh0bWwgJiYgU3RhcnQgJWZ5bCUuaHRtbA0KDQpncHVwZGF0ZSAvZm9yY2UgL3N5bmMgL0Jvb3QNCiAgICANClNldCBGeWw9Yzp
                cdGVtcFxMb2NhbE9ubHkNCmdwcmVzdWx0IC14ICVmeWwlLnhtbA0KZ3ByZXN1bHQgLWggJWZ5bCUuaHRtbCAmJiBTdGFydCAlZnlsJS5o
                dG1sDQo=')
            # $gpB4AftCmds | %{$_  -replace '^gpresult ','gpresult @('-replace ' ',"','"}
            # $gpB4AftCmds | %{[string]$_  -creplace '^[^\ ]*\ '}
            # $gpB4AftCmds | %{[string]$_  -creplace '(?s)^.*\ '}
            # $gpB4AftCmds -replace '^[^\s]*\s'
        #>

    <#

        $xmlpath = "c:\temp\test.xml"
        & gpresult.exe /x $xmlpath
        $xml = [xml](Get-Content $xmlpath)
        $T = $xml.DocumentElement.ComputerResults.ExtensionData.extension.Type
        $x = $T | ?{$_ -like "*firewall*"}
        ($xml.DocumentElement.ComputerResults.ExtensionData.extension | ? {$_.type -like "*firewall*"}).inboundfirewallrules
        $xml.DocumentElement.ComputerResults.ExtensionData | Select -exp Extension,Name

    #>

    <#
    # Kill Legal Banner
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeCaption -Value ''
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LegalNoticeText -Value ''
# RDP Mods
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name SecurityLayer -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTsConnections -Value 0
# Consent Behavior (Elevation)
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorUser -Value 1
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableSecureUIAPaths -Value 0
# Collect User Scala SID
    $trgUser = New-Object System.Security.Principal.NTAccount("Scala")
    $strSID = ($trgUser.Translate([System.Security.Principal.SecurityIdentifier])).Value
# Lock Taskbar for Scala User
    $regpath = "HKU:\$strSID\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3"
    $AttrName = 'Settings'
    $oldValue = [byte[]]((Get-ItemProperty -Path $regpath -Name $AttrName).Settings)
    $newvalue = $oldValue
    ($newvalue[8] = 2)
    Set-ItemProperty -Path $RegPath -Name $AttrName -Value ([byte[]]($newvalue))
# IE Compatibility List Scala User
    Function Get-DomainEntry($domain) {
        [byte[]] $tmpbinary = @()
        [byte[]] $length = [BitConverter]::GetBytes([int16]$domain.Length)
        [byte[]] $data = [System.Text.Encoding]::Unicode.GetBytes($domain)
 
        $tmpbinary += $delim_b
        $tmpbinary += $filler
        $tmpbinary += $delim_a
        $tmpbinary += $length
        $tmpbinary += $data
        Return $tmpbinary
        }
    $key = "HKU:\$strSID\Software\Microsoft\Internet Explorer\BrowserEmulation\ClearableListData"
    $item = "UserFilter"
    # Setup  Binary Data
        [byte[]] $regbinary = @()
        #This seems constant
        [byte[]] $header = 0x41,0x1F,0x00,0x00,0x53,0x08,0xAD,0xBA
 
        #This appears to be some internal value delimeter
        [byte[]] $delim_a = 0x01,0x00,0x00,0x00
 
        #This appears to separate entries
        [byte[]] $delim_b = 0x0C,0x00,0x00,0x00
 
        #This is some sort of checksum, but this value seems to work
        [byte[]] $checksum = 0xFF,0xFF,0xFF,0xFF
 
        #This could be some sort of timestamp for each entry ending with 0x01, but setting to this value seems to work
        [byte[]] $filler = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    $domains = @("armybiznet.local","armybiznet.com")
    If ($domains.Length -gt 0) {
        [int32] $count = $domains.Length
        [byte[]] $entries = @()
        ForEach ($domain in $domains) { $entries += Get-DomainEntry $domain }
 
        $regbinary = $header
        $regbinary += [byte[]] [BitConverter]::GetBytes($count)
        $regbinary += $checksum
        $regbinary += $delim_a
        $regbinary += [byte[]] [BitConverter]::GetBytes($count)
        $regbinary += $entries
        }
 
    Set-ItemProperty -Path $key -Name $item -Value $regbinary
#>


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
            *IE is instructed to render the report in IE5 Quirks Mode.
            *A mark-of-the-web meta tag is added to eliminate the need to unblock the VBScript responsible for Expand/Collapse, 
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
                *Malwarebytes Anti-Malware: Will prevent IE VBScript from running if the Real-Time Protection >> Exploit Protection >> Advanced Settings >> 
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
    '<!-*saved from url=(0016)https://localhost -->
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

    #region - Template Definition tweks
        $srcAdmx = (gci 'Source ADMX files Path' -Recurse -Force -File )
        $trgAdmx = 'Target folder Path'

        ForEach ($file in $srcAdmx)
        {
            Switch ($file.Extension)
            {
                '.admx' { Copy $file.FullName $trgAdmx -Force -Vebose }
                '.adml' { Copy $file.FullName $trgAdmx -Force -Vebose } 
            }
        }
    #endregion


$gpStat = @{
    User = 'ComputerSettingsDisabled';Computer = 'UserSettingsDisabled'
    Both =  'AllSettingsEnabled';Disabled = 'AllSettingsDisabled'
    }


#region - Searching GPOs Fixes
    Function Search-GPOText
    {
        [CmdletBinding()]
        Param
        (
            $String,
            [string]$Domain = ([ADSI]"LDAP://ROOTDSE").ldapServiceName.split(':')[0],
            $gpStat,
            [switch]$silent
        )
        $gpList = New-Object System.Collections.ArrayList
        $NearestDC = (Get-ADDomaincontroller -Discover -Nextclosestsite).Name

        #Get a list of GPOs from the domain
            $GPOs = Get-GPO -All -Domain $Domain -server $NearestDC | Sort-Object DisplayName
            If ($gpStat -is [object]){ $GPOs = $GPOs | Where GpoStatus -eq $gpStat }

        # Go through each object and check its XML against $String
            Foreach ($GPO in $GPOs)
            {
                If ($Silent.IsPresent -eq $false){ Write-Host ( 'working on {0}' -f $GPO.DisplayName) }
                # Get current GPO Report (XML)
                $currentGPOReport = Get-GPOReport -Guid $GPO.Id -ReportType Xml -Domain $Domain -server $NearestDC
                If ($CurrentGPOReport -match $String)
                {
                    If ($Silent.IsPresent -eq $false)
                    {
                        Write-Host ('A Group Policy matching "{0}" has been found:' -f ( $String)) -Foregroundcolor Green
                        Write-Host ('* GPO Name: {0}' -f $GPO.DisplayName) -Foregroundcolor Green
                        write-Host ('* GPO Status: {0}' -f $GPO.GpoStatus) -Foregroundcolor Green
                        Write-Host ('* GPO Id: {0}' -f $GPO.Id) -Foregroundcolor Green
                    }
                    $gpList.Add($GPO.DisplayName) | Out*Null
                }
            }
            If ($Silent.IsPresent -eq $true){ Return $gplist }
    }
    Search-GPOText -string 'behavior of the elevation prompt' -silent
    Search-GPOText -string 'scripts' -gpStat $gpStat.Computer
    $gps_w_scripts = Search-GPOText -string 'ql:script' -silent
    $gps_w_psscripts = Search-GPOText -string '.psl' -silent
    $gps_w_batscripts = Search-GPOText -string '.bat' -silent
    $gps_w_cmdscripts = Search-GPOText -String '.cmd' -silent
    $gps_w_Drivemaps = Search-GPOText -string 'drive map' -silent
    $gpr = $gpos | where DisplayName -Match
    $CurrentGPOReport = [xml](Get-GPOReport -Guid $gpr.Id -ReportType xml -Domain $Domain -server $NearestDC)
    Search-GPOText -string 'usbstor'
#endregion



