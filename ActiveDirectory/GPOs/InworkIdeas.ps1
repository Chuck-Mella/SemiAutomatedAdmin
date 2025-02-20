    #region Compare GPO
    # ----------------------------------------------------------------------------- 
    # Compare-GPO.ps1 
    # ed wilson, msft, 7/13/2010 
    # 
    # HSG-07-15-2010 
    # ----------------------------------------------------------------------------- 
    #requires -version 2.0 
    Param( 
        [string]$domain ="t.state.gov", 
        [string]$server = "TTPRODC01", 
        [array]$gponame = @("Default Domain Policy","2012-R2 Domain Policy"), 
        [string]$folder = "c:\fso", 
        [switch]$user, 
        [switch]$computer 
        ) 
 
    Function Get-MyModule { 
        Param([string]$name) 
        If (-not(Get-Module -name $name)){  
            If (Get-Module -ListAvailable | Where-Object { $_.name -eq $name }){  
                Import-Module -Name $name  
                $true 
                } #end If module available then import 
            Else { $false } #module not available 
            } # end If not module 
        Else { $true } #module already loaded 
        } #Get-MyModule   
 
    Function Get-GPOAsXML { 
        Param( 
            [array]$gponame, 
            [string]$domain, 
            [string]$server, 
            [string]$folder 
            ) 
        $gpoReports = $null 
        ForEach($gpo in $gpoName){ 
            $path = Join-Path -Path $folder -ChildPath "$gpo.xml" 
            (Get-GPO -Name $gpo -Domain $domain -Server $server).GenerateReportToFile("xml",$path) 
            #[fix][array]$gpoReports + $path 
            [array]$gpoReports += $path 
            } 
        Return $gpoReports 
        } #Get-GPOAsXML 
 
    Function Compare-XMLGPO { 
        Param ([string[]]$gpoReports, [switch]$user, [switch]$computer) 
        [xml]$xml1 = Get-Content -Path $gpoReports[0] 
        [xml]$xml2 = Get-Content -Path $gpoReports[1] 
        #[fix]$regpolicyComputerNodes1 = $xml1.gpo.Computer.extensiondata.extension.ChildNodes | Select-Object name, state 
        $regpolicyComputerNodes1 = $xml1.gpo.Computer.extensiondata | ForEach-Object { $_.extension.policy | Select-Object name,state }

        #[fix]$regpolicyComputerNodes2 = $xml2.gpo.Computer.extensiondata.extension.ChildNodes | Select-Object name, state 
         $regpolicyComputerNodes2 = $xml2.gpo.Computer.extensiondata | ForEach-Object { $_.extension.policy | Select-Object name,state }

        #[fix]$regpolicyUserNodes1 = $xml1.gpo.User.extensiondata.extension.ChildNodes | Select-Object name, state 
        $regpolicyUserNodes1 = $xml1.gpo.User.extensiondata | ForEach-Object { $_.extension.policy | Select-Object name,state }

        #[fix]$regpolicyUserNodes2 = $xml2.gpo.User.extensiondata.extension.ChildNodes | Select-Object name, state 
        $regpolicyUserNodes2 = $xml2.gpo.User.extensiondata | ForEach-Object { $_.extension.policy | Select-Object name,state }
    
        If ($computer){ 
            Try { 
                Write-Host "Comparing Computer GPO's $($gpoReports[0]) to $($gpoReports[1])`r`n" -f Green
                Compare-Object -ReferenceObject $regpolicyComputerNodes1 -DIfferenceObject $regpolicyComputerNodes2 -IncludeEqual -property name -ea Stop} 
            Catch { 
                If ($regPolicyComputerNodes1){ 
                    "Computer GPO $($gpoReports[0]) settings `r`f" 
                    $regPolicyComputerNodes1 
                    } 
                Else { "Computer GPO $($gpoReports[0]) not set" } 
                If ($regPolicyComputerNodes2){ 
                    "Computer GPO $($gpoReports[1]) settings `r`f" 
                    $regPolicyComputerNodes2 
                    } 
                Else { "Computer GPO $($gpoReports[1]) not set"} 
                } #end catch 
            } #end If computer 
        If ($user){ 
            Try { 
                Write-Host "Comparing User GPO's $($gpoReports[0]) to $($gpoReports[1])`r`n" -f Green 
                Compare-Object -ReferenceObject $regpolicyUserNodes1 -DIfferenceObject $regpolicyUserNodes2  -SyncWindow 5 -IncludeEqual -property name
                } 
            Catch { 
                If($regPolicyUserNodes1){ 
                    "User GPO $($gpoReports[0]) settings `r`f" 
                    $regPolicyUserNodes1 
                    } 
                Else { "User GPO $($gpoReports[0]) not set" } 
                If ($regPolicyUserNodes2){ 
                    "User GPO $($gpoReports[1]) settings `r`f" 
                    $regPolicyUserNodes2 
                    } 
                Else { "User GPO $($gpoReports[1]) not set"} 
                } #end catch
            }  
        } #Compare-XMLGPO 
 
    # *** Entry Point to Script *** 
 
    If (-not ($user -or $computer)) { "Please specIfy either -computer or -user when running script" ; Break } 
    If (-not (Get-MyModule -name "GroupPolicy")) { Break } 
 
    $gpoReports = Get-GpoAsXML -gponame $gponame -server $server -domain $domain -folder $folder 
 
    Compare-XMLGPO -gpoReports $gpoReports -user -computer
 

    #endregion
    #region inwork rsop
    #region COMPARE RSoP
        #region
            <#
                Process RSOP XML file (with namespaces)

                September 6, 2011 bertvanlandeghem Active Directory, Powershell
                Here's how to query the rsop xml reports generated from the script in the previous post. 
                The xml file uses namespaces, so we need to take this into account when querying the files.
            #>
            $usrExts = $xml.DocumentElement.UserResults.ExtensionData.Extension
            $cmpExts = $xml.DocumentElement.ComputerResults.ExtensionData.Extension #.Name
            Function X($a) {Return (($a|GM -MemberType Property)|?{$_.Definition -match 'string'}).Name}
                $aT = x $usrExts
                $bT = x $cmpExts
            $cmpExts.xmlns
            $file1
             $xml.ChildNodes
             ($xml.DocumentElement.UserResults.ExtensionData.Extension)
            $xml = [xml] $(gc c:\temp\test.xml)
            $XmlNamespaceManager = New-Object system.Xml.XmlNamespaceManager( $xml.NameTable )
            $XmlNamespaceManager.AddNamespace("q1","http://www.microsoft.com/GroupPolicy/Settings/Security")
            $XmlNamespaceManager.AddNamespace("q2","http://www.microsoft.com/GroupPolicy/Settings/Registry")
            $XmlNamespaceManager.AddNamespace("q3","http://www.microsoft.com/GroupPolicy/Settings/PublicKey")

            $xml.SelectNodes("//q1:SecurityOptions", $XmlNamespaceManager) | select
                @{Label="Name";Expression={[string]::Concat(  $_.KeyName, $_.SystemAccessPolicyName)}}, 
                @{Label="Value";Expression={[string]::Concat( $_.SettingNumber,$_.SettingString, $( $_.SettingStrings | `
                ForEach-Object -Begin{$output = @()} -Process {$output += $_.Value} -End { $([string]::join('|',$output))} ) )}} | sort Name
            $xml.SelectNodes("//q2:PublicKeySettings", $XmlNamespaceManager) | select `
                @{Label="Name";Expression={[string]::Concat(  $_.KeyName, $_.SystemAccessPolicyName)}}, 
                @{Label="Value";Expression={[string]::Concat( $_.SettingNumber,$_.SettingString, $( $_.SettingStrings | `
                ForEach-Object -Begin{$output = @()} -Process {$output += $_.Value} -End { $([string]::join('|',$output))} ) )}} | sort Name

            <#
                The important line is:

                $xml.SelectNodes("//q1:SecurityOptions", $XmlNamespaceManager)

                which takes into account the $xmlNamespaceManager. The following lines
                are merely formatting etc. If you need to know more about it, drop me line.
                You could save the output as a csv file then, and merge the files of
                all servers for processing with Pivot tables in Excel. That way you can
                report on all your servers and see if all settings are applied consistently.
                Handy for troubleshooting….
            #>
            http://www.microsoft.com/GroupPolicy/Sett... q2:SoftwareInstallationSettings              http://www.microsoft.com/GroupPolicy/Sett...
                                                         q3:AuditSettings                             http://www.microsoft.com/GroupPolicy/Sett...
                                                         q4:SecuritySettings                          http://www.microsoft.com/GroupPolicy/Sett...
                                                         q5:PublicKeySettings                         http://www.microsoft.com/GroupPolicy/Sett...
                                                         q6:WindowsFirewallSettings                   http://www.microsoft.com/GroupPolicy/Sett...
                                                         q7:RegistrySettings                          http://www.microsoft.com/GroupPolicy/Sett...



            PS C:\windows\system32> $xml.DocumentElement.UserResults.ExtensionData.Extension



            q1              : http://www.microsoft.com/GroupPolicy/Settings/Registry
            type            : q1:RegistrySettings
            xmlns           : http://www.microsoft.com/GroupPolicy/Settings



            # Retrieve the current applied policies (must be run from an elevated PS window in order to retrieve computer results)
            gpresult.exe /x C:\Temp\results.xml /f
        #endregion
        #region

            # Import the XML file
            $results = [xml] (Get-Content c:\temp\test.xml)

            # Output the results
            $results.DocumentElement.ComputerResults.ExtensionData | select -ExpandProperty extension | select Account | select -ExpandProperty * | select Name, SettingNumber, SettingBoolean, Type | FT -AutoSize

        #endregion
        #region

            [xml]$results = cat c:\temp\test.xml
            [System.Xml.XmlNamespaceManager]$nsmgr = $results.NameTable;

            # set up namespaces for queries
            $nsmgr.AddNamespace('df',$results.Rsop.xmlns);
            $nsmgr.AddNamespace('base','http://www.microsoft.com/GroupPolicy/Settings/Base')
            $nsmgr.AddNamespace('ex', 'http://www.microsoft.com/GroupPolicy/Settings')
            $nsmgr.AddNamespace('types', 'http://www.microsoft.com/GroupPolicy/Types')

            # get the GUID of a GPO
            $node=$results.selectSingleNode('//df:Rsop/df:ComputerResults/df:GPO/df:Name[text()="Default Domain Policy"]', $nsmgr)
            $node | select *
            $xpath='//df:Rsop/df:ComputerResults/df:GPO/df:Name[text()="Default Domain Policy"]/../df:Path/types:Identifier'
            $guid=$results.selectSingleNode($xpath, $nsmgr).'#text'

            # get extensions
            $extensions = $results.selectNodes('//df:Rsop/df:ComputerResults/df:ExtensionData/ex:Extension', $nsmgr)

            # next we have to update our extensions query to extract only yhe entries associated with our target policy

        #endregion
        #region wmiRSoP
            $wmiRSoP = {
                $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -replace '-', '_'
                $Computer = $env:COMPUTERNAME
                # ($uPols = GWMI -Namespace root\rsop\user\$user -Class RSOP_PolicySetting | FL Name,registryKey,value*
                ($uPols = GWMI -Namespace root\rsop\user\$user -Class RSOP_RegistryPolicySetting) | FL Name,registryKey,value*
                ($cPols = GWMI -Namespace root\rsop\computer -Class RSOP_RegistryPolicySetting) | FL Name,registryKey,value*
                $uRSoPClass = GWMI -Namespace root\rsop\user\$user  -List RSOP*
                $cRSoPClass = GWMI -Namespace root\rsop\computer  -List RSOP*
                }
            & $wmiRSoP
            $b.Properties
            compare $a $uPols -IncludeEqual
        #endregion wmiRSoP
    #endregion COMPARE RSoP


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
                If ($XmlGPReport.GPO.Computer.VersionDirectory -eq 0 -and $XmlGPReport.GPO.Computer.VersionSysvol -eq 0){ $ComputerSettings="NeverModified"}else{$ComputerSettings="Modified" }
                If ($XmlGPReport.GPO.User.VersionDirectory -eq 0 -and $XmlGPReport.GPO.User.VersionSysvol -eq 0){ $UserSettings="NeverModified"}else{$UserSettings="Modified" }

                #GPO content
                If ($XmlGPReport.GPO.User.ExtensionData -eq $null){ $UserSettingsConfigured=$false}else{$UserSettingsConfigured=$true }
                If ($XmlGPReport.GPO.Computer.ExtensionData -eq $null){ $ComputerSettingsConfigured=$false}else{$ComputerSettingsConfigured=$true }

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
                    'ACLs'               = $XmlGPReport.gpo.SecurityDescriptor.Permissions.TrusteePermissions | ForEach-Object -Process {
                        New-Object -TypeName PSObject -Property @{
                            'User'           = $_.trustee.name.'#Text'
                            'PermissionType' = $_.type.PermissionType
                            'Inherited'      = $_.Inherited
                            'Permissions'    = $_.Standard.GPOGroupedAccessEnum
                        }
                    }
                    }
            }
        }
        End {  }
    }

    ${SearchGPOsForSetting.ps1} = {
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
        Param (
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
        Function print {	
          Param ( $displayName, $value )
          $host.UI.WriteLine();
          $stringToPrint = "The Gpo '" + $displayName + "' has a " + $Extension + " setting where '" + $Where + "' is equal to '" + $Is + "'";
          If ($Return -ne $null) { $stringToPrint += " and the value of its '" + $Return + "' property is: '" + $value + "'"; }
          $host.UI.Write([ConsoleColor]::Magenta, [ConsoleColor]::Black,	$stringToPrint);
          $host.UI.WriteLine();
            }
        Function processNodes {
          Param ( $nodes, $foundWhere )
          $thePropertyWeWant = $Where;
          # If we already found the $Where then we are looking for our $Return value now.
          If ($foundWhere) { $thePropertyWeWant = $Return; }
            ForEach ($node in $nodes) {
            $valueWeFound = $null;
            #Here we are checking siblings
            $lookingFor = Get-Member -InputObject $node -Name $thePropertyWeWant;
            if ($lookingFor -ne $null) { $valueWeFound = $node.($lookingFor.Name); }
            else { #Here we are checking attributes.
              if ($node.Attributes -ne $null) {
                $lookingFor = $node.Attributes.GetNamedItem($thePropertyWeWant);
                if ( $lookingFor -ne $null) { $valueWeFound = $lookingFor; }
                  }
                }
            if ( $lookingFor -ne $null) {
              #If we haven't found the $Where yet, then we may have found it now.
              if (! $foundWhere) {
                # We have found the $Where if it has the value we want.
                if ( [String]::Compare($valueWeFound, $Is, $true) -eq 0 ) {
                  # Ok it has the value we want too.  Now, are we looking for a specific
                  # sibling or child of this node or are we done here?
                  if ($Return -eq $null) {
                    #we are done, there is no $Return to look for
                    print -displayName $Gpo.DisplayName -value $null;
                    return;
                      }
                  else {
                      # Now lets look for $Return in the siblings and then if no go, the children.
                      processNodes -nodes $node -foundWhere $true;
                      }
                    }
                  }
              else {
                #we are done.  We already found the $Where, and now we have found the $Return.
                print -displayName $Gpo.DisplayName -value $valueWeFound;
                return;
                  }
                }
            if (! [String]::IsNullOrEmpty($node.InnerXml)) { processNodes -nodes $node.ChildNodes -foundWhere $foundWhere; }
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
        ForEach ($Gpo in $allGposInDomain) {				
          $xmlDoc = [xml] (Get-GPOReport -Guid $Gpo.Id -ReportType xml -Domain $Gpo.DomainName);		
          $xmlNameSpaceMgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable);
 
          $xmlNameSpaceMgr.AddNamespace("", $xmlnsGpSettings);
          $xmlNameSpaceMgr.AddNamespace("gp", $xmlnsGpSettings);
          $xmlNameSpaceMgr.AddNamespace("xsi", $xmlnsSchemaInstance);
          $xmlNameSpaceMgr.AddNamespace("xsd", $xmlnsSchema);
 
          $extensionNodes = $xmlDoc.DocumentElement.SelectNodes($QueryString, $XmlNameSpaceMgr);
          ForEach ($extensionNode in $extensionNodes) {
            if ([String]::Compare(($extensionNode.Attributes.Item(0)).Value, 
              "http://www.microsoft.com/GroupPolicy/Settings/" + $Extension, $true) -eq 0) {
              # We have found the Extension we are looking for now recursively search
              # for $Where (the property we are looking for a specific value of).
                    processNodes -nodes $extensionNode.ChildNodes -foundWhere $false;
                    } #If
                } #FE extensionNode
            } #FE Gpo
        } #sb


    $xmlpath = "c:\temp\test.xml"
    & gpresult.exe /x $xmlpath
    $xml = [xml](Get-Content $xmlpath)
    $T = $xml.DocumentElement.ComputerResults.ExtensionData.extension.Type
    $x = $T | ?{$_ -like "*firewall*"}
    ($xml.DocumentElement.ComputerResults.ExtensionData.extension | ? {$_.type -like "*firewall*"}).inboundfirewallrules
    $xml.DocumentElement.ComputerResults.ExtensionData | Select -exp Extension,Name

    $xml | Get-CGPOReportExtensionData -ExtensionName "Drive Maps"

    filter Get-CGPOReportExtensionData {
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
        #region cmdletbinding
            [CmdletBinding()]
        #endregion
        #region parameters
            Param (
                [parameter(Mandatory=$true,ValueFromPipeline=$true)]
                [Xml.XmlDocument] $gpoReport,
                [parameter(Mandatory=$false)][Xml.XmlNamespaceManager] $namespaceMgr,
                [parameter(Mandatory=$true)]
                [String] $extensionName
                )
        #endregion
        Process {
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
        }


    #region Call GPO Imports
    <##############################################################################
    Ashley McGlone
    Microsoft Premier Field Engineer
    April 2014
    http://aka.ms/GoateePFE

    Module for Group Policy migration.

    Requirements / Setup
    -Windows 7/2008 R2 (or above) RSAT with AD PowerShell cmdlets installed.
    -GPMC with GroupPolicy module installed.
    -Import-Module GroupPolicy
    -Import-Module ActiveDirectory

    These are the default permissions required unless specific permission
    delegations have been created:
    Domain Admins to create policies and link them.
    Enterprise Admins if linking policies to sites.


    LEGAL DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not
    intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
    RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
    EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
    nonexclusive, royalty-free right to use and modify the Sample Code and to
    reproduce and distribute the object code form of the Sample Code, provided
    that You agree: (i) to not use Our name, logo, or trademarks to market Your
    software product in which the Sample Code is embedded; (ii) to include a valid
    copyright notice on Your software product in which the Sample Code is embedded;
    and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
    against any claims or lawsuits, including attorneys' fees, that arise or result
    from the use or distribution of the Sample Code.
 
    This posting is provided "AS IS" with no warranties, and confers no rights. Use
    of included script samples are subject to the terms specified
    at http://www.microsoft.com/info/cpyright.htm.
    ##########################################################################sdg#>



    <#
        .Setup
            Your working folder path should include your MigrationTableCSV files, a copy
            of this script, a copy of the GPOMigration.psm1 module file, and the GPO
            backup folder from the export.

            This example assumes that a backup will run under a source credential and server,
            and the import will run under a destination credential and server.  Between these
            two operations you will need to copy your working folder from one environment to
            the other.

            NOTE: Before running you will need at least one MigrationTableCSV file using
                this format:
                Source,Destination,Type
                "OldDomain.FQDN","NewDomain.FQDN","Domain"
                "OldDomainNETBIOSName","NewDomainNETBIOSName","Domain"
                "\\foo\server","\\baz\server","UNC"
        .Examples
            DEV to QA
                $DestDomain, $DestServer, $MigTableCSVPath  = 'qa.wingtiptoys.com', 'dc1.qa.wingtiptoys.com', '.\MigTable_DEV_to_QA.csv'
                Start-GPOImport -DestDomain $DestDomain -DestServer $DestServer -Path $Path -BackupPath $BackupPath -MigTableCSVPath $MigTableCSVPath -CopyACL

            DEV to PROD
                $DestDomain, $DestServer, $MigTableCSVPath  = 'prod.wingtiptoys.com', 'dc1.prod.wingtiptoys.com', '.\MigTable_DEV_to_PROD.csv'
                Start-GPOImport -DestDomain $DestDomain -DestServer $DestServer -Path $Path -BackupPath $BackupPath -MigTableCSVPath $MigTableCSVPath -CopyACL
    #>
    $trgPth = [Environment]::GetFolderPath('Desktop') + '\GPOMigration'
    $trgBU = 'GPO Backup t.state.gov 2017-05-15-13-41-46'

    Set-Location $trgPth

    Import-Module GroupPolicy
    Import-Module ActiveDirectory
    Import-Module ".\GPOMigration" -Force

    # This path must be absolute, not relative
    $Path        = $PWD  # Current folder specified in Set-Location above
    $BackupPath  = "$PWD\$trgBU"

    # Get Source Domain NetBIOS name
    $rdmBU = (GC ((GCI $BackupPath -Recurse -Filter 'B*.XML').FullName |Select -First 1))
    $srcNBDom = [regex]::Match($rdmBU,'(?<=\<NetBIOSDomainName\>\<\!\[CDATA\[).*').Value.Split(']')[0]

    # TweaK Pemissions File 
    Copy-Item "$BackupPath\GPPermissions.csv" "$BackupPath\GPPermissions.src.csv"
    (GC "$BackupPath\GPPermissions.src.csv") -replace $srcNBDom,(Get-ADDomain).NetBIOSName | Out-File "$BackupPath\GPPermissions.dst.csv"
    # Import-CSV "$BackupPath\GPPermissions.dst.csv"
    Copy-Item "$BackupPath\GPPermissions.dst.csv" "$BackupPath\GPPermissions.csv" -Force

    ###############################################################################
    # IMPORT
    ###############################################################################
    $DestDomain  = (Get-ADDomain).DNSRoot
    $DestServer  = (Get-ADDomain).PDCEmulator
    $MigTableCSVPath = '.\MigTable_sample.csv'

    Start-GPOImport `
        -DestDomain $DestDomain `
        -DestServer $DestServer `
        -Path $Path `
        -BackupPath $BackupPath `
        -MigTableCSVPath $MigTableCSVPath `
        -CopyACL

    #endregion
    #region Call GPO Exports
     <##############################################################################
    <#
    Ashley McGlone
    Microsoft Premier Field Engineer
    April 2014
    http://aka.ms/GoateePFE

    Module for Group Policy migration.

    Requirements / Setup
    -Windows 7/2008 R2 (or above) RSAT with AD PowerShell cmdlets installed.
    -GPMC with GroupPolicy module installed.
    -Import-Module GroupPolicy
    -Import-Module ActiveDirectory

    These are the default permissions required unless specific permission
    delegations have been created:
    Domain Admins to create policies and link them.
    Enterprise Admins if linking policies to sites.


    LEGAL DISCLAIMER
    This Sample Code is provided for the purpose of illustration only and is not
    intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
    RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
    EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
    MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
    nonexclusive, royalty-free right to use and modify the Sample Code and to
    reproduce and distribute the object code form of the Sample Code, provided
    that You agree: (i) to not use Our name, logo, or trademarks to market Your
    software product in which the Sample Code is embedded; (ii) to include a valid
    copyright notice on Your software product in which the Sample Code is embedded;
    and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
    against any claims or lawsuits, including attorneys' fees, that arise or result
    from the use or distribution of the Sample Code.
 
    This posting is provided "AS IS" with no warranties, and confers no rights. Use
    of included script samples are subject to the terms specified
    at http://www.microsoft.com/info/cpyright.htm.
    #>##########################################################################sdg#>



    <##############################################################################
    Setup

    Your working folder path should include a copy of this script, and a copy of
    the GPOMigration.psm1 module file.

    This example assumes that a backup will run under a source credential and server,
    and the import will run under a destination credential and server.  Between these
    two operations you will need to copy your working folder from one environment to
    the other.

    Modify the following to your needs:
     working folder path
     source domain and server
     destination domain and server
     the GPO DisplayName Where criteria to target your policies for migration
    ##############################################################################>

    Set-Location C:\Users\mellaca\Downloads\GPOMigration

    Import-Module GroupPolicy
    Import-Module ActiveDirectory
    Import-Module ".\GPOMigration" -Force

    # This path must be absolute, not relative
    $Path        = $PWD  # Current folder specified in Set-Location above
    $SrceDomain  = (Get-ADDomain).DNSRoot
    $SrceServer  = (Get-ADDomain).PDCEmulator
    $DisplayName = Get-GPO -All -Domain $SrceDomain -Server $SrceServer <#| ?{$_.DisplayName -like '*test*'}#> | Select -Exp DisplayName

    Start-GPOExport `
        -SrceDomain $SrceDomain `
        -SrceServer $SrceServer `
        -DisplayName $DisplayName `
        -Path $Path
    
    ###############################################################################
    # END
    ###############################################################################

    #endregion
    #region Reset GPO Cache
    #Reset-GPOCache.ps1
    #Alan dot Kaplan at VA dot GOV
    #3/17/2015

    #Deletes local copies of GPO and forces a GPUpdate

    [long]$HKLM = 2147483650
    $computer = $env:COMPUTERNAME

    Add-Type -assemblyname Microsoft.visualBasic
    $Computer = [Microsoft.VisualBasic.Interaction]::InputBox("Enter computer name to reset GPO cache", "Name", "$computer")
    if ($computer.length -eq 0){exit}

    if ((Test-Connection -Count 1 -ComputerName $computer -Quiet) -eq $False) {
    Write-Warning "$computer is offline"
    Exit
    }

    Try{
    $WMIConnect = "\\"+$computer+"\root\Default:StdRegProv"
    $RegProv = [WMIClass]$WMIConnect
    }Catch{
        Write-Warning $Error[0].Exception.Message
        Exit
    }

    $ShellFolders = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    $AppData = ($RegProv.GetStringValue($HKLM, $ShellFolders, "Common AppData")).svalue
    $DeletePath = "\\"+$computer+"\"+$AppData.Replace(":","$")+"\Application Data\Microsoft\Group Policy\History\"
    c: 
    write "Deleting cache files in $deletePath"
    Remove-Item -Path $DeletePath -Recurse  -Force -ErrorAction SilentlyContinue


    $startup=[wmiclass]"Win32_ProcessStartup"
    #Create a process with process startup configuration to hide the window using [wmiclass] accelerator
    $startup.Properties['ShowWindow'].value=$False
    $command = "GPUpdate /force"
    Try{
        $retval = ([wmiclass]"\\$Computer\ROOT\CIMV2:Win32_Process").create($command,$null,$Startup)
        Write "Ran `"$command`" on $computer"
        exit
    }Catch{
        Write-Warning "Failed to run $command on $computer with error:"
        $errmsg = $Error[0].Exception.Message
        [regex]::Matches($errmsg,'Error.*').value
        }	

    #endregion
    #region Update GPO Links
    #Update-GPOLinks.ps1 
    #Alan dot Kaplan at va dot gov
    #2/17/15 initial version 1
    #3/27/15 v 1.1 Changed titles, tried to fix error message and success message printing when error occurs.
    #10/13/16 v 2 Added support of attributes linked, enforced, link order, test for domain admin membership

    #requires -version 3
    #requires -module activedirectory
    #requires -module GroupPolicy

    Import-module grouppolicy, activedirectory
    Add-Type -assemblyname Microsoft.visualBasic

    Function EchoAndLog { param([string] $strText)
      #Echo to host and append to file
        Tee-Object -Append -FilePath $logfile -inputobject $strText 
    }

    Function Bool2String($bVar){
      if ($bVar -eq $true) {'Yes'}ELSE {'No'}
    }

    Function Get-AllGPOLinks{  
        #Requires -module GroupPolicy
        #Requires -module ActiveDirectory
        #Requires -version 3

        <#
        .Synopsis
           Get all the GPO links for a specified domain
        .DESCRIPTION
          This script gets all the GPO links for a specified domain
        .EXAMPLE
            $domain = 'contosco.com'
            $GPOName = 'My GPO Settings'
            Get-AllGPOLinks $domain | where {$_.gpname -eq $GPOName}
        .Notes
        Alan Kaplan
        10-5-2016
        This is a version of the script found here:
        http://techibee.com/group-policies/find-link-status-and-enforcement-status-of-group-policies-using-powershell/2424
        My version collects all GPO links, allows you to specify domain, adds error handling, and converted
        output to PSCustomObject, added comments about closing brackets, added advanced function and #Required
        #>
        [CmdletBinding()]
        Param
        (
            # dns domain Name
            [Parameter(Mandatory=$true,
                       ValueFromPipelineByPropertyName=$true,
                       Position=0)]
            $Domain
        )

       $OUs =Get-ADOrganizationalUnit -Filter * -Properties GPLink -server $domain
            
       $AllLinks = foreach($OU in $OUs) {            
         $OUName = $OU.Name            
         $OUDN = $OU.DistinguishedName            
         #Hacky way to get LDAP strings. Regex might be best option here
        if ($OU.GPLink){
         $OUGPLinks = $OU.GPLink.split("][")            
 
         #Get rid of all empty entries the array            
         $OUGPLinks =  @($OUGPLinks | ? {$_}) 

         if ($OUGPLinks.Length -gt 1) {
         $order = $OUGPLinks.Count

         foreach($GPLink in $OUGPLinks) {
          $error.Clear()
          Try{
            $objGPO = [adsi]$GPLink.Split(";")[0]
            $GpName = $objGPO | select -expandProperty displayName
            $GpStatus = $GPLink.split(";")[1]            
            $EnableStatus = $EnforceStatus = 0            
            switch($GPStatus) {            
              "1" {$EnableStatus = $false; $EnforceStatus = $false}            
              "2" {$EnableStatus = $true; $EnforceStatus = $true}            
              "3" {$EnableStatus = $false; $EnforceStatus = $true}            
              "0" {$EnableStatus = $true; $EnforceStatus = $false}            
            }            
            [PSCustomobject]@{          
               OUName  = $OUName            
               OUDN = $OUDN            
               GPName = $GPName            
               IsLinked = $EnableStatus            
               IsEnforced = $EnforceStatus            
               GPOrder = $Order            
            } #end PSCustomObject
            }Catch{
                Write-warning $error[0].exception.message
                Get-GPO -Domain $Domain -Guid 
            }
            $order --      
         } #End foreach GPLink
        } #End if $OUGPLinks.Length
     } #End if $OU.GPLink
    }

    $AllLinks | sort OUDN, GPOrder
    }

    Function Get-AllSecurityGroupsForUser{
    <#
    .Synopsis
    Get all security groups that a user belongs to, directly and indirectly
    .DESCRIPTION
    This script uses ADSI to get all of the groups that a user is a member of.
    The forest is searrched for the user's SamAccountName
    .PARAMETER Name
    The SamAccountName for the user.  Because the entire forest is searched, the domain should be omitted
    .EXAMPLE
    Get-AllGroupsForUser $env:UserName | Out-GridView
    .Notes
    The interesting bits are from http://abhishek225.spaces.live.com/, Function to list the Security Groups a User is Member Of
    Kaplan switched to DN for input, added handling for SIDs in output also added code to search for name in forest from comments below
    https://blogs.technet.microsoft.com/heyscriptingguy/2010/10/12/use-powershell-to-translate-a-users-sid-to-an-active-directory-account-name/
    #>
        [CmdletBinding()]
            Param
        (
        [Parameter(
            Mandatory=$true,
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true, 
            Position=0,
            HelpMessage="Enter SamAccount for user")]
            [string]$Name
      )  
        Begin{
            $forest=[system.directoryservices.activedirectory.Forest]::GetCurrentForest().Name
        }

        Process    {
        $SAMName = $Name
        If ($name.Contains("@")){
            Write-Warning "$Name is not a name in the NT format, quitting"
            Break
        }
     
        if ($name.Contains("\")){
            $a = ($name).Split("\")
            $SAMName = $a[1]
        }


        $searcher=[adsisearcher]"samaccountname=$SAMName"
        $searcher.SearchRoot="GC://$Forest"
        $searcher.PropertiesToLoad.Add('distinguishedname') | Out-Null
        $results=$searcher.FindOne()
        $DistinguishedName = $($results.Properties.distinguishedname).ToString()
        # assumes you have the right permissions, otherwise use new-object and pass creds
        $user = [adsi]"LDAP://$DistinguishedName"
        # Load the TokenGroups attribute in the Property Cache
        $user.psbase.refreshCache(@("TokenGroups"))
        # Convert the SID to to NT Account
        $irc = new-object System.Security.Principal.IdentityReferenceCollection
        foreach($sidByte in $user.TokenGroups)
         {
           $irc.Add((new-object System.Security.Principal.SecurityIdentifier $sidByte,0))
         }

          ($irc.Translate([System.Security.Principal.NTAccount]) | 
            foreach {
            #Kaplan - takes care of some built-in groups that don't work with name-translate
            if ($_.isAccountSid){
                $bind = "LDAP://<SID=$($_)>"
                ([adsi]$Bind).name
                }ELSE{$_}
             }).GetEnumerator().value | sort
            }
    } 

    Function Main{
        $FindGPO = $List |Out-GridView -OutputMode Single -Title "Select the Current GPO to Find and click OK" 
        if ($FindGPO -eq $null) {Break}
        $FindGPOName = ($FindGPO).DisplayName.ToString()
    
        $ReplaceGPO = $List |Out-GridView -OutputMode Single -Title "Select the New GPO to Replace it with and click OK" 
        if ($ReplaceGPO -eq $null) {Break}
        $ReplaceGPOName = ($ReplaceGPO).DisplayName.ToString()

        #If log is new, add header
        if ((Test-Path $logfile) -eq $False) {
            $header = "Update GPO-Links Log.  $env:UserName on " + (Get-Date).ToString()
            if ($bTest){$header += "`n******* Test Mode, no changes made *******`n"}
            Out-File -FilePath $logfile -inputobject $header
        }


        $GPOInfo=Get-GPOReport -domain $domain -server $domain -Name $FindGPOName -ReportType xml 
        $msg = "Checking all OUs in $Domain to create a list of existing links"
        Write $msg


        $AllDNlinks = Get-AllGPOLinks $domain 
        $DNlinks = $AllDNlinks| Where {$_.GPName -eq $FindGPOName}

        if ($DNlinks.count -eq 0){
        Write-Warning "No links found for $FindGPOName"
        Exit
        }
        $error.Clear()

        Write "`n`nDone. Have the list of links, unlinking $FindGPOName`n"
        #Unlink Old
        $DNlinks | Foreach {
        $msg =""
        $OUDN = [string]($_).OUDN
        #$iLinkOrder = ($_).GPOrder
        #$bEnforce = Bool2String ($_).isEnforced
        #$LinkEnabled = Bool2String ($_).isLinked 

        Remove-GPLink -Domain $domain -Target $OUDN -Name $FindGPOName -WhatIf:$bTest -ErrorAction SilentlyContinue
        if ($error){
                $Msg = "`nFailed to remove $FindGPOName GPO in the $domain domain from the Active Directory container with the LDAP path $OUDN. " +`
                    $error[0].Exception.Message
                $error.Clear()
            }Else{
                $Msg = "`nRemoved the link from for the $FindGPOName GPO in the $domain domain to the Active Directory container with the LDAP path $OUDN."
            }
            EchoAndLog $Msg
        } 

        Write "Now linking $ReplaceGPOName`n"

        $DNlinks | Foreach {
        $OUDN = [string]($_).OUDN
        $iLinkOrder = ($_).GPOrder
        $bEnforce = Bool2String ($_).isEnforced
        $LinkEnabled = Bool2String ($_).isLinked 
        New-GPLink -domain $domain -Target $OUDN -Name $ReplaceGPOName -LinkEnabled $LinkEnabled -Order $iLinkOrder -Enforced $bEnforce -WhatIf:$bTest -ErrorAction SilentlyContinue
            if ($error){
                $Msg = "`nFailed to create a link for $ReplaceGPOName GPO in the $domain domain to the Active Directory container with the LDAP path " + $OUDN.tostring()  + ". LinkOrder is $iLinkOrder,  Enforced is $bEnforce,   LinkEnabled is $LinkEnabled`. " +`
                    $error[0].Exception.Message
                $error.Clear()
            }Else{
                $Msg = "`nCreated a link from for the $ReplaceGPOName GPO in the $domain domain to the Active Directory container with the LDAP path "+ $OUDN.tostring() + ". LinkOrder is $iLinkOrder,  Enforced is $bEnforce,   LinkEnabled is $LinkEnabled`. " 
            }
                EchoAndLog $Msg
        } 
    }

    #=========== Script Begins ===============

    $MySecGroups = Get-AllSecurityGroupsForUser $env:userName
    if (![regex]::IsMatch($MySecGroups, 'Domain Admins')){
        Write-Warning "Quitting.  To ensure all GPOs are processed, please rerun this script as a Domain Admin"
        Exit
    }

    $msg =@"
    This script allows you to replace links to a current GPO with links to a newer version.
    It assumes that you have sufficient permissions, and that both new and old GPOs are present.
    Select GPOs in what domain?
"@

    $Script:domain = [Microsoft.VisualBasic.Interaction]::InputBox($msg, "Domain", "$env:userdnsdomain")
    if ($domain.Length -eq 0)   {Exit}
    $domain = $domain.ToUpper()

    $msg = @"
    1) Commit AD Changes
    2) Run in Test Mode
    0) Quit
"@

    $retval= [Microsoft.VisualBasic.Interaction]::InputBox($msg,"Continue with Group Policy Search Replace",2)

    Switch( $retval ){
      1       {$bTest = $False ; Break}
      2       {$bTest = $True ;Break}
      default {Exit}
    }

    #Define default log
    $logFile = $env:userprofile + "\desktop\"+$Domain+"_GPOUpdateLog.txt"

    #prompt for logfile
    $Logfile = [Microsoft.VisualBasic.Interaction]::InputBox("Path to Log", "Logfile", "$logfile")
    if ($Logfile.Length -eq 0)   {Exit}

    Write "Reading the list of all group policy objects in $domain.  Please wait ...."
    $List = Get-GPO -All -server $domain  -Domain $domain  |
    Select-Object -Property DisplayName,Owner, GPOStatus,ID | Sort DisplayName

    $retval = "Yes"
    do
    {
        Main

        $msg="Do another within $script:domain"+'?'
        $retval = [Microsoft.VisualBasic.Interaction]::MsgBox($msg,'YesNo,defaultbutton2,Question', "Respond please")
    }

    until ($retval -eq "No")

    Write "Done.`n"


    #endregion
    #region Call GPImExport
    <#
        Ashley McGlone
            Microsoft Premier Field Engineer
            April 2014
            http://aka.ms/GoateePFE

        Module for Group Policy migration.

        Requirements / Setup
            -Windows 7/2008 R2 (or above) RSAT with AD PowerShell cmdlets installed.
            -GPMC with GroupPolicy module installed.
            -Import-Module GroupPolicy
            -Import-Module ActiveDirectory

        These are the default permissions required unless specific permission delegations have been created:
        Domain Admins to create policies and link them.
        Enterprise Admins if linking policies to sites.

        .LEGAL DISCLAIMER
            This Sample Code is provided for the purpose of illustration only and is not
            intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
            RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
            EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
            MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
            nonexclusive, royalty-free right to use and modify the Sample Code and to
            reproduce and distribute the object code form of the Sample Code, provided
            that You agree: (i) to not use Our name, logo, or trademarks to market Your
            software product in which the Sample Code is embedded; (ii) to include a valid
            copyright notice on Your software product in which the Sample Code is embedded;
            and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
            against any claims or lawsuits, including attorneys' fees, that arise or result
            from the use or distribution of the Sample Code.
         
            This posting is provided "AS IS" with no warranties, and confers no rights. Use
            of included script samples are subject to the terms specified
            at http://www.microsoft.com/info/cpyright.htm.

        .Setup
            Your working folder path should include your MigrationTableCSV files, a copy
            of this script, a copy of the GPOMigration.psm1 module file, and the GPO
            backup folder from the export.

            This example assumes that a backup will run under a source credential and server,
            and the import will run under a destination credential and server.  Between these
            two operations you will need to copy your working folder from one environment to
            the other.

            NOTE: Before running you will need at least one MigrationTableCSV file using
                this format:
                Source,Destination,Type
                "OldDomain.FQDN","NewDomain.FQDN","Domain"
                "OldDomainNETBIOSName","NewDomainNETBIOSName","Domain"
                "\\foo\server","\\baz\server","UNC"
        .Examples
            DEV to QA
                $DestDomain, $DestServer, $MigTableCSVPath  = 'qa.wingtiptoys.com', 'dc1.qa.wingtiptoys.com', '.\MigTable_DEV_to_QA.csv'
                Start-GPOImport -DestDomain $DestDomain -DestServer $DestServer -Path $Path -BackupPath $BackupPath -MigTableCSVPath $MigTableCSVPath -CopyACL

            DEV to PROD
                $DestDomain, $DestServer, $MigTableCSVPath  = 'prod.wingtiptoys.com', 'dc1.prod.wingtiptoys.com', '.\MigTable_DEV_to_PROD.csv'
                Start-GPOImport -DestDomain $DestDomain -DestServer $DestServer -Path $Path -BackupPath $BackupPath -MigTableCSVPath $MigTableCSVPath -CopyACL
    #>
    Param (
        $trgPth,
        $trgBU,
        [switch]$Import
        # [switch]$Import = $true
        )
    Begin {
        Import-Module GroupPolicy
        Import-Module ActiveDirectory
    
        If ([String]::IsNullOrEmpty($trgPth)){ $trgPth = [Environment]::GetFolderPath('Desktop') }
        $trgPth = $trgPth + '\GPOMigration'
        If ($Import.IsPresent){ $trgBU = (GCI $trgPth | ?{ $_.PSIsContainer -and $_.Name -match 'GPO B'} | Sort LastWriteTime | Select -Last 1).Name }
        Else { $trgBU = "GPO Backup " + "$((Get-ADDomain).DNSRoot) " + (Get-Date -f 'yyyy-MM-dd-HH-mm-ss') }
    
        Set-Location $trgPth 
        Import-Module ".\GPOMigration" -Force
        $currDom = (Get-ADDomain)
        $MigTableCSVPath = '.\MigTable_sample.csv'
        } #Begin
    Process {
        Switch ($Import.IsPresent){
            $false {
                $DisplayName = Get-GPO -All -Domain $currDom.DNSRoot -Server $currDom.PDCEmulator | ?{$_.GpoStatus -ne 'AllSettingsDisabled' -AND $_.ModificationTime -ge (Get-Date '3/06/2017 07:00:00 AM')} | Select -Exp DisplayName
                Start-GPOExport -SrceDomain ($currDom.DNSRoot) -SrceServer ($currDom.PDCEmulator) -DisplayName $DisplayName -Path $trgPth
                }
            $true  {
                # This path must be absolute, not relative
                $BackupPath  = "$trgPth\$trgBU"

                # Get Source Domain NetBIOS name
                $rdmBU = (GC ((GCI $BackupPath -Recurse -Filter 'B*.XML'|Select -Exp FullName) | Select -First 1))
                $srcNBDom = [regex]::Match($rdmBU,'(?<=\<NetBIOSDomainName\>\<\!\[CDATA\[).*').Value.Split(']')[0]

                # TweaK Pemissions File 
                Copy-Item "$BackupPath\GPPermissions.csv" "$BackupPath\GPPermissions.src.csv"
                (GC "$BackupPath\GPPermissions.src.csv") -replace $srcNBDom,(Get-ADDomain).NetBIOSName | Out-File "$BackupPath\GPPermissions.dst.csv"
                # Import-CSV "$BackupPath\GPPermissions.dst.csv"
                Copy-Item "$BackupPath\GPPermissions.dst.csv" "$BackupPath\GPPermissions.csv" -Force

                # IMPORT ######################################################################
                Start-GPOImport -DestDomain ($currDom.DNSRoot) -DestServer ($currDom.PDCEmulator) -Path $trgPth -BackupPath $BackupPath -MigTableCSVPath $MigTableCSVPath -CopyACL
                }
            } #sw
        } #Process
    End {} #End

    #endregion
    #region Get all gpo linked to OU
    #This script returns a unique list of all GPO's linked to an OU.  You can also run
    #a onelevel or subtree search to get a unique list of linked OUs at or below the selected OU.
    #You are prompted for the domain, and navigate to desired OU.

    #Alan dot Kaplan at VA dot Gov
    #4-20-16

    #Requires -version 3
    #requires -module GroupPolicy
    #Requires -module ActiveDirectory


    #Use VB for MsgBox and InputBox
    Add-Type -assemblyname Microsoft.visualBasic

    Function NavOU  { param([string] $adsPath)
        # onelevel for speed.  $server is a GC
        $a = Get-ADOrganizationalUnit -searchscope OneLevel -server $server -searchbase $adsPath -Filter 'Name -like "*"'  |
        Select-Object -Property name, distinguishedname |
        ogv -OutputMode Single -Title "Select an OU and click OK"

        if ($a.name.length -eq 0) {Exit}

        $script:adsPath = ($a).distinguishedname
        $Message = 'The currently selected path is ' + ($a).distinguishedname  + '. Continue Navigation?'
        $retval = [Microsoft.VisualBasic.Interaction]::MsgBox($Message,'YesNo,systemmodal,Question',"Continue Search")
        if ($retval -eq  'Yes') {NavOU ($a).distinguishedname}
    }

    Function GetAdsPath(){
        $adDomain = Get-AdDomain
        $Script:DomName = [Microsoft.VisualBasic.Interaction]::InputBox("Choose Starting Domain:", "Domain Name", $adDomain.dnsroot )
        if ($Domname.Length -eq 0)   {Exit}

      #Get a Global Catalog Server
        $adDomain = Get-AdDomain $domname
        $gc = get-addomaincontroller -server $DomName -Filter { isGlobalCatalog -eq $true}
        $script:server = $gc.Item(0).HostName
        #Write-Host $Server

        $adspath = $adDomain.DistinguishedName

        $Message = 'Do you want to select an Organizational Unit of ' + $adspath + '?'
        $retval = [Microsoft.VisualBasic.Interaction]::MsgBox($Message,'YesNo,systemmodal,Question','Navigate OU Structure?')

        if ($retval -eq  'Yes') {
            #Initial Path
            navOU $adsPath
        }
            else {
            $script:adsPath = $adDomain.DistinguishedName
        }
    }

    function Out-TextBox
    {
        [CmdletBinding()]
        Param
        (
            # StrText help description
            [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            Position=0)]
            $objIn,

            # Title help description
            [Parameter(Mandatory=$False,
            Position=1)]
            [string]$Title = "Results"
        )

        $strText = $objIn | out-string
        ########################################################################
        # Code Generated By: SAPIEN Technologies PrimalForms (Community Edition) v1.0.10.0
        # By: Alan Kaplan
        ########################################################################

        #region Import the Assemblies
        [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
        [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
        #endregion

        #region Generated Form Objects
        $DisplayForm = New-Object System.Windows.Forms.Form
        $textBox1 = New-Object System.Windows.Forms.TextBox
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
        #endregion Generated Form Objects

        $OnLoadForm_StateCorrection=
        {#Correct the initial state of the form to prevent the .Net maximized form issue
          $DisplayForm.WindowState = $InitialFormWindowState
        }

        #----------------------------------------------
        #region Edited Generated Form Code
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 560
        $System_Drawing_Size.Width = 660
        $DisplayForm.ClientSize = $System_Drawing_Size
        $DisplayForm.DataBindings.DefaultDataSourceUpdateMode = 0
        $DisplayForm.Name = "DisplayForm"
        $DisplayForm.StartPosition = 1
        $DisplayForm.Text = $title

        $textBox1.DataBindings.DefaultDataSourceUpdateMode = 0
        $textBox1.Dock = 5
        $System_Drawing_Point = New-Object System.Drawing.Point
        $System_Drawing_Point.X = 0
        $System_Drawing_Point.Y = 0
        $textBox1.Location = $System_Drawing_Point
        $textBox1.Multiline = $True
        $textBox1.Name = "textBox1"
        $textBox1.ScrollBars = 3
        $System_Drawing_Size = New-Object System.Drawing.Size
        $System_Drawing_Size.Height = 560
        $System_Drawing_Size.Width = 660
        $textBox1.Size = $System_Drawing_Size
        $textBox1.TabIndex = 0
        $textBox1.Text = $strText.trim()
        $textBox1.Font = "Courier New"

        #This bit de-selects text in box
        if($displayForm.CanFocus){
           $DisplayForm.Focus()
           }else{
           $DisplayForm.Select()
        }
        $DisplayForm.Controls.Add($textBox1)

        #endregion Edited Generated Form Code

        #Save the initial state of the form
        $InitialFormWindowState = $DisplayForm.WindowState
        #Init the OnLoad event to correct the initial state of the form
        $DisplayForm.add_Load($OnLoadForm_StateCorrection)
        #Show the Form
        $DisplayForm.ShowDialog()| Out-Null

    } #End Function

    Function ExportGPOs{
        $ReportPath =  [Microsoft.VisualBasic.Interaction]::InputBox("Write reports to what path?", `
            "Path", "$env:userprofile" +'\desktop\' + $domain + ' GPO Reports' )
        if ($reportpath.Length -eq 0)   {Exit}

        # if folder does not exist...
        if (!(Test-Path $ReportPath)) {
        # create it
        [void](new-item $ReportPath -itemType directory)
        }


        #loosely based on code at
        #http://proproit.com/group-policy/the-simplest-way-to-get-group-policy-objects-reports/

        $GPList.split("`n") | foreach {
            $Name = $_
            Write-Host "Exporting HTML GPO Report for `"$name`" to`n`t`t $reportpath\$name.html"
            Get-GPOReport -name $name -ReportType HTML -server $domain -Domain $domain -Path $reportpath\$name.html
            }
        ii $ReportPath
    }

    ## ============== Script Begins ========

    $msg = "This script will list and export the GPOs linked to an OU.  It can also collect a single unique list of all linked GPOs for sub-OUs."

    $retval = [Microsoft.VisualBasic.Interaction]::MsgBox($msg,'OkCancel,defaultbutton1,Question', "Linked GPOs")
    if ($retval -eq "Cancel"){exit}


    getAdsPath

    $adsPath = $adsPath.Trim()
    $arraylist = New-Object System.Collections.ArrayList(,(@{}))
    $domain = $domName
    $sb = $adsPath


    $msg = "Return results Linked GPOs to $sb for:`
    1) this OU only (Base)`
    2) this OU and the immediate level below (OneLevel)`
    3) this OU and all below it (SubTree)`n`
    0) Quit"

    [int]$iScope = [Microsoft.VisualBasic.Interaction]::InputBox($msg,"Search Depth",1)
    switch ($iScope)
    {
        1{$scope = 'Base'}
        2{$scope = 'OneLevel'}
        3{$scope = 'Subtree'}
        Default {Exit}
    }

    Write "Getting all GPOs linked in $sb with searchscope of $scope`n"
    Get-ADOrganizationalUnit -Server $domain -SearchBase $sb -SearchScope $scope -filter * |
    where {($_.linkedGroupPolicyObjects).count -GT 0} |
    select distinguishedName  |
    foreach {
        $GPInfo = get-gpinheritance -Target $_.distinguishedname -Domain $domain
        $GPInfo | select -ExpandProperty gpolinks | select displayName |foreach {$arraylist.add($_.displayName) | out-null}
        $GPInfo| select -ExpandProperty InheritedGPOLinks | select DisplayName|foreach {$arraylist.add($_.displayName) | Out-Null}
    }
    $Script:GPList = $arraylist | sort | select -Unique
    cls

    $msg = "Got the list.  Do you want to:`
    1) Just show me`
    2) Export the list to a file`
    3) Export all or part of the list to HTML reports`n`
    0) Quit"

    [int]$iScope = [Microsoft.VisualBasic.Interaction]::InputBox($msg,"Results",1)
    switch ($iScope)
    {
        1{$GPList | Out-TextBox}
        2{
            $logfile = "$env:USERPROFILE\desktop\GPOLinkList.txt"
            $GPList | Add-Content $logfile
            ii $logfile
        }
        3{ExportGPOs}
        Default {Exit}
    }

    Write "Done"

    #endregion
    #region GPO SettingsList
    <#
        The other day I had to finish off the documentation for a XenApp 6.5 Implementation I did a couple of months
        back for one of our customers.  Of course group policies are a configuration item, I wanted to have in that 
        document. What I did not want was the default format that the Group Policy Management Console offers in its
        HTML Reports of GPO settings. 

        What else could I do? 

        Of course there is the option to create an XML export with the Group policy module imported into PowerShell. 
        The problem is, the output can't be parsed generically, instead parsing has to be done individually for each
        type of Settings. The first step is to export all GPOs to xml files and copy them somewhere I have access to
        without the need of being a Domain Admin. 
    #> 
        import-module grouppolicy
        (Get-GPO -all | Select displayname) | %{get-gporeport -name $_.displayname -reporttype xml -path $path }

        $xml = [xml](gc $filename)
    #The content of $xml is the base for an XPath query searching for the Node "Extension".

        $nsmgr = New-Object System.XML.XmlNamespaceManager($xml.NameTable)
        $nsmgr.AddNamespace('root','http://www.microsoft.com/GroupPolicy/Settings')
        $settings = [array]$xml.SelectNodes('//root:Extension',$nsmgr)
    #Next step is to read the type of the GPO (f.e: RegistrySettings, FolderRedirectionSettings, SecuritySettings, DriveMapSettings …)

        $types = $settings|select -ExpandProperty type|%{$_.split(":")[1]}
    # To convert the actual settings of a random type into something that is easy to read, each of those types must
    # be inspected in order to develop a mini parser for it. Two simple examples are "Registry Settings" and "Internet
    # Explorer Settings"

    # Type = RegistrySettings
        $settings|?{$_.type -match "RegistrySettings"}|%{$_.RegistrySettings.Registry}|select -expand Properties

    # Type = InternetExplorerSettings
        $settings|%{$_.FavoriteURL|select Name, URL}

    # An example for a more complicated structure is "Securitysettings"
        $kname = $settings|%{$_.SecurityOptions|select -expand KeyName}
        $dname = $settings|%{$_.SecurityOptions.Display.DisplayString}
        For ($i=0;$i -lt $kname.length;$i++){ $out += ($kname[$i],$dname[$i] -join (",")) }
        $out | Out-File -FilePath $outputfile -Append
        $outgroups = @()
        $outgroups += ""
        $outgroups += "Restricted Group" + ";" + "Members"
        $outgroups += ""
        $restrgroups = $securitysettings|%{$_.RestrictedGroups.Groupname.Name|select -expand "#text"}
        for ($j=0;$j -lt $restrgroups.length;$j++){
            $securitysettings.RestrictedGroups | ?{$_.GroupName.Name."#text" -match "$($restrgroups[$j].split("\\")[1])"} | %{
                $restrgroupmembers = ($_.Member.Name|select -expand "#text") -join (",")
                $outgroups += $restrgroups[$j] + ";" + $restrgroupmembers
                } #fe
            } #for
        $outgroups += ""
        $outgroups | Out-File -FilePath $outputfile -Append
        $settings | ?{$_.type -match "Account"}|%{$_.Account} | select Name,SettingBoolean,Type


    # After I have determined "Type" (and if necessary "Name") of each node, 
    # I run a switch Loop and call a function depending on "Type" (I have already finished the below types, there are heaps more).
        if ($nroftypes -gt 1){
            for ($i=0;$i -lt $nroftypes;$i++){
                switch ($types[$i]){
                    RegistrySettings          { get-RegistrySettings }
                    FolderRedirectionSettings { get-FolderRedirectionSettings }
                    SecuritySettings          { get-securitysettings }
                    InternetExplorerSettings  { get-InternetExplorerSettings }
                    DriveMapSettings          { get-DriveMapSettings }
                    } #sw
                } #for
            } #if


      
    #endregion


#region LPO From GPO
    #region 1  -  Initialize Global Variables
        Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
        $Global:ModuleData = [psCustomObject]@{} | Select prefNet,xmlRepos,ModuleList,ModuleScan,DataTypes,ModuleXML
        $Global:infAD = [psCustomObject]@{} | Select DCs,Sites
        $Global:infDomain = @{} | Select DName,OU1,Dom,fqdnRoot,ipDnsSvrs,swRoot
        $Global:infPolicy = @{} | Select polRoot
        $Global:infScript = @{} | Select Local,srcDrv,ScriptRoot,prefWrkSpace
        $Global:sbADSI = { Param($trg)([adsi]"LDAP://$trg,$(([adsi]'').distinguishedname)").psbase.Children }
        $Global:psTab = "`t"
        $Global:psCRLF = [Environment]::NewLine # "$([Char]([int]13))$([Char]([int]10))"
        $Global:GUIDPtrn = [Convert]::ToString((get-date "9/15/63" -f "MMddyyyy"),16)
        $infDomain.ipDnsSvrs = @((gwmi win32_networkadapterconfiguration |?{$_.ipaddress})|Select -expandproperty DNSServerSearchOrder -first 1)
        $infScript.prefWrkSpace = [environment]::GetFolderPath('Desktop')
        $Global:Repos = [Ordered]@{
            Help = 'TUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogbXVsdGlwYXJ0L3JlbGF0ZWQ7IGJvdW5kYXJ5PSItLS0tPV9OZXh0UGFydF8wMUQyM0ZERi41QzhGN0M5MCINCg0KVGhpcyBkb2N1bWVudCBpcyBhIFNpbmdsZSBGaWxlIFdlYiBQYWdlLCBhbHNvIGtub3duIGFzIGEgV2ViIEFyY2hpdmUgZmlsZS4gIElmIHlvdSBhcmUgc2VlaW5nIHRoaXMgbWVzc2FnZSwgeW91ciBicm93c2VyIG9yIGVkaXRvciBkb2Vzbid0IHN1cHBvcnQgV2ViIEFyY2hpdmUgZmlsZXMuICBQbGVhc2UgZG93bmxvYWQgYSBicm93c2VyIHRoYXQgc3VwcG9ydHMgV2ViIEFyY2hpdmUsIHN1Y2ggYXMgV2luZG93c64gSW50ZXJuZXQgRXhwbG9yZXKuLg0KDQotLS0tLS09X05leHRQYXJ0XzAxRDIzRkRGLjVDOEY3QzkwDQpDb250ZW50LUxvY2F0aW9uOiBmaWxlOi8vL0M6L0FDQ0JDQUI5L1JlcG9zaXRvcnkuaHRtDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5nOiBxdW90ZWQtcHJpbnRhYmxlDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbDsgY2hhcnNldD0idXMtYXNjaWkiDQoNCjxodG1sIHhtbG5zOnY9M0QidXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTp2bWwiDQp4bWxuczpvPTNEInVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206b2ZmaWNlOm9mZmljZSINCnhtbG5zOnc9M0QidXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTpvZmZpY2U6d29yZCINCnhtbG5zOm09M0QiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS9vZmZpY2UvMjAwNC8xMi9vbW1sIg0KeG1sbnM9M0QiaHR0cDovL3d3dy53My5vcmcvVFIvUkVDLWh0bWw0MCI+DQoNCjxoZWFkPg0KPG1ldGEgaHR0cC1lcXVpdj0zRENvbnRlbnQtVHlwZSBjb250ZW50PTNEInRleHQvaHRtbDsgY2hhcnNldD0zRHVzLWFzY2lpIj4NCjxtZXRhIG5hbWU9M0RQcm9nSWQgY29udGVudD0zRFdvcmQuRG9jdW1lbnQ+DQo8bWV0YSBuYW1lPTNER2VuZXJhdG9yIGNvbnRlbnQ9M0QiTWljcm9zb2Z0IFdvcmQgMTQiPg0KPG1ldGEgbmFtZT0zRE9yaWdpbmF0b3IgY29udGVudD0zRCJNaWNyb3NvZnQgV29yZCAxNCI+DQo8bGluayByZWw9M0RGaWxlLUxpc3QgaHJlZj0zRCJSZXBvc2l0b3J5X2ZpbGVzL2ZpbGVsaXN0LnhtbCI+DQo8dGl0bGU+UG93ZXJTaGVsbCBSZXBvc2l0b3J5IEhlbHA8L3RpdGxlPg0KPCEtLVtpZiBndGUgbXNvIDldPjx4bWw+DQogPG86RG9jdW1lbnRQcm9wZXJ0aWVzPg0KICA8bzpBdXRob3I+Q2h1Y2sgTWVsbGE8L286QXV0aG9yPg0KICA8bzpMYXN0QXV0aG9yPkRIUyBVc2VyPC9vOkxhc3RBdXRob3I+DQogIDxvOlJldmlzaW9uPjE8L286UmV2aXNpb24+DQogIDxvOlRvdGFsVGltZT4xNDwvbzpUb3RhbFRpbWU+DQogIDxvOkNyZWF0ZWQ+MjAxNi0xMS0xNlQxMjo0NTowMFo8L286Q3JlYXRlZD4NCiAgPG86TGFzdFNhdmVkPjIwMTYtMTEtMTZUMTI6NTk6MDBaPC9vOkxhc3RTYXZlZD4NCiAgPG86UGFnZXM+MTwvbzpQYWdlcz4NCiAgPG86V29yZHM+MjI2PC9vOldvcmRzPg0KICA8bzpDaGFyYWN0ZXJzPjEyOTM8L286Q2hhcmFjdGVycz4NCiAgPG86Q29tcGFueT5IU0ROPC9vOkNvbXBhbnk+DQogIDxvOkxpbmVzPjEwPC9vOkxpbmVzPg0KICA8bzpQYXJhZ3JhcGhzPjM8L286UGFyYWdyYXBocz4NCiAgPG86Q2hhcmFjdGVyc1dpdGhTcGFjZXM+MTUxNjwvbzpDaGFyYWN0ZXJzV2l0aFNwYWNlcz4NCiAgPG86VmVyc2lvbj4xNC4wMDwvbzpWZXJzaW9uPg0KIDwvbzpEb2N1bWVudFByb3BlcnRpZXM+DQo8L3htbD48IVtlbmRpZl0tLT4NCjxsaW5rIHJlbD0zRHRoZW1lRGF0YSBocmVmPTNEIlJlcG9zaXRvcnlfZmlsZXMvdGhlbWVkYXRhLnRobXgiPg0KPGxpbmsgcmVsPTNEY29sb3JTY2hlbWVNYXBwaW5nIGhyZWY9M0QiUmVwb3NpdG9yeV9maWxlcy9jb2xvcnNjaGVtZW1hcHBpbmcuPQ0KeG1sIj4NCjwhLS1baWYgZ3RlIG1zbyA5XT48eG1sPg0KIDx3OldvcmREb2N1bWVudD4NCiAgPHc6U3BlbGxpbmdTdGF0ZT5DbGVhbjwvdzpTcGVsbGluZ1N0YXRlPg0KICA8dzpHcmFtbWFyU3RhdGU+Q2xlYW48L3c6R3JhbW1hclN0YXRlPg0KICA8dzpUcmFja01vdmVzPmZhbHNlPC93OlRyYWNrTW92ZXM+DQogIDx3OlRyYWNrRm9ybWF0dGluZy8+DQogIDx3OlB1bmN0dWF0aW9uS2VybmluZy8+DQogIDx3OlZhbGlkYXRlQWdhaW5zdFNjaGVtYXMvPg0KICA8dzpTYXZlSWZYTUxJbnZhbGlkPmZhbHNlPC93OlNhdmVJZlhNTEludmFsaWQ+DQogIDx3Oklnbm9yZU1peGVkQ29udGVudD5mYWxzZTwvdzpJZ25vcmVNaXhlZENvbnRlbnQ+DQogIDx3OkFsd2F5c1Nob3dQbGFjZWhvbGRlclRleHQ+ZmFsc2U8L3c6QWx3YXlzU2hvd1BsYWNlaG9sZGVyVGV4dD4NCiAgPHc6RG9Ob3RQcm9tb3RlUUYvPg0KICA8dzpMaWRUaGVtZU90aGVyPkVOLVVTPC93OkxpZFRoZW1lT3RoZXI+DQogIDx3OkxpZFRoZW1lQXNpYW4+WC1OT05FPC93OkxpZFRoZW1lQXNpYW4+DQogIDx3OkxpZFRoZW1lQ29tcGxleFNjcmlwdD5YLU5PTkU8L3c6TGlkVGhlbWVDb21wbGV4U2NyaXB0Pg0KICA8dzpDb21wYXRpYmlsaXR5Pg0KICAgPHc6QnJlYWtXcmFwcGVkVGFibGVzLz4NCiAgIDx3OlNuYXBUb0dyaWRJbkNlbGwvPg0KICAgPHc6V3JhcFRleHRXaXRoUHVuY3QvPg0KICAgPHc6VXNlQXNpYW5CcmVha1J1bGVzLz4NCiAgIDx3OkRvbnRHcm93QXV0b2ZpdC8+DQogICA8dzpTcGxpdFBnQnJlYWtBbmRQYXJhTWFyay8+DQogICA8dzpFbmFibGVPcGVuVHlwZUtlcm5pbmcvPg0KICAgPHc6RG9udEZsaXBNaXJyb3JJbmRlbnRzLz4NCiAgIDx3Ok92ZXJyaWRlVGFibGVTdHlsZUhwcy8+DQogIDwvdzpDb21wYXRpYmlsaXR5Pg0KICA8dzpCcm93c2VyTGV2ZWw+TWljcm9zb2Z0SW50ZXJuZXRFeHBsb3JlcjQ8L3c6QnJvd3NlckxldmVsPg0KICA8bTptYXRoUHI+DQogICA8bTptYXRoRm9udCBtOnZhbD0zRCJDYW1icmlhIE1hdGgiLz4NCiAgIDxtOmJya0JpbiBtOnZhbD0zRCJiZWZvcmUiLz4NCiAgIDxtOmJya0JpblN1YiBtOnZhbD0zRCImIzQ1Oy0iLz4NCiAgIDxtOnNtYWxsRnJhYyBtOnZhbD0zRCJvZmYiLz4NCiAgIDxtOmRpc3BEZWYvPg0KICAgPG06bE1hcmdpbiBtOnZhbD0zRCIwIi8+DQogICA8bTpyTWFyZ2luIG06dmFsPTNEIjAiLz4NCiAgIDxtOmRlZkpjIG06dmFsPTNEImNlbnRlckdyb3VwIi8+DQogICA8bTp3cmFwSW5kZW50IG06dmFsPTNEIjE0NDAiLz4NCiAgIDxtOmludExpbSBtOnZhbD0zRCJzdWJTdXAiLz4NCiAgIDxtOm5hcnlMaW0gbTp2YWw9M0QidW5kT3ZyIi8+DQogIDwvbTptYXRoUHI+PC93OldvcmREb2N1bWVudD4NCjwveG1sPjwhW2VuZGlmXS0tPjwhLS1baWYgZ3RlIG1zbyA5XT48eG1sPg0KIDx3OkxhdGVudFN0eWxlcyBEZWZMb2NrZWRTdGF0ZT0zRCJmYWxzZSIgRGVmVW5oaWRlV2hlblVzZWQ9M0QidHJ1ZSINCiAgRGVmU2VtaUhpZGRlbj0zRCJ0cnVlIiBEZWZRRm9ybWF0PTNEImZhbHNlIiBEZWZQcmlvcml0eT0zRCI5OSINCiAgTGF0ZW50U3R5bGVDb3VudD0zRCIyNjciPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJOb3JtYWwiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiaGVhZGluZyAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCI9DQpoZWFkaW5nIDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiPQ0KaGVhZGluZyA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCI9DQpoZWFkaW5nIDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiPQ0KaGVhZGluZyA3Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCI9DQpoZWFkaW5nIDgiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgOSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgNyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgOCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgTmFtZT0zRCJ0b2MgOSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzNSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEPQ0KImNhcHRpb24iLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMTAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIlRpdGxlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjEiIE5hbWU9M0QiRGVmYXVsdCBQYXJhZ3JhcGg9DQogRm9udCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIxMSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiU3VidGl0bGUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMjIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIlN0cm9uZyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIyMCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiRW1waGFzaXMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNTkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJUYWJsZSBHcmlkIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIlBsYWNlaG89DQpsZGVyIFRleHQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiTm8gU3BhY2luZyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IFNoYWRpbmciLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBMaXN0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgR3JpZCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY1IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjciIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY4IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJEYXJrIExpc3QiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBTaGFkaW5nIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgTGlzdCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIEdyaWQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBTaGFkaW5nIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgTGlzdCBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IEdyaWQgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAxIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY0IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMiBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDEgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiUmV2aXNpbz0NCm4iLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMzQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIkxpc3QgUGFyYWdyYXBoIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjI5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJRdW90ZSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzMCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiSW50ZW5zZSBRdW90ZSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDIgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjciIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAxIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY4IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMiBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDMgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJEYXJrIExpc3QgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBTaGFkaW5nIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgTGlzdCBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIEdyaWQgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBTaGFkaW5nIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgTGlzdCBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IEdyaWQgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAxIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY0IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMiBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDEgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjYiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAyIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY3IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMSBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDIgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAzIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiRGFyayBMaXN0IEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgU2hhZGluZyBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIExpc3QgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBHcmlkIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgU2hhZGluZyBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IExpc3QgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBHcmlkIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYzIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMSBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDIgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjUiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAxIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY2IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMiBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDEgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjgiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAyIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMyBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkRhcmsgTGlzdCBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIFNoYWRpbmcgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBMaXN0IEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjczIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgR3JpZCBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IFNoYWRpbmcgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBMaXN0IEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgR3JpZCBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDEgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAyIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY1IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMSBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDIgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjciIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAxIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY4IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMiBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDMgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJEYXJrIExpc3QgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBTaGFkaW5nIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgTGlzdCBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIEdyaWQgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBTaGFkaW5nIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgTGlzdCBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IEdyaWQgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAxIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY0IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMiBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDEgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjYiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAyIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY3IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMSBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDIgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAzIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiRGFyayBMaXN0IEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgU2hhZGluZyBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIExpc3QgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBHcmlkIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgU2hhZGluZyBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IExpc3QgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBHcmlkIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYzIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMSBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDIgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjUiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAxIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY2IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMiBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDEgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjgiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAyIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMyBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkRhcmsgTGlzdCBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIFNoYWRpbmcgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBMaXN0IEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjczIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgR3JpZCBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIxOSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiU3VidGxlIEVtcGhhc2lzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjIxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJJbnRlbnNlIEVtcGhhc2lzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjMxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJTdWJ0bGUgUmVmZXJlbmNlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjMyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJJbnRlbnNlIFJlZmVyZW5jZSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzMyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiQm9vayBUaXRsZSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzNyIgTmFtZT0zRCJCaWJsaW9ncmFwaHkiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMzkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRD0NCiJUT0MgSGVhZGluZyIvPg0KIDwvdzpMYXRlbnRTdHlsZXM+DQo8L3htbD48IVtlbmRpZl0tLT4NCjxzdHlsZT4NCjwhLS0NCiAvKiBGb250IERlZmluaXRpb25zICovDQogQGZvbnQtZmFjZQ0KCXtmb250LWZhbWlseTpDYWxpYnJpOw0KCXBhbm9zZS0xOjIgMTUgNSAyIDIgMiA0IDMgMiA0Ow0KCW1zby1mb250LWNoYXJzZXQ6MDsNCgltc28tZ2VuZXJpYy1mb250LWZhbWlseTpzd2lzczsNCgltc28tZm9udC1waXRjaDp2YXJpYWJsZTsNCgltc28tZm9udC1zaWduYXR1cmU6LTUzNjg3MDE0NSAxMDczNzg2MTExIDEgMCA0MTUgMDt9DQpAZm9udC1mYWNlDQoJe2ZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7DQoJcGFub3NlLTE6MiAxMSA2IDkgNCA1IDQgMiAyIDQ7DQoJbXNvLWZvbnQtY2hhcnNldDowOw0KCW1zby1nZW5lcmljLWZvbnQtZmFtaWx5Om1vZGVybjsNCgltc28tZm9udC1waXRjaDpmaXhlZDsNCgltc28tZm9udC1zaWduYXR1cmU6LTIxNDc0ODI5OTMgNjE0NCAwIDAgMzEgMDt9DQogLyogU3R5bGUgRGVmaW5pdGlvbnMgKi8NCiBwLk1zb05vcm1hbCwgbGkuTXNvTm9ybWFsLCBkaXYuTXNvTm9ybWFsDQoJe21zby1zdHlsZS11bmhpZGU6bm87DQoJbXNvLXN0eWxlLXFmb3JtYXQ6eWVzOw0KCW1zby1zdHlsZS1wYXJlbnQ6IiI7DQoJbWFyZ2luLXRvcDowaW47DQoJbWFyZ2luLXJpZ2h0OjBpbjsNCgltYXJnaW4tYm90dG9tOjEwLjBwdDsNCgltYXJnaW4tbGVmdDowaW47DQoJbGluZS1oZWlnaHQ6MTE1JTsNCgltc28tcGFnaW5hdGlvbjp3aWRvdy1vcnBoYW47DQoJZm9udC1zaXplOjExLjBwdDsNCglmb250LWZhbWlseToiQ2FsaWJyaSIsInNhbnMtc2VyaWYiOw0KCW1zby1hc2NpaS1mb250LWZhbWlseTpDYWxpYnJpOw0KCW1zby1hc2NpaS10aGVtZS1mb250Om1pbm9yLWxhdGluOw0KCW1zby1mYXJlYXN0LWZvbnQtZmFtaWx5OkNhbGlicmk7DQoJbXNvLWZhcmVhc3QtdGhlbWUtZm9udDptaW5vci1sYXRpbjsNCgltc28taGFuc2ktZm9udC1mYW1pbHk6Q2FsaWJyaTsNCgltc28taGFuc2ktdGhlbWUtZm9udDptaW5vci1sYXRpbjsNCgltc28tYmlkaS1mb250LWZhbWlseToiVGltZXMgTmV3IFJvbWFuIjsNCgltc28tYmlkaS10aGVtZS1mb250Om1pbm9yLWJpZGk7fQ0Kc3Bhbi5TcGVsbEUNCgl7bXNvLXN0eWxlLW5hbWU6IiI7DQoJbXNvLXNwbC1lOnllczt9DQpzcGFuLkdyYW1FDQoJe21zby1zdHlsZS1uYW1lOiIiOw0KCW1zby1ncmFtLWU6eWVzO30NCi5Nc29DaHBEZWZhdWx0DQoJe21zby1zdHlsZS10eXBlOmV4cG9ydC1vbmx5Ow0KCW1zby1kZWZhdWx0LXByb3BzOnllczsNCglmb250LWZhbWlseToiQ2FsaWJyaSIsInNhbnMtc2VyaWYiOw0KCW1zby1hc2NpaS1mb250LWZhbWlseTpDYWxpYnJpOw0KCW1zby1hc2NpaS10aGVtZS1mb250Om1pbm9yLWxhdGluOw0KCW1zby1mYXJlYXN0LWZvbnQtZmFtaWx5OkNhbGlicmk7DQoJbXNvLWZhcmVhc3QtdGhlbWUtZm9udDptaW5vci1sYXRpbjsNCgltc28taGFuc2ktZm9udC1mYW1pbHk6Q2FsaWJyaTsNCgltc28taGFuc2ktdGhlbWUtZm9udDptaW5vci1sYXRpbjsNCgltc28tYmlkaS1mb250LWZhbWlseToiVGltZXMgTmV3IFJvbWFuIjsNCgltc28tYmlkaS10aGVtZS1mb250Om1pbm9yLWJpZGk7fQ0KLk1zb1BhcERlZmF1bHQNCgl7bXNvLXN0eWxlLXR5cGU6ZXhwb3J0LW9ubHk7DQoJbWFyZ2luLWJvdHRvbToxMC4wcHQ7DQoJbGluZS1oZWlnaHQ6MTE1JTt9DQpAcGFnZSBXb3JkU2VjdGlvbjENCgl7c2l6ZToxMS4waW4gOC41aW47DQoJbXNvLXBhZ2Utb3JpZW50YXRpb246bGFuZHNjYXBlOw0KCW1hcmdpbjoxLjBpbiAxLjBpbiAxLjBpbiAxLjBpbjsNCgltc28taGVhZGVyLW1hcmdpbjouNWluOw0KCW1zby1mb290ZXItbWFyZ2luOi41aW47DQoJbXNvLXBhcGVyLXNvdXJjZTowO30NCmRpdi5Xb3JkU2VjdGlvbjENCgl7cGFnZTpXb3JkU2VjdGlvbjE7fQ0KLS0+DQo8L3N0eWxlPg0KPCEtLVtpZiBndGUgbXNvIDEwXT4NCjxzdHlsZT4NCiAvKiBTdHlsZSBEZWZpbml0aW9ucyAqLw0KIHRhYmxlLk1zb05vcm1hbFRhYmxlDQoJe21zby1zdHlsZS1uYW1lOiJUYWJsZSBOb3JtYWwiOw0KCW1zby10c3R5bGUtcm93YmFuZC1zaXplOjA7DQoJbXNvLXRzdHlsZS1jb2xiYW5kLXNpemU6MDsNCgltc28tc3R5bGUtbm9zaG93OnllczsNCgltc28tc3R5bGUtcHJpb3JpdHk6OTk7DQoJbXNvLXN0eWxlLXBhcmVudDoiIjsNCgltc28tcGFkZGluZy1hbHQ6MGluIDUuNHB0IDBpbiA1LjRwdDsNCgltc28tcGFyYS1tYXJnaW4tdG9wOjBpbjsNCgltc28tcGFyYS1tYXJnaW4tcmlnaHQ6MGluOw0KCW1zby1wYXJhLW1hcmdpbi1ib3R0b206MTAuMHB0Ow0KCW1zby1wYXJhLW1hcmdpbi1sZWZ0OjBpbjsNCglsaW5lLWhlaWdodDoxMTUlOw0KCW1zby1wYWdpbmF0aW9uOndpZG93LW9ycGhhbjsNCglmb250LXNpemU6MTEuMHB0Ow0KCWZvbnQtZmFtaWx5OiJDYWxpYnJpIiwic2Fucy1zZXJpZiI7DQoJbXNvLWFzY2lpLWZvbnQtZmFtaWx5OkNhbGlicmk7DQoJbXNvLWFzY2lpLXRoZW1lLWZvbnQ6bWlub3ItbGF0aW47DQoJbXNvLWhhbnNpLWZvbnQtZmFtaWx5OkNhbGlicmk7DQoJbXNvLWhhbnNpLXRoZW1lLWZvbnQ6bWlub3ItbGF0aW47fQ0KPC9zdHlsZT4NCjwhW2VuZGlmXS0tPjwhLS1baWYgZ3RlIG1zbyA5XT48eG1sPg0KIDxvOnNoYXBlZGVmYXVsdHMgdjpleHQ9M0QiZWRpdCIgc3BpZG1heD0zRCIxMDI2Ii8+DQo8L3htbD48IVtlbmRpZl0tLT48IS0tW2lmIGd0ZSBtc28gOV0+PHhtbD4NCiA8bzpzaGFwZWxheW91dCB2OmV4dD0zRCJlZGl0Ij4NCiAgPG86aWRtYXAgdjpleHQ9M0QiZWRpdCIgZGF0YT0zRCIxIi8+DQogPC9vOnNoYXBlbGF5b3V0PjwveG1sPjwhW2VuZGlmXS0tPg0KPC9oZWFkPg0KDQo8Ym9keSBsYW5nPTNERU4tVVMgc3R5bGU9M0QndGFiLWludGVydmFsOi41aW4nPg0KDQo8ZGl2IGNsYXNzPTNEV29yZFNlY3Rpb24xPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0KY2xhc3M9M0RHcmFtRT48c3BhbiBzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDPQ0Kb25zb2xlIjsNCmNvbG9yOmRhcmtncmVlbic+Iy08c3BhbiBzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsgPC9zcGFuPkxvYWQ8L3NwYT0NCm4+PC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPg0KQ29kZSBSZXBvc2l0b3J5IEhlbHBlciBGdW5jdGlvbnM8c3BhbiBzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsNCjwvc3Bhbj4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLT0NCi0tLS0tLS08L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48bzpwPjwvbzpwPj0NCjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6bz0NCnJhbmdlcmVkJz4kPHNwYW4NCmNsYXNzPTNEU3BlbGxFPmxDb250ZW50PC9zcGFuPjwvc3Bhbj4gPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPj0zRDwvcz0NCnBhbj4gPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JDxzcGFuIGNsYXNzPTNEU3BlbGxFPmxzdE1vZHpDb250PC9zcGFuPjwvc3Bhbj47ID0NCjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiRsaXN0PC9zcGFuPiA8c3BhbiBjbGFzcz0zREdyYW1FPjxzcGFuIHN0eWxlPTNEJ2M9DQpvbG9yOmRhcmtncmF5Jz49M0Q8L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyA8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kPD0NCi9zcGFuPjwvc3Bhbj48c3Bhbg0KY2xhc3M9M0RTcGVsbEU+PHNwYW4gc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz5sc3RNb2R6PC9zcGFuPjwvc3Bhbj48bzpwPjwvPQ0KbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6bz0NCnJhbmdlcmVkJz4kbG9hZDwvc3Bhbj4NCjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz49M0Q8L3NwYW4+IDxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JD0NCjxzcGFuDQpjbGFzcz0zRFNwZWxsRT5Nb2R1bGVEYXRhPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOndpbmRvd3RleHQnPnhtbEZ1bmN0aW9uczwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheT0NCic+Ljwvc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6d2luZG93dGV4dCc+RnVuY3Rpb248L3NwYW4+PC9zcGFuPjwvc3Bhbj4gPHNwYW4gY2xhc3M9M0RHcmFtPQ0KRT48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPnw8L3NwYW4+IDxzcGFuIHN0eWxlPTNEJ2NvbG9yOmJsdWUnPj88L3NwYW4+PC9zcGFuPQ0KPns8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kXzwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Ljwvc3Bhbj5NPQ0Kb2R1bGUgPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz4tPHNwYW4gY2xhc3M9M0RTcGVsbEU+ZXE8L3NwYW4+PC9zcGFuPiA8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JzxzcGFuIGNsYXNzPTNEU3BlbGxFPmZuX01vZHVsZVRvb2xzPC9zcGFuPic8L3NwYW4+PQ0KfTxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7Jm5ic3A7Jm5ic3A7IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpvPQ0KcmFuZ2VyZWQnPiRsb2FkPC9zcGFuPg0KPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPnw8L3NwYW4+IDxzcGFuIHN0eWxlPTNEJ2NvbG9yOmJsdWUnPiU8L3NwYW4+PQ0KPHNwYW4NCmNsYXNzPTNER3JhbUU+ezxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JDwvc3Bhbj48L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+YTwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+PTNEPC9zcGFuPj0NCjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiRfPC9zcGFuPjsgPHNwYW4gc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kPHNwYW4NCmNsYXNzPTNEU3BlbGxFPnJjbWQ8L3NwYW4+PC9zcGFuPiA8c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+PTNEPC9zcGFuPj0NCiA8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPls8L3NwYW4+PHNwYW4gY2xhc3M9M0RTcGVsbEU+PHNwYW4gc3R5bGU9M0QnY29sb3I6PQ0KdGVhbCc+U2NyaXB0QmxvY2s8L3NwYW4+PC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+XTo6PC9zcGFuPkNyZWF0ZSg8c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrcmVkJz4mcXU9DQpvdDsNCkZ1bmN0aW9uIEdsb2JhbDo8L3NwYW4+JCg8c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Wzwvc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6dGVhbCc+c3RyaW5nPC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz5dPC9zcGFuPjxzPQ0KcGFuDQpzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiQ8c3BhbiBjbGFzcz0zRFNwZWxsRT5hPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2c9DQpyYXknPi48L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOndpbmRvd3RleHQnPk5hbWU8L3NwYW4+PC9zcGFuPjwvc3Bhbj4pPHNwYW4gc3R5bGU9M0QnY29sb3I6ZD0NCmFya3JlZCc+DQp7YG48L3NwYW4+JCg8c3BhbiBzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiRhPC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmQ9DQphcmtncmF5Jz4uPC9zcGFuPkNvZGU8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JyM8c3Bhbg0KY2xhc3M9M0RTcGVsbEU+Y2RhdGE8L3NwYW4+LXNlY3Rpb24nIDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+PQ0KfDwvc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpibHVlJz4lPC9zcGFuPns8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpibHVlJz5EZWM2NDwvc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiQ8c3BhbiBjbGFzPQ0Kcz0zREdyYW1FPl88c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjp3aW5kb3d0ZXh0Jz59PC9zcGFuPjwvPQ0Kc3Bhbj48L3NwYW4+KTxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrcmVkJz5gdH0mcXVvdDs8L3NwYW4+KTsgPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPiY9DQphbXA7PC9zcGFuPg0KPHNwYW4gc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kPHNwYW4gY2xhc3M9M0RTcGVsbEU+cmNtZDwvc3Bhbj48L3NwYW4+PHNwPQ0KYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyA8L3NwYW4+fTxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7PC9zcGFuPjxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCmNsYXNzPTNER3JhbUU+PHNwYW4gc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQz0NCm9uc29sZSI7DQpjb2xvcjpkYXJrZ3JlZW4nPiMtPHNwYW4gc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7IDwvc3Bhbj5SZWxvYWQ8L3M9DQpwYW4+PC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPg0KTW9kdWxlIERhdGEgJmFtcDsgTGlzdCBDb250ZW50czxzcGFuIHN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOw0KPC9zcGFuPi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tPQ0KLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tPC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PG86cD48L286cD49DQo8L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSInPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOm89DQpyYW5nZXJlZCc+JDxzcGFuDQpjbGFzcz0zRFNwZWxsRT5zYl9SZWxvYWRNb2R6PC9zcGFuPjwvc3Bhbj4gPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPj0NCj0zRDwvc3Bhbj4gPHNwYW4NCmNsYXNzPTNER3JhbUU+eyA8c3BhbiBzdHlsZT0zRCdjb2xvcjpibHVlJz5JRVg8L3NwYW4+PC9zcGFuPiA8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JnF1b3Q7PC9zcGFuPiQoKDxzcGFuIGNsYXNzPTNEU3BlbGxFPjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpibHVlJz5nYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+ICZxdW90Ozw9DQovc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kPHNwYW4gY2xhc3M9M0RTcGVsbEU+c2NyaXB0cm9vdDwvc3Bhbj48L3NwYW4+PHNwPQ0KYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPlxDTS5Qb3dlclNoZWxsX3Byb2ZpbGUucHMxJnF1b3Q7PC9zcGFuPik8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+c3BsaXQoPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPls8L3NwPQ0KYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOnRlYWwnPmNoYXI8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPl08L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOnB1cnBsZSc+MTA8L3NwYW4+KTxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiA8L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz58PC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiA8L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmJsdWUnPj88L3NwYW4+ezxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JF88L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiA8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi1tYXRjaDwvc3Bhbj0NCj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+ICc8c3BhbiBjbGFzcz0zRFNwZWxsRT5Nb2R1bGVEYXRhPC9zcGFuPic8L3NwYW4+fTxzPQ0KcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+fDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpibHVlJz5PdXQtU3RyaW5nPC9zcGE9DQpuPik8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JnF1b3Q7PC9zcGFuPiB9PG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSInPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmQ9DQphcmtncmF5Jz4mYW1wOzwvc3Bhbj4NCjxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JDxzcGFuIGNsYXNzPTNEU3BlbGxFPnNiX1JlbG9hZE1vZHo8L3NwYW4+PD0NCi9zcGFuPjxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLXRvcDowaW47bWFyZ2luLXJpZ2h0Oi0yNy4wcHQ7bWFyZ2luLWJvPQ0KdHRvbToNCjBpbjttYXJnaW4tbGVmdDowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtaGVpZ2h0Om5vcm1hbDtiYWNrZ3JvdW5kOndoaT0NCnRlOw0KbXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwYW4gc3R5bGU9M0QnZm9udC1zaXplOjkuPQ0KMHB0Ow0KbXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6bz0NCnJhbmdlcmVkJz4kPHNwYW4NCmNsYXNzPTNEU3BlbGxFPmxzdE1vZHo8L3NwYW4+PC9zcGFuPiA8c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+fDwvc3Bhbj0NCj4gPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmJsdWUnPiU8L3NwYW4+eyA8c3BhbiBzdHlsZT0zRCdjb2xvcjpibHVlJz5Xcml0ZS1Ib3N0PC9zcGFuPj0NCiAoPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiZxdW90Ozwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiQ8c3Bhbg0KY2xhc3M9M0RHcmFtRT5fPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+PHNwYW4gc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllPQ0Kcyc+Jm5ic3A7DQo8L3NwYW4+KDwvc3Bhbj48L3NwYW4+PC9zcGFuPiQoKDxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JDxzcGFuDQpjbGFzcz0zRFNwZWxsRT5sc3RNb2R6Q29udDwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3M9DQpwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JF88L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PD0NCnNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiZxdW90Ozwvc3Bhbj4kKDxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JF88Lz0NCnNwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz4uPC9zcGFuPjxzcGFuIGNsYXNzPTNEU3BlbGxFPjxzcGFuIGNsYXNzPTNER3JhbUU+VD0NCnJpbUVuZDwvc3Bhbj48L3NwYW4+PHNwYW4NCmNsYXNzPTNER3JhbUU+KDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpvcmFuZ2VyZWQnPiRfPC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Wzwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpwdXJwbGUnPi0xPC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+XTwvc3Bhbj4pKTxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPiZxdW90Ozwvc3A9DQphbj4pPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz4uPC9zcGFuPkNvdW50KTxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtyZWQnPikmcXVvdD0NCjs8L3NwYW4+DQo8c3BhbiBzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Kzwvc3Bhbj4gPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPls8L3M9DQpwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOnRlYWwnPkVudmlyb25tZW50PC9zcGFuPjxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz5dOjo8Lz0NCnNwYW4+PHNwYW4NCmNsYXNzPTNEU3BlbGxFPk5ld0xpbmU8L3NwYW4+KSA8c3BhbiBzdHlsZT0zRCdjb2xvcjpuYXZ5Jz4tZjwvc3Bhbj4gPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmJsdWV2aW9sZXQnPkdyZWVuPC9zcGFuPjsgPHNwYW4gc3R5bGU9M0QnY29sb3I6Ymx1ZSc+SUVYPC9zcD0NCmFuPiA8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JnF1b3Q7Q29tbWVudCBgJDxzcGFuIGNsYXNzPTNEU3BlbGxFPmxDb250ZW50PC9zcGFuPQ0KPi48L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JF88L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya3JlZCc+JnF1b3Q7PC9zcD0NCmFuPjs8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPls8L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6dGVhbCc+RW52aXJvbm1lbnQ8L3NwPQ0KYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz5dOjo8L3NwYW4+PHNwYW4gY2xhc3M9M0RTcGVsbEU+TmV3TGluZTwvc3Bhbj4gfTxvOj0NCnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiO2NvbG9yOmRhcmtncj0NCmVlbic+PG86cD4mbmJzcDs8L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0KY2xhc3M9M0RHcmFtRT48c3BhbiBzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDPQ0Kb25zb2xlIjsNCmNvbG9yOmRhcmtncmVlbic+Iy08c3BhbiBzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsgPC9zcGFuPkNvbXBhcmU8Lz0NCnNwYW4+PC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPg0KRnVuY3Rpb25zIHRvIE1vZHVsZXM8c3BhbiBzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsNCjwvc3Bhbj4tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLT0NCi0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS08L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48bzpwPjwvbzpwPj0NCjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+KDxzcGFuIHN0eWxlPTNEJ2NvbG9yOj0NCm9yYW5nZXJlZCc+JDxzcGFuDQpjbGFzcz0zRFNwZWxsRT5Nb2R1bGVEYXRhPHNwYW4gc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2NvbG9yOndpbmRvd3RleHQnPk1vZHVsZUxpc3Q8L3NwYW4+PC9zcGFuPjwvc3Bhbj4pPHNwYW4NCnN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz4uPC9zcGFuPkNvdW50PG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSInPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPig8c3BhbiBzdHlsZT0zRCdjb2xvcjo9DQpvcmFuZ2VyZWQnPiQ8c3Bhbg0KY2xhc3M9M0RTcGVsbEU+TW9kdWxlRGF0YTxzcGFuIHN0eWxlPTNEJ2NvbG9yOmRhcmtncmF5Jz4uPC9zcGFuPjxzcGFuDQpzdHlsZT0zRCdjb2xvcjp3aW5kb3d0ZXh0Jz5Nb2R1bGVTY2FuPC9zcGFuPjwvc3Bhbj48L3NwYW4+KTxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Ljwvc3Bhbj5Db3VudDxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7Jm5ic3A7Jm5ic3A7IDwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjpiPQ0KbHVlJz5Db21wYXJlLU9iamVjdDwvc3Bhbj4NCjxzcGFuIHN0eWxlPTNEJ2NvbG9yOm9yYW5nZXJlZCc+JDxzcGFuIGNsYXNzPTNEU3BlbGxFPk1vZHVsZURhdGE8c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6d2luZG93dGV4dCc+TW9kdWxlTGlzPQ0KdDwvc3Bhbj48c3Bhbg0Kc3R5bGU9M0QnY29sb3I6ZGFya2dyYXknPi48L3NwYW4+PHNwYW4gc3R5bGU9M0QnY29sb3I6d2luZG93dGV4dCc+TmFtZTwvc3BhPQ0Kbj48L3NwYW4+PC9zcGFuPg0KPHNwYW4gc3R5bGU9M0QnY29sb3I6b3JhbmdlcmVkJz4kPHNwYW4gY2xhc3M9M0RTcGVsbEU+TW9kdWxlRGF0YTxzcGFuDQpzdHlsZT0zRCdjb2xvcjpkYXJrZ3JheSc+Ljwvc3Bhbj48c3BhbiBzdHlsZT0zRCdjb2xvcjp3aW5kb3d0ZXh0Jz5Nb2R1bGVTY2E9DQpuPC9zcGFuPjwvc3Bhbj48L3NwYW4+PG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSInPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDs8L3NwYW4+PG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7Y29sb3I6ZGFya2dyPQ0KZWVuJz4mbHQ7IzxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiO2NvbG9yOmRhcmtncj0NCmVlbic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+RVhBTVBMRVM6PG86cD48L286cD48Lz0NCnNwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7Y29sb3I6ZGFya2dyPQ0KZWVuJz48bzpwPiZuYnNwOzwvbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPkZpbmQtU2NyaXB0MiAnZ2V0LWZpbGU9DQonIC08c3Bhbg0KY2xhc3M9M0RTcGVsbEU+cnRuRGF0YTwvc3Bhbj4gLXNjb3BlIG5hbWU8bzpwPjwvbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPkZpbmQtPHNwYW4gY2xhc3M9M0RTcGU9DQpsbEU+RnVuY3Rpb25CeU5hbWU8L3NwYW4+DQonRmluZC1TY3JpcHQyJyAtTG9hZDxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiO2NvbG9yOmRhcmtncj0NCmVlbic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOyZuYnNwOyZuYnNwOyA8L3NwYW4+RmluZC08c3BhbiBjbGFzcz0zRFNwZT0NCmxsRT5GdW5jdGlvbkJ5TmFtZTwvc3Bhbj4NCidOZXctPHNwYW4gY2xhc3M9M0RTcGVsbEU+VGhpbmNsaWVudElOSTwvc3Bhbj4nIC1Mb2FkPG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7Y29sb3I6ZGFya2dyPQ0KZWVuJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7Jm5ic3A7Jm5ic3A7IDwvc3Bhbj5GaW5kLTxzcGFuIGNsYXNzPTNEU3BlPQ0KbGxFPlNjcmlwdEJsb2NrQnlOYW1lPC9zcGFuPg0KJzxzcGFuIGNsYXNzPTNEU3BlbGxFPnNiX0dQQlU8L3NwYW4+JyB8IE91dC1DbGlwYm9hcmQ8bzpwPjwvbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPkZpbmQtPHNwYW4gY2xhc3M9M0RTcGU9DQpsbEU+RnVuY3Rpb25zQnlNb2R1bGU8L3NwYW4+DQonU1RJRycgPG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7Y29sb3I6ZGFya2dyPQ0KZWVuJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7Jm5ic3A7Jm5ic3A7IDwvc3Bhbj5GaW5kLTxzcGFuIGNsYXNzPTNEU3BlPQ0KbGxFPlNjcmlwdEJsb2NrQnlNb2R1bGU8L3NwYW4+DQonU1RJRyc8bzpwPjwvbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIjtjb2xvcjpkYXJrZ3I9DQplZW4nPjxzcGFuDQpzdHlsZT0zRCdtc28tc3BhY2VydW46eWVzJz4mbmJzcDsmbmJzcDsmbmJzcDsgPC9zcGFuPkZpbmQtPHNwYW4gY2xhc3M9M0RTcGU9DQpsbEU+VmFyaWFibGVzQnlOYW1lPC9zcGFuPg0KJzxzcGFuIGNsYXNzPTNEU3BlbGxFPmdwPC9zcGFuPicgfCBPdXQtQ2xpcGJvYXJkPG86cD48L286cD48L3NwYW4+PC9wPg0KDQo8cCBjbGFzcz0zRE1zb05vcm1hbCBzdHlsZT0zRCdtYXJnaW4tYm90dG9tOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQ7bGluZS09DQpoZWlnaHQ6DQpub3JtYWw7YmFja2dyb3VuZDp3aGl0ZTttc28tbGF5b3V0LWdyaWQtYWxpZ246bm9uZTt0ZXh0LWF1dG9zcGFjZTpub25lJz48c3A9DQphbg0Kc3R5bGU9M0QnZm9udC1zaXplOjkuMHB0O21zby1iaWRpLWZvbnQtZmFtaWx5OiJMdWNpZGEgQ29uc29sZSI7Y29sb3I6ZGFya2dyPQ0KZWVuJz48c3Bhbg0Kc3R5bGU9M0QnbXNvLXNwYWNlcnVuOnllcyc+Jm5ic3A7Jm5ic3A7Jm5ic3A7IDwvc3Bhbj5GaW5kLTxzcGFuIGNsYXNzPTNEU3BlPQ0KbGxFPlZhcmlhYmxlc0J5TW9kdWxlPC9zcGFuPg0KJ1NUSUcnIDxvOnA+PC9vOnA+PC9zcGFuPjwvcD4NCg0KPHAgY2xhc3M9M0RNc29Ob3JtYWwgc3R5bGU9M0QnbWFyZ2luLWJvdHRvbTowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0O2xpbmUtPQ0KaGVpZ2h0Og0Kbm9ybWFsO2JhY2tncm91bmQ6d2hpdGU7bXNvLWxheW91dC1ncmlkLWFsaWduOm5vbmU7dGV4dC1hdXRvc3BhY2U6bm9uZSc+PHNwPQ0KYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiO2NvbG9yOmRhcmtncj0NCmVlbic+IyZndDs8L3NwYW4+PHNwYW4NCnN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDttc28tYmlkaS1mb250LWZhbWlseToiTHVjaWRhIENvbnNvbGUiJz48bzpwPjwvbzpwPj0NCjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsIHN0eWxlPTNEJ21hcmdpbi1ib3R0b206MGluO21hcmdpbi1ib3R0b206LjAwMDFwdDtsaW5lLT0NCmhlaWdodDoNCm5vcm1hbDtiYWNrZ3JvdW5kOndoaXRlO21zby1sYXlvdXQtZ3JpZC1hbGlnbjpub25lO3RleHQtYXV0b3NwYWNlOm5vbmUnPjxzcD0NCmFuDQpzdHlsZT0zRCdmb250LXNpemU6OS4wcHQ7bXNvLWJpZGktZm9udC1mYW1pbHk6Ikx1Y2lkYSBDb25zb2xlIic+PHNwYW4NCnN0eWxlPTNEJ21zby1zcGFjZXJ1bjp5ZXMnPiZuYnNwOzwvc3Bhbj48bzpwPjwvbzpwPjwvc3Bhbj48L3A+DQoNCjxwIGNsYXNzPTNETXNvTm9ybWFsPjxzcGFuIHN0eWxlPTNEJ2ZvbnQtc2l6ZTo5LjBwdDtsaW5lLWhlaWdodDoxMTUlJz48bzpwPj0NCiZuYnNwOzwvbzpwPjwvc3Bhbj48L3A+DQoNCjwvZGl2Pg0KDQo8L2JvZHk+DQoNCjwvaHRtbD4NCg0KLS0tLS0tPV9OZXh0UGFydF8wMUQyM0ZERi41QzhGN0M5MA0KQ29udGVudC1Mb2NhdGlvbjogZmlsZTovLy9DOi9BQ0NCQ0FCOS9SZXBvc2l0b3J5X2ZpbGVzL3RoZW1lZGF0YS50aG14DQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5nOiBiYXNlNjQNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vdm5kLm1zLW9mZmljZXRoZW1lDQoNClVFc0RCQlFBQmdBSUFBQUFJUURwM2crLy93QUFBQndDQUFBVEFBQUFXME52Ym5SbGJuUmZWSGx3WlhOZExuaHRiS3lSeTA3RE1CQkYNCjkwajhnK1V0U3B5eVFBZ2w2WUxIanNlaWZNREltU1FXeWRpeXAxWDc5MHpTVkVLb0lCWnNMTmt6OTU0NzQzSzlId2UxdzVpY3AwcXYNCjhrSXJKT3NiUjEybDN6ZFAyYTFXaVlFYUdEeGhwUStZOUxxK3ZDZzNoNEJKaVpwU3BYdm1jR2RNc2oyT2tISWZrS1RTK2pnQ3l6VjINCkpvRDlnQTdOZFZIY0dPdUprVGpqeVVQWDVRTzJzQjFZUGU3bCtaZ2s0cEMwdWo4MlRxeEtRd2lEczhDUzFPeW8rVWJKRmtJdXlya24NCjlTNmtLNG1oelZuQ1ZQa1pzT2hlWlRYUk5hamVJUElMakJMRHNBeUpYODluSUJrdDVyODdub25zMjlaWmJMemRqcktPZkRaZXpFN0INCi94Umc5VC9vRTlQTWYxdC9BZ0FBLy84REFGQkxBd1FVQUFZQUNBQUFBQ0VBcGRhbjU4QUFBQUEyQVFBQUN3QUFBRjl5Wld4ekx5NXkNClpXeHpoSS9QYXNNd0RJZnZoYjJEMFgxUjBzTVlKWFl2cFpCREw2TjlBT0VvZjJnaUc5c2I2OXRQeHdZS3V3aUVwTy8zcVQzK3JvdjUNCjRaVG5JQmFhcWdiRDRrTS95MmpoZGoyL2Y0TEpoYVNuSlFoYmVIQ0dvM3ZidFYrOFVOR2pQTTB4RzZWSXRqQ1ZFZytJMlUrOFVxNUMNClpOSEpFTkpLUmRzMFlpUi9wNUZ4WDljZm1KNFo0RFpNMC9VV1V0YzNZSzZQcU1uL3M4TXd6SjVQd1grdkxPVkZCRzQzbEV4cDVHS2gNCnFDL2pVNzJRcUdXcTFCN1F0Ymo1MXYwQkFBRC8vd01BVUVzREJCUUFCZ0FJQUFBQUlRQnJlWllXZ3dBQUFJb0FBQUFjQUFBQWRHaGwNCmJXVXZkR2hsYldVdmRHaGxiV1ZOWVc1aFoyVnlMbmh0YkF6TVRRckRJQkJBNFgyaGQ1RFpOMk83S0VWaXNzdXV1L1lBUTV3YVFjZWcNCjBwL2IxK1hqZ3pmTzN4VFZtMHNOV1N5Y0J3MktaYzB1aUxmd2ZDeW5HNmphU0J6RkxHemh4eFhtNlhnWXliU05FOTlKeUhOUmZTUFYNCmtJV3R0ZDBnMXJVcjFTSHZMTjFldVNScVBZdEhWK2pUOXluaVJlc3JKZ29DT1AwQkFBRC8vd01BVUVzREJCUUFCZ0FJQUFBQUlRQXcNCjNVTXBxQVlBQUtRYkFBQVdBQUFBZEdobGJXVXZkR2hsYldVdmRHaGxiV1V4TG5odGJPeFpUMi9iTmhTL0Q5aDNJSFJ2WXlkMkdnZDENCml0aXhteTFORzhSdWh4NXBpWmJZVUtKQTBrbDlHOXJqZ0FIRHVtR0hGZGh0aDJGYmdSYllwZnMwMlRwc0hkQ3ZzRWRTa3NWWVhwSTINCjJJcXRQaVFTK2VQNy94NGZxYXZYN3NjTUhSSWhLVS9hWHYxeXpVTWs4WGxBazdEdDNSNzJMNjE1U0NxY0JKanhoTFM5S1pIZXRZMzMNCjM3dUsxMVZFWW9KZ2ZTTFhjZHVMbEVyWGw1YWtEOE5ZWHVZcFNXQnV6RVdNRmJ5S2NDa1ErQWpveG14cHVWWmJYWW94VFR5VTRCakkNCjNocVBxVS9RVUpQME5uTGlQUWF2aVpKNndHZGlvRWtUWjRYQkJnZDFqWkJUMldVQ0hXTFc5b0JQd0krRzVMN3lFTU5Td1VUYnE1bWYNCnQ3UnhkUW12WjR1WVdyQzJ0SzV2ZnRtNmJFRndzR3g0aW5CVU1LMzNHNjByV3dWOUEyQnFIdGZyOWJxOWVrSFBBTER2ZzZaV2xqTE4NClJuK3Qzc2xwbGtEMmNaNTJ0OWFzTlZ4OGlmN0tuTXl0VHFmVGJHV3lXS0lHWkI4YmMvaTEybXBqYzluQkc1REZOK2Z3amM1bXQ3dnENCjRBM0k0bGZuOFAwcnJkV0dpemVnaU5Ia1lBNnRIZHJ2WjlRTHlKaXo3VXI0R3NEWGFobDhob0pvS0tKTHN4anpSQzJLdFJqZjQ2SVANCkFBMWtXTkVFcVdsS3h0aUhLTzdpZUNRbzFnendPc0dsR1R2a3k3a2h6UXRKWDlCVXRiMFBVd3daTWFQMzZ2bjNyNTQvUmNjUG5oMC8NCitPbjQ0Y1BqQno5YVFzNnFiWnlFNVZVdnYvM3N6OGNmb3orZWZ2UHkwUmZWZUZuRy8vckRKNy84L0hrMUVOSm5KczZMTDUvODl1ekoNCmk2OCsvZjI3UnhYd1RZRkhaZmlReGtTaW0rUUk3Zk1ZRkROV2NTVW5JM0crRmNNSTAvS0t6U1NVT01HYVN3WDlub29jOU0wcFpwbDMNCkhEazZ4TFhnSFFIbG93cDRmWExQRVhnUWlZbWlGWngzb3RnQjduTE9PbHhVV21GSDh5cVplVGhKd21ybVlsTEc3V044V01XN2l4UEgNCnY3MUpDblV6RDB0SDhXNUVIREgzR0U0VURrbENGTkp6L0lDUUN1M3VVdXJZZFpmNmdrcytWdWd1UlIxTUswMHlwQ01ubW1hTHRta00NCmZwbFc2UXorZG15emV3ZDFPS3ZTZW9zY3VraklDc3dxaEI4UzVwanhPcDRvSEZlUkhPS1lsUTErQTZ1b1NzakJWUGhsWEU4cThIUkkNCkdFZTlnRWhadGVhV0FIMUxUdC9CVUxFcTNiN0xwckdMRklvZVZORzhnVGt2STdmNFFUZkNjVnFGSGRBa0ttTS9rQWNRb2hqdGNWVUYNCjMrVnVodWgzOEFOT0ZycjdEaVdPdTArdkJyZHA2SWcwQ3hBOU14RVZ2cnhPdUJPL2d5a2JZMkpLRFJSMXAxYkhOUG03d3Mwb1ZHN0wNCjRlSUtONVRLRjE4L3JwRDdiUzNabTdCN1ZlWE05b2xDdlFoM3NqeDN1UWpvMjErZHQvQWsyU09RRVBOYjFMdmkvSzQ0ZS8vNTRyd28NCm55KytKTStxTUJSbzNZdllSdHUwM2ZIQ3JudE1HUnVvS1NNM3BHbThKZXc5UVI4RzlUcHo0aVRGS1N5TjRGRm5NakJ3Y0tIQVpnMFMNClhIMUVWVFNJY0FwTmU5M1RSRUtaa1E0bFNybUV3NklacnFTdDhkRDRLM3ZVYk9wRGlLMGNFcXRkSHRqaEZUMmNuelVLTWthcTBCeG8NCmMwWXJtc0JabWExY3lZaUNicS9Ecks2Rk9qTzN1aEhORkVXSFc2R3lOckU1bElQSkM5VmdzTEFtTkRVSVdpR3c4aXFjK1RWck9PeGcNClJnSnRkK3VqM0MzR0N4ZnBJaG5oZ0dRKzBuclArNmh1bkpUSHlwd2lXZzhiRFByZ2VJclZTdHhhbXV3YmNEdUxrOHJzR2d2WTVkNTcNCkV5L2xFVHp6RWxBN21ZNHNLU2NuUzlCUjIyczFsNXNlOG5IYTlzWndUb2JIT0FXdlM5MUhZaGJDWlpPdmhBMzdVNVBaWlBuTW02MWMNCk1UY0o2bkQxWWUwK3A3QlRCMUloMVJhV2tRME5NNVdGQUVzMEp5di9jaFBNZWxFS1ZGU2pzMG14c2diQjhLOUpBWFowWFV2R1krS3INCnNyTkxJOXAyOWpVcnBYeWlpQmhFd1JFYXNZbll4K0IrSGFxZ1QwQWxYSGVZaXFCZjRHNU9XOXRNdWNVNVM3cnlqWmpCMlhITTBnaG4NCjVWYW5hSjdKRm00S1VpR0RlU3VKQjdwVnltNlVPNzhxSnVVdlNKVnlHUC9QVk5IN0NkdytyQVRhQXo1Y0RRdU1kS2EwUFM1VXhLRUsNCnBSSDErd0lhQjFNN0lGcmdmaGVtSWFqZ2d0cjhGK1JRLzdjNVoybVl0SVpEcE5xbklSSVU5aU1WQ1VMMm9DeVo2RHVGV0QzYnV5eEoNCmxoRXlFVlVTVjZaVzdCRTVKR3lvYStDcTN0czlGRUdvbTJxU2xRR0RPeGwvN251V1FhTlFOem5sZkhNcVdiSDMyaHo0cHpzZm04eWcNCmxGdUhUVU9UMjc4UXNXZ1BacnVxWFcrVzUzdHZXUkU5TVd1ekdubFdBTFBTVnRESzB2NDFSVGpuVm1zcjFwekd5ODFjT1BEaXZNWXcNCldEUkVLZHdoSWYwSDlqOHFmR2EvZHVnTmRjajNvYllpK0hpaGlVSFlRRlJmc28wSDBnWFNEbzZnY2JLRE5wZzBLV3ZhckhYU1ZzczMNCjZ3dnVkQXUrSjR5dEpUdUx2ODlwN0tJNWM5azV1WGlSeHM0czdOamFqaTAwTlhqMlpJckMwRGcveUJqSG1NOWs1UzlaZkhRUEhMMEYNCjN3d21URWtUVFBDZFNtRG9vUWNtRHlENUxVZXpkT012QUFBQS8vOERBRkJMQXdRVUFBWUFDQUFBQUNFQURkR1FuN1lBQUFBYkFRQUENCkp3QUFBSFJvWlcxbEwzUm9aVzFsTDE5eVpXeHpMM1JvWlcxbFRXRnVZV2RsY2k1NGJXd3VjbVZzYzRTUFRRckNNQlNFOTRKM0NHOXYNCjA3b1FrU2JkaU5DdDFBT0U1RFVOTmo4a1VlenREYTRzQ0M2SFliNlphYnVYbmNrVFl6TGVNV2lxR2dnNjZaVnhtc0Z0dU95T1FGSVcNClRvblpPMlN3WUlLT2J6ZnRGV2VSU3loTkppUlNLQzR4bUhJT0owcVRuTkNLVlBtQXJqaWpqMWJrSXFPbVFjaTcwRWozZFgyZzhac0INCmZNVWt2V0lRZTlVQUdaWlFtdit6L1RnYWlXY3ZIeFpkL2xGQmM5bUZCU2lpeHN6Z0k1dXFUQVRLVzdxNnhOOEFBQUQvL3dNQVVFc0INCkFpMEFGQUFHQUFnQUFBQWhBT25lRDcvL0FBQUFIQUlBQUJNQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUZ0RGIyNTBaVzUwWDFSNWNHVnoNClhTNTRiV3hRU3dFQ0xRQVVBQVlBQ0FBQUFDRUFwZGFuNThBQUFBQTJBUUFBQ3dBQUFBQUFBQUFBQUFBQUFBQXdBUUFBWDNKbGJITXYNCkxuSmxiSE5RU3dFQ0xRQVVBQVlBQ0FBQUFDRUFhM21XRm9NQUFBQ0tBQUFBSEFBQUFBQUFBQUFBQUFBQUFBQVpBZ0FBZEdobGJXVXYNCmRHaGxiV1V2ZEdobGJXVk5ZVzVoWjJWeUxuaHRiRkJMQVFJdEFCUUFCZ0FJQUFBQUlRQXczVU1wcUFZQUFLUWJBQUFXQUFBQUFBQUENCkFBQUFBQUFBQU5ZQ0FBQjBhR1Z0WlM5MGFHVnRaUzkwYUdWdFpURXVlRzFzVUVzQkFpMEFGQUFHQUFnQUFBQWhBQTNSa0orMkFBQUENCkd3RUFBQ2NBQUFBQUFBQUFBQUFBQUFBQXNna0FBSFJvWlcxbEwzUm9aVzFsTDE5eVpXeHpMM1JvWlcxbFRXRnVZV2RsY2k1NGJXd3UNCmNtVnNjMUJMQlFZQUFBQUFCUUFGQUYwQkFBQ3RDZ0FBQUFBPQ0KDQotLS0tLS09X05leHRQYXJ0XzAxRDIzRkRGLjVDOEY3QzkwDQpDb250ZW50LUxvY2F0aW9uOiBmaWxlOi8vL0M6L0FDQ0JDQUI5L1JlcG9zaXRvcnlfZmlsZXMvY29sb3JzY2hlbWVtYXBwaW5nLnhtbA0KQ29udGVudC1UcmFuc2Zlci1FbmNvZGluZzogcXVvdGVkLXByaW50YWJsZQ0KQ29udGVudC1UeXBlOiB0ZXh0L3htbA0KDQo8P3htbCB2ZXJzaW9uPTNEIjEuMCIgZW5jb2Rpbmc9M0QiVVRGLTgiIHN0YW5kYWxvbmU9M0QieWVzIj8+DQo8YTpjbHJNYXAgeG1sbnM6YT0zRCJodHRwOi8vc2NoZW1hcy5vcGVueG1sZm9ybWF0cy5vcmcvZHJhd2luZ21sLzIwMDYvbWFpbiI9DQogYmcxPTNEImx0MSIgdHgxPTNEImRrMSIgYmcyPTNEImx0MiIgdHgyPTNEImRrMiIgYWNjZW50MT0zRCJhY2NlbnQxIiBhY2NlbnQ9DQoyPTNEImFjY2VudDIiIGFjY2VudDM9M0QiYWNjZW50MyIgYWNjZW50ND0zRCJhY2NlbnQ0IiBhY2NlbnQ1PTNEImFjY2VudDUiIGE9DQpjY2VudDY9M0QiYWNjZW50NiIgaGxpbms9M0QiaGxpbmsiIGZvbEhsaW5rPTNEImZvbEhsaW5rIi8+DQotLS0tLS09X05leHRQYXJ0XzAxRDIzRkRGLjVDOEY3QzkwDQpDb250ZW50LUxvY2F0aW9uOiBmaWxlOi8vL0M6L0FDQ0JDQUI5L1JlcG9zaXRvcnlfZmlsZXMvZmlsZWxpc3QueG1sDQpDb250ZW50LVRyYW5zZmVyLUVuY29kaW5nOiBxdW90ZWQtcHJpbnRhYmxlDQpDb250ZW50LVR5cGU6IHRleHQveG1sOyBjaGFyc2V0PSJ1dGYtOCINCg0KPHhtbCB4bWxuczpvPTNEInVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206b2ZmaWNlOm9mZmljZSI+DQogPG86TWFpbkZpbGUgSFJlZj0zRCIuLi9SZXBvc2l0b3J5Lmh0bSIvPg0KIDxvOkZpbGUgSFJlZj0zRCJ0aGVtZWRhdGEudGhteCIvPg0KIDxvOkZpbGUgSFJlZj0zRCJjb2xvcnNjaGVtZW1hcHBpbmcueG1sIi8+DQogPG86RmlsZSBIUmVmPTNEImZpbGVsaXN0LnhtbCIvPg0KPC94bWw+DQotLS0tLS09X05leHRQYXJ0XzAxRDIzRkRGLjVDOEY3QzkwLS0NCg=='
            }
        $Global:rgx = [psCustomObject]@{
            Help = 'RnJvbTogPFNhdmVkIGJ5IE1vemlsbGEgNS4wIChXaW5kb3dzKT4NClN1YmplY3Q6IFF1aWNrLVN0YXJ0OiBSZWdleCBDaGVhdCBTaGVldA0KRGF0ZTogTW9uLCAwNyBOb3YgMjAxNiAwNzoxNjozOSAtMDUwMA0KTUlNRS1WZXJzaW9uOiAxLjANCkNvbnRlbnQtVHlwZTogdGV4dC9odG1sOw0KCWNoYXJzZXQ9IndpbmRvd3MtMTI1MiINCkNvbnRlbnQtVHJhbnNmZXItRW5jb2Rpbmc6IHF1b3RlZC1wcmludGFibGUNCkNvbnRlbnQtTG9jYXRpb246IHVubWh0Oi8vdW5taHQvZmlsZS41L0M6L1RlbXAvdG1wLm1odC8NClgtTUFGLUluZm9ybWF0aW9uOiBQcm9kdWNlZCBCeSBNQUYgVjMuMS4zDQoNCjxodG1sIHhtbG5zOnY9M0QidXJuOnNjaGVtYXMtbWljcm9zb2Z0LWNvbTp2bWwiIHhtbG5zOm89M0QidXJuOnNjaGVtYXMtbWljcj0NCm9zb2Z0LWNvbTpvZmZpY2U6b2ZmaWNlIiB4bWxuczp3PTNEInVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206b2ZmaWNlOndvcmQiPQ0KIHhtbG5zOmR0PTNEInV1aWQ6QzJGNDEwMTAtNjVCMy0xMWQxLUEyOUYtMDBBQTAwQzE0ODgyIiB4bWxuczptPTNEImh0dHA6Ly9zPQ0KY2hlbWFzLm1pY3Jvc29mdC5jb20vb2ZmaWNlLzIwMDQvMTIvb21tbCIgeG1sbnM9M0QiaHR0cDovL3d3dy53My5vcmcvVFIvUkVDPQ0KLWh0bWw0MCI+PGhlYWQ+DQo8bWV0YSBodHRwLWVxdWl2PTNEImNvbnRlbnQtdHlwZSIgY29udGVudD0zRCJ0ZXh0L2h0bWw7IGNoYXJzZXQ9M0R3aW5kb3dzLTE9DQoyNTIiPg0KPG1ldGEgaHR0cC1lcXVpdj0zRCJDb250ZW50LVR5cGUiIGNvbnRlbnQ9M0QidGV4dC9odG1sOyBjaGFyc2V0PTNEd2luZG93cy0xPQ0KMjUyIj4NCjxtZXRhIG5hbWU9M0QiUHJvZ0lkIiBjb250ZW50PTNEIldvcmQuRG9jdW1lbnQiPg0KPG1ldGEgbmFtZT0zRCJHZW5lcmF0b3IiIGNvbnRlbnQ9M0QiTWljcm9zb2Z0IFdvcmQgMTQiPg0KPG1ldGEgbmFtZT0zRCJPcmlnaW5hdG9yIiBjb250ZW50PTNEIk1pY3Jvc29mdCBXb3JkIDE0Ij4NCjxsaW5rIHJlbD0zRCJGaWxlLUxpc3QiIGhyZWY9M0QidW5taHQ6Ly91bm1odC9maWxlLjUvQzovVGVtcC90bXAubWh0L2ZpbGVsaT0NCnN0LnhtbCI+DQo8bGluayByZWw9M0QidGhlbWVEYXRhIiBocmVmPTNEInVubWh0Oi8vdW5taHQvZmlsZS41L0M6L1RlbXAvdG1wLm1odC90aGVtZWQ9DQphdGEudGhteCI+DQo8bGluayByZWw9M0QiY29sb3JTY2hlbWVNYXBwaW5nIiBocmVmPTNEInVubWh0Oi8vdW5taHQvZmlsZS41L0M6L1RlbXAvdG1wLm09DQpodC9jb2xvcnNjaGVtZW1hcHBpbmcueG1sIj4NCjwhLS1baWYgZ3RlIG1zbyA5XT48eG1sPg0KIDx3OldvcmREb2N1bWVudD4NCiAgPHc6Wm9vbT4xMzA8L3c6Wm9vbT4NCiAgPHc6U3BlbGxpbmdTdGF0ZT5DbGVhbjwvdzpTcGVsbGluZ1N0YXRlPg0KICA8dzpHcmFtbWFyU3RhdGU+Q2xlYW48L3c6R3JhbW1hclN0YXRlPg0KICA8dzpUcmFja01vdmVzPmZhbHNlPC93OlRyYWNrTW92ZXM+DQogIDx3OlRyYWNrRm9ybWF0dGluZy8+DQogIDx3OlZhbGlkYXRlQWdhaW5zdFNjaGVtYXMvPg0KICA8dzpTYXZlSWZYTUxJbnZhbGlkPmZhbHNlPC93OlNhdmVJZlhNTEludmFsaWQ+DQogIDx3Oklnbm9yZU1peGVkQ29udGVudD5mYWxzZTwvdzpJZ25vcmVNaXhlZENvbnRlbnQ+DQogIDx3OkFsd2F5c1Nob3dQbGFjZWhvbGRlclRleHQ+ZmFsc2U8L3c6QWx3YXlzU2hvd1BsYWNlaG9sZGVyVGV4dD4NCiAgPHc6RG9Ob3RQcm9tb3RlUUYvPg0KICA8dzpMaWRUaGVtZU90aGVyPkVOLVVTPC93OkxpZFRoZW1lT3RoZXI+DQogIDx3OkxpZFRoZW1lQXNpYW4+WC1OT05FPC93OkxpZFRoZW1lQXNpYW4+DQogIDx3OkxpZFRoZW1lQ29tcGxleFNjcmlwdD5YLU5PTkU8L3c6TGlkVGhlbWVDb21wbGV4U2NyaXB0Pg0KICA8dzpDb21wYXRpYmlsaXR5Pg0KICAgPHc6QnJlYWtXcmFwcGVkVGFibGVzLz4NCiAgIDx3OlNwbGl0UGdCcmVha0FuZFBhcmFNYXJrLz4NCiAgPC93OkNvbXBhdGliaWxpdHk+DQogIDx3OkJyb3dzZXJMZXZlbD5NaWNyb3NvZnRJbnRlcm5ldEV4cGxvcmVyNDwvdzpCcm93c2VyTGV2ZWw+DQogIDxtOm1hdGhQcj4NCiAgIDxtOm1hdGhGb250IG06dmFsPTNEIkNhbWJyaWEgTWF0aCIvPg0KICAgPG06YnJrQmluIG06dmFsPTNEImJlZm9yZSIvPg0KICAgPG06YnJrQmluU3ViIG06dmFsPTNEIiYjNDU7LSIvPg0KICAgPG06c21hbGxGcmFjIG06dmFsPTNEIm9mZiIvPg0KICAgPG06ZGlzcERlZi8+DQogICA8bTpsTWFyZ2luIG06dmFsPTNEIjAiLz4NCiAgIDxtOnJNYXJnaW4gbTp2YWw9M0QiMCIvPg0KICAgPG06ZGVmSmMgbTp2YWw9M0QiY2VudGVyR3JvdXAiLz4NCiAgIDxtOndyYXBJbmRlbnQgbTp2YWw9M0QiMTQ0MCIvPg0KICAgPG06aW50TGltIG06dmFsPTNEInN1YlN1cCIvPg0KICAgPG06bmFyeUxpbSBtOnZhbD0zRCJ1bmRPdnIiLz4NCiAgPC9tOm1hdGhQcj48L3c6V29yZERvY3VtZW50Pg0KPC94bWw+PCFbZW5kaWZdLS0+PCEtLVtpZiBndGUgbXNvIDldPjx4bWw+DQogPHc6TGF0ZW50U3R5bGVzIERlZkxvY2tlZFN0YXRlPTNEImZhbHNlIiBEZWZVbmhpZGVXaGVuVXNlZD0zRCJ0cnVlIg0KICBEZWZTZW1pSGlkZGVuPTNEInRydWUiIERlZlFGb3JtYXQ9M0QiZmFsc2UiIERlZlByaW9yaXR5PTNEIjk5Ig0KICBMYXRlbnRTdHlsZUNvdW50PTNEIjI2NyI+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIk5vcm1hbCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJoZWFkaW5nIDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiPQ0KaGVhZGluZyAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCI9DQpoZWFkaW5nIDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiPQ0KaGVhZGluZyA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjkiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCI9DQpoZWFkaW5nIDciLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIj0NCmhlYWRpbmcgOCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI5IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiPQ0KaGVhZGluZyA5Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA3Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA4Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM5IiBOYW1lPTNEInRvYyA5Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM1IiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0Q9DQoiY2FwdGlvbiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIxMCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiVGl0bGUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMSIgTmFtZT0zRCJEZWZhdWx0IFBhcmFncmFwaD0NCiBGb250Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjExIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJTdWJ0aXRsZSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIyMiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiU3Ryb25nIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjIwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJFbXBoYXNpcyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI1OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIlRhYmxlIEdyaWQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiUGxhY2Vobz0NCmxkZXIgVGV4dCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJObyBTcGFjaW5nIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgU2hhZGluZyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IExpc3QiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBHcmlkIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYzIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjUiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY2IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjgiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkRhcmsgTGlzdCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIFNoYWRpbmciLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBMaXN0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjczIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgR3JpZCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IFNoYWRpbmcgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBMaXN0IEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgR3JpZCBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDEgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAyIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY1IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMSBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJSZXZpc2lvPQ0KbiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzNCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBRRm9ybWF0PTNEInRydWUiIE5hbWU9M0QiTGlzdCBQYXJhZ3JhcGgiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMjkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIlF1b3RlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjMwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJJbnRlbnNlIFF1b3RlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY2IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMiBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDEgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjgiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAyIEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMyBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkRhcmsgTGlzdCBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIFNoYWRpbmcgQWNjZW50IDEiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBMaXN0IEFjY2VudCAxIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjczIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgR3JpZCBBY2NlbnQgMSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IFNoYWRpbmcgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBMaXN0IEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgR3JpZCBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDEgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAyIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY1IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMSBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDIgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjciIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAxIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY4IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMiBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDMgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJEYXJrIExpc3QgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBTaGFkaW5nIEFjY2VudCAyIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgTGlzdCBBY2NlbnQgMiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIEdyaWQgQWNjZW50IDIiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBTaGFkaW5nIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgTGlzdCBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IEdyaWQgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAxIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY0IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMiBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDEgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjYiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAyIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY3IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMSBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDIgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAzIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiRGFyayBMaXN0IEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgU2hhZGluZyBBY2NlbnQgMyIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIExpc3QgQWNjZW50IDMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBHcmlkIEFjY2VudCAzIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgU2hhZGluZyBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IExpc3QgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBHcmlkIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYzIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMSBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDIgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjUiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAxIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY2IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMiBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDEgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjgiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAyIEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMyBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkRhcmsgTGlzdCBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIFNoYWRpbmcgQWNjZW50IDQiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBMaXN0IEFjY2VudCA0Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjczIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgR3JpZCBBY2NlbnQgNCIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IFNoYWRpbmcgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBMaXN0IEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgR3JpZCBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBTaGFkaW5nIDEgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjQiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAyIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY1IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIExpc3QgMSBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDIgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjciIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAxIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY4IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMiBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDMgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJEYXJrIExpc3QgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBTaGFkaW5nIEFjY2VudCA1Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcyIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgTGlzdCBBY2NlbnQgNSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MyIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIEdyaWQgQWNjZW50IDUiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjAiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJMaWdodCBTaGFkaW5nIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjYxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTGlnaHQgTGlzdCBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkxpZ2h0IEdyaWQgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gU2hhZGluZyAxIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY0IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIFNoYWRpbmcgMiBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2NSIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBMaXN0IDEgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjYiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gTGlzdCAyIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjY3IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiTWVkaXVtIEdyaWQgMSBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI2OCIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIk1lZGl1bSBHcmlkIDIgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNjkiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJNZWRpdW0gR3JpZCAzIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcwIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiRGFyayBMaXN0IEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjcxIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIE5hbWU9M0QiQ29sb3JmdWwgU2hhZGluZyBBY2NlbnQgNiIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCI3MiIgU2VtaUhpZGRlbj0zRCJmYWxzZSINCiAgIFVuaGlkZVdoZW5Vc2VkPTNEImZhbHNlIiBOYW1lPTNEIkNvbG9yZnVsIExpc3QgQWNjZW50IDYiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiNzMiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgTmFtZT0zRCJDb2xvcmZ1bCBHcmlkIEFjY2VudCA2Ii8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjE5IiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJTdWJ0bGUgRW1waGFzaXMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMjEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIkludGVuc2UgRW1waGFzaXMiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMzEiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIlN1YnRsZSBSZWZlcmVuY2UiLz4NCiAgPHc6THNkRXhjZXB0aW9uIExvY2tlZD0zRCJmYWxzZSIgUHJpb3JpdHk9M0QiMzIiIFNlbWlIaWRkZW49M0QiZmFsc2UiDQogICBVbmhpZGVXaGVuVXNlZD0zRCJmYWxzZSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEIkludGVuc2UgUmVmZXJlbmNlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjMzIiBTZW1pSGlkZGVuPTNEImZhbHNlIg0KICAgVW5oaWRlV2hlblVzZWQ9M0QiZmFsc2UiIFFGb3JtYXQ9M0QidHJ1ZSIgTmFtZT0zRCJCb29rIFRpdGxlIi8+DQogIDx3OkxzZEV4Y2VwdGlvbiBMb2NrZWQ9M0QiZmFsc2UiIFByaW9yaXR5PTNEIjM3IiBOYW1lPTNEIkJpYmxpb2dyYXBoeSIvPg0KICA8dzpMc2RFeGNlcHRpb24gTG9ja2VkPTNEImZhbHNlIiBQcmlvcml0eT0zRCIzOSIgUUZvcm1hdD0zRCJ0cnVlIiBOYW1lPTNEPQ0KIlRPQyBIZWFkaW5nIi8+DQogPC93OkxhdGVudFN0eWxlcz4NCjwveG1sPjwhW2VuZGlmXS0tPg0KPHN0eWxlPjwhLS0NCg0KLyogRWZmZWN0aXZlIHN0eWxlc2hlZXQgcHJvZHVjZWQgYnkgc25hcHNob3Qgc2F2ZSAqLw0KDQpAZm9udC1mYWNlIHsNCiAgZm9udC1mYW1pbHk6ICJNUyBHb3RoaWMiOw0KfQ0KDQpAZm9udC1mYWNlIHsNCiAgZm9udC1mYW1pbHk6ICJSYWF2aSI7DQp9DQoNCkBmb250LWZhY2Ugew0KICBmb250LWZhbWlseTogIlJhYXZpIjsNCn0NCg0KQGZvbnQtZmFjZSB7DQogIGZvbnQtZmFtaWx5OiAiQ2FsaWJyaSI7DQp9DQoNCkBmb250LWZhY2Ugew0KICBmb250LWZhbWlseTogIk1TIFVJIEdvdGhpYyI7DQp9DQoNCkBmb250LWZhY2Ugew0KICBmb250LWZhbWlseTogIkBNUyBHb3RoaWMiOw0KfQ0KDQpAZm9udC1mYWNlIHsNCiAgZm9udC1mYW1pbHk6ICJATVMgVUkgR290aGljIjsNCn0NCg0KcCB7IG1hcmdpbi1yaWdodDogMGluOyBtYXJnaW4tbGVmdDogMGluOyBmb250LXNpemU6IDEycHQ7IGZvbnQtZmFtaWx5OiAiVGltPQ0KZXMgTmV3IFJvbWFuIiwic2VyaWYiOyB9DQoNCnNwYW4uU3BlbGxFIHsgIH0NCg0Kc3Bhbi5HcmFtRSB7ICB9DQoNCmRpdi5Xb3JkU2VjdGlvbjEgeyAgfQ0KDQotLT48L3N0eWxlPg0KPCEtLVtpZiBndGUgbXNvIDEwXT4NCjxzdHlsZT4NCiAvKiBTdHlsZSBEZWZpbml0aW9ucyAqLw0KIHRhYmxlLk1zb05vcm1hbFRhYmxlDQoJe21zby1zdHlsZS1uYW1lOiJUYWJsZSBOb3JtYWwiOw0KCW1zby10c3R5bGUtcm93YmFuZC1zaXplOjA7DQoJbXNvLXRzdHlsZS1jb2xiYW5kLXNpemU6MDsNCgltc28tc3R5bGUtbm9zaG93OnllczsNCgltc28tc3R5bGUtcHJpb3JpdHk6OTk7DQoJbXNvLXN0eWxlLXBhcmVudDoiIjsNCgltc28tcGFkZGluZy1hbHQ6MGluIDUuNHB0IDBpbiA1LjRwdDsNCgltc28tcGFyYS1tYXJnaW46MGluOw0KCW1zby1wYXJhLW1hcmdpbi1ib3R0b206LjAwMDFwdDsNCgltc28tcGFnaW5hdGlvbjp3aWRvdy1vcnBoYW47DQoJZm9udC1zaXplOjEwLjBwdDsNCglmb250LWZhbWlseToiVGltZXMgTmV3IFJvbWFuIiwic2VyaWYiO30NCjwvc3R5bGU+DQo8IVtlbmRpZl0tLT48IS0tW2lmIGd0ZSBtc28gOV0+PHhtbD4NCj0yMA0KPC94bWw+PCFbZW5kaWZdLS0+PCEtLVtpZiBndGUgbXNvIDldPjx4bWw+DQo9MjANCiA9MjANCiA8L3htbD48IVtlbmRpZl0tLT4NCjwvaGVhZD4NCg0KPGJvZHkgc3R5bGU9M0QidGFiLWludGVydmFsOi41aW4iIGxhbmc9M0QiRU4tVVMiPg0KDQo8ZGl2IGNsYXNzPTNEIldvcmRTZWN0aW9uMSI+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MT0NCjcuMHB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5RdWljay1TdGFydDogUmVnZXg9DQogQ2hlYXQgU2hlZXQ8L3NwYW4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxNy4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2E9DQpsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2IHN0eWxlPTNEIm1hcmdpbi1sZWZ0OjUuNHB0O21hcmdpbi10b3A6Mi43NXB0Ij4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMC4wPQ0KcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDs7Y29sb3I6Z3JheSI+TW9uZGF5LD0NCiBOb3ZlbWJlciAwNywgMjAxNjwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTAuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7O2NvbG9yOmdyYXkiPjY6NTIgQU08PQ0KL3NwYW4+PC9wPg0KDQo8L2Rpdj4NCg0KPGRpdiBzdHlsZT0zRCJtYXJnaW4tdG9wOjQuNHB0Ij4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wPQ0KcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MT0NCjguMHB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5DaGFyYWN0ZXJzPC9zcGFuPjwvPQ0KYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTguMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2FuPQ0Kcy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCg0KPGRpdj4NCg0KPHRhYmxlIGNsYXNzPTNEIk1zb05vcm1hbFRhYmxlIiBzdHlsZT0zRCJib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Ym9yZGVyOm5vPQ0KbmU7bXNvLWJvcmRlci1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiBtc28teWZ0aS10Ymxsb29rOjExODQ7bXNvLXBhZGRpbmctYWx0OjBpbiAwaW4gMGluIDBpbiIgY2VsbHBhZGRpbmc9M0QiMCI9DQogY2VsbHNwYWNpbmc9M0QiMCIgYm9yZGVyPTNEIjEiPg0KIDx0Ym9keT48dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzowO21zby15ZnRpLWZpcnN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2hhcmFjdGVyPC9zcGFuPjw9DQovYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2E9DQpucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA0LjJwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMzkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5FeGFtcGxlPC9zcGFuPjwvYj0NCj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5TYW1wbGUgTWF0Y2g8L3NwYT0NCm4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdD0NCjtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxkPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Nb3N0IGVuZ2luZXM6IG9uZT0NCiBkaWdpdDwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmZyb20gMCB0byA5PC9zcGFuPQ0KPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmZpbGVfXGRcZDwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+ZmlsZV8yNTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoyIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XGQ8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMyLjk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPi5ORVQsIFB5dGhvbiAzOj0NCiBvbmUgVW5pY29kZSBkaWdpdCBpbiBhbnkNCiAgc2NyaXB0PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmZpbGVfXGRcZDwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+ZmlsZV85PC9zcGFuPjxzcGE9DQpuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7UmFhdmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiY9DQpxdW90Ozttc28tYmlkaS1sYW5ndWFnZToNCiAgUEEiIGxhbmc9M0QiUEEiPiYjMjY2NTs8L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdCI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cdzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MzIuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TW9zdCBlbmdpbmVzOiAid289DQpyZCBjaGFyYWN0ZXIiOg0KICBBU0NJSSBsZXR0ZXIsIGRpZ2l0IG9yIHVuZGVyc2NvcmU8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHctXHdcd1x3PC9zcGFuPjw9DQovcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUwLjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BLWJfMTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHc8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMyLjk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPi5QeXRob24gMzogIndvcmQ9DQogY2hhcmFjdGVyIjoNCiAgVW5pY29kZSBsZXR0ZXIsIGlkZW9ncmFtLCBkaWdpdCwgb3IgdW5kZXJzY29yZTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDQuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMzkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cdy1cd1x3XHc8L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtNUyBHb3RoaWMmcXVvdDsiPiYjMjMzODM7PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6PQ0KZToxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+LTwvc3Bhbj48c3BhbiBzdHk9DQpsZT0zRCJmb250LXNpemU6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtNUyBHb3RoaWMmcXVvdDsiPiYjMTI0MTQ7PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6PQ0KZToxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Xzwvc3Bhbj48c3BhbiBkaXI9DQo9M0QiUlRMIj48L3NwYW4+PHNwYW4gZGlyPTNEIlJUTCIgc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXU9DQpvdDtBcmlhbCZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ow0KICBtc28tYmlkaS1sYW5ndWFnZTpGQSIgbGFuZz0zRCJGQSI+PHNwYW4gZGlyPTNEIlJUTCI+PC9zcGFuPiYjMTc3OTs8L3NwYW4+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdCI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjUiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cdzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MzIuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Lk5FVDogIndvcmQgY2hhcmE9DQpjdGVyIjogVW5pY29kZQ0KICBsZXR0ZXIsIGlkZW9ncmFtLCBkaWdpdCwgb3IgY29ubmVjdG9yPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlx3LVx3XHdcdzwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O01TIEdvdGhpYyZxdW90OyI+JiMyMzM4Mzs8L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXo9DQplOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4tPC9zcGFuPjxzcGFuIHN0eT0NCmxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O01TIEdvdGhpYyZxdW90OyI+JiMxMjQxNDsmIzgyNTU7PC9zcGFuPjxzcGFuIGRpcj0zRCJSVEw9DQoiPjwvc3Bhbj48c3BhbiBkaXI9M0QiUlRMIiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0FyaWE9DQpsJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDs7DQogIG1zby1iaWRpLWxhbmd1YWdlOkZBIiBsYW5nPTNEIkZBIj48c3BhbiBkaXI9M0QiUlRMIj48L3NwYW4+JiMxNzc5Ozwvc3Bhbj49DQo8c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NiI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxzPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Nb3N0IGVuZ2luZXM6ICJ3aD0NCml0ZXNwYWNlDQogIGNoYXJhY3RlciI6IHNwYWNlLCB0YWIsIG5ld2xpbmUsIGNhcnJpYWdlIHJldHVybiwgdmVydGljYWwgdGFiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmFcPHNwYW4gY2xhc3M9M0QiPQ0KU3BlbGxFIj5zYjwvc3Bhbj5cPHNwYW4gY2xhc3M9M0QiU3BlbGxFIj5zYzwvc3Bhbj48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmEgYjwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxzPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uTkVULCBQeXRob24gMyw9DQogSmF2YVNjcmlwdDoNCiAgIndoaXRlc3BhY2UgY2hhcmFjdGVyIjogYW55IFVuaWNvZGUgc2VwYXJhdG9yPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmFcPHNwYW4gY2xhc3M9M0QiPQ0KU3BlbGxFIj5zYjwvc3Bhbj5cPHNwYW4gY2xhc3M9M0QiU3BlbGxFIj5zYzwvc3Bhbj48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmEgYjwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6OCI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxEPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgY2hhcmFjdGVyIHRoYT0NCnQgaXMgbm90IGEgPGk+ZGlnaXQ8L2k+DQogIGFzIGRlZmluZWQgYnkgeW91ciBlbmdpbmUncyA8aT5cZDwvaT48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XERcRFxEPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUwLjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BQkM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6OSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxXPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgY2hhcmFjdGVyIHRoYT0NCnQgaXMgbm90IGEgPGk+d29yZA0KICBjaGFyYWN0ZXI8L2k+IGFzIGRlZmluZWQgYnkgeW91ciBlbmdpbmUncyA8aT5cdzwvaT48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XFdcV1xXXFdcVzwvc3Bhbj49DQo8L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Ki0rPTNEKTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxMDttc28teWZ0aS1sYXN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxTPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMi45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgY2hhcmFjdGVyIHRoYT0NCnQgaXMgbm90IGEgPGk+d2hpdGVzcGFjZQ0KICBjaGFyYWN0ZXI8L2k+IGFzIGRlZmluZWQgYnkgeW91ciBlbmdpbmUncyA8aT5cczwvaT48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XFNcU1xTXFM8L3NwYW4+PC89DQpwPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPllveW88L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQo8L3Rib2R5PjwvdGFibGU+DQoNCjwvZGl2Pg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjA9DQpwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxPQ0KOC4wcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlF1YW50aWZpZXJzPC9zcGFuPjw9DQovYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTguMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2E9DQpucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCg0KPGRpdj4NCg0KPHRhYmxlIGNsYXNzPTNEIk1zb05vcm1hbFRhYmxlIiBzdHlsZT0zRCJib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Ym9yZGVyOm5vPQ0KbmU7bXNvLWJvcmRlci1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiBtc28teWZ0aS10Ymxsb29rOjExODQ7bXNvLXBhZGRpbmctYWx0OjBpbiAwaW4gMGluIDBpbiIgY2VsbHBhZGRpbmc9M0QiMCI9DQogY2VsbHNwYWNpbmc9M0QiMCIgYm9yZGVyPTNEIjEiPg0KIDx0Ym9keT48dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzowO21zby15ZnRpLWZpcnN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1My4yNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjcxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UXVhbnRpZmllcjwvc3Bhbj49DQo8L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3M9DQphbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MjkuNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1Ljc1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6ODUuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMTQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5TYW1wbGUgTWF0Y2g8L3NwYT0NCm4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdD0NCjtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1My4yNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPis8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDI5LjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+T25lIG9yIG1vcmU8L3NwYW49DQo+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1Ljc1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE0MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlZlcnNpb24gXHctXHcrPC9zPQ0KcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjg1LjI1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjExNCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlZlcnNpb24gQS1iMV8xPC9zPQ0KcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjIiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTMuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij57M308L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDI5LjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhY3RseSB0aHJlZSB0aW09DQplczwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDUuNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XER7M308L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6ODUuMjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTE0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QUJDPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTMuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij57Miw0fTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MjkuNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Ud28gdG8gZm91ciB0aW1lcz0NCjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDUuNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XGR7Miw0fTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo4NS4yNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMTQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4xNTY8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NCI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1My4yNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnszLH08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDI5LjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+VGhyZWUgb3IgbW9yZSB0aW09DQplczwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDUuNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHd7Myx9PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjg1LjI1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjExNCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJTcGVsbEUiPjxzcGE9DQpuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmk9DQpmJnF1b3Q7Ij5yZWdleF90dXRvcmlhbDwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWY9DQphbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo1Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUzLjI1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjcxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Kjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MjkuNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5aZXJvIG9yIG1vcmUgdGltZT0NCnM8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1Ljc1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE0MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkEqQipDKjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo4NS4yNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMTQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BQUFDQzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo2O21zby15ZnRpLWxhc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUzLjI1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjcxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Pzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MjkuNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmNlIG9yIG5vbmU8L3NwYT0NCm4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1Ljc1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE0MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJHcmFtRSI+PHNwYW49DQogc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWY9DQomcXVvdDsiPnBsdXJhbHM8L3NwYW4+PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnE9DQp1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4/PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjg1LjI1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjExNCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnBsdXJhbDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCg0KPC9kaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE9DQo4LjBwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TW9yZSBDaGFyYWN0ZXJzPC9zcD0NCmFuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTguMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1bz0NCnQ7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCg0KPGRpdj4NCg0KPHRhYmxlIGNsYXNzPTNEIk1zb05vcm1hbFRhYmxlIiBzdHlsZT0zRCJib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Ym9yZGVyOm5vPQ0KbmU7bXNvLWJvcmRlci1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiBtc28teWZ0aS10Ymxsb29rOjExODQ7bXNvLXBhZGRpbmctYWx0OjBpbiAwaW4gMGluIDBpbiIgY2VsbHBhZGRpbmc9M0QiMCI9DQogY2VsbHNwYWNpbmc9M0QiMCIgYm9yZGVyPTNEIjEiPg0KIDx0Ym9keT48dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzowO21zby15ZnRpLWZpcnN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2hhcmFjdGVyPC9zcGFuPjw9DQovYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2E9DQpucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMS41NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1LjA1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTQuNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+U2FtcGxlIE1hdGNoPC9zcGE9DQpuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q9DQo7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjEiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uPC9zcGFuPjwvYj48c3Bhbj0NCiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MzEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QW55IGNoYXJhY3RlciBleGM9DQplcHQgbGluZSBicmVhazwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDUuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmEuYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdD0NCjtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NC40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmFiYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdD0NCjtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoyIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Ljwvc3Bhbj48L2I+PHNwYW49DQogc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMxLjU1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkFueSBjaGFyYWN0ZXIgZXhjPQ0KZXB0IGxpbmUgYnJlYWs8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTA1LjA1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE0MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPi4qPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU0LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gY2xhc3M9M0QiR3JhbUUiPjxzcGFuPQ0KIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmPQ0KJnF1b3Q7Ij53aGF0ZXZlcjwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomPQ0KcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiwgbWFuLjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzozIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XDxiPi48L2I+PC9zcGFuPjw9DQovcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMS41NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BIHBlcmlvZCAoc3BlY2lhbD0NCiBjaGFyYWN0ZXI6IG5lZWRzIHRvIGJlDQogIGVzY2FwZWQgYnkgYSBcKTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDUuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+YVwuYzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NC40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmEuYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdD0NCjtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MzEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXNjYXBlcyBhIHNwZWNpYWw9DQogY2hhcmFjdGVyPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNS4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cLlwqXCtcPz1BMD1BMD1BMD0NCj1BMFwkXF5cL1xcPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU0LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uKis/PUEwPUEwPUEwPUEwJD0NCl4vXDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo1O21zby15ZnRpLWxhc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MzEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXNjYXBlcyBhIHNwZWNpYWw9DQogY2hhcmFjdGVyPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwNS4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cW1x7XChcKVx9XF08L3NwYT0NCm4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTQuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlt7KCl9XTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCg0KPC9kaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MT0NCjguMHB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48YnI+DQpMb2dpYzwvc3Bhbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE4LjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnE9DQp1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQoNCjxkaXY+DQoNCjx0YWJsZSBjbGFzcz0zRCJNc29Ob3JtYWxUYWJsZSIgc3R5bGU9M0QiYm9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO2JvcmRlcjpubz0NCm5lO21zby1ib3JkZXItYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogbXNvLXlmdGktdGJsbG9vazoxMTg0O21zby1wYWRkaW5nLWFsdDowaW4gMGluIDBpbiAwaW4iIGNlbGxwYWRkaW5nPTNEIjAiPQ0KIGNlbGxzcGFjaW5nPTNEIjAiIGJvcmRlcj0zRCIxIj4NCiA8dGJvZHk+PHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MDttc28teWZ0aS1maXJzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTguNTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxvZ2ljPC9zcGFuPjwvYj48PQ0Kc3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozODguOTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1MTkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5MZWdlbmQ8L3NwYW4+PC9iPj0NCjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwMy45NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEzOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkV4YW1wbGU8L3NwYW4+PC9iPQ0KPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY5LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI5MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU4LjU1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc4Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+fDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozODguOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTE5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QWx0ZXJuYXRpb24gLyBPUj0NCiBvcGVyYW5kPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwMy45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMzkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4yMnwzMzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2OS40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjkzIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+MzM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MiI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC41NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiggPTg1ICk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Mzg4Ljk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjUxOSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkNhcHR1cmluZyBncm91cDwvPQ0Kc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDMuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QSg8c3BhbiBjbGFzcz0zRCI9DQpTcGVsbEUiPm50fHBwbGU8L3NwYW4+KTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2OS40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjkzIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QXBwbGUgKGNhcHR1cmVzPQ0KICI8c3BhbiBjbGFzcz0zRCJTcGVsbEUiPnBwbGU8L3NwYW4+Iik8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC41NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlwxPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjM4OC45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1MTkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Db250ZW50cyBvZiBHcm91cD0NCiAxPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEwMy45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMzkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5yKFx3KWdcMXg8L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjkuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI5MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnJlZ2V4PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjQiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTguNTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzgiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cMjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozODguOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTE5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q29udGVudHMgb2YgR3JvdXA9DQogMjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDMuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KFxkXGQpXCsoXGRcZCk9M0Q9DQpcMlwrXDE8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjkuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI5MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjEyKzY1PTNENjUrMTI8L3NwPQ0KYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NTttc28teWZ0aS1sYXN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC41NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/OiA9ODUgKTwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozODguOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTE5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Tm9uLWNhcHR1cmluZyBncm89DQp1cDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMDMuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTM5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QSg/OjxzcGFuIGNsYXNzPQ0KPTNEIlNwZWxsRSI+bnR8cHBsZTwvc3Bhbj4pPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiOTMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BcHBsZTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCg0KPC9kaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE9DQo4LjBwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TW9yZSBXaGl0ZS1TcGFjZTwvcz0NCnBhbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE4LjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdT0NCm90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQoNCjxkaXY+DQoNCjx0YWJsZSBjbGFzcz0zRCJNc29Ob3JtYWxUYWJsZSIgc3R5bGU9M0QiYm9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO2JvcmRlcjpubz0NCm5lO21zby1ib3JkZXItYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogbXNvLXlmdGktdGJsbG9vazoxMTg0O21zby1wYWRkaW5nLWFsdDowaW4gMGluIDBpbiAwaW4iIGNlbGxwYWRkaW5nPTNEIjAiPQ0KIGNlbGxzcGFjaW5nPTNEIjAiIGJvcmRlcj0zRCIxIj4NCiA8dGJvZHk+PHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MDttc28teWZ0aS1maXJzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkNoYXJhY3Rlcjwvc3Bhbj48PQ0KL2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhPQ0KbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0ODIuN3B0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY0NCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDkuNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHQ8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDgyLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQ0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+VGFiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5UXHRcd3syfTwvc3Bhbj48Lz0NCnA+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OC43NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlQ9QTA9QTA9QTA9QTA9QTBhPQ0KYjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoyIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHI8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDgyLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQ0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2FycmlhZ2UgcmV0dXJuPQ0KIGNoYXJhY3Rlcjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+c2VlIGJlbG93PC9zcGFuPjw9DQovcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ4Ljc1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cbjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0ODIuN3B0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NDQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5MaW5lIGZlZWQgY2hhcmFjdD0NCmVyPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5zZWUgYmVsb3c8L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NCI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxyXG48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDgyLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQ0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TGluZSBzZXBhcmF0b3Igb249DQogV2luZG93czwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QUJcclw8c3BhbiBjbGFzcz0NCj0zRCJTcGVsbEUiPm5DRDwvc3Bhbj48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BQjwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkNEPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjUiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cTjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0ODIuN3B0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NDQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5QZXJsLCBQQ1JFIChDLCBQSD0NClAsIFI9ODUpOiBvbmUNCiAgY2hhcmFjdGVyIHRoYXQgaXMgbm90IGEgbGluZSBmZWVkPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cTis8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BQkM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NiI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlx2PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ4Mi43cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY0NCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPi5ORVQsIEphdmFTY3JpcHQsPQ0KIFB5dGhvbiwgUnVieTogdmVydGljYWwNCiAgdGFiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDouN2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlx2PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ4Mi43cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY0NCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlBlcmwsIFBDUkUgKEMsIFBIPQ0KUCwgUj04NSksIEphdmE6IG9uZQ0KICB2ZXJ0aWNhbCB3aGl0ZXNwYWNlIGNoYXJhY3RlcjogbGluZSBmZWVkLCBjYXJyaWFnZSByZXR1cm4sIHZlcnRpY2FsIHRhYiw9DQogZm9ybQ0KICBmZWVkLCBwYXJhZ3JhcGggb3IgbGluZSBzZXBhcmF0b3I8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDkuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OC43NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo4Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XFY8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDgyLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQ0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UGVybCwgUENSRSAoQywgUEg9DQpQLCBSPTg1KSwgSmF2YTogYW55DQogIGNoYXJhY3RlciB0aGF0IGlzIG5vdCBhIHZlcnRpY2FsIHdoaXRlc3BhY2U8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDkuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OC43NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo5O21zby15ZnRpLWxhc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XFI8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDgyLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQ0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UGVybCwgUENSRSAoQywgUEg9DQpQLCBSPTg1KSwgSmF2YTogb25lDQogIGxpbmUgYnJlYWsgKGNhcnJpYWdlIHJldHVybiArIGxpbmUgZmVlZCBwYWlyLCBhbmQgYWxsIHRoZSBjaGFyYWN0ZXJzIG1hdGM9DQpoZWQNCiAgYnkgXHYpPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDguNzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQo8L3Rib2R5PjwvdGFibGU+DQoNCjwvZGl2Pg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjA9DQpwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxPQ0KOC4wcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk1vcmUgUXVhbnRpZmllcnM8L3M9DQpwYW4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXU9DQpvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUzLjI1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5RdWFudGlmaWVyPC9zcGFuPj0NCjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7cz0NCmFucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ3Ny4wNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjYzNiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjEuMHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjgxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+U2FtcGxlIE1hdGNoPC9zcGE9DQpuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q9DQo7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjEiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTMuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4rPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ3Ny4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2MzYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5UaGUgKyAob25lIG9yIG1vcj0NCmUpIGlzICJncmVlZHkiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjYxLjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cZCs8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjEyMzQ1PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjIiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTMuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4/PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ3Ny4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2MzYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5NYWtlcyBxdWFudGlmaWVycz0NCiAibGF6eSI8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjEuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxkKz88L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjEgaW4gPGI+MTwvYj4yMzQ1PQ0KPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTMuMjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4qPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ3Ny4wNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2MzYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5UaGUgKiAoemVybyBvciBtbz0NCnJlKSBpcw0KICAiZ3JlZWR5Ijwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2MS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjgxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QSo8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkFBQTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUzLjI1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjcxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Pzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0NzcuMDVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjM2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TWFrZXMgcXVhbnRpZmllcnM9DQogImxhenkiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjYxLjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BKj88L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTAuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmVtcHR5IGluIEFBQTwvc3BhPQ0Kbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo1Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUzLjI1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjcxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+ezIsNH08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDc3LjA1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjYzNiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlR3byB0byBmb3VyIHRpbWVzPQ0KLCAiZ3JlZWR5Ijwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2MS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjgxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHd7Miw0fTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmFiY2Q8L3NwYW4+PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1bz0NCnQ7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6Njttc28teWZ0aS1sYXN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1My4yNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj88L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDc3LjA1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjYzNiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk1ha2VzIHF1YW50aWZpZXJzPQ0KICJsYXp5Ijwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2MS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjgxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XHd7MjxzcGFuIGNsYXNzPQ0KPTNEIkdyYW1FIj4sNDwvc3Bhbj59Pzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+YWIgaW4gPHNwYW4gY2xhc3M9DQo9M0QiU3BlbGxFIj48Yj5hYjwvYj5jZDwvc3Bhbj48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQo8L3Rib2R5PjwvdGFibGU+DQoNCjwvZGl2Pg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE4LjA9DQpwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxPQ0KOC4wcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkNoYXJhY3RlciBDbGFzc2VzPC89DQpzcGFuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTguMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnE9DQp1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCg0KPGRpdj4NCg0KPHRhYmxlIGNsYXNzPTNEIk1zb05vcm1hbFRhYmxlIiBzdHlsZT0zRCJib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Ym9yZGVyOm5vPQ0KbmU7bXNvLWJvcmRlci1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiBtc28teWZ0aS10Ymxsb29rOjExODQ7bXNvLXBhZGRpbmctYWx0OjBpbiAwaW4gMGluIDBpbiIgY2VsbHBhZGRpbmc9M0QiMCI9DQogY2VsbHNwYWNpbmc9M0QiMCIgYm9yZGVyPTNEIjEiPg0KIDx0Ym9keT48dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzowO21zby15ZnRpLWZpcnN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1Ni4xNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2hhcmFjdGVyPC9zcGFuPjw9DQovYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2E9DQpucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjI1NS4xcHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMzQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TGVnZW5kPC9zcGFuPjwvYj49DQo8c3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NC45NXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5TYW1wbGUgTWF0Y2g8L3NwYT0NCm4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdD0NCjtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1Ni4xNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlsgPTg1IF08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjU1LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMzQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+T25lIG9mIHRoZSBjaGFyYWM9DQp0ZXJzIGluIHRoZSBicmFja2V0czwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NC45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPltBRUlPVV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjU3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+T25lIHVwcGVyY2FzZSB2b3c9DQplbDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoyIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU2LjE1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+WyA9ODUgXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyNTUuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIzNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgb2YgdGhlIGNoYXJhYz0NCnRlcnMgaW4gdGhlIGJyYWNrZXRzPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY0Ljk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+VFs8c3BhbiBjbGFzcz0zRCI9DQpTcGVsbEUiPmFvPC9zcGFuPl1wPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjE5Mi45cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48aT48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlRhcDwvc3Bhbj48L2k+PHNwPQ0KYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4gb3IgPGk+VG9wPQ0KPC9pPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzozIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU2LjE1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+LTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyNTUuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIzNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5SYW5nZSBpbmRpY2F0b3I8Lz0NCnNwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjQuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bYS16XTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxOTIuOXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgbG93ZXJjYXNlIGxldD0NCnRlcjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU2LjE1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W3gteV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjU1LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMzQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+T25lIG9mIHRoZSBjaGFyYWM9DQp0ZXJzIGluIHRoZSByYW5nZSBmcm9tIHgNCiAgdG8geTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NC45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPltBLVpdKzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxOTIuOXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5HUkVBVDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo1Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU2LjE1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+WyA9ODUgXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyNTUuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIzNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgb2YgdGhlIGNoYXJhYz0NCnRlcnMgaW4gdGhlIGJyYWNrZXRzPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY0Ljk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W0FCMS01dy16XTwvc3Bhbj49DQo8L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxOTIuOXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgb2YgZWl0aGVyOiBBLD0NCkIsMSwyLDMsNCw1LHcseCx5LHo8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NiI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1Ni4xNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlt4LXldPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjI1NS4xcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjM0MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk9uZSBvZiB0aGUgY2hhcmFjPQ0KdGVycyBpbiB0aGUgcmFuZ2UgZnJvbSB4DQogIHRvIHk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjQuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bJiM4MTk0Oy1+XSs8L3NwYT0NCm4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjU3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2hhcmFjdGVycyBpbiB0aGU9DQogcHJpbnRhYmxlIHNlY3Rpb24gb2YNCiAgdGhlIEFTQ0lJIHRhYmxlLjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo3Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU2LjE1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W154XTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyNTUuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIzNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgY2hhcmFjdGVyIHRoYT0NCnQgaXMgbm90IHg8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjQuOTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bXmEtel17M308L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjU3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QTEhPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjgiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTYuMTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bXngteV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjU1LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMzQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+T25lIG9mIHRoZSBjaGFyYWM9DQp0ZXJzIDxiPm5vdDwvYj4gaW4gdGhlDQogIHJhbmdlIGZyb20geCB0byB5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY0Ljk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W14mIzgxOTQ7LX5dKzwvc3A9DQphbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxOTIuOXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5DaGFyYWN0ZXJzIHRoYXQ9DQogYXJlIDxiPm5vdDwvYj4gaW4gdGhlDQogIHByaW50YWJsZSBzZWN0aW9uIG9mIHRoZSBBU0NJSSB0YWJsZS48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6OSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1Ni4xNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPltcZFxEXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyNTUuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIzNDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PbmUgY2hhcmFjdGVyIHRoYT0NCnQgaXMgYSBkaWdpdCBvciBhDQogIG5vbi1kaWdpdDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NC45NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPltcZFxEXSs8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjU3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QW55IGNoYXJhY3RlcnMsPQ0KIDxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+aW5jPC9zcGFuPi08L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gY2xhc3M9M0QiU3BlbGxFIj48c3BhPQ0KbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpPQ0KZiZxdW90OyI+bHVkaW5nPC9zcGFuPjwvc3Bhbj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxPQ0KdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+IG5ldyBsaW5lcywgd2hpY2gNCiAgdGhlIHJlZ3VsYXIgZG90IGRvZXNuJ3QgbWF0Y2g8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MTA7bXNvLXlmdGktbGFzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTYuMTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bXHg0MV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjU1LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMzQwIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TWF0Y2hlcyB0aGUgY2hhcmE9DQpjdGVyIGF0IGhleGFkZWNpbWFsDQogIHBvc2l0aW9uIDQxIGluIHRoZSBBU0NJSSB0YWJsZSwgaS5lLiBBPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY0Ljk1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1x4NDEtXHg0NV17M308L3M9DQpwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTkyLjlwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjU3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QUJFPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KPC90Ym9keT48L3RhYmxlPg0KDQo8L2Rpdj4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wPQ0KcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MT0NCjguMHB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BbmNob3JzIGFuZCBCb3VuZGFyPQ0KaWVzPC9zcGFuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTguMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvPQ0KdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCg0KPGRpdj4NCg0KPHRhYmxlIGNsYXNzPTNEIk1zb05vcm1hbFRhYmxlIiBzdHlsZT0zRCJib3JkZXItY29sbGFwc2U6Y29sbGFwc2U7Ym9yZGVyOm5vPQ0KbmU7bXNvLWJvcmRlci1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiBtc28teWZ0aS10Ymxsb29rOjExODQ7bXNvLXBhZGRpbmctYWx0OjBpbiAwaW4gMGluIDBpbiIgY2VsbHBhZGRpbmc9M0QiMCI9DQogY2VsbHNwYWNpbmc9M0QiMCIgYm9yZGVyPTNEIjEiPg0KIDx0Ym9keT48dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzowO21zby15ZnRpLWZpcnN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BbmNob3I8L3NwYW4+PC9iPj0NCjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ0My4yNXB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU5MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjUuMzVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkV4YW1wbGU8L3NwYW4+PC9iPQ0KPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU1LjBwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5ePC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ0My4yNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1OTEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHU+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5TdGFydCBvZiBzdHJpbmc8Lz0NCnNwYW4+PC91PjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcT0NCnVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4gb3I8dT4gc3RhcnQgb2YNCiAgbGluZTwvdT4gZGVwZW5kaW5nIG9uIG11bHRpbGluZSBtb2RlLiAoQnV0IHdoZW4gW15pbnNpZGUgYnJhY2tldHNdLCBpdCBtZT0NCmFucw0KICAibm90Iik8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjUuMzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5ePHNwYW4gY2xhc3M9M0QiUz0NCnBlbGxFIj48c3BhbiBjbGFzcz0zRCJHcmFtRSI+YWJjPC9zcGFuPjwvc3Bhbj48c3BhbiBjbGFzcz0zRCJHcmFtRSI+IC48L3NwYT0NCm4+Kjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmFiYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdD0NCjtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiAobGluZSBzdGFydCk8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MiI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+JDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0NDMuMjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTkxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjx1PjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RW5kIG9mIHN0cmluZzwvc3A9DQphbj48L3U+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW89DQp0O3NhbnMtc2VyaWYmcXVvdDsiPiBvciA8dT5lbmQgb2YNCiAgbGluZTwvdT4gZGVwZW5kaW5nIG9uIG11bHRpbGluZSBtb2RlLiBNYW55IGVuZ2luZS1kZXBlbmRlbnQgc3VidGxldGllcy48Lz0NCnNwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjUuMzVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uKj8gdGhlIGVuZCQ8L3NwYT0NCm4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTUuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnRoaXMgaXMgdGhlIGVuZDwvPQ0Kc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzozIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cQTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0NDMuMjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTkxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QmVnaW5uaW5nIG9mIHN0cmk9DQpuZzwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPihhbGwgbWFqb3IgZW5naW5lPQ0KcyBleGNlcHQgSlMpPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY1LjM1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XDxzcGFuIGNsYXNzPTNEIlM9DQpwZWxsRSI+QWFiYzwvc3Bhbj5bXGRcRF0qPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU1LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gY2xhc3M9M0QiU3BlbGxFIj48c3BhPQ0KbiBjbGFzcz0zRCJHcmFtRSI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpPQ0KJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPmFiYzwvc3Bhbj48L3NwYW4+PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtPQ0Kc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4gKHN0cmluPQ0KZy4uLjwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPi4uLnN0YXJ0KTwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cejwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0NDMuMjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTkxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+VmVyeSBlbmQgb2YgdGhlPQ0KIHN0cmluZzwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk5vdCBhdmFpbGFibGUgaW49DQogUHl0aG9uIGFuZCBKUzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NS4zNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnRoZSBlbmRcejwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+dGhpcyBpcy4uLlxuLi4uPGI9DQo+dGhlIGVuZDwvYj48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XFo8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDQzLjI1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU5MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48dT48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkVuZCBvZiBzdHJpbmc8L3NwPQ0KYW4+PC91PjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvPQ0KdDtzYW5zLXNlcmlmJnF1b3Q7Ij4gb3IgKGV4Y2VwdA0KICBQeXRob24pIGJlZm9yZSBmaW5hbCBsaW5lIGJyZWFrPC9zcGFuPjwvcD4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Tm90IGF2YWlsYWJsZSBpbj0NCiBKUzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NS4zNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnRoZSBlbmRcWjwvc3Bhbj48PQ0KL3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+dGhpcyBpcy4uLlxuLi4uPGI9DQo+dGhlIGVuZDwvYj5cbjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo2Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ5LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cRzwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0NDMuMjVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTkxIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QmVnaW5uaW5nIG9mIFN0cmk9DQpuZyBvciBFbmQgb2YgUHJldmlvdXMNCiAgTWF0Y2g8L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uTkVULCBKYXZhLCBQQ1JFPQ0KIChDLCBQSFAsIFI9ODUpLA0KICBQZXJsLCBSdWJ5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY1LjM1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU1LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0OS40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+XGI8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDQzLjI1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU5MSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPldvcmQgYm91bmRhcnk8L3NwPQ0KYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Nb3N0IGVuZ2luZXM6IHBvcz0NCml0aW9uIHdoZXJlIG9uZSBzaWRlDQogIG9ubHkgaXMgYW4gQVNDSUkgbGV0dGVyLCBkaWdpdCBvciB1bmRlcnNjb3JlPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY1LjM1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Qm9iLipcPHNwYW4gY2xhc3M9DQo9M0QiU3BlbGxFIj5iY2F0PC9zcGFuPlxiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU1LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Cb2IgYXRlIHRoZSA8Yj5jYT0NCnQ8L2I+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjgiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDkuNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxiPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ0My4yNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1OTEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Xb3JkIGJvdW5kYXJ5PC9zcD0NCmFuPjwvcD4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Lk5FVCwgSmF2YSwgUHl0aG89DQpuIDMsIFJ1Ynk6IHBvc2l0aW9uDQogIHdoZXJlIG9uZSBzaWRlIG9ubHkgaXMgYSBVbmljb2RlIGxldHRlciwgZGlnaXQgb3IgdW5kZXJzY29yZTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2NS4zNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkJvYi4qXGJcPC9zcGFuPjxzPQ0KcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlPQ0KcmlmJnF1b3Q7O21zby1hbnNpLWxhbmd1YWdlOg0KICBSVSIgbGFuZz0zRCJSVSI+JiMxMDgyOyYjMTA4NjsmIzEwOTY7JiMxMDgyOyYjMTA3Mjs8L3NwYW4+PHNwYW4gc3R5bGU9M0QiPQ0KZm9udC1zaXplOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cYjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1NS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjczIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Qm9iIGF0ZSB0aGUgPC9zcGE9DQpuPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDs9DQpzYW5zLXNlcmlmJnF1b3Q7O21zby1hbnNpLWxhbmd1YWdlOg0KICBSVSIgbGFuZz0zRCJSVSI+JiMxMDgyOyYjMTA4NjsmIzEwOTY7JiMxMDgyOyYjMTA3Mjs8L3NwYW4+PC9iPjxzcGFuIHN0eWxlPQ0KPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93Ojk7bXNvLXlmdGktbGFzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDkuNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlxCPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ0My4yNXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1OTEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Ob3QgYSB3b3JkIGJvdW5kYT0NCnJ5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjY1LjM1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Yy4qXDxzcGFuIGNsYXNzPQ0KPTNEIlNwZWxsRSI+QmNhdDwvc3Bhbj5cQi4qPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU1LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzMiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5jb3B5PGI+Y2F0PC9iPnM8Lz0NCnNwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQo8L3Rib2R5PjwvdGFibGU+DQoNCjwvZGl2Pg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjA9DQpwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxPQ0KOC4wcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlBPU0lYIENsYXNzZXM8L3NwYW49DQo+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDs9DQpzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5DaGFyYWN0ZXI8L3NwYW4+PD0NCi9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYT0NCm5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMzLjFwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NzciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5MZWdlbmQ8L3NwYW4+PC9iPj0NCjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEuM2luO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjEyNSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkV4YW1wbGU8L3NwYW4+PC9iPQ0KPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjExNi4wcHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+U2FtcGxlIE1hdGNoPC9zcGE9DQpuPjwvYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q9DQo7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjEiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bOmFscGhhOl08L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMzLjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UENSRSAoQywgUEhQLCBSPQ0KPTg1KTogQVNDSUkgbGV0dGVycw0KICBBLVogYW5kIGEtejwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxLjNpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTI1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+WzhbOmFscGhhOl1dKzwvc3A9DQphbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMTYuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxNTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5XZWxsRG9uZTg4PC9zcGFuPj0NCjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjIiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bOmFscGhhOl08L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMzLjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UnVieSAyOiBVbmljb2RlPQ0KIGxldHRlciBvciBpZGVvZ3JhbTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxLjNpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTI1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1s6YWxwaGE6XVxkXSs8L3M9DQpwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90Ozttc28tYW5zaS1sYT0NCm5ndWFnZTpSVSIgbGFuZz0zRCJSVSI+JiMxMDgyOyYjMTA4NjsmIzEwOTY7JiMxMDgyOyYjMTA3Mjs8L3NwYW4+PHNwYW4gc3R5bD0NCmU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdD0NCjsiPjk5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bOjxzcGFuIGNsYXNzPTNEIj0NClNwZWxsRSI+YWxudW08L3NwYW4+Ol08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMzLjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UENSRSAoQywgUEhQLCBSPQ0KPTg1KTogQVNDSUkgZGlnaXRzIGFuZA0KICBsZXR0ZXJzIEEtWiBhbmQgYS16PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEuM2luO2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bWzo8c3BhbiBjbGFzcz0zRD0NCiJTcGVsbEUiPmFsbnVtPC9zcGFuPjpdXXsxMH08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QUJDREUxMjM0NTwvc3Bhbj49DQo8L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Wzo8c3BhbiBjbGFzcz0zRCI9DQpTcGVsbEUiPmFsbnVtPC9zcGFuPjpdPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMy4xcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlJ1YnkgMjogVW5pY29kZT0NCiBkaWdpdCwgbGV0dGVyIG9yIGlkZW9ncmFtPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEuM2luO2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxMjUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bWzo8c3BhbiBjbGFzcz0zRD0NCiJTcGVsbEUiPmFsbnVtPC9zcGFuPjpdXXsxMH08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90Ozttc28tYW5zaS1sYT0NCm5ndWFnZTpSVSIgbGFuZz0zRCJSVSI+JiMxMDgyOyYjMTA4NjsmIzEwOTY7JiMxMDgyOyYjMTA3Mjs8L3NwYW4+PHNwYW4gc3R5bD0NCmU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdD0NCjsiPjkwMjEwPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjUiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Ljdpbjtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjciPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bOjxzcGFuIGNsYXNzPTNEIj0NClNwZWxsRSI+cHVuY3Q8L3NwYW4+Ol08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDMzLjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTc3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UENSRSAoQywgUEhQLCBSPQ0KPTg1KTogQVNDSUkNCiAgcHVuY3R1YXRpb24gbWFyazwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxLjNpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTI1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1s6PHNwYW4gY2xhc3M9M0Q9DQoiU3BlbGxFIj5wdW5jdDwvc3Bhbj46XV0rPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjExNi4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE1NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj8hLiw6Ozwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo2O21zby15ZnRpLWxhc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOi43aW47Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY3Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Wzo8c3BhbiBjbGFzcz0zRCI9DQpTcGVsbEUiPnB1bmN0PC9zcGFuPjpdPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQzMy4xcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU3NyI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlJ1Ynk6IFVuaWNvZGUgcHVuPQ0KY3R1YXRpb24gbWFyazwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxLjNpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTI1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1s6PHNwYW4gY2xhc3M9M0Q9DQoiU3BlbGxFIj5wdW5jdDwvc3Bhbj46XV0rPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjExNi4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE1NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiYjODI1MzssOjwvc3Bhbj48PQ0Kc3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtNUyBVSSBHb3RoaWMmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+JiMxMjM9DQo0OTsmIzgyNjI7PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCg0KPC9kaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE9DQo4LjBwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+SW5saW5lIE1vZGlmaWVyczwvcz0NCnBhbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE4LjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdT0NCm90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Ob25lIG9mIHRoZXNlIGFyZT0NCiBzdXBwb3J0ZWQgaW4gSmF2YVNjcmlwdC4NCkluIFJ1YnksIGJld2FyZSBvZiAoPHNwYW4gY2xhc3M9M0QiR3JhbUUiPj9zPC9zcGFuPikgYW5kICg/bSkuIDwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU4LjRwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk1vZGlmaWVyPC9zcGFuPjwvPQ0KYj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2FuPQ0Kcy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQxNi4wcHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TGVnZW5kPC9zcGFuPjwvYj49DQo8c3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxODkuMHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1MiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkV4YW1wbGU8L3NwYW4+PC9iPQ0KPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUxLjU1cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci1sZWZ0Om5vbmU7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0PQ0KIDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5TYW1wbGUgTWF0Y2g8L3NwYT0NCm4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdD0NCjtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6MSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc4Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD88c3BhbiBjbGFzcz0zRCI9DQpTcGVsbEUiPmk8L3NwYW4+KTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MTYuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5DYXNlLWluc2Vuc2l0aXZlPQ0KIG1vZGU8L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4oZXhjZXB0IEphdmFTY3JpcD0NCnQpPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjE4OS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1MiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/PHNwYW4gY2xhc3M9M0QiPQ0KU3BlbGxFIj5pPC9zcGFuPilNb25kYXk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gY2xhc3M9M0QiU3BlbGxFIj48c3BhPQ0KbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpPQ0KZiZxdW90OyI+bW9uREFZPC9zcGFuPjwvc3Bhbj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxPQ0KdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjIiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTguNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/cyk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RE9UQUxMIG1vZGUgKGV4Y2U9DQpwdCBKUyBhbmQgUnVieSkuIFRoZSBkb3QNCiAgKC4pIG1hdGNoZXMgbmV3IGxpbmUgY2hhcmFjdGVycyAoXHJcbikuIEFsc28ga25vd24gYXMgInNpbmdsZS1saW5lDQogIG1vZGUiIGJlY2F1c2UgdGhlIGRvdCB0cmVhdHMgdGhlIGVudGlyZSBpbnB1dCBhcyBhIHNpbmdsZSBsaW5lPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjE4OS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1MiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/cylGcm9tIEEuKnRvIFo8PQ0KL3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5Gcm9tIEE8L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij50byBaPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTguNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/bSk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TXVsdGlsaW5lIG1vZGU8L3M9DQpwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4oZXhjZXB0IFJ1YnkgYW5kPQ0KIEpTKSBeIGFuZCAkIG1hdGNoIGF0IHRoZQ0KICBiZWdpbm5pbmcgYW5kIGVuZCBvZiBldmVyeSBsaW5lPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjE4OS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1MiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/bSkxXHJcbl4yJFxyXG5ePQ0KMyQ8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4xPC9zcGFuPjwvcD4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Mjwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjM8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NCI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc4Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD9tKTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MTYuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5JbiBSdWJ5OiB0aGUgc2FtZT0NCiBhcyAoP3MpIGluIG90aGVyDQogIGVuZ2luZXMsIGkuZS4gRE9UQUxMIG1vZGUsIGkuZS4gZG90IG1hdGNoZXMgbGluZSBicmVha3M8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTg5LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjUyIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD9tKUZyb20gQS4qdG8gWjw9DQovc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1MS41NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkZyb20gQTwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnRvIFo8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6NSI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc4Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD94KTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MTYuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5GcmVlLVNwYWNpbmcgTW9kZT0NCiA8c3BhbiBjbGFzcz0zRCJTcGVsbEUiPm1vZGU8L3NwYW4+PC9zcGFuPjwvcD4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KDxzcGFuIGNsYXNzPTNEIkc9DQpyYW1FIj5leGNlcHQ8L3NwYW4+DQogIEphdmFTY3JpcHQpLiBBbHNvIGtub3duIGFzIGNvbW1lbnQgbW9kZSBvciB3aGl0ZXNwYWNlIG1vZGU8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTg5LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjUyIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD94KSAjIHRoaXMgaXMgYTw9DQovc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiMgY29tbWVudDwvc3Bhbj48PQ0KL3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJTcGVsbEUiPjxzcGE9DQpuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmk9DQpmJnF1b3Q7Ij5hYmM8L3NwYW4+PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q9DQo7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4gIyB3cml0ZSBvbg0KICBtdWx0aXBsZTwvc3Bhbj48L3A+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiMgbGluZXM8L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bIF1kICMgc3BhY2VzIG11cz0NCnQgYmU8L3NwYW4+PC9wPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4jIGluIGJyYWNrZXRzPC9zcD0NCmFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUxLjU1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIGNsYXNzPTNEIlNwZWxsRSI+PHNwYT0NCm4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaT0NCmYmcXVvdDsiPmFiYzwvc3Bhbj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdD0NCjtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPiBkPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjYiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTguNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/bik8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDE2LjBwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTU1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Lk5FVDogbmFtZWQgY2FwdHU9DQpyZSBvbmx5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjE4OS4wcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI1MiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlR1cm5zIGFsbCAocGFyZW50PQ0KaGVzZXMpIGludG8gbm9uLWNhcHR1cmUNCiAgZ3JvdXBzLiBUbyBjYXB0dXJlLCB1c2UgPHU+bmFtZWQgZ3JvdXBzPC91Pi48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTEuNTVwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KICA8L3RkPg0KIDwvdHI+DQogPHRyIHN0eWxlPTNEIm1zby15ZnRpLWlyb3c6Nzttc28teWZ0aS1sYXN0cm93OnllcyI+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo1OC40cHQ7Ym9yZGVyOnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIGJvcmRlci10b3A6bm9uZTttc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdCAzLjA9DQpwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjc4Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD9kKTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MTYuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5KYXZhOiBVbml4IDxzcGFuPQ0KIGNsYXNzPTNEIlNwZWxsRSI+bGluZWJyZWFrczwvc3Bhbj4NCiAgb25seTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxODkuMHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyNTIiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5UaGUgZG90IGFuZCB0aGU9DQogXiBhbmQgJCBhbmNob3JzIGFyZSBvbmx5DQogIGFmZmVjdGVkIGJ5IFxuPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUxLjU1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjY5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PUEwPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KPC90Ym9keT48L3RhYmxlPg0KDQo8L2Rpdj4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wPQ0KcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJTcGVsbEUiPjxiPjxzcD0NCmFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcj0NCmlmJnF1b3Q7Ij5Mb29rYXJvdW5kczwvc3Bhbj48L2I+PC9zcGFuPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udD0NCi1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU5LjZwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJTcGVsbEUiPjxiPjw9DQpzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXM9DQplcmlmJnF1b3Q7Ij5Mb29rYXJvdW5kPC9zcGFuPjwvYj48L3NwYW4+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb249DQp0LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo0MDQuNjVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5MZWdlbmQ8L3NwYW4+PC9iPj0NCjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjIuMmluO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjIxMSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkV4YW1wbGU8L3NwYW4+PC9iPQ0KPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToNCiAgMTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjYzLjZwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjU5LjZwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzkiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4oPz0zRD04NSk8L3NwYW4+PD0NCi9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDA0LjY1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU0MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlBvc2l0aXZlIDxzcGFuIGNsPQ0KYXNzPTNEIlNwZWxsRSI+bG9va2FoZWFkPC9zcGFuPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyLjJpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjExIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD89M0RcZHsxMH0pXGR7NX09DQo8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjMuNnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjAxMjM0IGluIDxiPjAxMjM0PQ0KPC9iPjU2Nzg5PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjIiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTkuNnB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/Jmx0Oz0zRD04NSk8L3NwPQ0KYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDA0LjY1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU0MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlBvc2l0aXZlIDxzcGFuIGNsPQ0KYXNzPTNEIlNwZWxsRSI+bG9va2JlaGluZDwvc3Bhbj48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6Mi4yaW47Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjIxMSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/Jmx0Oz0zRFxkKWNhdDwvPQ0Kc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2My42cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Y2F0IGluIDE8Yj5jYXQ8L2I9DQo+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTkuNnB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/IT04NSk8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NDA0LjY1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjU0MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPk5lZ2F0aXZlIDxzcGFuIGNsPQ0KYXNzPTNEIlNwZWxsRSI+bG9va2FoZWFkPC9zcGFuPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyLjJpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjExIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KD8hdGhlYXRyZSl0aGVcdys9DQo8L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjMuNnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI4NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPnRoZW1lPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjQ7bXNvLXlmdGktbGFzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTkuNnB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPig/Jmx0OyE9ODUpPC9zcGFuPQ0KPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQwNC42NXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI1NDAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5OZWdhdGl2ZSA8c3BhbiBjbD0NCmFzcz0zRCJTcGVsbEUiPmxvb2tiZWhpbmQ8L3NwYW4+PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjIuMmluO2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDpub25lOw0KICBib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyMTEiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cd3szfSg/Jmx0OyFtb24pPD0NCnNwYW4gY2xhc3M9M0QiU3BlbGxFIj5zdGVyPC9zcGFuPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDo2My42cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Om5vbmU7DQogIGJvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+TXVuc3Rlcjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCjwvdGJvZHk+PC90YWJsZT4NCg0KPC9kaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMD0NCnB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij49QTA8L3NwYW4+PC9wPg0KDQo8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjE9DQo4LjBwdDsNCmZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+Q2hhcmFjdGVyIENsYXNzIE9wZT0NCnJhdGlvbnM8L3NwYW4+PC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaT0NCiZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUyLjdwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkNsYXNzIE9wZXJhdGlvbjwvPQ0Kc3Bhbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxPQ0KdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjQxNSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTM5LjFwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxODUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PGI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplPQ0KOjExLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5FeGFtcGxlPC9zcGFuPjwvYj0NCj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6DQogIDExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyMTQuMnB0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI4NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUyLjdwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bPTg1LVs9ODVdXTwvc3Bhbj0NCj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI0MTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uTkVUOiBjaGFyYWN0ZXI9DQogY2xhc3Mgc3VidHJhY3Rpb24uIE9uZQ0KICBjaGFyYWN0ZXIgdGhhdCBpcyBpbiB0aG9zZSBvbiB0aGUgbGVmdCwgYnV0IG5vdCBpbiB0aGUgc3VidHJhY3RlZCBjbGFzcy48PQ0KL3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTM5LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W2Etei1bPHNwYW4gY2xhc3M9DQo9M0QiU3BlbGxFIj5hZWlvdTwvc3Bhbj5dXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyMTQuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyODYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BbnkgbG93ZXJjYXNlIGNvbj0NCnNvbmFudDwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoyIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUyLjdwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bPTg1LVs9ODVdXTwvc3Bhbj0NCj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI0MTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij4uTkVUOiBjaGFyYWN0ZXI9DQogY2xhc3Mgc3VidHJhY3Rpb24uPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjEzOS4xcHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjE4NSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPltccHs8c3BhbiBjbGFzcz0NCj0zRCJTcGVsbEUiPklzQXJhYmljPC9zcGFuPn0tW1xEXV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjE0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjg2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QW4gQXJhYmljIGNoYXJhY3Q9DQplciB0aGF0IGlzIG5vdCBhDQogIG5vbi1kaWdpdCwgaS5lLiwgYW4gQXJhYmljIGRpZ2l0PC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTIuN3B0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPls9ODUmYW1wOyZhbXA7Wz0NCj04NV1dPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjMxMS40cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjQxNSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkphdmEsIFJ1YnkgMis6IGNoPQ0KYXJhY3RlciBjbGFzcw0KICBpbnRlcnNlY3Rpb24uIE9uZSBjaGFyYWN0ZXIgdGhhdCBpcyBib3RoIGluIHRob3NlIG9uIHRoZSBsZWZ0IGFuZCBpbiB0aGUNCiAgJmFtcDsmYW1wOyBjbGFzcy48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTM5LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1xTJmFtcDsmYW1wO1tcRF09DQpdPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjIxNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI4NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJHcmFtRSI+PHNwYW49DQogc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWY9DQomcXVvdDsiPkFuPC9zcGFuPjwvc3Bhbj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0M9DQphbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+IG5vbi13aGl0ZXNwYWNlDQogIGNoYXJhY3RlciB0aGF0IGlzIGEgbm9uLWRpZ2l0Ljwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzo0Ij4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUyLjdwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNzAiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bPTg1JmFtcDsmYW1wO1s9DQo9ODVdXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI0MTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5KYXZhLCBSdWJ5IDIrOiBjaD0NCmFyYWN0ZXIgY2xhc3MNCiAgaW50ZXJzZWN0aW9uLjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoxMzkuMXB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIxODUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5bXFMmYW1wOyZhbXA7W1xEXT0NCiZhbXA7JmFtcDtbXmEtPHNwYW4gY2xhc3M9M0QiU3BlbGxFIj56QTwvc3Bhbj4tWl1dPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjIxNC4ycHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjI4NiI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBjbGFzcz0zRCJHcmFtRSI+PHNwYW49DQogc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWY9DQomcXVvdDsiPkFuPC9zcGFuPjwvc3Bhbj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTEuMHB0O2ZvbnQtZmFtaWx5OiZxdW90O0M9DQphbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+IG5vbi13aGl0ZXNwYWNlDQogIGNoYXJhY3RlciB0aGF0IGEgbm9uLWRpZ2l0IGFuZCBub3QgYSBsZXR0ZXIuPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjUiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTIuN3B0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPls9ODUmYW1wOyZhbXA7W149DQo9ODVdXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI0MTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5KYXZhLCBSdWJ5IDIrOiBjaD0NCmFyYWN0ZXIgY2xhc3MNCiAgc3VidHJhY3Rpb24gaXMgb2J0YWluZWQgYnkgaW50ZXJzZWN0aW5nIGEgY2xhc3Mgd2l0aCBhIG5lZ2F0ZWQgY2xhc3M8L3NwYT0NCm4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTM5LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W2EteiZhbXA7JmFtcDtbXjw9DQpzcGFuIGNsYXNzPTNEIlNwZWxsRSI+YWVpb3U8L3NwYW4+XV08L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MjE0LjJwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMjg2Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+QW4gRW5nbGlzaCBsb3dlcmM9DQphc2UgbGV0dGVyIHRoYXQgaXMgbm90IGENCiAgdm93ZWwuPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KIDx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjY7bXNvLXlmdGktbGFzdHJvdzp5ZXMiPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NTIuN3B0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItdG9wOm5vbmU7bXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQgMy4wPQ0KcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI3MCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MTE9DQouMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPls9ODUmYW1wOyZhbXA7W149DQo9ODVdXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDozMTEuNHB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI0MTUiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5KYXZhLCBSdWJ5IDIrOiBjaD0NCmFyYWN0ZXIgY2xhc3MNCiAgc3VidHJhY3Rpb248L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6MTM5LjFwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiMTg1Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+W1xwezxzcGFuIGNsYXNzPQ0KPTNEIlNwZWxsRSI+SW5BcmFiaWM8L3NwYW4+fSZhbXA7JmFtcDtbXlxwe0x9XHB7Tn1dXTwvc3Bhbj48L3A+DQogIDwvdGQ+DQogIDx0ZCBzdHlsZT0zRCJ3aWR0aDoyMTQuMnB0O2JvcmRlci10b3A6bm9uZTtib3JkZXItbGVmdDoNCiAgbm9uZTtib3JkZXItYm90dG9tOnNvbGlkICNBM0EzQTMgMS4wcHQ7Ym9yZGVyLXJpZ2h0OnNvbGlkICNBM0EzQTMgMS4wcHQ7DQogIG1zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMz0NCiAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCIyODYiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5BbiBBcmFiaWMgY2hhcmFjdD0NCmVyIHRoYXQgaXMgbm90IGEgbGV0dGVyDQogIG9yIGEgbnVtYmVyPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KPC90Ym9keT48L3RhYmxlPg0KDQo8L2Rpdj4NCg0KPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMS4wPQ0KcHQ7DQpmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPj1BMDwvc3Bhbj48L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6MT0NCjguMHB0Ow0KZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5PdGhlciBTeW50YXg8L3NwYW4+PQ0KPC9iPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxOC4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzPQ0KYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KDQo8ZGl2Pg0KDQo8dGFibGUgY2xhc3M9M0QiTXNvTm9ybWFsVGFibGUiIHN0eWxlPTNEImJvcmRlci1jb2xsYXBzZTpjb2xsYXBzZTtib3JkZXI6bm89DQpuZTttc28tYm9yZGVyLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KIG1zby15ZnRpLXRibGxvb2s6MTE4NDttc28tcGFkZGluZy1hbHQ6MGluIDBpbiAwaW4gMGluIiBjZWxscGFkZGluZz0zRCIwIj0NCiBjZWxsc3BhY2luZz0zRCIwIiBib3JkZXI9M0QiMSI+DQogPHRib2R5Pjx0ciBzdHlsZT0zRCJtc28teWZ0aS1pcm93OjA7bXNvLXlmdGktZmlyc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ4LjBwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgcGFkZGluZzoxLjk1cHQgMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI2NCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlN5bnRheDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NS4zNWluO2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjUxNCI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPkxlZ2VuZDwvc3Bhbj48L2I+PQ0KPHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NjEuN3B0O2JvcmRlcjpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBib3JkZXItbGVmdDpub25lO21zby1ib3JkZXItbGVmdC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDtwYWRkaW5nOjEuOTVwdD0NCiAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjgyIj4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZT0NCjoxMS4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+RXhhbXBsZTwvc3Bhbj48L2I9DQo+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOg0KICAxMS4wcHQ7Zm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij48L3NwYW4+PC9wPg0KICA8L3RkPg0KICA8dGQgc3R5bGU9M0Qid2lkdGg6NzQuMTVwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLWxlZnQ6bm9uZTttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7cGFkZGluZzoxLjk1cHQ9DQogMy4wcHQgMS45NXB0IDMuMHB0IiB2YWxpZ249M0QidG9wIiB3aWR0aD0zRCI5OSI+DQogIDxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48Yj48c3BhbiBzdHlsZT0zRCJmb250LXNpemU9DQo6MTEuMHB0Ow0KICBmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90O3NhbnMtc2VyaWYmcXVvdDsiPlNhbXBsZSBNYXRjaDwvc3BhPQ0Kbj48L2I+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExLjBwdDtmb250LWZhbWlseTomcXVvdDtDYWxpYnJpJnF1b3Q7LCZxdW90PQ0KO3NhbnMtc2VyaWYmcXVvdDsiPjwvc3Bhbj48L3A+DQogIDwvdGQ+DQogPC90cj4NCiA8dHIgc3R5bGU9M0QibXNvLXlmdGktaXJvdzoxO21zby15ZnRpLWxhc3Ryb3c6eWVzIj4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjQ4LjBwdDtib3JkZXI6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgYm9yZGVyLXRvcDpub25lO21zby1ib3JkZXItdG9wLWFsdDpzb2xpZCAjQTNBM0EzIDEuMHB0O3BhZGRpbmc6MS45NXB0IDMuMD0NCnB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNjQiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cUT04NVxFPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjUuMzVpbjtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6DQogIG5vbmU7Ym9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiNTE0Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+UGVybCwgUENSRSAoQywgUEg9DQpQLCBSPTg1KSwgPHNwYW4gY2xhc3M9M0QiR3JhbUUiPkphdmE8L3NwYW4+OiB0cmVhdCBhbnl0aGluZyBiZXR3ZWVuIHRoZSBkZWw9DQppbWl0ZXJzIGFzIGEgbGl0ZXJhbA0KICBzdHJpbmcuIFVzZWZ1bCB0byBlc2NhcGUgPHNwYW4gY2xhc3M9M0QiU3BlbGxFIj5tZXRhY2hhcmFjdGVyczwvc3Bhbj4uPC9zPQ0KcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjYxLjdwdDtib3JkZXItdG9wOm5vbmU7Ym9yZGVyLWxlZnQ6bm9uZTsNCiAgYm9yZGVyLWJvdHRvbTpzb2xpZCAjQTNBM0EzIDEuMHB0O2JvcmRlci1yaWdodDpzb2xpZCAjQTNBM0EzIDEuMHB0Ow0KICBtc28tYm9yZGVyLXRvcC1hbHQ6c29saWQgI0EzQTNBMyAxLjBwdDttc28tYm9yZGVyLWxlZnQtYWx0OnNvbGlkICNBM0EzQTM9DQogMS4wcHQ7DQogIHBhZGRpbmc6MS45NXB0IDMuMHB0IDEuOTVwdCAzLjBwdCIgdmFsaWduPTNEInRvcCIgd2lkdGg9M0QiODIiPg0KICA8cCBzdHlsZT0zRCJtYXJnaW46MGluO21hcmdpbi1ib3R0b206LjAwMDFwdCI+PHNwYW4gc3R5bGU9M0QiZm9udC1zaXplOjExPQ0KLjBwdDsNCiAgZm9udC1mYW1pbHk6JnF1b3Q7Q2FsaWJyaSZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7Ij5cPHNwYW4gY2xhc3M9M0QiRz0NCnJhbUUiPlEoPC9zcGFuPkMrKyA/KVxFPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiAgPHRkIHN0eWxlPTNEIndpZHRoOjc0LjE1cHQ7Ym9yZGVyLXRvcDpub25lO2JvcmRlci1sZWZ0Og0KICBub25lO2JvcmRlci1ib3R0b206c29saWQgI0EzQTNBMyAxLjBwdDtib3JkZXItcmlnaHQ6c29saWQgI0EzQTNBMyAxLjBwdDsNCiAgbXNvLWJvcmRlci10b3AtYWx0OnNvbGlkICNBM0EzQTMgMS4wcHQ7bXNvLWJvcmRlci1sZWZ0LWFsdDpzb2xpZCAjQTNBM0EzPQ0KIDEuMHB0Ow0KICBwYWRkaW5nOjEuOTVwdCAzLjBwdCAxLjk1cHQgMy4wcHQiIHZhbGlnbj0zRCJ0b3AiIHdpZHRoPTNEIjk5Ij4NCiAgPHAgc3R5bGU9M0QibWFyZ2luOjBpbjttYXJnaW4tYm90dG9tOi4wMDAxcHQiPjxzcGFuIHN0eWxlPTNEImZvbnQtc2l6ZToxMT0NCi4wcHQ7DQogIGZvbnQtZmFtaWx5OiZxdW90O0NhbGlicmkmcXVvdDssJnF1b3Q7c2Fucy1zZXJpZiZxdW90OyI+KEMrPHNwYW4gY2xhc3M9M0Q9DQoiR3JhbUUiPisgPzwvc3Bhbj4pPC9zcGFuPjwvcD4NCiAgPC90ZD4NCiA8L3RyPg0KPC90Ym9keT48L3RhYmxlPg0KDQo8L2Rpdj4NCg0KPC9kaXY+DQoNCjxkaXY+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij49QTA8L3A+DQoNCjxwIHN0eWxlPTNEIm1hcmdpbjowaW47bWFyZ2luLWJvdHRvbTouMDAwMXB0Ij48c3BhbiBzdHlsZT0zRCJmb250LXNpemU6OS4wcD0NCnQ7DQpmb250LWZhbWlseTomcXVvdDtBcmlhbCZxdW90OywmcXVvdDtzYW5zLXNlcmlmJnF1b3Q7O2NvbG9yOiM5Njk2OTYiPkNyZWF0ZWQ9DQogd2l0aCBNaWNyb3NvZnQgT25lTm90ZQ0KMjAxMDxicj4NCjxzcGFuIGNsYXNzPTNEIkdyYW1FIj5PbmU8L3NwYW4+IHBsYWNlIGZvciBhbGwgeW91ciBub3RlcyBhbmQgaW5mb3JtYXRpb248Lz0NCnNwYW4+PC9wPg0KDQo8L2Rpdj4NCg0KPC9kaXY+DQoNCg0KDQoNCjwvYm9keT48L2h0bWw+'
            Email = "^[\w.]+@[\w.]+$"
            SAM = '^[a-zA_Z.]+\\[a-zA_Z.]+$'
            SID = '^S-\d{1}-\d{1}-\d{2}-+'
            GUID = '{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}'
            UNC = '\\\\[a-zA_Z.]+\\[a-zA_Z.]+'
            IP = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
            MAC = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
            Email2 = "^[\w.]+@$($env:userdnsdomain.ToLower())$"
            JVFull = '^j(dk|re)\-[678]u[0-9][0-9]\-windows-(i586|x64)\.exe$'
            JVMSI  = '^j(dk|re)1.[678].0_[0-9][0-9](_x64.msi|.msi)$'
            rsopU  = '(^q[1-9]\:|^q1[01]\:)'
            rsopC  = '(^q1[2-9]\:|^q2[0-9]\:)'
            cdata  = 'CDATA\[.*]]'
            cleanCode  = '((?<=[\=\,\\])(dhs|dmz|hsdn)|22\.[67]|SVR\d{3,4}|WKS\d{3,4}|\d{6}\-|\d{6}\-[SW])'
            }
        $Global:rgxHelp = { Dec64 $rgx.Help | SC ( $fl = 'C:\Temp\tmp.mht'); & "C:\Program Files\Internet Explorer\iexplore.exe" $fl}
        $Global:libHelp = { Dec64 $Repos.Help | SC ( $fl = 'C:\Temp\tmp.mht'); & "C:\Program Files\Internet Explorer\iexplore.exe" $fl}
        Set-Alias Out-ClipBoard $env:SystemRoot\System32\clip.exe -Scope Global
    #endregion 1
    #region 2
        $infDomain | %{
            $_.DName = [string]([adsi]'').distinguishedname; $_.OU1 = "OU=$($env:UserDomain),";
            $_.Dom = $env:UserDomain; $_.fqdnRoot=($env:UserDNSDomain).ToLower();
            }
        $infDomain.SwRoot = "\\$($infDomain.Dom)\root";
        $infPolicy | %{ $_.polRoot = "\\$($infDomain.Dom)\SYSVOL\$($infDomain.fqdnRoot)\Policies" }
        $infScript.local = $true
        $infScript | %{ $_.srcDrv = If ($_.local -eq $true){ "C:\Temp" }  Else { If (!(Test-Path "P:\")){"$($infDomain.swRoot)\users\$Env:UserName" } Else { "P:" } } }
        $infScript.ScriptRoot = "$($infScript.srcDrv)\Scripts" 
        If ($infScript.local -eq $true){ $infScript.prefWrkSpace = "C:\Temp" }
                
        $Global:ScriptRoot = $infScript.ScriptRoot
        $uModz = "$swRoot\tier3\Scripts\CentralShare\PowerShell\Modules"

        $infAD.DCs = (($(& $sbADSI 'ou=domain controllers').Path)|%{($_).Split(',')[0]}).Replace("LDAP://CN=",'')
        $Global:spltDNSDomain = @($($infDomain.fqdnRoot).split("."))
        $infAD | %{
            $_.Sites = (($(& $sbADSI 'CN=Sites,CN=Configuration').Path)|%{($_).Split(',')[0]}).Replace("LDAP://CN=",'')
            }

        $rgxM = [regex]'^fn_(Com|Exch|Fire|For(ens|mWiz)|iLO|Inwork|Java|LanD|Med|Mon|Pat|Print|pwrG|Qu|Rem|Soft|SPS|System|Thin|USMT).*$'
    #endregion 2
    #region 3  -  Initialize Remaining Global Variables
        $Global:DocsRoot = "$($infScript.srcDrv)\My Documents"
        $Global:MyBUDir = "$srcDrv$($infScript.srcDrv)\Scripts\MyBUs"
        $Global:DocBUDir = "$DocsRoot\MyBUs"
        $Global:Systernals = "C:\SysinternalsSuite"
        $ModuleData.prefNet = $envLoc
        $ModuleData.xmlRepos = "$ScriptRoot\Repos.ps1xml"
        $ModuleData.ModuleXML = ([xml](gc $ModuleData.xmlRepos))
        $ModuleData.DataTypes = (($ModuleData.ModuleXML.ChildNodes|gm)|?{$_.MemberType -eq 'Property'}).Name
        $ModuleData.DataTypes | %{ Add-Member -InputObject $ModuleData -Name "xml$_" -Type NoteProperty -Value ($ModuleData.ModuleXML.Repository.$_) }
        $Global:lstModz = $ModuleData.DataTypes;$Global:lstModzCont=$ModuleData.ModuleXML.Repository
            $ModuleData.ModuleList = $lstModzCont.Modules.Module | Select Name,ModuleVersion,Description | Sort Name
            $ModuleData.ModuleScan = ($lstModz | %{Try{ $lstModzCont.$_."$($_.TrimEnd($_[-1]))" | Select -EXP Module}Catch{}}) | Sort -Unique
            $ModuleData.ModuleScan = $ModuleData.ModuleScan | ?{![string]::IsNullOrEmpty($_)}
            $Global:sb_ReloadModz = { IEX "$((gc "$scriptroot\CM.PowerShell_profile.ps1").split([char]10) | ?{$_ -match 'ModuleData' -and $_ -notmatch 'sb_ReloadModz'} | Out-String)" }
            #region  -  Load Code Repository Helper Functions  --------------------------------------------------------------------------------
                $Global:lContent = $lstModzCont; $Global:list =  $lstModz
                $load = $ModuleData.xmlFunctions.Function | ?{$_.Module -eq 'fn_ModuleTools'}
                $load | %{$a=$_; $rcmd = [ScriptBlock]::Create(" Function Global:$([string]$a.Name) {`n$($a.Code.'#cdata-section' | %{ Dec64 $_ })`t}"); & $rcmd  }
                'fn_ModuleTools' | %{ Load-Modules -trgModules $_ -vb -rtnData}
            #endregion  -  Load Code Repository Helper Functions  -----------------------------------------------------------------------------
            #region  -  Load Core Modules  ------------------------------------------------------------------------------------------------------
                'fn_Security','fn_psTools','fn_GPOs' | %{ Load-Modules -trgModules $_ -rtnData}
            #endregion  -  Load Core Modules  ---------------------------------------------------------------------------------------------------
    #endregion 3

    Dec64 ($ModuleData.xmlMimed.Mime | ?{$_.Subj -match 'GPO-2-LPO'} | Select -EXP Code).'#cdata-section' | Out-file 'C:\Temp\GPO-2-LPO.ps1xml'  


    Function ConvertFrom-GPO2LPO {
        [CmdletBinding(DefaultParameterSetName='Name')]
        Param (
            [Parameter(ParameterSetName='Name')] $srcGPName = ('TEST - CMP - Windows 7 Safe Settings'),
            [Parameter(ParameterSetName='GUID')] $srcGPGuid = ('{E5E48185-1186-4F7C-84EF-1B0F5A5A69C1}')

            )
        Begin {
            #region Environment
                Function Dec64($a) { $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
                Function DeMime {
                    # DeMime -srcPath "C:\Users\Charles\Documents\Qsync\Scripts\_GPO2LPO\LGPO-Pack\LocalPol.exe"
                    Param ( [Parameter(Mandatory=$true)][string]$srcPath, [string]$trgPath )
                    Function Resolve-PathSafe($Path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path) }
                    If ([string]::IsNullOrEmpty($trgPath)){ $trgPath = ($srcPath -replace '.Enc.txt')  }
                    'srcPath','trgPath' | %{ IEX "`$$_ = Resolve-PathSafe `$$_" }
                    $bufferSize = 9000 <#Multiplier of 4#>
                    $buffer = New-Object char[] $bufferSize
                    $Reader = [System.IO.File]::OpenText($srcPath)
                    $Writer = [System.IO.File]::OpenWrite($trgPath)
                    $bytesRead = 0
                    Do {
                        $bytesRead = $Reader.Read($buffer,0,$bufferSize)
                        $bytes = [Convert]::FromBase64CharArray($buffer,0,$bytesRead)
                        $Writer.Write($bytes,0,$bytes.Length)
                        } While ($bytesRead -eq $bufferSize)
                    $Reader.Dispose()
                    $Writer.Dispose()
                    } #DeMime Convert-mime "C:\Temp\{E49B0E51-4464-4FCD-A37E-8226032502A3}\LocalSecurityDB.sdb" -encode
                Function ProcessItem($x){ # $x = 'Machine'
                    $rPath = "$dirLPO\DomainSysvol\GPO\$x"
                    If (!(Test-Path -literalPath $rPath)){ New-Item $rPath -Type Container }
                    'Scripts','Microsoft' | %{ $y = $_; Copy-Item "$srcDirGPO\$x\$y" -Recurse -Force -Destination "$rPath" -ea Stop}
                    Copy-Item "$srcDirGPO\$x\Scripts" -Recurse -Force -Destination "$rPath"
                    Copy-Item "$srcDirGPO\$x\Microsoft" -Recurse -Force -Destination "$rPath"
                    $domPol.LoadFile("$srcDirGPO\$x\registry.pol") 
                    $locPol = $domPol
                    $locPol.FileName = "$rPath\Registry.pol"
                    $locPol.SaveFile()
                    } #ProcessItem
                Function Get-Prefs($x){
                    $rPath = "$dirLPO\DomainSysvol\GPO\$x"
                    [System.Collections.ArrayList]$cntScripts = @{}
                    $dirContent = (GCI "$srcDirGPO\$x\Preferences" -Recurse -Force) | ?{$_.PSIsContainer -eq $false}
                    Switch ($x){
                        'Machine' { $drTa = 'Machine'; $drTb = 'Startup' }
                        'User'    { $drTa = 'User'; $drTb = 'Logon' }
                        'Both'    { $drTa = ''; $drTb = '' }
                        default   { Return }
                        } #sw
                    $locPol.LoadFile("$rPath\Registry.pol") 
                    #region Groups Prefs
                        If ((gv).name -contains 'psGpCmd'){ clv psGpCmd }
                        $psGpCmd = (Dec64 'JGNuID0gW2Fkc2ldIldpbk5UOi8vJGVudjpDb21wdXRlck5hbWUiDQokbG9jVXNlcnMgPSAoJnsgW0FEU0ldJHNlcnZlcj0kY247ICRzZXJ2ZXIuY2hpbGRyZW4gfCA/
                                eyRfLnNjaGVtYWNsYXNzbmFtZSAtZXEgInVzZXIifSB9KS5OYW1lDQokbG9jR3JwcyA9ICgmeyBbQURTSV0kc2VydmVyPSRjbjsgJHNlcnZlci5jaGlsZHJlbiB8ID97JF8uc2NoZW1hY2x
                                hc3NuYW1lIC1lcSAiZ3JvdXAifSB9KS5OYW1lDQo=')
                        $grpInfo = (Dec64 'JGdyb3VwID0gJGNuLkNyZWF0ZSgiR3JvdXAiLCc8R1JQTkFNRT4nKQ0KCSRncm91cC5TZXRJbmZvKCkNCgkkZ3JvdXAuRGVzY3JpcHRpb24gPSAnPEdSUERFU0M+Jw0KCSRncm91cC5TZXRJbmZvKCkNCg==')
                        $grpMbrInfo = (Dec64 'JG1icnMgPSBAKDxNQlJTPikNCkZvckVhY2ggKCRtYnIgaW4gJG1icnMpew0KCUlmICgkbG9jVXNlcnMgLWNvbnRhaW5zICRtYnIpIHsNCgkgICAgW0FEU0ldJGxncnBQZXJtID0gIldpbk5UOi8vJGVudjpDb21wdXRlck5hbWUvJzxHUlA+Jyxncm91cCINCgkgICAgJGxncnBQZXJtLkFkZCgiV2luTlQ6Ly8kbWJyLHVzZXIiKQ0KCSAgICAgJGxncnBQZXJtLlNldEluZm8oKQ0KCSAgICAgfSAjSWYgbG9jVXNlcnMNCgl9ICNGRSBtYnINCg==')
            
                        $Groups = $dirContent | ?{$_.BaseName -match 'Groups'}
                        Try { 
                            $grpData = [xml](GC $Groups.FullName)
                            ForEach ($Group in $grpData.Groups){
                                $Grp = $Group.Group
                                $grpItems = $Grp.Properties
                                ForEach ($itm in $grpItems){#}
                                    $lclGrpName = ((New-Object System.Security.Principal.SecurityIdentifier($itm.groupSid)).Translate([System.Security.Principal.NTAccount]).Value).Split('\')[-1]
                                    $lclGrp = (&{ [ADSI]$server="WinNT://$env:computername"; $server.children | ?{$_.schemaclassname -eq "Group" -AND $_.name -eq $lclGrpName}})
                                    $lclGrpMbrs = ($lclGrp | Select -EXP Description)
                                    $lclGrpDesc = ($lclGrp | Select -EXP Description)
                    
                                    # Create the Group
                                        $psGpCmd += ($grpInfo -replace '<GRPNAME>',$lclGrpName -replace '<GRPDESC>',$lclGrpDesc)
                                    # Leave Members Empty
                                        If ($itm.deleteAllUsers -eq 1){ Continue }
                                    # Add Groups to Members
                                        # If ($itm.deleteAllGroups -eq 1){ Continue }
                                    # Add Users to Members
                                        If ($addAccts -eq $true){
                                            $gmbrs = @($lclGrp.psbase.Invoke("Members"))
                                            $mbrs = $gmbrs | %{ $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) } #FE
                                            $jmbrs = $mbrs -replace '^',"'" -replace '$',"'" -join ','
                                            $psGpCmd += $grpMbrInfo -replace '<MBRS>',$jmbrs -replace '<GRP>',$lclGrpName
                                            } #If removeAccounts
                                    } #FE itm
                                } #FE Group
                            }
                        Catch {}
                        If ([bool]$grpItems) {
                            $drTrg = "$dirLPO\DomainSysvol\GPO\$drTa\Scripts\$drTb\grpsSTIG.ps1"
                            $tmpFile = [io.path]::GetTempFileName()
                            $psGpCmd | Out-File -FilePath $tmpFile -Encoding ascii -Force
                            Move-Item $tmpFile -Force -Destination $drTrg
                            $cntScripts.Add($drTrg)
                            } #If grpItems
                    #endregion Groups Prefs
                    #region Registry Prefs
                        $regKeys = $dirContent | ?{$_.BaseName -match 'Registry'}
                        $regData = [xml](GC $regKeys.FullName)
                        ForEach ($rData in $regData.RegistrySettings){
                            $rDat = $rData.Registry
                            $regItems = $rDat.Properties
                            $regItems | %{
                                $key = ($_.key).Trim()
                                $name = ($_.name).Trim()
                                $val = ($_.value).Trim()
                                If ($_.type -match 'WORD'){$val = "0x$val"}
                                Switch ($_.Type){
                                    'REG_BINARY' { $locPol.SetBinaryValue($key,$name,$val) }
                                    'REG_DWORD' { $locPol.SetDWORDValue($key,$name,$val) }
                                    'REG_QWORD' { $locPol.SetQWORDValue($key,$name,$val) }
                                    'REG_SZ' { $locPol.SetStringValue($key,$name,$val) }
                                    #'REG_EXPAND_SZ' { $locPol.SetExpandString($key,$name,$val) }
                                    'REG_MULTI_SZ' { $locPol.SetMultiStringValue($key,$name,$val) }
                                    } #sw
                                } #fe
                            } #FE rData
                        # Save directly to regpol file (No PS Script)
                        $locPol.SaveFile()
                    #endregion Registry Prefs
                    #region Services Prefs
                        If ((gv).name -contains 'psGpCmd'){ clv psGpCmd }
                        $Services = $dirContent |?{$_.BaseName -match 'Services'}
                        $svcItems = ([xml](GC $Services.FullName)).NTServices.NTService.Properties
                        $psSvcCmd = $svcItems | %{ "If (Get-Service -ServiceName $($_.serviceName)){ Set-Service -Name $($_.serviceName) -StartupType $($_.startupType) }" }
                        # Add local PS Script to apply Settings
                        If ([bool]$svcItems) {
                            $drTrg = "$dirLPO\DomainSysvol\GPO\$drTa\Scripts\$drTb\svcsSTIG.ps1"
                            $tmpFile = [io.path]::GetTempFileName()
                            $psSvcCmd | Out-File -FilePath $tmpFile -Encoding ascii -Force
                            Move-Item $tmpFile -Force -Destination $drTrg
                            $cntScripts.Add($drTrg)
                            } #If
                    #endregion Services Prefs
                    #region Set script pointer INI file contents
                        $iniContent = (Dec64 'W1NjcmlwdHNDb25maWddDQpTdGFydEV4ZWN1dGVQU0ZpcnN0PXRydWUNCltTdGFydHVwXQ==') + $([Environment]::NewLine)
                        $x = 0
                        $cntScripts | %{
                            $iniContent += "$($x)CmdLine=$($_ -replace "^.*LPO ",'LPO ')" + $([Environment]::NewLine)
                            $iniContent += "$($x)Parameters=" + $([Environment]::NewLine)
                            $x++
                            } #fe
                        $tmpFile = [io.path]::GetTempFileName()
                        $iniContent | Out-File -FilePath $tmpFile -Encoding unicode -Force
                        Move-Item $tmpFile -Force -Destination "$dirLPO\DomainSysvol\GPO\$drTa\Scripts\psscripts.ini"
                        $tmpFile = [io.path]::GetTempFileName()
                        '' | Out-File -FilePath $tmpFile -Encoding unicode -Force
                        Move-Item $tmpFile -Force -Destination "$dirLPO\DomainSysvol\GPO\$drTa\Scripts\scripts.ini"
                    #endregion Set script pointer INI file contents
                    #region New Scripts from Prefs
                        # Set script pointer registry entries
                        #    $scpRegRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0'
                        #        $locPol.SetStringValue($scpRegRoot,"GPO-ID","cn={0253C616-BC86-47FE-B201-F5E6242ED08E},cn=policies,cn=system,DC=dhs,DC=sgov,DC=gov")
                        #        $locPol.SetStringValue($scpRegRoot,"SOM-ID","OU=Win7,OU=Workstations,OU=Devices,OU=DHS_NEW,DC=dhs,DC=sgov,DC=gov")
                        #        $locPol.SetStringValue($scpRegRoot,"FileSysPath","\\\\dhs.sgov.gov\\SysVol\\dhs.sgov.gov\\Policies\\{0253C616-BC86-47FE-B201-F5E6242ED08E}\\Machine")
                        #        $locPol.SetStringValue($scpRegRoot,"DisplayName","CMP - Win7 (A - Temp Admins)")
                        #        $locPol.SetStringValue($scpRegRoot,"GPOName","{0253C616-BC86-47FE-B201-F5E6242ED08E}")
                        #        $locPol.SetDWORDValue($scpRegRoot,"PSScriptOrder",0x3)
                        #    $scpRegRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0'
                        #        $locPol.SetStringValue($scpRegRoot,"Script","\\\\dhs.sgov.gov\\SysVol\\dhs.sgov.gov\\scripts\\GrantTempAdmin.ps1")
                        #        $locPol.SetStringValue($scpRegRoot,"Parameters","")
                        #        $locPol.SetDWORDValue($scpRegRoot,"IsPowershell",0x1)
                        #        $locPol.SetQWORDValue($scpRegRoot,"ExecTime",'hex(b):00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00')
                        #    $locPol.SaveFile()
                    #endregion New Scripts from Prefs
                    ########################################################################################
                    # $locPol.Entries | OGV -Title "$($locPol.FileName)-Settings [$($locPol.Entries.Count)]"
                    ########################################################################################
                    }
                $wrkDir = "$Env:UserProfile\Desktop"
                $srcScriptXml = 'C:\TEMP\GPO-2-LPO.ps1xml'  # $srcScript = $myinvocation.InvocationName
                $locUsers = (&{ [ADSI]$server="WinNT://$env:computername"; $server.children | ?{$_.schemaclassname -eq "user"} }).Name
                # Load External Data
                    # Set-Content -Path ($tmpds = [io.path]::GetTempFileName()) -Value $srcScriptXml
                    # $datastore = Import-CliXml -Path $tmpds
                    #< External File Method
                        If (!(Test-Path $srcScriptXml -Type Leaf)){ $edata = 0 } Else { $edata = 1 }
                        Switch ($eData){
                            0 { Throw 'LPO folder datastore missing!' }
                            1 { $datastore = Import-CliXml -Path $srcScriptXml }
                            } #sw
                    #>
            #endregion Environment
            } #Begin
        Process {
            #region Select Domain GPO and copy locally
                # Get GPO GUID
                If ([String]::IsNullOrEmpty($srcGPGuid)){ $trgGUID = (Get-GPO -name $srcGPName).ID.Guid }
                Else { $trgGUID = $srcGPGuid.Trim('[{}]') }
                If (![String]::IsNullOrEmpty($srcGPGuid)){ $srcGPName = (Get-GPO -ID $srcGPGuid).DisplayName }
           
                # Error on Sysvol folder not found otherwise copy to local desktop
                If (!(Test-Path "$polRoot\{$trgGUID}" -Type Container)){ $gpDir = 0 } Else { $gpDir = 1 }
                Switch ($gpDir){
                    0 { Throw 'GPO DS folder not found!' }
                    1 { Copy-Item "$polRoot\{$trgGUID}" -Recurse -Force -Destination "$wrkDir\$trgGUID" }
                    } #sw
                $srcDirGPO = "$wrkDir\$trgGUID"
            #endregion Select Domain GPO and copy locally
            #region Create new (empty) Local policy
                $trgLPO = "LPO [$srcGPName]"
                $dirLPO = "$wrkDir\$trgLPO"
                # $dirLPO = [char]34 + "$wrkDir\$trgLPO" + [char]34 
                Try { New-Item "$dirLPO" -Type Container -EA Stop} Catch { Write-Warning 'LPO folder already exists!';Break }
                # Insert default files
                    ForEach ($file in $datastore){
                        If (($file.FileName -eq 'LocalPol.exe') -OR ($file.FileName -eq 'LocalSecurityDB.sdb')){
                            $tmpEncTxt = [io.path]::GetTempFileName()
                            Set-Content -Path $tmpEncTxt -Value $file.Content -Encoding $file.Encoding
                            DeMime $tmpEncTxt $dirLPO\$($file.FileName)
                            Remove-Item $tmpEncTxt
                            }
                            # Remove-Item "$dirLPO\*.txt" -Force -Include
                            # $dirLPO\$($file.FileName) -Force }
                        If ($file.FileName -eq 'ntypPol.cs'){ Continue }
                        $tmpFile = [io.path]::GetTempFileName()
                        (Dec64 $file.Content) | Out-file $tmpFile -Encoding $file.Encoding
                        Move-Item -Force -Path $tmpFile -Destination "$dirLPO\$($file.FileName)"
                        } #FE file
                    Try { New-Item "$dirLPO\DomainSysvol" -Type Directory -EA Stop }
                    Catch { Write-Warning 'LPO folder already exists!'; Break }
                    '\GPO','\GPO\Machine','\GPO\User' | %{
                        Try { New-Item "$dirLPO\DomainSysvol\$_" -Type Directory -EA Stop}
                        Catch { Write-Warning 'LPO folder already exists!';Break }
                        } #fe
                # Load local policy Editor class
                    #$ntypPol = 
                    Add-Type $(Dec64 $datastore[4].Content) -ErrorAction Stop
                    'domPol','locPol','blnkPol' | %{ New-Variable -Name $_ -Value $(New-Object TJX.PolFileEditor.PolFile) }
                # Add blank pol file to LPO Root
                    $blnkPol.FileName = "$dirLPO\registry.pol"
                    $blnkPol.SaveFile()
                    #rv blnkPol
                # Need other LPO Files (LocalPol.exe,LocalSecurityDB.sdb)
            #endregion Create new (empty) Local policy
            #region Import Domain GPO Settings
                $sigVerCheck = (((GC "$srcDirGPO\GPO.cmt" -Encoding Unicode) | ?{$_ -match 'Applicable STIG/Ver:'}).Split(':')[-1]).Trim()
                # Get data types (User, Machine)
                $datUser = ((gci "$srcDirGPO\User" -Recurse -Force).Count -ge 1)
                $datMachine = ((gci "$srcDirGPO\Machine" -Recurse -Force).Count -ge 1)
                If ($datUser -xor $datMachine){
                    If ($datMachine){ $trgSettings = 'Machine' }
                    If ($datUser){ $trgSettings = 'User' }
                    } #If xor
                ElseIf (($datUser -and $datMachine)){ $trgSettings = 'Both' }
                Else { $trgSettings = 'None' }
                Switch ($trgSettings){
                    'Machine' {
                        'Machine' | %{ ProcessItem $_; If (Test-Path "$srcDirGPO\$_\Preferences"){ Get-Prefs $_ } } #fe
                        } #Machine
                    'User'     {
                        'User' | %{ ProcessItem $_; If (Test-Path "$srcDirGPO\$_\Preferences"){ Get-Prefs $_ } } #fe
                        } #User
                    'Both'     {
                        'Machine','User' | %{ ProcessItem $_; If (Test-Path "$srcDirGPO\$_\Preferences"){ Get-Prefs $_ } } #fe
                        } #Both
                    'None'     { 'No Settings Found!'; Break } #None
                    default    { 'DAMN!'; Break } #None
                    } #sw 
            #endregion Import Domain GPO Settings
            } #Process
        End {  } #End
         #ConvertFrom-GPO2LPO
            # ConvertFrom-GPO2LPO -srcGPName 'TEST - CMP - Windows 7 Safe Settings' -srcGPGuid 
        }

#endregion


Function i__Compare-RSoP
{
    Param
    (
        $File1,
        $file2
    )
    Function Get-Exts($a) {Return (($a|Get-Member -MemberType Property)|Where-Object{$_.Definition -match 'string'}).Name}
    <#
        Process RSOP XML file (with namespaces)

        September 6, 2011 bertvanlandeghem Active Directory, Powershell
        Here is how to query the rsop xml reports generated from the script in the previous post. 
        The xml file uses namespaces, so we need to take this into account when querying the files.
    #>
    $usrExts = $xml.DocumentElement.UserResults.ExtensionData.Extension
    $cmpExts = $xml.DocumentElement.ComputerResults.ExtensionData.Extension #.Name
    $aT = Get-Exts $usrExts
    $bT = Get-Exts $cmpExts
    $cmpExts.xmlns
    $file1
    $xml.ChildNodes
    ($xml.DocumentElement.UserResults.ExtensionData.Extension)
    #region
        $xml = [xml] $(Get-Content c:\temp\test.xml)
        $XmlNamespaceManager = New-Object system.Xml.XmlNamespaceManager( $xml.NameTable )
        $XmlNamespaceManager.AddNamespace("q1","http://www.microsoft.com/GroupPolicy/Settings/Security")
        $XmlNamespaceManager.AddNamespace("q2","http://www.microsoft.com/GroupPolicy/Settings/Registry")
        $XmlNamespaceManager.AddNamespace("q3","http://www.microsoft.com/GroupPolicy/Settings/PublicKey")

        $xml.SelectNodes("//q1:SecurityOptions", $XmlNamespaceManager) | Select-Object `
            @{Label="Name";Expression={[string]::Concat(  $_.KeyName, $_.SystemAccessPolicyName)}}, 
            @{Label="Value";Expression={[string]::Concat( $_.SettingNumber,$_.SettingString, $( $_.SettingStrings | `
            ForEach-Object -Begin { $output = @() } `
                            -Process { $output += $_.Value } `
                            -End { $([string]::join('|',$output))} ) )} } | Sort-Object Name

        $xml.SelectNodes("//q2:PublicKeySettings", $XmlNamespaceManager) | Select-Object `
            @{Label="Name";Expression={[string]::Concat(  $_.KeyName, $_.SystemAccessPolicyName)}}, 
            @{Label="Value";Expression={[string]::Concat( $_.SettingNumber,$_.SettingString, $( $_.SettingStrings | `
            ForEach-Object -Begin{$output = @()} -Process {$output += $_.Value} -End { $([string]::join('|',$output))} ) )}} | Sort-Object Name

        <#
            The important line is:

            $xml.SelectNodes("//q1:SecurityOptions", $XmlNamespaceManager)

            which takes into account the $xmlNamespaceManager. The following lines
            are merely formatting etc. If you need to know more about it, drop me line.
            You could save the output as a csv file then, and merge the files of
            all servers for processing with Pivot tables in Excel. That way you can
            report on all your servers and see if all settings are applied consistently.
            Handy for troubleshooting….
            http://www.microsoft.com/GroupPolicy/Sett... 
                q2:SoftwareInstallationSettings              http://www.microsoft.com/GroupPolicy/Sett...
                q3:AuditSettings                             http://www.microsoft.com/GroupPolicy/Sett...
                q4:SecuritySettings                          http://www.microsoft.com/GroupPolicy/Sett...
                q5:PublicKeySettings                         http://www.microsoft.com/GroupPolicy/Sett...
                q6:WindowsFirewallSettings                   http://www.microsoft.com/GroupPolicy/Sett...
                q7:RegistrySettings                          http://www.microsoft.com/GroupPolicy/Sett...
        #>

        <#
            PS C:\windows\system32> $xml.DocumentElement.UserResults.ExtensionData.Extension

                q1              : http://www.microsoft.com/GroupPolicy/Settings/Registry
                type            : q1:RegistrySettings
                xmlns           : http://www.microsoft.com/GroupPolicy/Settings
        #>



        # Retrieve the current applied policies (must be run from an elevated PS window in order to retrieve computer results)
        gpresult.exe /x C:\Temp\results.xml /f
    #endregion
    #region

        # Import the XML file
        $results = [xml] (Get-Content c:\temp\test.xml)

        # Output the results
        $results.DocumentElement.ComputerResults.ExtensionData | Select-Object -ExpandProperty extension | Select-Object Account | Select-Object -ExpandProperty * | Select-Object Name, SettingNumber, SettingBoolean, Type | Format-Table -AutoSize

    #endregion
    #region
        [xml]$results = Get-Content c:\temp\test.xml
        [System.Xml.XmlNamespaceManager]$nsmgr = $results.NameTable;

        # set up namespaces for queries
        $nsmgr.AddNamespace('df',$results.Rsop.xmlns);
        $nsmgr.AddNamespace('base','http://www.microsoft.com/GroupPolicy/Settings/Base')
        $nsmgr.AddNamespace('ex', 'http://www.microsoft.com/GroupPolicy/Settings')
        $nsmgr.AddNamespace('types', 'http://www.microsoft.com/GroupPolicy/Types')

        # get the GUID of a GPO
        $node=$results.selectSingleNode('//df:Rsop/df:ComputerResults/df:GPO/df:Name[text()="Default Domain Policy"]', $nsmgr)
        $node | Select-Object *
        $xpath='//df:Rsop/df:ComputerResults/df:GPO/df:Name[text()="Default Domain Policy"]/../df:Path/types:Identifier'
        $guid=$results.selectSingleNode($xpath, $nsmgr).'#text'

        # get extensions
        $extensions = $results.selectNodes('//df:Rsop/df:ComputerResults/df:ExtensionData/ex:Extension', $nsmgr)

        # next we have to update our extensions query to extract only yhe entries associated with our target policy
    #endregion

    #region wmiRSoP
        $wmiRSoP = {
            $user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -replace '-', '_'
            $Computer = $env:COMPUTERNAME
            # ($uPols = GWMI -Namespace root\rsop\user\$user -Class RSOP_PolicySetting | FL Name,registryKey,value*
            ($uPols = Get-WmiObject -Namespace root\rsop\user\$user -Class RSOP_RegistryPolicySetting) | Format-List Name,registryKey,value*
            ($cPols = Get-WmiObject -Namespace root\rsop\computer -Class RSOP_RegistryPolicySetting) | Format-List Name,registryKey,value*
            $uRSoPClass = Get-WmiObject -Namespace root\rsop\user\$user  -List RSOP*
            $cRSoPClass = Get-WmiObject -Namespace root\rsop\computer  -List RSOP*
            }
        & $wmiRSoP
        $b.Properties
        Compare-Object $a $uPols -IncludeEqual
    #endregion wmiRSoP
}



#region - SearchGPOforSetting (OBSOLETE)
    Function SearchGPOsForSetting {
        <#
            SearchGPOsForSetting

            Shamelessly stolen from this page (after fixing 1 bug):
                http://blogs.technet.com/b/grouppolicy/archive/2009/04/14/tool-images.aspx
                http://blogs.technet.com/b/grouppolicy/archive/2009/04/17/find-settings-in-every-gpo.aspx

            Powershell function that does the following:
            SearchGPOsForSetting
                [-IsComputerConfiguration] <boolean>
                [-Extension] <string>
                [-Where] </string><string>
                [-Is] </string><string>
                [[-Return] </string><string>]
                [[-DomainName] </string><string>]
                [-Verbose] [-Debug]
                [-ErrorAction <actionpreference>]
                [-WarningAction </actionpreference><actionpreference>]
                [-ErrorVariable <string>]
                [-WarningVariable </string><string>]
                [-OutVariable </string><string>]
                [-OutBuffer <int32>]

            Example:
                SearchGPOsForSetting -IsComputerConfiguration $true -Extension Security -Where Name -Is LockoutDuration -Return SettingNumber

            Example:
                SearchGPOsForSetting -IsComputerConfiguration $true -Extension Registry -Where Name -Is ACSettingIndex -Return SettingNumber
        #>
        Param (
            [Parameter(Mandatory=$true)] [Boolean] $IsComputerConfiguration,
            [Parameter(Mandatory=$true)] [string] $Extension,
            [Parameter(Mandatory=$true)] [string] $Where,
            [Parameter(Mandatory=$true)] [string] $Is,
            [Parameter(Mandatory=$false)] [string] $Return,
            [Parameter(Mandatory=$false)] [string] $DomainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            )
        Function print{
            Param ( $displayName, $value )
            $host.UI.WriteLine();
            $stringToPrint = "The Gpo '" + $displayName + "' has a " + $Extension + " setting where '" + $Where + "' is equal to '" + $Is + "'";
            if ($Return -ne $null)	{ $stringToPrint += " and the value of its '" + $Return + "' property is: '" + $value + "'"; }
            $host.UI.Write([ConsoleColor]::Magenta, [ConsoleColor]::Black,	$stringToPrint);	$host.UI.WriteLine();
            }
        Function processNodes {
            Param ( $nodes, $foundWhere )
            $thePropertyWeWant = $Where;
            # If we already found the $Where then we are looking for our $Return value now.
            if ($foundWhere){ $thePropertyWeWant = $Return;	}
            foreach($node in $nodes){
                $valueWeFound = $null;
                #Here we are checking siblings
                $lookingFor = Get-Member -InputObject $node -Name $thePropertyWeWant
                if ($lookingFor -ne $null){ $valueWeFound = $node.($lookingFor.Name) }
                else {
                    #Here we are checking attributes.
                    if ($node.Attributes -ne $null) {
                        $lookingFor = $node.Attributes.GetNamedItem($thePropertyWeWant);
                        if( $lookingFor -ne $null) {  $valueWeFound = $lookingFor; }
                        }
                    }
                if( $lookingFor -ne $null){
                    #If we haven't found the $Where yet, then we may have found it now.
                    if (! $foundWhere){
                        # We have found the $Where if it has the value we want.
                        if ( [String]::Compare($valueWeFound, $Is, $true) -eq 0 ){
                            # Ok it has the value we want too.  Now, are we looking for a specific
                            # sibling or child of this node or are we done here?
                            if ($Return -eq $null){
                                #we are done, there is no $Return to look for
                                print -displayName $Gpo.DisplayName -value $null;
                                return;
                                }
                            else {
                                # Now lets look for $Return in the siblings and then if no go, the children.
                                processNodes -nodes $node -foundWhere $true;
                                }
                            }
                        }
                    else {
                        #we are done.  We already found the $Where, and now we have found the $Return.
                        print -displayName $Gpo.DisplayName -value $valueWeFound;
                        return;
                        }
                    }
                if (! [String]::IsNullOrEmpty($node.InnerXml)){ processNodes -nodes $node.ChildNodes -foundWhere $foundWhere; }
                }
            }
        #Import our module for the call to the Get-GPO cmdlet

        Import-Module GroupPolicy;
        $allGposInDomain = Get-GPO -All -Domain $DomainName;
        $xmlnsGpSettings = "http://www.microsoft.com/GroupPolicy/Settings";
        $xmlnsSchemaInstance = "http://www.w3.org/2001/XMLSchema-instance";
        $xmlnsSchema = "http://www.w3.org/2001/XMLSchema";
        $QueryString = "gp:";
        if ($IsComputerConfiguration){ $QueryString += "Computer/gp:ExtensionData/gp:Extension"; }
        else{ $QueryString += "User/gp:ExtensionData/gp:Extension"; }
        foreach ($Gpo in $allGposInDomain){
            $xmlDoc = [xml] (Get-GPOReport -Guid $Gpo.Id -ReportType xml -Domain $Gpo.DomainName);
            $xmlNameSpaceMgr = New-Object System.Xml.XmlNamespaceManager($xmlDoc.NameTable);
            $xmlNameSpaceMgr.AddNamespace("", $xmlnsGpSettings);
            $xmlNameSpaceMgr.AddNamespace("gp", $xmlnsGpSettings);
            $xmlNameSpaceMgr.AddNamespace("xsi", $xmlnsSchemaInstance);
            $xmlNameSpaceMgr.AddNamespace("xsd", $xmlnsSchema); 
            $extensionNodes = $xmlDoc.DocumentElement.SelectNodes($QueryString, $XmlNameSpaceMgr);
            foreach ($extensionNode in $extensionNodes){
                if ([String]::Compare(($extensionNode.Attributes.Item(0)).Value,"http://www.microsoft.com/GroupPolicy/Settings/" + $Extension, $true) -eq 0){
                    # We have found the Extension we are looking for now recursively search
                    # for $Where (the property we are looking for a specific value of).
                    processNodes -nodes $extensionNode.ChildNodes -foundWhere $false;
                    }
                }
            } 
        } #SearchGPOsForSetting
#endregion



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
    $null = ($aclShares = ($shares = Get-SmbShare) | Get-SmbShareAccess)
    $Shares | Export-Clixml -Path "$filePath\ShareData.xml"
    $aclShares | Export-Clixml -Path "$filePath\ShareAclData.xml"
    $shrTest = Import-Clixml "$filePath\ShareData.xml"
    $shrAclTest = Import-Clixml "$filePath\ShareAclData.xml"

    fsutil behavior query disable8dot3
    ipmo -Name PoshWSuS
    $ws = Connect-PSWSUSServer -WsusServer 'fabconwsus01' -Port 8530
    $ws.GetConfiguration()

    install-module

    #region - Search-GPOsForSetting
        Function Search-GPOsForSetting
        {
            <#
                http://blogs.technet.com/b/grouppolicy/archive/2009/04/14/tool-images.aspx
                http://blogs.technet.com/b/grouppolicy/archive/2009/04/17/find-settings-in-every-gpo.aspx
        
                Powershell script that does the following:
                Search-GPOsForSetting  [-IsComputerConfiguration] <boolean>
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
                -----*                                 ----------*                      ------*-------*-----
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
                -----*                            ----------*------*-------*-----
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
                -----*           ----------*          ------*-------*-----
                dc=company,dc=pri Default Domain Policy True    True         1
                dc=company,dc=pri PKI AutoEnroll        True    True         2
                Other possible TargetType values are OU and Site.
                .Example
                PS C:\>  Get-GPLink | sort Target | Format-Table -view link
                    Target: dc=company,dc=pri
                DisplayName                         Enabled    Enforced    Order
                ----------*                        ------*   -------*   -----
                PKI AutoEnroll                      True       False           2
                Default Domain Policy               True       True            1
                    Target: ou=dev,dc=company,dc=pri
                DisplayName                         Enabled    Enforced    Order
                ----------*                        ------*   -------*   -----
                Demo 1                              True       False           1
                Demo 2                              False      False           2
                ...

            .Example 4
                PS C:\> Get-GPLink | Sort TargetType | Format-Table -view targetType
                    TargetType: Domain
                Target                          DisplayName                  Enabled    Enforced     Order
                -----*                         ----------*                 ------*   -------*    -----
                dc=company,dc=pri               PKI AutoEnroll               True       True             2
                dc=company,dc=pri               Default Domain Policy        True       True             1
                    TargetType: OU
                Target                            DisplayName                Enabled    Enforced     Order
                -----*                           ----------*               ------*   -------*    -----
                ou=accounting,dc=company,dc=pri   Accounting-dev-test-foo    True       False            1
                ou=sales,dc=company,dc=pri        Demo 1                     True       False            1
                ...

            .Example 5
                PS C:\> Get-GPLink | Sort Name | Format-Table -view gpo
                    DisplayName: Default Domain Controllers Policy
                Target                                        Enabled    Enforced    Order
                -----*                                       ------*   -------*   -----
                ou=domain controllers,dc=company,dc=pri       True       False           1
                    DisplayName: Default Domain Policy
                Target                                        Enabled    Enforced    Order
                -----*                                       ------*   -------*   -----
                dc=company,dc=pri                             True       True            1
                    DisplayName: Demo 1
                Target                                        Enabled    Enforced    Order
                -----*                                       ------*   -------*   -----
                ou=dev,dc=company,dc=pri                      True       False           1
                CN=Default-First-Site-Name,cn=Sites,CN=Config True       True            2
                uration,DC=Company,DC=Pri
                ...

            .Example 6
                PS C:\> Get-GPLink | Format-Table -GroupBy Domain -Property Link,GPO,Enabled,Enforced
                    Domain: Company.Pri
                Link                                    GPO                               Enabled Enforced
                ---*                                   --*                              ------*--------
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
                    [String[]]$SiteName = "Default-First-Site-Name",
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
                    For ( $i = $links.count - 1; $i -ge 0 ; $i--)
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
                            $null = Set-GPRegistryValue -Disable -Name $DestinationGPO -Key $Value.FullKeyPath -Verbose
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

                            $null = Set-GPRegistryValue -Disable -Name $DestinationGPO -Key $Value.FullKeyPath -ValueName $Value.Valuename -Verbose
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

                        $null = $Value | Set-GPRegistryValue -Name $DestinationGPO -Verbose
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
            $null = New-GPO -Name $DestinationGPO -Verbose
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


    <#


    # Help
    Help Get-GPLink -Full
    Help Get-GPUnlinked -Full
    Help Copy-GPRegistryValue -Full

    # Copy one GPO registry settings into another
    Copy-GPRegistryValue -Mode Computer -SourceGPO "MS-B" `
        -DestinationGPO 'Microsoft 365 Apps v2206 - Computer' -Verbose

    # Copy one GPO registry settings into another, just user settings
    Copy-GPRegistryValue -Mode User -SourceGPO '_Microsoft 365 Apps v2206 - DDE Block - User' `
        -DestinationGPO '_Microsoft 365 Apps User' -Verbose

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
        #>
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
