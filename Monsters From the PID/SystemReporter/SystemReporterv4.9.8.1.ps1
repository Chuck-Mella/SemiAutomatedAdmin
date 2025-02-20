<#
    Add negative report
    Alt Creds?
    use tmp files
    enablke remote execution
#>
#Requires -RunAsAdministrator

Param
(
    $Systems = $env:COMPUTERNAME
)

$rptParams = [Ordered]@{
    CurrentTime = (Get-Date)
    Systems = $Systems
    lclWorkPath = $env:TEMP
    drvFreeSpaceTest = 90
    evtCount = 10
    newAppCount = 10
    ProccessNumToFetch = 10
    srchMethod = 'WMI'  ##  'REG' 'PKG'
    email = $false
    emailTo = @("youremail@yourcompany.com")
    emailFrom = ([string]"youremail@yourcompany.com")
    emailSvr = "yourmailserver.yourcompany.com"
    colDrv_VolName = 'Jenny'
    useAltCreds = $true
    useCaC = $true
    }

Function Get-SystemReport
{
    <#
        .SYNOPSIS
            Generates an HTML report of System config/status and all software installed on the computer.

            .PARAMETER CurrentTime
                Defaults to DateTime script is run.

            .PARAMETER Systems
                If querying one or more remote computers (2+ use a comma separated list), defaults to local computername.

            .PARAMETER localFilePath
                Defines the local path to save the report files to, defaults to script file location.

            .PARAMETER drvFreeSpaceTest
                The Drive freespace threshhold (in %) for including in the report.

            .PARAMETER drvFreeSpaceTest
                The Drive freespace threshhold (in %) for including in the report.

            .PARAMETER evtCount
                The number of most recent admin events to include in the report. (Default = 5)
                If the context is not elevated then the Scurity log is not included.

            .PARAMETER ProccessNumToFetch
                The number of active processes to include in the report. (Default = 10)

            .PARAMETER srchMethod  [Fixed Set *WMI,REG,PKG]
                Determines Collection Method for installed application data using Windows Management Instrumentation 'WMI',
                    Windows Registry 'REG', or Windows Packaging Service 'PKG'.

            .PARAMETER colDrv_VolName
                The text value of the VolumeName of the collection drive to exclude from the final report.

            .PARAMETER useAltCreds = (Get-Credential -UserName AdminUser -Message 'Enter Administrator User & Password')
                The credial values (Administrator User & Password) to use for script functions requiring elevated access (use domain\user format).

            .PARAMETER useCaC *SWITCH
                Tells Script to attempt to use Common Access Card (CaC) credentials.


            [FUTURE PENDING]

            .PARAMETER emailTo  [FUTURE PENDING]
                The email address(s) to send the report to (2+ use a comma separated list)

            .PARAMETER emailFrom  [FUTURE PENDING]
                The sender email address to use to send the report.

            .PARAMETER emailSvr  [FUTURE PENDING]
                The number of the SMTP email server to use to send report email.

            .PARAMETER email [Switch]  [FUTURE PENDING]
                If enabled, report will attempt to email itserlf to selected recipients.


            .EXAMPLE
                Get-SystemReport

                This example retrieves all OS/System/Memory/Drive info/most recent events/installed SW/most recent SW installs and other information on the local computer.

            .NOTES  
                Author     : Chuck Mella
                Version    : 1.4.9.2 20220610 ( Initial Build )
                Version    : 1.5.0.1 20220612 ( Corrected disk info data )
                Version    : 1.8.0.7 20220626 ( Added and corrected network config data )
                Version    : 1.8.5.9 20220714 ( Added WMI collection 0ption for SW collection )
                Version    : 2.0.2.2 20220829 ( Added Fileshare collection )
                Version    : 2.0.2.5 20221019 ( Added MAC address to network collection )
                Version    : 3.0.1.2 20230118 ( Added MultiNic Potential to network collection )
                Version    : 3.0.6.3 20230219 ( Added MultiDisk Potential to Disk collection and ability to ignore usb collection drive)
                Version    : 4.0.0.5 20230227 ( Added ExecutionPolicy manipulation )
                Version    : 4.1.0.8 20230228 ( Added Processor Info to System collection )
                Version    : 4.3.0.9 20230310 ( Added Username to repoort footer )
                Version    : 4.5.0.1 20230228 ( Embedded Images in lieu of external files (Single file reports) )
                Version    : 4.7.5.1 20230331 ( Added Installed OS Features & Roles to report )
                Version    : 4.7.9.4 20230811 ( Added Default Browser Detection )
                Version    : 4.7.9.6 20230814 ( changed network reporting to facilitate remote collections )
                Version    : 4.8.1.7 20230814 ( Added multiple system reporting )
                Version    : 4.9.8.1 20230901 Current Build ( Added ability to use SmartCard (CaC) credentials )
    #>
    [CmdletBinding()]
    Param (
        $CurrentTime,
        $Systems,
        $lclWorkPath,
        $drvFreeSpaceTest,
        [int]$evtCount,
        [int]$newAppCount,
        [int]$ProccessNumToFetch,
        [ValidateSet('WMI','REG','PKG')]$srchMethod,

        $colDrv_VolName,
        [switch]$useAltCreds,
        [Switch]$useCaC,

        $emailTo,
        $emailFrom,
        $emailSvr,
        [switch]$email
        )
    BEGIN
    {
        [void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
        [void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms.DataVisualization")

        #region  * Functions & Scriptblocks
            Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
            Function Enc64 { Param($a) $b = [System.Convert]::ToBase64String($a.ToCharArray());Return $b };
            Function Get-SmartCardCred
            {
                <#
                    .SYNOPSIS
                        Get certificate credentials from the user's certificate store.

                    .DESCRIPTION
                        Returns a PSCredential object of the user's selected certificate.

                    .EXAMPLE
                        Get-SmartCardCred
                        UserName                       Password
                        -------*                      --------
                        @@BVkEYkWiqJgd2d9xz3-5BiHs1cAN System.Security.SecureString

                        .EXAMPLE
                        $Cred = Get-SmartCardCred

                    .OUTPUTS
                        [System.Management.Automation.PSCredential]

                    .NOTES
                        Author: Joshua Chase
                        Last Modified: 01 August 2018
                        C# code used from https://github.com/bongiovimatthew-microsoft/pscredentialWithCert
                #>
                [cmdletbinding()]
                param()
                Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };

                $SmartCardCode = (Dec64 'Ly8gQ29weXJpZ2h0IChjKSBNaWNyb3NvZnQgQ29ycG9yYXRpb24uIEFsbCByaWdodHMgcmVzZXJ2ZWQuDQovLyBMaWNlbnNlZCB1bmRlciB0aGUgTUlUIExpY2Vuc2UuDQoNCnVzaW5nIFN5c3RlbTsNCnVzaW5nIFN5c3RlbS5NYW5hZ2VtZW50LkF1dG9tYXRpb247DQp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7DQp1c2luZyBTeXN0ZW0uU2VjdXJpdHk7DQp1c2luZyBTeXN0ZW0uU2VjdXJpdHkuQ3J5cHRvZ3JhcGh5Llg1MDlDZXJ0aWZpY2F0ZXM7DQoNCg0KbmFtZXNwYWNlIFNtYXJ0Q2FyZExvZ29uew0KDQogICAgc3RhdGljIGNsYXNzIE5hdGl2ZU1ldGhvZHMNCiAgICB7DQoNCiAgICAgICAgcHVibGljIGVudW0gQ1JFRF9NQVJTSEFMX1RZUEUNCiAgICAgICAgew0KICAgICAgICAgICAgQ2VydENyZWRlbnRpYWwgPSAxLA0KICAgICAgICAgICAgVXNlcm5hbWVUYXJnZXRDcmVkZW50aWFsDQogICAgICAgIH0NCg0KICAgICAgICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCldDQogICAgICAgIGludGVybmFsIHN0cnVjdCBDRVJUX0NSRURFTlRJQUxfSU5GTw0KICAgICAgICB7DQogICAgICAgICAgICBwdWJsaWMgdWludCBjYlNpemU7DQogICAgICAgICAgICBbTWFyc2hhbEFzKFVubWFuYWdlZFR5cGUuQnlWYWxBcnJheSwgU2l6ZUNvbnN0ID0gMjApXQ0KICAgICAgICAgICAgcHVibGljIGJ5dGVbXSByZ2JIYXNoT2ZDZXJ0Ow0KICAgICAgICB9DQoNCiAgICAgICAgW0RsbEltcG9ydCgiYWR2YXBpMzIuZGxsIiwgQ2hhclNldCA9IENoYXJTZXQuVW5pY29kZSwgU2V0TGFzdEVycm9yID0gdHJ1ZSldDQogICAgICAgIHB1YmxpYyBzdGF0aWMgZXh0ZXJuIGJvb2wgQ3JlZE1hcnNoYWxDcmVkZW50aWFsKA0KICAgICAgICAgICAgQ1JFRF9NQVJTSEFMX1RZUEUgQ3JlZFR5cGUsDQogICAgICAgICAgICBJbnRQdHIgQ3JlZGVudGlhbCwNCiAgICAgICAgICAgIG91dCBJbnRQdHIgTWFyc2hhbGVkQ3JlZGVudGlhbA0KICAgICAgICApOw0KDQogICAgICAgIFtEbGxJbXBvcnQoImFkdmFwaTMyLmRsbCIsIFNldExhc3RFcnJvciA9IHRydWUpXQ0KICAgICAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIENyZWRGcmVlKFtJbl0gSW50UHRyIGJ1ZmZlcik7DQoNCiAgICB9DQoNCiAgICBwdWJsaWMgY2xhc3MgQ2VydGlmaWNhdGUNCiAgICB7DQoNCiAgICAgICAgcHVibGljIHN0YXRpYyBQU0NyZWRlbnRpYWwgTWFyc2hhbEZsb3coc3RyaW5nIHRodW1icHJpbnQsIFNlY3VyZVN0cmluZyBwaW4pDQogICAgICAgIHsNCiAgICAgICAgICAgIC8vDQogICAgICAgICAgICAvLyBTZXQgdXAgdGhlIGRhdGEgc3RydWN0DQogICAgICAgICAgICAvLw0KICAgICAgICAgICAgTmF0aXZlTWV0aG9kcy5DRVJUX0NSRURFTlRJQUxfSU5GTyBjZXJ0SW5mbyA9IG5ldyBOYXRpdmVNZXRob2RzLkNFUlRfQ1JFREVOVElBTF9JTkZPKCk7DQogICAgICAgICAgICBjZXJ0SW5mby5jYlNpemUgPSAodWludClNYXJzaGFsLlNpemVPZih0eXBlb2YoTmF0aXZlTWV0aG9kcy5DRVJUX0NSRURFTlRJQUxfSU5GTykpOw0KDQogICAgICAgICAgICAvLw0KICAgICAgICAgICAgLy8gTG9jYXRlIHRoZSBjZXJ0aWZpY2F0ZSBpbiB0aGUgY2VydGlmaWNhdGUgc3RvcmUgDQogICAgICAgICAgICAvLw0KICAgICAgICAgICAgWDUwOUNlcnRpZmljYXRlMiBjZXJ0Q3JlZGVudGlhbCA9IG5ldyBYNTA5Q2VydGlmaWNhdGUyKCk7DQogICAgICAgICAgICBYNTA5U3RvcmUgdXNlck15U3RvcmUgPSBuZXcgWDUwOVN0b3JlKFN0b3JlTmFtZS5NeSwgU3RvcmVMb2NhdGlvbi5DdXJyZW50VXNlcik7DQogICAgICAgICAgICB1c2VyTXlTdG9yZS5PcGVuKE9wZW5GbGFncy5SZWFkT25seSk7DQogICAgICAgICAgICBYNTA5Q2VydGlmaWNhdGUyQ29sbGVjdGlvbiBjZXJ0c1JldHVybmVkID0gdXNlck15U3RvcmUuQ2VydGlmaWNhdGVzLkZpbmQoWDUwOUZpbmRUeXBlLkZpbmRCeVRodW1icHJpbnQsIHRodW1icHJpbnQsIGZhbHNlKTsNCiAgICAgICAgICAgIHVzZXJNeVN0b3JlLkNsb3NlKCk7DQoNCiAgICAgICAgICAgIGlmIChjZXJ0c1JldHVybmVkLkNvdW50ID09IDApDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgdGhyb3cgbmV3IEV4Y2VwdGlvbigiVW5hYmxlIHRvIGZpbmQgdGhlIHNwZWNpZmllZCBjZXJ0aWZpY2F0ZS4iKTsNCiAgICAgICAgICAgIH0NCg0KICAgICAgICAgICAgLy8NCiAgICAgICAgICAgIC8vIE1hcnNoYWwgdGhlIGNlcnRpZmljYXRlIA0KICAgICAgICAgICAgLy8NCiAgICAgICAgICAgIGNlcnRDcmVkZW50aWFsID0gY2VydHNSZXR1cm5lZFswXTsNCiAgICAgICAgICAgIGNlcnRJbmZvLnJnYkhhc2hPZkNlcnQgPSBjZXJ0Q3JlZGVudGlhbC5HZXRDZXJ0SGFzaCgpOw0KICAgICAgICAgICAgaW50IHNpemUgPSBNYXJzaGFsLlNpemVPZihjZXJ0SW5mbyk7DQogICAgICAgICAgICBJbnRQdHIgcENlcnRJbmZvID0gTWFyc2hhbC5BbGxvY0hHbG9iYWwoc2l6ZSk7DQogICAgICAgICAgICBNYXJzaGFsLlN0cnVjdHVyZVRvUHRyKGNlcnRJbmZvLCBwQ2VydEluZm8sIGZhbHNlKTsNCiAgICAgICAgICAgIEludFB0ciBtYXJzaGFsZWRDcmVkZW50aWFsID0gSW50UHRyLlplcm87DQogICAgICAgICAgICBib29sIHJlc3VsdCA9IE5hdGl2ZU1ldGhvZHMuQ3JlZE1hcnNoYWxDcmVkZW50aWFsKE5hdGl2ZU1ldGhvZHMuQ1JFRF9NQVJTSEFMX1RZUEUuQ2VydENyZWRlbnRpYWwsIHBDZXJ0SW5mbywgb3V0IG1hcnNoYWxlZENyZWRlbnRpYWwpOw0KDQogICAgICAgICAgICBzdHJpbmcgY2VydEJsb2JGb3JVc2VybmFtZSA9IG51bGw7DQogICAgICAgICAgICBQU0NyZWRlbnRpYWwgcHNDcmVkcyA9IG51bGw7DQoNCiAgICAgICAgICAgIGlmIChyZXN1bHQpDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgY2VydEJsb2JGb3JVc2VybmFtZSA9IE1hcnNoYWwuUHRyVG9TdHJpbmdVbmkobWFyc2hhbGVkQ3JlZGVudGlhbCk7DQogICAgICAgICAgICAgICAgcHNDcmVkcyA9IG5ldyBQU0NyZWRlbnRpYWwoY2VydEJsb2JGb3JVc2VybmFtZSwgcGluKTsNCiAgICAgICAgICAgIH0NCg0KICAgICAgICAgICAgTWFyc2hhbC5GcmVlSEdsb2JhbChwQ2VydEluZm8pOw0KICAgICAgICAgICAgaWYgKG1hcnNoYWxlZENyZWRlbnRpYWwgIT0gSW50UHRyLlplcm8pDQogICAgICAgICAgICB7DQogICAgICAgICAgICAgICAgTmF0aXZlTWV0aG9kcy5DcmVkRnJlZShtYXJzaGFsZWRDcmVkZW50aWFsKTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgICAgIA0KICAgICAgICAgICAgcmV0dXJuIHBzQ3JlZHM7DQogICAgICAgIH0NCiAgICB9DQp9')
                Add-Type -TypeDefinition $SmartCardCode -Language CSharp
                Add-Type -AssemblyName System.Security

                $ValidCerts = [System.Security.Cryptography.X509Certificates.X509Certificate2[]](Get-ChildItem 'Cert:\CurrentUser\My' |
                    Where-Object {$_.Extensions.EnhancedKeyUsages.Value -eq '1.3.6.1.4.1.311.20.2.2'})
                    # Smart Card Log-on from KB287547 http://officeredir.microsoft.com/r/rlidGPOIDAndCrypt2O14?clid=1033

                if ($ValidCerts.Length -eq 1) {$Cert = $ValidCerts | Select-Object -First 1}
                else
                {
                    $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2UI]::SelectFromCollection($ValidCerts, 'Choose a certificate', 'Choose a certificate', 0)
                }

                $Pin = Read-Host "Enter your PIN: " -AsSecureString

                Write-Output ([SmartCardLogon.Certificate]::MarshalFlow($Cert.Thumbprint, $Pin))
            }
            Function Test-IsAdmin
            {
                $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
                Switch ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
                {
                    $true  { $global:isAdmin = $true }
                    $false { $global:isAdmin = $false }
                }
                Return ($isAdmin)
            }
            Function Get-DefaultWeb 
            {
                $htDfltApps = @{}
                $RegPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
                GCI "$RegPath\*\UserChoice\" -ErrorAction SilentlyContinue | %{ $htDfltApps.Add( (get-item $_.PSParentPath).PSChildName,$_.GetValue('progId')) }
                Return $htDfltApps.http
            }
            Function Create-PieChart()
            {
                [CmdletBinding()]
                param (
                    [string]$FileName,
                    [string]$txtTitle,
                    $colorOrder,
                    [Array]$DataPoints,
                    [int]$imgWidth = 300,
                    [int]$imgHeight = 290,
                    [int]$imgLeft = 10,
                    [int]$imgTop = 10
                    )
                [void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
                [void][Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms.DataVisualization")
                #Create our chart object
                    $Chart = New-object System.Windows.Forms.DataVisualization.Charting.Chart
                    $Chart.Width = 300
                    $Chart.Height = 290
                    $Chart.Left = 10
                    $Chart.Top = 10

                # chart colour palette (must match data array order)
                    # [String[]]$colorOrder = 'brown','green'
                    # $ttlColors = 0
                    # do
                    # {
                    #     $ColorOrder[$ttlColors] = [System.Drawing.Color]::FromName(($ColorOrder[$ttlColors]))
                    #     Write-Host -f c "Converting chart Colors $( $ColorOrder[$ttlColors] )"

                    #     $ttlColors ++  
                    # }
                    # until ($ttlColors -eq $ColorOrder.Count)

                    $chart.Palette = [System.Windows.Forms.DataVisualization.Charting.ChartColorPalette]::None
                    $Chart.PaletteCustomColors = @( $colorOrder ) # @( [System.Drawing.Color]::Brown,  [System.Drawing.Color]::Gold, etc )

                #Create a chartarea to draw on and add this to the chart
                    $ChartArea = New-Object System.Windows.Forms.DataVisualization.Charting.ChartArea
                    $Chart.ChartAreas.Add($ChartArea)
                    [void]$Chart.Series.Add("Data")

                    #Add a datapoint for each value specified in the arguments (args)
                    $ttlPoints = 0
                    do
                    {
                        $dp = $DataPoints[$ttlPoints]
                        Write-Host -f y "Now processing $txtTitle chart $(  (($Filename.Split('\'))[-1]).Split('-')[0]  ) value: $($dp[0])"
                        $datapoint = new-object System.Windows.Forms.DataVisualization.Charting.DataPoint(0, $dp[-1])
                        $datapoint.AxisLabel = "$($dp[0]) (" + $dp[-1] + " GB)"
                        $Chart.Series["Data"].Points.Add($datapoint)

                        $ttlPoints ++  
                    }
                    until ($ttlPoints -eq $DataPoints.Count)

                # Set Chart styles
                    $Chart.Series["Data"].ChartType = [System.Windows.Forms.DataVisualization.Charting.SeriesChartType]::Pie
                    $Chart.Series["Data"]["PieLabelStyle"] = "Outside"
                    $Chart.Series["Data"]["PieLineColor"] = "Black"
                    $Chart.Series["Data"]["PieDrawingStyle"] = "Concave"
                    $Chart.Series["Data"].Points.FindMaxByValue()["Exploded"] = $true

                #Set the title of the Chart to the current date and time
                    $Title = new-object System.Windows.Forms.DataVisualization.Charting.Title
                    $Chart.Titles.Add($Title)
                    $Chart.Titles[0].Text = $txtTitle
                    #Save the chart to a file
                    $Chart.SaveImage($FileName,"png") # + ".png"
            }
            function Convert-Img2Html
            {
                Param ( $Image )
                    $ImageHTML = $Image | % {
                    $ImageBits = [Convert]::ToBase64String((Get-Content $_ -Encoding Byte))
                    "<img src=data:image/png;base64,$($ImageBits) alt='My Image'/>"
                    }

                ConvertTo-Html -fragment $style -PreContent $imageHTML # | Out-File "C:\path\to\report.html"
            }


            $Global:sbADSI = { Param($trg)([adsi]"LDAP://$trg,$(([adsi]'').distinguishedname)").psbase.Children };
        #endregion
        #region  * Initialize Fixed Variables
            #region - Alternate or CaC Credentials
                If ($useAltCreds.IsPresent -eq $true) { $altCredentials = (Get-Credential -UserName 'domain\user' -Message 'Enter Administrator User or Alternate User & Password') }
                If ($useCaC.IsPresent -eq $true){ $altCaCCreds = Get-SmartCardCred }
                ###  FIX-FIX-FIX  ### Define how to use captured values 
               
            #endregion
            Set-Alias -Name web       -Value "$env:ProgramFiles\Internet Explorer\iexplore.exe"
            Set-Alias -Name webEdge   -Value "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
            Set-Alias -Name webChrome -Value "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"
            Set-Alias -Name webFFox   -Value "$env:ProgramFiles\Mozilla Firefox\firefox.exe"
            ## ([system.Diagnostics.Process]::Start("msedge",""))
            $failedSystems = [System.Collections.ArrayList]@()
            $emailReports = [System.Collections.ArrayList]@()
            $Global:rgxPatterns = [psCustomObject]@{
                Email = "^[\w.]+@[\w.]+$"
                SAM = '^[a-zA_Z.]+\\[a-zA_Z.]+$'
                SID = '^S-\d{1}-\d{1}-\d{2}-+'
                GUID = '{\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}'
                UNC = '\\\\[a-zA_Z.]+\\[a-zA_Z.]+'
                IPv4 = '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
                IPv6 = '^(?:\w{4}\:)(\:\w{4}){4}' 
                MAC = '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
                cdata  = 'CDATA\[.*]]'
                };
            # Assemble the HTML Header and CSS for the Report
                $header = (Dec64 'CjxzdHlsZT4KCiAgICBoMSB7CgogICAgICAgIGZvbnQtZmFtaWx5OiBBcmlhbCwgSGVsdmV0aWNhLCBzYW5zLXNlcmlmOwogICAgICAgIGNvbG9yOiAjZTY4YTAwOwogICAgICAgIGZvbnQtc2l6ZTogMjhweDsKCiAgICB9C
                    gogICAgCiAgICBoMiB7CgogICAgICAgIGZvbnQtZmFtaWx5OiBBcmlhbCwgSGVsdmV0aWNhLCBzYW5zLXNlcmlmOwogICAgICAgIGNvbG9yOiAjMDAwMDk5OwogICAgICAgIGZvbnQtc2l6ZTogMTZweDsKCiAgICB9CgogICAgCiAgICAKICAg
                    dGFibGUgewoJCWZvbnQtc2l6ZTogMTJweDsKCQlib3JkZXI6IDBweDsgCgkJZm9udC1mYW1pbHk6IEFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7Cgl9IAoJCiAgICB0ZCB7CgkJcGFkZGluZzogNHB4OwoJCW1hcmdpbjogMHB4OwoJCWJ
                    vcmRlcjogMDsKCX0KCQogICAgdGggewogICAgICAgIGJhY2tncm91bmQ6ICMzOTU4NzA7CiAgICAgICAgYmFja2dyb3VuZDogbGluZWFyLWdyYWRpZW50KCM0OTcwOGYsICMyOTNmNTApOwogICAgICAgIGNvbG9yOiAjZmZmOwogICAgICAgIG
                    ZvbnQtc2l6ZTogMTFweDsKICAgICAgICB0ZXh0LXRyYW5zZm9ybTogdXBwZXJjYXNlOwogICAgICAgIHBhZGRpbmc6IDEwcHggMTVweDsKICAgICAgICB2ZXJ0aWNhbC1hbGlnbjogbWlkZGxlOwoJfQoKICAgIHRib2R5IHRyOm50aC1jaGlsZ
                    ChldmVuKSB7CiAgICAgICAgYmFja2dyb3VuZDogI2YwZjBmMjsKICAgIH0KICAgIAoKCiAgICAjQ3JlYXRpb25EYXRlIHsKCiAgICAgICAgZm9udC1mYW1pbHk6IEFyaWFsLCBIZWx2ZXRpY2EsIHNhbnMtc2VyaWY7CiAgICAgICAgY29sb3I6
                    ICNmZjMzMDA7CiAgICAgICAgZm9udC1zaXplOiAxMnB4OwoKICAgIH0KCgoKICAgIC5TdG9wU3RhdHVzIHsKCiAgICAgICAgY29sb3I6ICNmZjAwMDA7CiAgICB9CiAgICAKICAKICAgIC5SdW5uaW5nU3RhdHVzIHsKCiAgICAgICAgY29sb3I
                    6ICMwMDgwMDA7CiAgICB9CgoKCgo8L3N0eWxlPgo=')
            # Create the chart(s) using the Chart Function
                $stdPieSize = @{
                    imgWidth = 300
                    imgHeight = 290
                    imgLeft = 10
                    imgTop = 10
                    }
        #endregion
    }
    PROCESS
    {
        #Invoke-Command -ComputerName (& HostName) -Credential $altCaCCreds -ScriptBlock {
        ForEach ($System in $Systems)
        {

            #region  * Collect Relevant Data
                # Set temp file name and location
                    $filename = "SystemReport_$($System)_$(Get-Date -f yyyyMMdd-HHmm)"
                    $lclWrkTmpPath = $(If ($PSVersionTable.PSVersion.Major -ge 5) { (New-TemporaryFile).DirectoryName } Else { [System.IO.Path]::GetTempFileName() -replace '\\+[^\\]+$' })
                # Add name of the computer to Report
                    $SystemName = "<h1>Computer name:  $System</h1>"


                # If unreachable, create failed report otherwise collect data
                    If ([Bool](Test-Connection -ComputerName $system -Count 2 -Quiet) -eq $true)
                    {
                        $failedSystems.Add("$system`,$(Get-Date -F 'MM-dd-yyyy,HH:mm:ss')`,Failed")

                        $rptContext =  "<h2>Unable to reach [$system] at $(Get-Date -F 'MM-dd-yyyy *HH:mm:ss')</h2>"
                    }
                    Else
                    {
                        # Is Report in ADMIN context?
                            $rptContext =  "<h2>System Report Run As Admin: $(Test-IsAdmin)</h2>"
                        #region Collect System Data Points
                            #region System Info
                                $fmtUT = '{0:00} Days, {1:00} Hours, {2:00} Minutes, {3:00} Seconds'
                                Try 
                                {
                                    $OSinfo = Get-CimInstance -Class Win32_OperatingSystem -computername $System -ea Stop |
                                        Select Version,Caption,BuildNumber,Manufacturer,LastBootUpTime,
                                        @{n='Uptime';e={$ut = ((Get-Date) *$_.LastBootUpTime);$fmtUT -f $ut.Days, $ut.Hours, $ut.Minutes, $ut.Seconds}},
                                        @{n='Memory Total (GB)';e={$_.TotalVisibleMemorySize | Measure-Object -Sum | % {[Math]::Round($_.sum/1024/1024,1)}}},
                                        @{n='Memory Free (GB)';e={$_.FreePhysicalMemory | Measure-Object -Sum | % {[Math]::Round($_.sum/1024/1024,1)}}}
                                }
                                Catch
                                {
                                    $OSinfo = Get-WmiObject -Class Win32_OperatingSystem -computername $System |
                                        Select Version,Caption,BuildNumber,Manufacturer,@{n='LastBootUpTime';e={Get-date $_.ConvertToDateTime($_.LastBootUpTime)}},
                                        @{n='Uptime';e={$ut = ((Get-Date) *$_.LastBootUpTime);$fmtUT -f $ut.Days, $ut.Hours, $ut.Minutes, $ut.Seconds}},
                                        @{n='Memory Total (GB)';e={$_.TotalVisibleMemorySize | Measure-Object -Sum | % {[Math]::Round($_.sum/1024/1024,1)}}},
                                        @{n='Memory Free (GB)';e={$_.FreePhysicalMemory | Measure-Object -Sum | % {[Math]::Round($_.sum/1024/1024,1)}}}
                                }
                                $RamPie = @{
                                    FileName = ($lclWrkTmpPath + '\' + "$($filename)_chartRAM.png")
                                    txtTitle = 'RAM Usage Chart (Used/Free)'
                                    colorOrder = ([System.Drawing.Color]::LightGreen, [System.Drawing.Color]::Gold)
                                    DataPoints = @('Free',$OSinfo.'Memory Free (GB)'),@('Used',($OSinfo.'Memory Total (GB)' *$OSinfo.'Memory Free (GB)'))
                                    }
                                Create-PieChart @RamPie

                                $SysInfo = ($OSinfo | ConvertTo-Html -As List -Fragment -PreContent "<h2>Operating System Information</h2>") -replace '</table>',"</table>`n$(Convert-Img2Html $ramPie.FileName)"
                                Remove-Item -Path $RamPie.FileName -Force
                            #endregion
                            #region BIOS Info
                                $Bios = Get-CimInstance -ClassName Win32_BIOS -ComputerName $System | Select SMBIOSBIOSVersion,Manufacturer,Name,SerialNumber
                                $BiosInfo = $Bios | ConvertTo-Html -As List -Fragment -PreContent "<h2>BIOS Information</h2>"
                            #endregion
                            #region Processor Info
                                $Procs = Get-WmiObject Win32_Processor -computername $System |
                                    Select @{n='ID';e={$_.DeviceID}},@{n='Family';e={$_.Caption}},
                                            @{n='Description';e={$_.Name}},@{n='Mfgr';e={$_.Manufacturer}},
                                            @{n='Max ClockSpeed';e={$_.MaxClockSpeed}},@{n='Core Count';e={$_.NumberOfCores}},
                                            @{n='Cores Enabled';e={$_.NumberOfEnabledCore}},@{n='Thread Count';e={$_.ThreadCount}},
                                            @{n='Socket';e={$_.SocketDesignation}}
                                $ProcInfo = $Procs | ConvertTo-Html -Fragment -As List  -PreContent "<h2>Processor Information</h2>"
                            #endregion
                            #region RAM Metrics
                                $sysMem = @{} | Select Total,Free,UsedRAM,PercentFree
                                    $sysMem.Total = $OSinfo.'Memory Total (GB)'
                                    $sysMem.Free = $OSinfo.'Memory Free (GB)'
                                    $sysMem.UsedRAM = ($OSinfo.'Memory Total (GB)' *$OSinfo.'Memory Free (GB)')
                                    $sysMem.PercentFree = [Math]::Round(($OSinfo.'Memory Free (GB)' / $sysMem.Total) * 100, 2)

                                $sysMemInfo = $sysMem | ConvertTo-Html -Fragment -Property Total,Free,UsedRAM,PercentFree -PreContent "<h2>Memory Stats</h2>"
                            #endregion
                            #region Process Metrics
                                $TopProcesses = Get-Process -ComputerName $System |
                                    Sort WS -Descending |
                                    Select ProcessName, Id, WS -First $ProccessNumToFetch
                                $ProcessInfo = $TopProcesses | ConvertTo-Html -Fragment -PreContent "<h2>ACTIVE Processes ($ProccessNumToFetch Selected)</h2>"
                            #endregion
                            #region Disk Metrics
                                Try
                                {
                                    $DiskInfo = Get-CimInstance -ComputerName $System Win32_LogicalDisk -ea Stop | Where-Object VolumeName -ne $colDrv_VolName |
                                        Where-Object{$_.DriveType -eq 3} | Where-Object{ ($_.freespace/$_.Size)*100 -lt $drvFreeSpaceTest}
                                }
                                Catch
                                {
                                    $DiskInfo = Get-WmiObject -ComputerName $System Win32_LogicalDisk | Where-Object VolumeName -ne $colDrv_VolName |
                                    Where-Object{$_.DriveType -eq 3} | Where-Object{ ($_.freespace/$_.Size)*100 -lt $drvFreeSpaceTest}
                                     
                                }
                                Finally { If ($DiskInfo -eq $null){$DiskInfo = 'No Data'} }
                                If($DiskInfo -ne 'No Data')
                                {
                                    $DiskInfo = $DiskInfo | Select-Object Name, VolumeName, DriveType,  @{n='Size (GB)';e={"{0:n2}" -f ($_.size/1gb)}},
                                                @{n='FreeSpace (GB)';e={"{0:n2}" -f ($_.freespace/1gb)}}, @{n='PercentFree';e={"{0:n2}" -f ($_.freespace/$_.size*100)}}
                                    ForEach ($disk in $DiskInfo)
                                    {
                                        $dskChart = $Disk | Select @{n='size';e={$_.'Size (GB)'}},@{n='free';e={$_.'FreeSpace (GB)'}}
                                        $DiskPie = @{
                                            FileName = ($lclWrkTmpPath + '\' + "$($filename)_chartDISK_$(($disk.Name)[0]).png")
                                            txtTitle = 'Drive Freespace Chart (Free/Used)'
                                            colorOrder = ([System.Drawing.Color]::Green, [System.Drawing.Color]::Brown)
                                            DataPoints = @('Free',($dskChart.free)),@('Used',(($dskChart.Size) *($dskChart.free)))
                                            }
                                        Create-PieChart @DiskPie # @stdPieSize
                                        #$img2Html = Convert-Img2Html $DiskPie.FileName
                                        Sleep -Seconds 2
                                        $DskInfo += ($Disk | ConvertTo-HTML -fragment -As List -PreContent "<h3> Disk [$($disk.Name)]</h3>") -replace '</table>',"$(Convert-Img2Html $DiskPie.FileName)`n</table>"
                                        Remove-Item -Path $DiskPie.FileName -Force
                                    }
                                    $DrvTitle = "<h2>Disk Information</h2>`n<DATA>"
                                    $DrvInfo = $DrvTitle -replace '<DATA>',$DskInfo
                                }
                                Else
                                {
                                    $DrvInfo = "<h2>Hard Disk Information</h2>`n<table>`n<tr><td>No</td><td>Data</td></tr>`n</table>"
                                }
                            #endregion
                            #region Net Config
                                $NICs = gwmi Win32_NetworkAdapterConfiguration -ComputerName $System
                                # Collect only NICs with IP Addresses
                                ForEach ($NIC in ($NICs | Where-Object{$_.ipaddress}))
                                {
                                    $IPv4 = $NIC.IPAddress | where { $_ -Match $rgxPatterns.IPv4 }
                                    $IPv6 = $NIC.IPAddress | where { $_ -Match $rgxPatterns.IPv6 }
                                    $ipAssignment = $(If ($NIC.DHCPEnabled -eq $true){'Dhcp'}Else{'Static'})

                                    $NicInfo = [Ordered]@{} | Select Primary,MACAddress,IpAddresses,Ipv4Address,Ipv6Address,DHCPEnabled,DHCPServer,AssignmentType,DefaultGateway,'DNS Servers',DNSDomain,ServiceName,Description,Index,' ',DomainContext,FQDNBreakdown
                                        $NicInfo.Primary        = If ($NIC.DefaultIPGateway -ne $null)  { 'True' } Else { 'False' }
                                        $NicInfo.MACAddress     = If ($NIC.MACAddress -eq $null)  { 'No Data' } Else { $NIC.MACAddress | Out-String }
                                        $NicInfo.IpAddresses    = If ($NIC.IpAddress -eq $null)  { 'No Data' } Else { $NIC.IpAddress | Out-String }
                                        $NicInfo.Ipv4Address    = If ($IPv4 -eq $null)  { 'No Data' } Else { $IPv4 }
                                        $NicInfo.Ipv6Address    = If ($IPv6 -eq $null)  { 'No Data' } Else { $IPv6 }
                                        $NicInfo.DHCPEnabled    = If ($NIC.DHCPEnabled -eq $null)  { 'No Data' } Else { $NIC.DHCPEnabled }
                                        $NicInfo.DHCPServer     = If ($NIC.DHCPEnabled -eq $null)  { 'No Data' } Else { $NIC.DHCPServer  }
                                        $NicInfo.AssignmentType = 'No Data'
                                            If ($IPv4 -eq $null){  }
                                            ElseIf ($IPv4 -match "^169.254.*"){ $NicInfo.AssignmentType = 'APIPA' }
                                            ElseIf ($NIC.DHCPEnabled -eq $true -AND $IPv4 -match $rgxPatterns.IPv4 -AND $IPv4 -notmatch "^169.254.*"){ $NicInfo.AssignmentType = 'DHCP' }
                                            ElseIf ($NIC.DHCPEnabled -eq $false -AND $IPv4 -match $rgxPatterns.IPv4 -AND $IPv4 -notmatch "^169.254.*"){ $NicInfo.AssignmentType = 'STATIC' }
                                        $NicInfo.DefaultGateway = If ($NIC.DefaultIPGateway -eq $null)  { 'No Data' } Else { $NIC.DefaultIPGateway | Select -ExpandProperty $_ }
                                        $NicInfo.'DNS Servers'  = If ($NIC.DNSServerSearchOrder -eq $null)  { 'No Data' } Else { $NIC | Select-Object -Exp DNSServerSearchOrder -First 1 | Out-String }
                                        $NicInfo.DNSDomain      = If ($NIC.DNSDomain -eq $null)  { 'No Data' } Else { $NIC.DNSDomain }
                                        $NicInfo.ServiceName    = If ($NIC.ServiceName -eq $null){ 'No Data' } Else { $NIC.ServiceName }
                                        $NicInfo.Description    = If ($NIC.Description -eq $null){ 'No Data' } Else { $NIC.Description }
                                        $NicInfo.Index          = If ($NIC.Index -eq $null)      { 'No Data' } Else { $NIC.Index }
                                        $NicInfo.DomainContext  = Try { ([ADSI]"LDAP://RootDSE").Get("rootDomainNamingContext") } Catch { 'No Data' }
                                        $NicInfo.FQDNBreakdown  = Try { @(([adsi]'').distinguishedname,"OU=$($env:UserDomain),","OU=$($env:UserDomain)_NEW,",$env:UserDomain,$env:UserDNSDomain).ToLower() | Out-String } Catch { 'No Data' }

                                    $NetInfo = $NetInfo + $NicInfo
                                }
                                $NetInfo = $NetInfo | ConvertTo-Html -Fragment -as List -PreContent "<h2>Network Information</h2>"
                            #endregion
                            #region Share Info
                                $trgShares = Get-SMBShare | Select Name,Path,Description,@{n='State';e={$_.ShareState}}
                                $trgShareData = @()
                                ForEach ($trg in $trgShares)
                                {
                                    $acl = [PSCustomObject]@{
                                        Name = $trg.Name
                                        Path = $trg.Path
                                        Description = $trg.Description
                                        State = $trg.State
                                        }
                                        $item =  $trg | Get-SmbShareAccess | Select @{n='Account';e={$_.AccountName}},@{n='AclType';e={$_.AccessControlType}},@{n='AclRight';e={$_.AccessRight}}
                                        $i = 0
                                        ForEach ($itm in $item)
                                        {
                                            $I ++
                                            Add-Member -InputObject $acl -MemberType NoteProperty -Name "ACL-$i" -Value "$($itm.Account)`t$($itm.AclType)`t $($itm.AclRight)"
                                        }
                                    $trgShareData += $acl
                                }
                                $ShareInfo = $trgShareData | ConvertTo-Html -Fragment -PreContent "<h2>Network Share Information</h2>"
                            #endregion
                            #region Stopped Automated Services
                                $ServicesReport = @()
                                $Services = Get-WmiObject -Class Win32_Service -ComputerName $System | Where {($_.StartMode -eq "Auto") -and ($_.State -eq "Stopped")}
                                foreach ($Service in $Services)
                                {
                                    $row = New-Object -Type PSObject -Property @{
                                        Name = $Service.Name
                                        Status = $Service.State
                                        StartMode = $Service.StartMode
                                        }
                                    $ServicesReport += $row
                                }
                                $SvcInfo = $ServicesReport | ConvertTo-Html -Fragment -PreContent "<h2>Stopped Automatic Services</h2>"
                            #endregion
                            #region Event Logs Report
                                $SystemEventsReport = @()
                                $SystemEvents = Get-EventLog -ComputerName $System -LogName System -EntryType Error,Warning -Newest $evtCount
                                foreach ($event in $SystemEvents)
                                {
                                    $row = New-Object -Type PSObject -Property @{
                                        TimeGenerated = $event.TimeGenerated
                                        EntryType = $event.EntryType
                                        Source = $event.Source
                                        Message = $event.Message
                                        }
                                    $SystemEventsReport += $row
                                }
                                $evtSystemInfo = $SystemEventsReport | ConvertTo-Html -Fragment -PreContent "<h2>$evtCount Most Recent Events [System]</h2>"

                                $ApplicationEventsReport = @()
                                $ApplicationEvents = Get-EventLog -ComputerName $System -LogName Application -EntryType Error,Warning -Newest $evtCount
                                foreach ($event in $ApplicationEvents)
                                {
                                    $row = New-Object -Type PSObject -Property @{
                                        TimeGenerated = $event.TimeGenerated
                                        EntryType = $event.EntryType
                                        Source = $event.Source
                                        Message = $event.Message
                                        }
                                    $ApplicationEventsReport += $row
                                }
                                $evtApplicationInfo = $ApplicationEventsReport | ConvertTo-Html -Fragment -PreContent "<h2>$evtCount Most Recent Events [Application]</h2>"

                                # Skip Security Log if not in ADMIN Context
                                    If ((Test-IsAdmin) -eq $true)
                                    {
                                        $SecurityEventsReport = @()
                                        $SecurityEvents = Get-EventLog -ComputerName  $Systems -LogName Security -EntryType failureAudit -Newest 15 $evtCount -ea SilentlyContinue  # SuccessAudit
                                        foreach ($event in $SecurityEvents)
                                        {
                                            $row = New-Object -Type PSObject -Property @{
                                                TimeGenerated = $event.TimeGenerated
                                                EntryType = $event.EntryType
                                                Source = $event.Source
                                                Message = $event.Message
                                                }
                                            $SecurityEventsReport += $row
                                        }
                                        $evtSecurityInfo = $SecurityEventsReport | ConvertTo-Html -Fragment -PreContent "<h2>$evtCount Most Recent Events [Security]</h2>"
                                    }
                                    Else
                                    {
                                        $evtSecurityInfo = "<h2>$evtCount Most Recent Events [Security]</h2>`n<table>`n<tr><td>No Data</td><td>Elevated Privledges Required to access Security Event Log</td></tr>`n</table>"
                                    }
                            #endregion
                            #region Installed Applications
                                $ApplicationReport = @()
                                Switch ($srchMethod)
                                {
                                    'WMI'
                                    {
                                        $Apps = Get-CimInstance -ClassName Win32_Product -ComputerName $System | Select Name,Caption,Description,Version,Vendor,InstallDate,IdentifyingNumber,URLInfoAbout,URLUpdateInfo,InstallSource,PackageName,Transforms
                                        # This method is quite easy. But it has a downside that it takes quite a while to return the results.

                                        foreach ($App in $Apps)
                                        {
                                            $row = @{} | Select-Object Name,Info,Version,Vendor,ID,InstallDate,URLs,Installer
                                                $row.Name = $App.Name
                                                $row.Info = ("Caption:  $($App.Caption)" + ([Environment]::NewLine) + "Description:  $($App.Description)" | Out-String)
                                                $row.Version = $App.Version
                                                $row.Vendor = "$(If([string]::IsNullOrEmpty($App.Vendor)){ "Unknown" } else { "$($App.Vendor)" })"
                                                $row.ID = "$(If([string]::IsNullOrEmpty($App.IdentifyingNumber)){ "Unknown" } else { "$($App.IdentifyingNumber)" })"
                                                $row.InstallDate = "$(If([string]::IsNullOrEmpty($App.InstallDate)){ "Unknown" } else { "$($App.InstallDate)" })"
                                                If([string]::IsNullOrEmpty($App.URLInfoAbout) -OR $App.URLInfoAbout -notmatch '^http'){ $urlAbout = "Unknown" } else { $urlAbout =  "$($App.InstallDate)" }
                                                If([string]::IsNullOrEmpty($App.URLUpdateInfo) -OR $App.URLUpdateInfo -notmatch '^http'){ $urlUpdate = "Unknown" } else { $urlUpdate = "$($App.URLUpdateInfo)" }
                                                $row.URLs = ("urlAbout: $urlAbout" + ([Environment]::NewLine) + "urlUpdate: $urlUpdate" | Out-String)
                                                $row.Installer = "$($App.InstallSource)\$($App.PackageName) *$(If([string]::IsNullOrEmpty($App.Transforms)){ "Xforms:None" } else { "Xforms:$($App.Transforms)" })"
                                            $ApplicationReport += $row
                                        }
                                    }
                                    'REG'
                                    {
                                        $regSWKeys = @{
                                            HKLM = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                                            HKLM32 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                                            HKCU = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
                                            HKCU32 = 'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
                                            }
                                        $Scopes = @{
                                            HKLM = 'All Users'
                                            HKCU = 'Current User'
                                            }
                                        $Architectures = @{
                                            $true = '32-Bit'
                                            $false = '64-Bit'
                                            }
                                        #region define calculated custom properties:
                                            # add the scope of the software based on whether the key is located
                                            # in HKLM: or HKCU:
                                            $Scope = [Ordered]@{
                                                Name = 'Scope'
                                                Expression = {$Scopes[$_.PSDrive.Name]}
                                                }

                                            # add architecture (32*or 64-bit) based on whether the registry key
                                            # contains the parent key WOW6432Node:
                                            $Architecture = [Ordered]@{
                                                Name = 'Architecture'
                                                Expression = {$Architectures[$_.PSParentPath -like '*\WOW6432Node\*']}
                                                }
                                        #endregion
                                        # Define the properties (registry values) to include into the result:
                                            $Values = 'AuthorizedCDFPrefix','Comments','Contact','DisplayName','DisplayVersion','EstimatedSize','HelpLink','HelpTelephone',
                                                        'InstallDate','InstallLocation','InstallSource','Language','ModifyPath','NoModify','PSChildName','PSDrive',
                                                        'PSParentPath','PSPath','PSProvider','Publisher','Readme','Size','SystemComponent','UninstallString',
                                                        'URLInfoAbout','URLUpdateInfo','Version','VersionMajor','VersionMinor','WindowsInstaller','Scope','Architecture'
                                        # Define the VISIBLE properties (that should be visible by default (keep this below 5 to produce table output))
                                            [string[]]$visible = 'DisplayName','DisplayVersion','Scope','Architecture', 'InstallDate'
                                            [Management.Automation.PSMemberInfo[]]$visibleProperties = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',$visible)
                                        #region read software from all four keys in Windows Registry:
                                            # read all four locations where software can be registered, and ignore non-existing keys

                                            ###  FIX-FIX-FIX  ### Access Denied error using computername switch
                                            $ApplicationReport = Invoke-Command  -ComputerName $System -ArgumentList $DisplayName -ScriptBlock {
                                                # emit only software that matches the value you submit:
                                                param ( [string] $DisplayName = '*' )
                                    
                                                Return (Get-ItemProperty -Path $regSWKeys.HKLM,$regSWKeys.HKLM32,$regSWKeys.HKCU,$regSWKeys.HKCU32 -ErrorAction Ignore |
                                                Where-Object DisplayName |                               ## exclude items with no DisplayName
                                                Where-Object { $_.DisplayName -like $DisplayName } |     ## include only items that match the user filter
                                                Select-Object -Property *, $Scope, $Architecture |       ## add the two calculated properties defined earlier
                                                Select-Object -Property $values |                        ## create final objects with all properties we want
                                                Sort-Object -Property DisplayName, Scope, Architecture | ## sort by name, then scope, then architecture
                                                Add-Member -MemberType MemberSet -Name PSStandardMembers -Value $visibleProperties -PassThru)  # add the property PSStandardMembers so PowerShell knows which properties to display by default:
                                                }
                                        #endregion
                                    }
                                    'PKG' ###  FIX-FIX-FIX  ### needs config
                                    {
                                            $T = Get-Package -IncludeSystemComponent -IncludeWindowsInstaller -AllVersions -ProviderName
                                            $T.count
                                            $T[0].Metadata.Keys | Select *
                                            $T[0] | Select Name,Version,FullPath,FromTrustedSource,FastPackageReference,IsCorpus,IsPatch,IsSupplemental,Links,Meta,Metadata,PackageFilename,Payload,ProviderName,SearchKey,Source,Status,Summary,SwidTags,SwidTagText,TagId,TagVersion,VersionScheme
                                            ($T[0].Metadata).GetHashCode() 
                                            $T |GM
                                    }
                                }

                                $AppInfo = $ApplicationReport | ConvertTo-Html -Fragment -PreContent "<h2>Installed Applications</h2>"
                            #endregion
                            #region RECENTLY Installed Applications
                                $recentSoftwareReport = Get-WinEvent -ComputerName $system -ProviderName msiinstaller |
                                                            where id -eq 1033 | Sort Timecreated -desc | 
                                                            select @{n='Install Date';e={$_.timecreated}},@{n='SWInfo';e={$_.message}} -First $newAppCount
                                $rnctSWInfo = $recentSoftwareReport | ConvertTo-Html -Fragment -PreContent "<h2>Most Recently Installed Applications ($newAppCount)</h2>"
                            #endregion
                            #region Installed Features (Servers Only)
                                If ((Gwmi win32_OperatingSystem -ComputerName $system).ProductType -eq 1)
                                { $FeatureInfo = "<h2>Installed Features & Roles</h2>`n<table>Client-level OS, No Featues/Roles to review</table>" }
                                Else
                                {
                                    $FeatureReport = Get-WindowsFeature -ComputerName $system | Where-Object { $_. installstate -eq "installed" } 
                                    $FeatureInfo = $FeatureReport | Select Name,Path,FeatureType | Sort Path | ConvertTo-Html -Fragment -PreContent "<h2>Installed Features & Roles</h2>"
                                }
                            #endregion
                        #endregion

                        $failedSystems.Add("$system`,$(Get-Date -F 'MM-dd-yyyy,HH:mm:ss')`,Success")
                    }
            #endregion
                    
            #region  -  Assemble System Report
                # Combine all the information gathered into a single HTML report
                    $Report = ConvertTo-HTML `
                        -Body "$SystemName $rptContext $SysInfo $BiosInfo $ProcInfo $sysMemInfo $ProcessInfo $DrvInfo $NetInfo $ShareInfo $SvcInfo $evtSystemInfo $evtApplicationInfo $evtSecurityInfo $AppInfo $FeatureInfo $rnctSWInfo"  `
                        -Head $header -Title "Computer Information Report - $Systems" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date) User:$env:UserName</p>"
            #endregion

            #region  -  Process System Report

                # Save the report to the collection drive or, if drive not attached, save to main temp path
                    # Determine Output Path (Create if needed)
                        $drvList = Get-CimInstance -ComputerName $System Win32_LogicalDisk -ea Stop
                        If ($drvList.VolumeName -contains $colDrv_VolName)  { $colPath = "$(($drvList | Where VolumeName -match $colDrv_VolName).DeviceID)\SystemReports" }
                        Else { $colPath = "$env:SystemDrive\Temp\SystemReports" }
                        If ((Test-Path $colPath) -eq $false) { New-Item -Path $colPath -ItemType Directory }
                        $reportPath = $colPath 
                
                    # Name Output File and save 
                        $outFile = "$($reportPath + '\' + $filename).html"
                        $Report | Out-File ($outFile) -Force

                    # Only open report if running individually on local system
                        $browser = Get-DefaultWeb

                        If ($Systems.Count -le 1 -and $system -eq (& HostName))
                        {
                            Switch ($browser)
                            {
                                {$_ -match 'MSEdgeHTM'}    { webEdge --profile-directory=Default $outFile }
                                {$_ -match 'ChromeHTML'}   { webChrome $outFile }
                                {$_ -match 'FirefoxURL'}   { webFFox $outFile }
                                default                    { Web $outFile }
                            }
                        }


                    # If email option is selected, add report to attachment list
                        If (($email.IsPresent) -eq $true){ $emailReports.add($outFile) }
            #endregion
        }
        #}
    }
    END
    {
        # Re-format runtime metadata
            $failedSystems = $failedSystems | ConvertFrom-Csv -Delimiter ',' -header System,Date,Time,Status
        
        # TEMP Output for MetaData
            ForEach ($fs in ($failedSystems | ? Status -eq 'Failed')) { $fs }
            ForEach ($fs in ($failedSystems | ? Status -eq 'Success')) { $fs }

        # Email the report(s) out
            If (($email.IsPresent) -eq $true)
            {
                $eml = @{
                    from = $emailFrom
                    to = $emailTo
                    subject = "Systems Report - $Systems"
                    BodyAsHTML = $true
                    body = $Report
                    priority = 'Normal'
                    smtpServer = $emailSvr
                    Attachments = $emailReports
                    }
                Send-MailMessage @eml
            }
    }
}


Get-SystemReport @rptParams
