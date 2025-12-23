#region - DL Latest Adobe Reader
    # rv ftp*
    $lclPath = $updPath 
    $ftpFolderUrl = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"

    #connect to ftp, and get directory listing
        $ftpRequest = [System.Net.FtpWebRequest]::Create("$ftpFolderUrl") 
        $ftpRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
        $ftpResponse = $ftpRequest.GetResponse()
        $ResponseStream = $ftpResponse.GetResponseStream()
        $ftpReader = New-Object System.IO.Streamreader -ArgumentList $ResponseStream
        $DirList = $ftpReader.ReadToEnd()

    # from Directory Listing get last entry in list of any numeric version
        $LatestUpdate = $DirList -split '[\n]' | Where {$_ -match '^\d'} | Sort | Select -Last 1

    # build file name & download url for latest file
        $LatestFile = "AcroRdrDCUpd" + $LatestUpdate + "_MUI.msp"
        $DownloadURL = "$ftpFolderUrl$LatestUpdate/$LatestFile"

    # download the file
        (New-Object System.Net.WebClient).DownloadFile($DownloadURL, $LatestFile)
        (New-Object System.Net.WebClient).DownloadFile($DownloadURL, ($lclPath + '\' + $LatestFile))
#endregion

#region - Idea 1
$t = "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/"

$r = Invoke-WebRequest -uri $t
$r.ParsedHtml.body.getElementsByTagName('Div')
#endregion
#region - Idea 2
$URI = "https://ardownload.adobe.com"
$HTML = Invoke-WebRequest -Uri $URI
$HTML.links | Out-Gridview
$HTML.AllElements | Out-Gridview
#endregion
#region - Idea 3
$baseuri = 'https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC'

$response = Invoke-WebRequest -Uri $baseuri -UseBasicParsing -TimeoutSec 10

$updatelist = switch -Regex ($response.Content -split '<li>'){
    'href="(?<URL>.+?)".+?(?<Version>\d{2}\.\d+?\.[\d\w]+?) (?<Type>[\w\s]+?), (?<Date>\w+? \d+, \d+)' {
        [PSCustomObject]@{
            Version = $matches.Version
            Type    = $matches.Type
            Date    = $matches.Date
            URL     = "$baseuri/{0}" -f $matches.Url
        }
    }

    'href="(?<URL>.+?)".+?(?<Win>\d{2}\.\d+?\.[\d\w]+? \(Win\)), (?<Mac>\d{2}\.\d+?\.[\d\w]+? \(Mac\)) (?<Type>[\w\s]+?), (?<Date>\w+? \d+, \d+)' {
        $ht = [ordered]@{
            Version = $matches.win
            Type    = $matches.Type
            Date    = $matches.Date
            URL     = "$baseuri/{0}" -f $matches.Url
        }

        [PSCustomObject]$ht

        $ht.Version = $matches.mac
    
        [PSCustomObject]$ht
    }
}
#endregion
#region - Idea 4
$ftp = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"
 
# We have to use .NET to read a directory listing from FTP, it is different than downloading a file.
# Original C# code at https://docs.microsoft.com/en-us/dotnet/framework/network-programming/how-to-list-directory-contents-with-ftp
 
$request = [System.Net.FtpWebRequest]::Create($ftp);
$request.Credentials = [System.Net.NetworkCredential]::new("anonymous", "password");
$request.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectoryDetails;
[System.Net.FtpWebResponse]$response = [System.Net.FtpWebResponse]$request.GetResponse();
[System.IO.Stream]$responseStream = $response.GetResponseStream();
[System.IO.StreamReader]$reader = [System.IO.StreamReader]::new($responseStream);
$DirList = $reader.ReadToEnd()
$reader.Close()
$response.close()

https://get.adobe.com/reader/download?os=Windows+11&lang=en&nativeOs=Windows+10&accepted=&declined=mss%2Ccr&preInstalled=&site=otherversions
https://get.adobe.com/reader/download?os=Windows+10&name=Reader+2023.006.20320+English+Windows%2864Bit%29&lang=en&nativeOs=Windows+10&accepted=1&declined=0&preInstalled=&site=enterprise
https://get.adobe.com/reader/download?os=Windows+10&name=Reader+2023.006.20320+English+for+Windows&lang=en&nativeOs=Windows+10&accepted=&declined=&preInstalled=&site=enterprise

# Download Newest Version Adobe Reader DC
$web = Invoke-WebRequest -Uri 'https://get.adobe.com/reader/download?os=Windows+10&lang=en&nativeOs=Windows+10&accepted=1&declined=0&preInstalled=&site=enterprise' -UseBasicParsing
$web = Invoke-WebRequest -Uri 'https://get.adobe.com/reader/?loc=us' -UseBasicParsing
$version = [regex]::match($web.Content,'Version ([\d\.]+)').Groups[1].Value.Substring(2).replace('.','')
$URI = "http://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/$Version/AcroRdrDC$($Version)_de_DE.exe"
$OutFile = "$env:USERPROFILE\Desktop\AcroRdrDC$($Version)_de_DE.exe"
Invoke-WebRequest -Uri $URI -OutFile $OutFile -Verbose
#endregion
#region - Idea 5
# Get Current Adobe reader version.
$CurrentReaderVersion = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object{$_.DisplayName -like "*Adobe*" -and $_.DisplayName -like "*Reader*"}

# If reader is installed then...
If ($CurrentReaderVersion -ne $null) {

# Tidy version to numeric string.
$CurrentReaderVersion = ($CurrentReaderVersion.DisplayVersion.ToString()).Replace(".","")

# Set download folder and ftp folder variables
$DownloadFolder = "C:\Windows\Temp\"
$FTPFolderUrl = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"

#connect to ftp, and get directory listing
$FTPRequest = [System.Net.FtpWebRequest]::Create("$FTPFolderUrl")
$FTPRequest.Method = [System.Net.WebRequestMethods+Ftp]::ListDirectory
$FTPResponse = $FTPRequest.GetResponse()
$ResponseStream = $FTPResponse.GetResponseStream()
$FTPReader = New-Object System.IO.Streamreader -ArgumentList $ResponseStream
$DirList = $FTPReader.ReadToEnd()

#from Directory Listing get last entry in list, but skip one to avoid the 'misc' dir
$LatestUpdate = $DirList -split '[\r\n]' | Where {$_} | Select -Last 1 -Skip 1

# Compare latest availiable update version to currently installed version.
If ($LatestUpdate -ne $CurrentReaderVersion){

#build file name
$LatestFile = "AcroRdrDC" + $LatestUpdate + "_en_US.exe"

#build download url for latest file
$DownloadURL = "$FTPFolderUrl$LatestUpdate/$LatestFile"

# Build filepath
$FilePath = "$DownloadFolder$LatestFile"

#download file
"1. Downloading latest Reader version."
(New-Object System.Net.WebClient).DownloadFile($DownloadURL, $FilePath)

# Install quietly
"2. Installing."
Start $FilePath /sAll -NoNewWindow -Wait

# Clean up after install
"3. Cleaning."
Remove-Item -Path $FilePath
}

Else
{"Latest version already installed."}
}

Else
{"Reader not installed."}
#endregion
#region - Idea 6
#requires -version 4
Set-StrictMode -Version 4

Function Get-AdobeReaderManifest() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader manifest file.

    .DESCRIPTION
    Gets the Adobe Reader manifest file.

    .PARAMETER ManifestType
    The type of manifest.

    .PARAMETER Path
    The folder path to save the manifest to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ARM'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'Reader'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ReaderServices' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderManifest -ManifestType 'ReaderServices' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The type of manifest')]
        [ValidateSet('ARM','Reader','ReaderServices', IgnoreCase = $true)]
        [string]$ManifestType,

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the manifest to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $baseUri = ''
    
    $installer = ''

    switch($ManifestType.ToLower()) {
        'arm' { $installer = 'ArmManifest.msi' ; $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/{1}' ; break }
        'reader' { $installer = 'ReaderDCManifest.msi' ;  $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/{1}'; break }
        'readerservices' { $installer = 'RdrManifest.msi' ; $baseUri = '{0}://armmf.adobe.com/arm-manifests/win/ServicesUpdater/DC/{1}' ; break }
        default { $installer = '' }
    }

    $uri = ($baseUri -f $protocol,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Get-AdobeReaderOfflineInstaller() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader offline installer file.

    .DESCRIPTION
    Gets the Adobe Reader offline installer file.

    .PARAMETER Version
    Specifies an Adobe Reader version.

    .PARAMETER Multilingual
    Get the Multilingual User Interface (MUI) version of Adobe Reader.

    .PARAMETER Path
    The folder path to save the installer to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.010.20060' -Multilingual

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.10.20060.0' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderOfflineInstaller -Version '2015.10.20060.0' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$Version,

        [Parameter(Mandatory=$false, HelpMessage='Get the Multilingual User Interface (MUI) version of Adobe Reader')]
        [switch]$Multilingual,     

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the installer to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $major = [string]$Version.Major

    if ($major.Length -gt 2) {
        $major = $major[-2,-1] -join '' # we only want the last 2 numbers
    }

    $minor = [string]$Version.Minor

    if ($minor.Length -lt 3) {
        $minor = '{0:000}' -f [Int32]$minor # force 0 padding to work
    }

    $build = [string]$Version.Build

    $formattedVersion = '{0}{1:000}{2}' -f $major,$minor,$build

    $installer = 'AcroRdrDC{0}_en_US.exe' -f $formattedVersion

    if ($Multilingual) {
        $installer = 'AcroRdrDC{0}_MUI.exe' -f $formattedVersion
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/{1}/{2}' -f $protocol,$formattedVersion,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

#todo: investigate incremental updates: http://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/1501720053/AcroRdrDCUpd1501720053_incr.msp
Function Get-AdobeReaderPatch() {
    <#
    .SYNOPSIS
    Gets the Adobe Reader .msp patch file.

    .DESCRIPTION
    Gets the Adobe Reader .msp patch file.

    .PARAMETER Version
    Specifies an Adobe Reader version.

    .PARAMETER Multilingual
    Get the Multilingual User Interface (MUI) version of Adobe Reader.

    .PARAMETER Path
    The folder path to save the patch file to.

    .PARAMETER UseHTTP
    Use HTTP instead of HTTPS.

    .EXAMPLE
    Get-AdobeReaderPatch -Version '15.010.20060.0'

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.010.20060' -Multilingual

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.10.20060.0' -Path 'C:\AdobeReader'

    .EXAMPLE
    Get-AdobeReaderPatch -Version '2015.10.20060.0' -Path 'C:\AdobeReader' -UseHTTP
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$true, HelpMessage='The Adobe Reader version')]
        [System.Version]$Version,

        [Parameter(Mandatory=$false, HelpMessage='Get the Multilingual User Interface (MUI) version of Adobe Reader')]
        [switch]$Multilingual,     

        [Parameter(Mandatory=$false, HelpMessage='The folder path to save the patch file to')]
        [string]$Path,

        [Parameter(Mandatory=$false, HelpMessage='Use HTTP instead of HTTPS')]
        [switch]$UseHTTP
    )

    # force PSBoundParameters to exist during debugging https://technet.microsoft.com/en-us/library/dd347652.aspx 
    $parameters = $PSBoundParameters

    $installerFolder = $env:USERPROFILE,'Downloads' -join '\'

    if ($parameters.ContainsKey('Path')) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        $installerFolder = $Path
    }
    
    if (-not(Test-Path -Path $installerFolder -PathType Container)) {
        throw "$installerFolder does not exist"
    }

    $major = [string]$Version.Major

    if ($major.Length -gt 2) {
        $major = $major[-2,-1] -join '' # we only want the last 2 numbers
    }

    $minor = [string]$Version.Minor

    if ($minor.Length -lt 3) {
        $minor = '{0:000}' -f [Int32]$minor # force 0 padding to work
    }

    $build = [string]$Version.Build

    $formattedVersion = '{0}{1:000}{2}' -f $major,$minor,$build

    $installer = 'AcroRdrDCUpd{0}.msp' -f $formattedVersion

    if ($Multilingual) {
        $installer = 'AcroRdrDCUpd{0}_MUI.msp' -f $formattedVersion
    }

    $protocol = 'https'

    if($UseHTTP) {
        $protocol = 'http'
    }

    $uri = ('{0}://ardownload.adobe.com/pub/adobe/reader/win/AcrobatDC/{1}/{2}' -f $protocol,$formattedVersion,$installer)
  
    $params = @{
        Uri = $uri;
        Method = 'Get';
        UserAgent = 'ARM WinINet Downloader'
    }

    $proxyUri = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy($uri)

    $ProgressPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

    if(([string]$proxyUri) -ne $uri) {
        $response = Invoke-WebRequest @params -Proxy $proxyUri -ProxyUseDefaultCredentials -UseBasicParsing
    } else {
        $response = Invoke-WebRequest @params -UseBasicParsing
    }

    $statusCode = $response.StatusCode 

    if ($statusCode -eq 200) {
        $bytes = $response.Content

        $installerFile = ($installerFolder,$installer) -join '\'

        Set-Content -Path $installerFile -Value $bytes -Encoding Byte -Force -NoNewline
    } else {
        throw 'Request failed with status code $statusCode'
    }
}

Function Install-AdobeUpdateTask() {
    <#
    .SYNOPSIS
    Installs a scheduled task that will trigger the Adobe Reader updater.

    .DESCRIPTION
    Installs a scheduled task that will trigger the Adobe Reader updater. The task installed by Adobe Reader does not work on Windows 10.

    .PARAMETER Force
    Force the task installation to occur even if Adobe Reader is not installed on the system.

    .PARAMETER Update
    Update the existing task.

    .EXAMPLE
    Install-AdobeUpdateTask

    .EXAMPLE
    Install-AdobeUpdateTask -Update

    .EXAMPLE
    Install-AdobeUpdateTask -Force

    .EXAMPLE
    Install-AdobeUpdateTask -Force -Update
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='Force the task installation to occur even if Adobe Reader is not installed on the system')]
        [switch]$Force,
        
        [Parameter(Mandatory=$false, HelpMessage='Update the existing task')]
        [switch]$Update  
    )

    $xml = @'
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2016-07-14T14:26:25.9610162</Date>
    <Author></Author>
    <URI>\Adobe Reader x64 Update Task</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <GroupId>S-1-5-4</GroupId> <!-- S-1-5-32-545 -->
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT1H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>"%ProgramFiles(x86)%\Common Files\Adobe\ARM\1.0\AdobeARM.exe"</Command>
    </Exec>
  </Actions>
</Task>
'@

    $paths = [string[]]@("$env:ProgramFiles\Common Files\Adobe\ARM\1.0","${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0","$env:ProgramW6432\Common Files\Adobe\ARM\1.0")
    $executable = 'AdobeARM.exe'

    $files = [System.IO.FileInfo[]]@(Get-ChildItem -Path $paths -Filter $executable -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PsIsContainer -eq $false } | Get-Unique)

    if($Force -or ($files.Count -ne 0)) {
        $taskName = 'Adobe Reader x64 Update Task'

        if (-not([System.Environment]::Is64BitOperatingSystem)) {
            $xml = $xml -replace $taskName,'Adobe Reader x86 Update Task'
            $xml = $xml -replace '%ProgramFiles\(x86\)%','%ProgramFiles%'
            $taskName = 'Adobe Reader x86 Update Task'
        }

        if ($Update -or ((Get-ScheduledTask -TaskName  $taskName -ErrorAction SilentlyContinue) -eq $null)) {
            Register-ScheduledTask -Xml $xml -TaskName $taskName -Force | Out-Null
        }
    }
}

Function Invoke-AdobeUpdate() {
    <#
    .SYNOPSIS
    Invokes the Adobe Reader update mechanism.

    .DESCRIPTION
    Invokes the Adobe Reader update mechanism.

    .PARAMETER Force
    Force the update to occur even if the update waiting time period has not elapsed and the EULA has not been accepted.

    .EXAMPLE
    Invoke-AdobeUpdate

    .EXAMPLE
    Invoke-AdobeUpdate -Force
    #>
    [CmdletBinding()] 
    [OutputType([void])]
    Param(
        [Parameter(Mandatory=$false, HelpMessage='Force the update to occur even if the update waiting time period has not elapsed')]
        [switch]$Force  
    )

    $paths = [string[]]@("$env:ProgramFiles\Common Files\Adobe\ARM\1.0","${env:ProgramFiles(x86)}\Common Files\Adobe\ARM\1.0","$env:ProgramW6432\Common Files\Adobe\ARM\1.0")
    $executable = 'AdobeARM.exe'

    $files = [System.IO.FileInfo[]]@(Get-ChildItem -Path $paths -Filter $executable -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.PsIsContainer -eq $false } | Get-Unique)

    if($files.Count -ne 0) {
        $file = $files[0]

        $armRegistryPath = 'hkcu:\Software\Adobe\Adobe ARM\1.0\ARM'

        if($Force -and (Test-Path -Path $armRegistryPath)) {
            $armDataPath = "$env:ProgramData\Adobe\ARM"

            if (Test-Path -Path $armDataPath) {
                $folders = [System.IO.DirectoryInfo[]]@(Get-ChildItem -Path $armDataPath | Where-Object {$_.Name.StartsWith('{')})

                if($folders.Count -ne 0) {
                    $folder = $folders[0]
                    $guid = $folder.Name

                    Remove-ItemProperty -Path $armRegistryPath -Name "tLastT_$guid" -Force -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $armRegistryPath -Name "tTimeWaitedFilesInUse_$guid" -Force -ErrorAction SilentlyContinue
                } 
            }

            Remove-ItemProperty -Path $armRegistryPath -Name 'tLastT_AdobeARM' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tLastT_Reader' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tTimeWaitedFilesInUse_AdobeARM' -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $armRegistryPath -Name 'tTimeWaitedFilesInUse_Reader' -Force -ErrorAction SilentlyContinue
            
            if([System.Environment]::Is64BitOperatingSystem) {
                $armPath = 'hklm:\Software\WOW6432Node\Adobe\Adobe ARM\1.0\ARM'
            } else {
                $armPath = 'hklm:\Software\Adobe\Adobe ARM\1.0\ARM'
            }

            # make sure systems where the user hasn't accepted the EULA will update
            # if running as a regular user then suppress the access denied error since this is in HKLM unlike the other values above
            Set-ItemProperty -Path $armPath -Name 'iDisableCheckEula' -Value 1 -Type DWORD -Force -ErrorAction SilentlyContinue
        }

        Start-Process -FilePath $file.FullName -NoNewWindow
    }
}
#endregion
#region - Idea 7
<#PSScriptInfo
.VERSION 1.0.2
.GUID e4d9eb84-bf65-4985-a5b4-9bcbe20afb05
.AUTHOR NickolajA
.DESCRIPTION Get the latest Adobe Reader DC setup installation details from the official Adobe FTP server
.COMPANYNAME SCConfigMgr
.COPYRIGHT
.TAGS AdobeReader Intune ConfigMgr PowerShell FTP
.LICENSEURI
.PROJECTURI https://github.com/SCConfigMgr/Other/blob/master/Get-LatestAdobeReaderInstaller.ps1
.ICONURI
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
    Get the latest Adobe Reader DC setup installation details from the official Adobe FTP server.
 
.DESCRIPTION
    Get the latest Adobe Reader DC setup installation details from the official Adobe FTP server.
 
.PARAMETER Type
    Specify the installer type, either EXE or MSP.
 
.PARAMETER Language
    Specify the desired language of the installer, e.g. 'en_US'.
 
.EXAMPLE
    # Retrieve the latest available Adobe Reader DC setup installer of type 'EXE' from the official Adobe FTP server:
    .\Get-LatestAdobeReaderInstaller.ps1 -Type EXE -Language en_US
 
    # Retrieve the latest available Adobe Reader DC patch installer of type 'MSP' from the official Adobe FTP server:
    .\Get-LatestAdobeReaderInstaller.ps1 -Type MSP
 
.NOTES
    FileName: Get-LatestAdobeReaderInstaller.ps1
    Author: Nickolaj Andersen
    Contact: @NickolajA
    Created: 2020-03-12
    Updated: 2020-04-22
     
    Version history:
    1.0.0 - (2020-03-12) Script created.
    1.0.1 - (2020-04-22) Fixed an issue where the SetupVersion was not interpretet correctly.
    1.0.2 - (2020-04-22) This time, it should work.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [parameter(Mandatory = $false, HelpMessage = "Specify the installer type, either EXE or MSP.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("EXE", "MSP")]
    [string]$Type = "EXE",

    [parameter(Mandatory = $false, HelpMessage = "Specify the desired language of the installer, e.g. 'en_US'.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("en_US", "de_DE", "es_ES", "fr_FR", "ja_JP")]
    [string]$Language = "en_US"
)
Process {
    # Set script error action preference
    $ErrorActionPreference = "Stop"

    # Functions
    function Get-AdobeReaderFTPItem {
        [CmdletBinding(SupportsShouldProcess = $true)]
        param(
            [parameter(Mandatory = $false, HelpMessage = "Specify the directory path, e.g. 'ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC'.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path = "ftp://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC"
        )
        Process {
            # Construct anonymous credentials to use when connecting to Adobe's FTP
            $FTPCredentials = ([System.Management.Automation.PSCredential]::new("anonymous", ("password" | ConvertTo-SecureString -AsPlainText -Force)))
       
            # Construct WebRequest object for recieving FTP data stream
            [System.Net.FtpWebRequest]$WebRequest = [System.Net.WebRequest]::Create($Path)
            $WebRequest.Method = [System.Net.WebRequestMethods+FTP]::ListDirectoryDetails
            $WebRequest.Credentials = $FTPCredentials
            $WebRequest.Timeout = 90000
            $WebRequest.KeepAlive = $false
            $WebRequest.UseBinary = $false
            $WebRequest.UsePassive = $true
    
            try {
                # Get FTP response data stream
                $FTPResponse = $WebRequest.GetResponse()
                $FTPResponseStream = $FTPResponse.GetResponseStream()
                $FTPStreamReader = New-Object -TypeName System.IO.StreamReader -ArgumentList $FTPResponseStream

                # Read each line of the stream and add it a list
                $StreamList = New-Object -TypeName System.Collections.ArrayList
                while ($ListItem = $FTPStreamReader.ReadLine()) {
                    # Split directory listing string into objects (borrowed from PSFTP module from PSGallery: https://www.powershellgallery.com/packages/PSFTP)
                    $null, $null, $null, $null, $null, $null, $null, [string]$Date, [string]$Name = [regex]::Split($ListItem, '^([d-])([rwxt-]{9})\s+(\d{1,})\s+([.@A-Za-z0-9-]+)\s+([A-Za-z0-9-]+)\s+(\d{1,})\s+(\w+\s+\d{1,2}\s+\d{1,2}:?\d{2})\s+(.+?)\s?$', "SingleLine,IgnoreCase,IgnorePatternWhitespace")
                    
                    # Parse date string into date object (borrowed from PSFTP module from PSGallery: https://www.powershellgallery.com/packages/PSFTP)
                    $DatePart = $Date -split "\s+"
                    $NewDateString = "$($DatePart[0]) $('{0:D2}' -f [int]$DatePart[1]) $($DatePart[2])"
                    if($DatePart[2] -match ":") {
                        $Month = ([DateTime]::ParseExact($DatePart[0],"MMM" ,[System.Globalization.CultureInfo]::InvariantCulture)).Month
                        if((Get-Date).Month -ge $Month) {
                            $NewDate = [DateTime]::ParseExact($NewDateString, "MMM dd HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)
                        }
                        else {
                            $NewDate = ([DateTime]::ParseExact($NewDateString, "MMM dd HH:mm", [System.Globalization.CultureInfo]::InvariantCulture)).AddYears(-1)
                        }
                    } 
                    else {
                        $NewDate = [DateTime]::ParseExact($NewDateString, "MMM dd yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
                    }

                    # Construct custom object to be added to array list
                    $PSObject = [PSCustomObject]@{
                        Path = -join@($Path, "/", $Name.Trim())
                        Date = $NewDate
                        Name = $Name.Trim()
                    }

                    # Filter out unwanted objects and add everything else to array list
                    if ($Name -notlike "misc") {
                        $StreamList.Add($PSObject) | Out-Null
                    }
                }

                # Handle return value from function
                Write-Output -InputObject ($StreamList | Sort-Object -Property Date)
            }
            catch [System.Exception] {
                throw $_.Exception.Message; break
            }
        }
        End {
            # Perform cleanup and disconnect FTP connection
            $FTPResponse.Close()
            $FTPResponse.Dispose()
        }
    }

    function Get-LatestAdobeReaderInstallerItem {
        $FTPDirectoryItem = Get-AdobeReaderFTPItem | Select-Object -Skip $LatestCount -Last 1
        if ($FTPDirectoryItem -ne $null) {
            $FTPDirectoryItems = Get-AdobeReaderFTPItem -Path $FTPDirectoryItem.Path
            if ($FTPDirectoryItems -ne $null) {
                switch ($Type) {
                    "EXE" {
                        $FTPSetupInstaller = $FTPDirectoryItems | Where-Object { ($_.Name -match $FTPDirectoryItem.Name) -and ($_.Name -match $Language) -and ($_.Name -match $Type.ToLower()) }
                    }
                    "MSP" {
                        $FTPSetupInstaller = $FTPDirectoryItems | Where-Object { ($_.Name -match $FTPDirectoryItem.Name) -and ($_.Name -match $Type.ToLower()) }
                    }
                }
                
                if ($FTPSetupInstaller -ne $null) {
                    foreach ($FTPSetupInstallerItem in $FTPSetupInstaller) {
                        $PSObject = [PSCustomObject]@{
                            FileName = $FTPSetupInstallerItem.Name
                            SetupVersion = -join@($FTPDirectoryItem.Name.SubString(0, 2), ".", $FTPDirectoryItem.Name.SubString(2, 3), ".", $FTPDirectoryItem.Name.SubString(5, 5))
                            URL = $FTPSetupInstallerItem.Path
                            Date = $FTPSetupInstallerItem.Date
                        }
                        Write-Output -InputObject $PSObject
                    }
                }
                else {
                    $LatestCount++
                    Get-LatestAdobeReaderInstallerItem
                }
            }
        }
    }

    # Retrieve the latest setup installer based on parameter input
    $LatestCount = 0
    Get-LatestAdobeReaderInstallerItem
}
#endregion
#region - Idea 8
#https://silentinstallhq.com/adobe-reader-dc-silent-install-how-to-guide/

#Used the browser F12 Dev tools to scrape the download link out of the Adobe Enterpise download page
#https://get.adobe.com/reader/enterprise/
#Find the Get Line and click on it. Then right click on the file name and go to copy >> Link Address

$URI = "https://ardownload2.adobe.com/pub/adobe/reader/win/AcrobatDC/2300620320/AcroRdrDC2300620320_en_US.exe"
wget -Uri $URI -OutFile "C:\temp\AcroRdrDC.exe" -Verbose
Start-Process -FilePath "c:\temp\AcroRdrDC.exe" -ArgumentList "/sAll /rs /msi EULA_ACCEPT=YES"
$uri = 'https://helpx.adobe.com/acrobat/release-note/release-notes-acrobat-reader.html'
$b = wget -Uri $URI 
$conv = [Ordered]@{
    '01' = 'jan'
    '02' = 'feb'
    '03' = 'mar'
    '04' = 'apr'
    '05' = 'may'
    '06' = 'jun'
    '07' = 'jul'
    '08' = 'aug'
    '09' = 'sep'
    '10' = 'oct'
    '11' = 'nov'
    '12' = 'dec'
    }
$conv = '
    01,jan
    02,feb
    03,mar
    04,apr
    05,may
    06,jun
    07,jul
    08,aug
    09,sep
    10,oct
    11,nov
    12,dec' | ConvertFrom-Csv -Delimiter ',' -Header Num,Mon
$l1 = ($b.Links | Where HRef -match "dccontinuous" | Where HRef -match "2023" | Select HREF | Sort).HRef
$l1 = $l1 -replace 'https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/continuous/dccontinuous'
$l1 = $l1 | %{($_).split('.')[0]} | Select -Unique
$conv | %{ $l1 = $l1 -replace $_.Mon,"$($_.Num)-" }
$l1 = $l1 | Select -Unique | Sort -Descending | Select -First 1
$deconv = $conv | Where Num -eq $l1.Substring(0,2)
$l1 = $l1 -replace "$($deconv.Num)-", $deconv.Mon
$c = ($b.Links | Where HRef -match $l1 | Where HRef -match 'classic').href
Invoke-WebRequest -Uri $c.Split('#')[0]
#endregion
#region - Idea 9
#region
    Getting File and folder acls
    function Get-File($initialDirectory) {   
        [void] [System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        if ($initialDirectory) { $OpenFileDialog.initialDirectory = $initialDirectory }
        $OpenFileDialog.Title = 'Select File(s) to Copy.'
        $OpenFileDialog.Multiselect = $true
        $OpenFileDialog.filter = 'All files (*.*)|*.*'
        [void] $OpenFileDialog.ShowDialog()
        return $OpenFileDialog.FileNames
    }
    ($FilePermissions = Get-File C:\ | get-acl | select -exp access | ft)


    Function Get-Folder($initialDirectory="")
    {
        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null

        $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
        $foldername.Description = "Select a folder"
        $foldername.rootfolder = "MyComputer"
        $foldername.SelectedPath = $initialDirectory

        if($foldername.ShowDialog() -eq "OK")
        {
            $folder += $foldername.SelectedPath
        }
        return $folder
    }

    $a = Get-Folder

    $foldername = New-Object System.Windows.Forms.FolderBrowserDialog
    $foldername.Description = "Select a folder"
    $foldername.rootfolder = "MyComputer"
    $foldername.SelectedPath = $initialDirectory

    $modalform = New-Object System.Windows.Forms.Form
    $modalform.TopMost = $true

    if($foldername.ShowDialog($modalform) -eq "OK")
    {
        $folder += $foldername.SelectedPath
    } else {
        # no folder selected
        # do something
        Exit
    }
    return $folder
#endregion


Get-ItemProperty HKLM:\software\Microsoft\Windows\CurrentVersion\Uninstall\* |Select-Object DisplayName, DisplayVersion, Publisher| Export-CSV -Path "C:\temp\Software.csv"
$URI = "https://get.adobe.com/uk/reader/"
$HTML = Invoke-WebRequest -Uri $URI
$HTML.AllElements | Out-Gridview

<#
 
.SYNOPSIS
    Checks for the current version of common software and sends an email notification if the version has been updated
 
.DESCRIPTION
    This script checks for the current version of some common software from their internet URLs.  It then checks a local file for the stored software version.  If the two don't match,
    an email will be sent notifying of the new version number.  The stored version number will then be updated for future version checking.
    Currently software list:
    Adobe Flash Player
    Adobe Acrobat Reader DC
    Java Runtime
    Notepad++
    Paint.net
    PDFCreator
 
.PARAMETER To
    The "To" email address for notifications
 
.PARAMETER From
    The "From" email address for notifications
 
.PARAMETER Smtpserver
    The smtpserver name for email notifications
 
.PARAMETER SoftwareVersionsFile
    The location of the file used to store the software versions
 
.EXAMPLE
    Check-SoftwareVersions.ps1
    Checks the internet URLs of common software for the current version number and sends an email if a new version has been released.
 
.NOTES
    Script name: Check-SoftwareVersions.ps1
    Author:      Trevor Jones
    Contact:     @trevor_smsagent
    DateCreated: 2015-06-11
    Link:        https://smsagent.wordpress.com
 
#>
 
 
[CmdletBinding(SupportsShouldProcess=$True)]
    param
        (
        [Parameter(Mandatory=$False, HelpMessage="The 'to' email address")]
            [string]$To="bill.gates@contoso.com",
        [Parameter(Mandatory=$False, HelpMessage="The 'from' email address")]
            [string]$From="PowerShell@contoso.com",
        [Parameter(Mandatory=$False, HelpMessage="The 'from' email address")]
            [string]$SmtpServer="myexchangebox",
        [parameter(Mandatory=$False, HelpMessage="The location of the software versions file")]
            [string]$SoftwareVersionsFile="C:\Scripts\temp\SoftwareVersions.txt"
        )
 
 
$EmailParams = @{
    To = $To
    From = $From
    Smtpserver = $SmtpServer
    }
 
# Note: to find the element that contains the version number, output all elements to gridview and search with the filter, eg:
# $URI = "https://get.adobe.com/uk/reader/"
# $HTML = Invoke-WebRequest -Uri $URI
# $HTML.AllElements | Out-Gridview
 
 
######################
# Adobe Flash Player #
######################
 
Write-Verbose "Checking Adobe Flash Player"
$URI = "http://www.adobe.com/uk/products/flashplayer/distribution3.html"
$HTML = Invoke-WebRequest -Uri $URI
$NewFlashVersion = (($HTML.AllElements | where {$_.innerHTML -like "Flash Player*Win*"}).innerHTML).Split(" ")[2]
Write-Verbose "Found version: $NewFlashVersion"
 
$CurrentFlashVersion = ((Get-Content $SoftwareVersionsFile | Select-string "Adobe Flash Player").ToString()).substring(20)
Write-Verbose "Stored version: $CurrentFlashVersion"
 
If ($NewFlashVersion -ne $CurrentFlashVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "Adobe Flash Update" -Body "Adobe Flash Player has been updated from $CurrentFlashVersion to $NewFlashVersion"
        write-verbose "Setting new stored version number for Adobe Flash Player"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("Adobe Flash Player: $CurrentFlashVersion","Adobe Flash Player: $NewFlashVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
 
 
###########################
# Adobe Acrobat Reader DC #
###########################
 
Write-Verbose "Checking Adobe Acrobet Reader DC"
$URI = "https://get.adobe.com/uk/reader/"
$HTML = Invoke-WebRequest -Uri $URI
$NewReaderVersion = (($HTML.AllElements | where {$_.innerHTML -like "Version *.*.*"}).innerHTML).Split(" ")[1]
Write-Verbose "Found version: $NewReaderVersion"
 
$CurrentReaderVersion = ((Get-Content $SoftwareVersionsFile | Select-string "Adobe Acrobat Reader DC").ToString()).Substring(25)
Write-Verbose "Stored version: $CurrentReaderVersion"
 
If ($NewReaderVersion -ne $CurrentReaderVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "Adobe Acrobat Reader Update" -Body "Adobe Acrobat Reader DC has been updated from $CurrentReaderVersion to $NewReaderVersion"
        write-verbose "Setting new stored version number for Adobe Acrobat Reader DC"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("Adobe Acrobat Reader DC: $CurrentReaderVersion","Adobe Acrobat Reader DC: $NewReaderVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
 
 
################
# Java Runtime #
################
 
Write-Verbose "Checking Java Runtime"
$URI = "http://www.java.com/en/download/windows_offline.jsp"
$HTML = Invoke-WebRequest -Uri $URI
$NewJavaVersion = (($HTML.AllElements | where {$_.innerHTML -like "Recommended Version * Update *"}).innerHTML).Substring(20).Split("(")[0]
Write-Verbose "Found version: $NewJavaVersion"
 
$CurrentJavaVersion = ((Get-Content $SoftwareVersionsFile | Select-string "Java Runtime").ToString()).Substring(14)
Write-Verbose "Stored version: $CurrentJavaVersion"
 
If ($NewJavaVersion -ne $CurrentJavaVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "Java Runtime Update" -Body "Java Runtime has been updated from $CurrentJavaVersion to $NewJavaVersion"
        write-verbose "Setting new stored version number for Java Runtime"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("Java Runtime: $CurrentJavaVersion","Java Runtime: $NewJavaVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
 
 
##############
# Notepad ++ #
##############
 
Write-Verbose "Checking Notepad++"
$URI = "http://notepad-plus-plus.org/"
$HTML = Invoke-WebRequest -Uri $URI
$NewNotepadVersion = (($HTML.AllElements | where {$_.outerText -like "Download*" -and $_.tagName -eq "P"}).innerText).Split(":")[1].Substring(1)
Write-Verbose "Found version: $NewNotepadVersion"
 
$CurrentNotepadVersion = ((Get-Content $SoftwareVersionsFile | Select-string "Notepad\+\+").ToString()).Substring(11)
Write-Verbose "Stored version: $CurrentNotepadVersion"
 
If ($NewNotepadVersion -ne $CurrentNotepadVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "Notepad++ Update" -Body "Notepad++ has been updated from $CurrentNotepadVersion to $NewNotepadVersion"
        write-verbose "Setting new stored version number for Notepad++"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("Notepad++: $CurrentNotepadVersion","Notepad++: $NewNotepadVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
 
 
##############
# Paint.net  #
##############
 
Write-Verbose "Checking Paint.net"
$URI = "http://www.getpaint.net/index.html"
$HTML = Invoke-WebRequest -Uri $URI
$NewPaintVersion = (($HTML.AllElements | where {$_.innerHTML -clike "paint.net*.*.*"}).innerHTML).Substring(10)
Write-Verbose "Found version: $NewPaintVersion"
 
$CurrentPaintVersion = ((Get-Content $SoftwareVersionsFile | Select-string "Paint.net").ToString()).Substring(11)
Write-Verbose "Stored version: $CurrentPaintVersion"
 
If ($NewPaintVersion -ne $CurrentPaintVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "Paint.Net Update" -Body "Paint.Net has been updated from $CurrentPaintVersion to $NewPaintVersion"
        write-verbose "Setting new stored version number for Paint.net"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("Paint.net: $CurrentPaintVersion","Paint.net: $NewPaintVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
 
 
##############
# PDFCreator #
##############
 
Write-Verbose "Checking PDFCreator"
$URI = "http://www.pdfforge.org/blog"
$HTML = Invoke-WebRequest -Uri $URI
$NewPDFCreatorVersion = ($HTML.AllElements | where {($_.innerHTML -eq $_.innerText) -and $_.tagName -eq "A" -and $_.innerHTML -like "PDFCreator*"})[0].innerHTML.Split(" ")[1]
Write-Verbose "Found version: $NewPDFCreatorVersion"
 
$CurrentPDFCreatorVersion = ((Get-Content $SoftwareVersionsFile | Select-string "PDFCreator").ToString()).Substring(12)
Write-Verbose "Stored version: $NewPDFCreatorVersion"
 
If ($NewPDFCreatorVersion -ne $CurrentPDFCreatorVersion)
    {
        Write-Verbose "Sending email"
        Send-MailMessage @EmailParams -Subject "PDFCreator Update" -Body "PDFCreator has been updated from $CurrentPDFCreatorVersion to $NewPDFCreatorVersion"
        write-verbose "Setting new stored version number for PDFCreator"
        $Content = Get-Content $SoftwareVersionsFile
        $NewContent = $Content.Replace("PDFCreator: $CurrentPDFCreatorVersion","PDFCreator: $NewPDFCreatorVersion")
        $NewContent | Out-File $SoftwareVersionsFile -Force
    }
#endregion
#region - Idea A
$web = New-Object Net.WebClient
$web | Get-Member
Try {
    $web.DownloadString("https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html")
    } 
Catch {
    Write-Warning "$($error[0])"
    }


$webRequest = [net.WebRequest]::Create("http://microsoft.com")
$webRequest | gm
$4 = $webrequest.GetResponse()
$webrequest.Res

$TEST = [net.WebRequest]::Create("https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/index.html")
$TEST1 = $TEST.GetResponse()
#endregion
#region Browser DL testing
    Install-Module -Name PowerHTML
    Import-Module -Name PowerHTML
    Get-Command -Module PowerHTML
    ConvertFrom-Html -URI $urlAdobe1

    $urlAdobe1 = Invoke-WebRequest -Uri "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC" -UseBasicParsing
    $urlAdobe2 = "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/continuous/dccontinuoussep2023.html#dccontinuousseptwentytwentythree"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12


    function downloadProgram ($readVersion, $version, $download, $name) {
        Write-Host "LOCAL VERSION: $readVersion"
        Write-Host "WEB__ VERSION: $version"
        Write-Host "LINK: $download"
        Write-Host "FILENAME: $name"
        Write-Host " "
        if ($readVersion -lt $version) {
            Write-Host "Newer Version Found Online!"
            Read-Host "Press Enter to Download"
            Import-Module BitsTransfer
            $start_time = Get-Date
            Start-BitsTransfer -Source "$download" -Destination "$name"
            Write-Output "Completed in: $((Get-Date).Subtract($start_time).Seconds) seconds"
        } else {
            Write-Host "No Newer Version Found."
        }
    }

    ####################################################################################
    ####################################################################################

    function Download-7zip {
        # SET VARIABLES
        $initialURL = "http://www.7-zip.org/download.html"
        $folderName = "7zip"
        $filenamePrefix = "7zip64"
        $filenameExtension = "msi"
        $defaultVersion = "0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        $program = (Invoke-WebRequest -Uri "$urlAdobe1").Links | Where-Object {($_.href -like "*x64.msi")} | select href
        $programURL = $program[0]
        $programSTRING = "$programURL"

        $programVERSION = $programSTRING -replace("@{href=a/7z","") -replace("-x64.msi}","")
        $programDOWNLOAD = $programSTRING -replace("@{href=","http://www.7-zip.org/") -replace("}","")
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################   
    }

    ####################################################################################

    function Download-Chrome {
        # SET VARIABLES
        $initialURL = "http://feeds.feedburner.com/GoogleChromeReleases"
        $folderName = "chrome"
        $filenamePrefix = "chrome64"
        $filenameExtension = "msi"
        $defaultVersion = "0.0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        [xml]$program = Invoke-webRequest "$initialURL"
        $programVersionLookup = ($program.feed.entry | Where-object{$_.title.'#text' -match 'Stable'}).content | Select-Object{$_.'#text'} | Where-Object{$_ -match 'Windows'} | ForEach{[version](($_ | Select-string -allmatches '(\d{1,4}\.){3}(\d{1,4})').matches | select-object -first 1 -expandProperty Value)} | Sort-Object -Descending | Select-Object -first 1

        $programVERSION = "$programVersionLookup"
        $programDOWNLOAD = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################
    }

    ####################################################################################

    function Download-Firefox {
        # SET VARIABLES
        $initialURL = "https://www.mozilla.org/en-US/firefox/all/?q=English%20(US)"
        $folderName = "firefox"
        $filenamePrefix = "firefox64"
        $filenameExtension = "exe"
        $defaultVersion = "0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        $program = (Invoke-WebRequest -Uri "$initialURL").Links | Where-Object {($_.href -like "*os=win64*")} | select href
        $programURL = $program[0]
        $programSTRING = "$programURL"

        $programVERSION = $programSTRING -replace("@{href=https://download.mozilla.org/\?product=firefox-","") -replace("-SSL&amp;os=win64&amp;lang=en-US}","")
        $programDOWNLOAD = $programSTRING -replace("@{href=","") -replace("}","")
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################
    }

    ####################################################################################

    function Download-FirefoxESR {
        # SET VARIABLES
        $initialURL = "https://www.mozilla.org/en-US/firefox/organizations/all/?q=English%20(US)"
        $folderName = "firefoxESR"
        $filenamePrefix = "firefox64ESR"
        $filenameExtension = "exe"
        $defaultVersion = "0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        $program = (Invoke-WebRequest -Uri "$initialURL").Links | Where-Object {($_.href -like "*os=win64*")} | select href
        $programURL = $program[0]
        $programSTRING = "$programURL"

        $programVERSION = $programSTRING -replace("@{href=https://download.mozilla.org/\?product=firefox-","") -replace("esr-SSL&amp;os=win64&amp;lang=en-US}","")
        $programDOWNLOAD = $programSTRING -replace("@{href=","") -replace("}","")
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################
    }

    ####################################################################################

    function Download-FlashActiveX {
    # CAN ONLY CHECK VERSION BUT NOT DOWNLOAD SINCE IT REQUIRES LOGIN TO ADOBE WEBSITE
        # SET VARIABLES
        $initialURL = "https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE"
        $folderName = "flashActiveX"
        $filenamePrefix = "flashActiveX"
        $filenameExtension = "msi"
        $defaultVersion = "0.0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        #$programVERSION = ((Invoke-WebRequest -Uri "$initialURL").AllElements | where {$_.tagName -eq "h4"} | select -expand innerText) -replace ("Downloads","") -replace ("Flash Player ","") -replace ("`n|`r","") -replace (" \(Win, Mac \& Linux\)","")
        [xml]$FlashMajorVersion = Invoke-WebRequest -Uri "http://fpdownload2.macromedia.com/pub/flashplayer/update/current/sau/currentmajor.xml"
        $FlashMajorVersionResult = $FlashMajorVersion.version.player.major
        [xml]$FlashVersionDetails = Invoke-WebRequest -Uri "http://fpdownload2.macromedia.com/pub/flashplayer/update/current/sau/$FlashMajorVersionResult/xml/version.xml"
        $FlashMinorVersion = $FlashVersionDetails.version.activex.minor
        $FlashBuildMajorVersion = $FlashVersionDetails.version.activex.buildMajor
        $FlashBuildMinorVersion = $FlashVersionDetails.version.activex.buildMinor
        $programVERSION = "$FlashMajorVersionResult.$FlashMinorVersion.$FlashBuildMajorVersion.$FlashBuildMinorVersion"
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        ###################

        Write-Host "LOCAL VERSION: $programREADVERSION"
        Write-Host "WEB__ VERSION: $programVERSION"
        Write-Host "LINK: https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE"
        Write-Host "FILENAME: $programFILENAME"
        Write-Host " "
        if ($programREADVERSION -lt $programVERSION) {
            Write-Host "Newer Version Found Online!"
            Write-Host " "
            Write-Host "Please login to Adobe website to manually download"
            Write-Host "and then rename to FILENAME indicated."
            Write-Host " "
            Read-Host "Press Enter to open browser and go to download page"
            Start-Process -FilePath https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE
            Read-Host "Press Enter to continue after manual download"
        } else {
            Write-Host "No Newer Version Found."
        }
    }

    ####################################################################################

    function Download-FlashNPAPI {
    # CAN ONLY CHECK VERSION BUT NOT DOWNLOAD SINCE IT REQUIRES LOGIN TO ADOBE WEBSITE
        # SET VARIABLES
        $initialURL = "https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE"
        $folderName = "flashNPAPI"
        $filenamePrefix = "flashNPAPI"
        $filenameExtension = "msi"
        $defaultVersion = "0.0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        #$programVERSION = ((Invoke-WebRequest -Uri "$initialURL").AllElements | where {$_.tagName -eq "h4"} | select -expand innerText) -replace ("Downloads","") -replace ("Flash Player ","") -replace ("`n|`r","") -replace (" \(Win, Mac \& Linux\)","")
        [xml]$FlashMajorVersion = Invoke-WebRequest -Uri "http://fpdownload2.macromedia.com/pub/flashplayer/update/current/sau/currentmajor.xml"
        $FlashMajorVersionResult = $FlashMajorVersion.version.player.major
        [xml]$FlashVersionDetails = Invoke-WebRequest -Uri "http://fpdownload2.macromedia.com/pub/flashplayer/update/current/sau/$FlashMajorVersionResult/xml/version.xml"
        $FlashMinorVersion = $FlashVersionDetails.version.plugin.minor
        $FlashBuildMajorVersion = $FlashVersionDetails.version.plugin.buildMajor
        $FlashBuildMinorVersion = $FlashVersionDetails.version.plugin.buildMinor
        $programVERSION = "$FlashMajorVersionResult.$FlashMinorVersion.$FlashBuildMajorVersion.$FlashBuildMinorVersion"
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        ###################

        Write-Host "LOCAL VERSION: $programREADVERSION"
        Write-Host "WEB__ VERSION: $programVERSION"
        Write-Host "LINK: https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE"
        Write-Host "FILENAME: $programFILENAME"
        Write-Host " "
        if ($programREADVERSION -lt $programVERSION) {
            Write-Host "Newer Version Found Online!"
            Write-Host " "
            Write-Host "Please login to Adobe website to manually download"
            Write-Host "and then rename to FILENAME indicated."
            Write-Host " "
            Read-Host "Press Enter to open browser and go to download page"
            Start-Process -FilePath https://INSERT-ADOBE-DISTRIBUTION-LINK-HERE
            Read-Host "Press Enter to continue after manual download"
        } else {
            Write-Host "No Newer Version Found."
        }
    }

    Function ConvertTo-NormalHTML {
        param([Parameter(Mandatory = $true, ValueFromPipeline = $true)]$HTML)

        $NormalHTML = New-Object -Com "HTMLFile"
        $NormalHTML.IHTMLDocument2_write($HTML.RawContent)
        return $NormalHTML
    }

    $Content = (Invoke-WebRequest -Uri $urlAdobe1 -UseBasicParsing ).Content

    $ParsedHTML = ConvertTo-NormalHTML -HTML $Content

    $ParsedHTML
    ####################################################################################

    function Download-Java {
        # SET VARIABLES
        $initialURL = "https://java.com/en/download/manual.jsp"
        $folderName = "java"
        $filenamePrefix = "java64"
        $filenameExtension = "exe"
        $defaultVersion = "0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        $program = (Invoke-WebRequest -Uri "$initialURL" -TimeoutSec 10).Links | Where-Object {($_.innerText -like "*Offline (64-bit)*")} | select href
        $programURL = $program[0]
        $programSTRING = "$programURL"

        $programVERSIONcrawl = (Invoke-WebRequest -uri "$initialURL").AllElements | where {$_.tagName -eq "h4"} | where {$_.outerHTML -like "*sub*"} | where {$_.innerText -like "*Recommended Version *"} | select -expand innerText
        $programVERSION = $programVERSIONcrawl -replace ("Recommended Version ","") -replace (" Update ",".")
        $programDOWNLOAD = $programSTRING -replace("@{href=","") -replace("}","")
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################
    }

    ####################################################################################

    function Download-VLC {
        # SET VARIABLES
        $initialURL = "http://www.videolan.org/vlc/download-windows.html"
        $folderName = "vlc"
        $filenamePrefix = "vlc64"
        $filenameExtension = "exe"
        $defaultVersion = "0.0.0"
        ###############

        # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
        $program = (Invoke-WebRequest -Uri "$initialURL").Links | Where-Object {($_.href -like "*-win64.exe")} | select href
        $programURL = $program[0]
        $programSTRING = "$programURL"

        $programVERSION = $programSTRING -replace("@{href=//get.videolan.org/vlc/\d{1}\.\d{1}\.\d{1}/win64/vlc-","") -replace("-win64.exe}","")
        $programDOWNLOAD = $programSTRING -replace("@{href=","http:") -replace("}","")
        ####################################################
    
        # NO CHANGES NEEDED
        $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
        $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
        if ($programREAD.length -eq 0) {
            $programREADVERSION = "$defaultVersion"
        } else {
            $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
        }
        downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
        ###################   
    }

    ####################################################################################
    ####################################################################################

    Write-Host "`nThis script will check for updates to:`n"
    Write-Host "- 7zip`n- Chrome`n- Firefox`n- Firefox ESR`n- Java`n- VLC"
    Write-Host "- Flash Player ActiveX (manual download)`n- Flash Player NPAPI (manual download)`n"
    Read-Host "Press Enter to start"

    '7zip','Chrome','Firefox','FirefoxESR','Java','VLC','FlashActiveX','FlashNPAPI'| %{
        Write-Host ("#"*80)
        Write-Host "Checking: $_"
        Write-Host ("#"*40)
        iex "Download-$_"
        Write-Host " "
        }

    Write-Host ("#"*80)
    Write-Host "`nSCRIPT COMPLETE"
    Read-Host "Press Enter to exit"
#endregion
#region WSUS testing
    <#
        .SYNOPSIS
            Powershell script to import an update, or multiple updates into WSUS based on the UpdateID from the catalog.

        .DESCRIPTION
            This script takes user input and attempts to connect to the WSUS server.
            Then it tries to import the update using the provided UpdateID from the catalog.

        .INPUTS
            The script takes WSUS server Name/IP, WSUS server port, SSL configuration option and UpdateID as input. UpdateID can be viewed and copied from the update details page for any update in the catalog, https://catalog.update.microsoft.com. 

        .OUTPUTS
            Writes logging information to standard output.

        .EXAMPLE
            # Use with remote server IP, port and SSL
            .\ImportUpdateToWSUS.ps1 -WsusServer 127.0.0.1 -PortNumber 8531 -UseSsl -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
            # Use with remote server Name, port and SSL
            .\ImportUpdateToWSUS.ps1 -WsusServer WSUSServer1.us.contoso.com -PortNumber 8531 -UseSsl -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
            # Use with remote server IP, defaultport and no SSL
            .\ImportUpdateToWSUS.ps1 -WsusServer 127.0.0.1  -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
            # Use with localhost default port
            .\ImportUpdateToWSUS.ps1 -UpdateId 12345678-90ab-cdef-1234-567890abcdef

        .EXAMPLE
            # Use with localhost default port, file with updateID's
            .\ImportUpdateToWSUS.ps1 -UpdateIdFilePath .\file.txt


        .NOTES  
            # On error, try enabling TLS: https://learn.microsoft.com/mem/configmgr/core/plan-design/security/enable-tls-1-2-client

            # Sample registry add for the WSUS server from command line. Restarts the WSUSService and IIS after adding:
            reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319 /V SchUseStrongCrypto /T REG_DWORD /D 1

            ## Sample registry add for the WSUS server from PowerShell. Restarts WSUSService and IIS after adding:
            $registryPath = "HKLM:\Software\Microsoft\.NETFramework\v4.0.30319"
            $Name = "SchUseStrongCrypto"
            $value = "1" 
            if (!(Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
            }
            New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType DWORD -Force | Out-Null
            Restart-Service WsusService, w3svc

            # Update import logs/errors are under %ProgramFiles%\Update Services\LogFiles\SoftwareDistribution.log

    #>
    Function X
    {
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Specifies the name of a WSUS server, if not specified connects to localhost")]
        # Specifies the name of a WSUS server, if not specified connects to localhost.
        [string]$WsusServer = $env:ComputerName,

        [Parameter(Mandatory = $false, HelpMessage = "Specifies the port number to use to communicate with the upstream WSUS server, default is 8530")]
        # Specifies the port number to use to communicate with the upstream WSUS server, default is 8530.
        [ValidateSet("80", "443", "8530", "8531")]
        [int32]$PortNumber = 8530,

        [Parameter(Mandatory = $false, HelpMessage = "Specifies that the WSUS server should use Secure Sockets Layer (SSL) via HTTPS to communicate with an upstream server")]
        # Specifies that the WSUS server should use Secure Sockets Layer (SSL) via HTTPS to communicate with an upstream server.  
        [Switch]$UseSsl,

        [Parameter(Mandatory = $true, HelpMessage = "Specifies the update Id we should import to WSUS", ParameterSetName = "Single")]
        # Specifies the update Id we should import to WSUS
        [ValidateNotNullOrEmpty()]
        [String]$UpdateId,

        [Parameter(Mandatory = $true, HelpMessage = "Specifies path to a text file containing a list of update ID's on each line", ParameterSetName = "Multiple")]
        # Specifies path to a text file containing a list of update ID's on each line.
        [ValidateNotNullOrEmpty()]
        [String]$UpdateIdFilePath
    )

    Set-StrictMode -Version Latest

    # set server options
    $serverOptions = "Get-WsusServer"
    if ($psBoundParameters.containsKey('WsusServer')) { $serverOptions += " -Name $WsusServer -PortNumber $PortNumber" }
    if ($UseSsl) { $serverOptions += " -UseSsl" }

    # empty updateID list
    $updateList = @()

    # get update id's
    if ($UpdateIdFilePath) {
        if (Test-Path $UpdateIdFilePath) {
            foreach ($id in (Get-Content $UpdateIdFilePath)) {
                $updateList += $id.Trim()
            }
        }
        else {
            Write-Error "[$UpdateIdFilePath]: File not found"
		    return
        }
    }
    else {
        $updateList = @($UpdateId)
    }

    # get WSUS server
    Try {
        Write-Host "Attempting WSUS Connection using $serverOptions... " -NoNewline
        $server = invoke-expression $serverOptions
        Write-Host "Connection Successful"
    }
    Catch {
        Write-Error $_
        return
    }

    # empty file list
    $FileList = @()

    # call ImportUpdateFromCatalogSite on WSUS
    foreach ($uid in $updateList) {
        Try {
            Write-Host "Attempting WSUS update import for Update ID: $uid... " -NoNewline
            $server.ImportUpdateFromCatalogSite($uid, $FileList)
            Write-Host "Import Successful"
        }
        Catch {
            Write-Error "Failed. $_"
        }
    }
    }
    X -WsusServer $env:ComputerName -PortNumber 8530 -UseSsl:$false -Verbose -UpdateId 4360eb76-b35b-4783-84d8-d8eaeac1865c
    Install-Module PSWindowsUpdate
    Import-Module PSWindowsUpdate -
    Get-Package -Name PSWindowsUpdate
    Get-Command -Module PSWindowsUpate 
    Get-WUList -ComputerName $env:ComputerName
#endregion
