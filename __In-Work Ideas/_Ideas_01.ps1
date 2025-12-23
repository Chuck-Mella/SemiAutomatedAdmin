$Parameters = @{
	Name = 'OSDeploy'
}
Install-Module @Parameters 
Import-Module -Name OSDeploy 
Get-Command -Module OSDeploy
Test-IsoBootable -ISOFile "C:\path\to\your.iso" 
#region - Backup User DataFolders
Function Backup-DataFolder {
    <#
                .SYNOPSIS
                    Useful function to backup selected app data folders.
                .DESCRIPTION
                    Useful function to backup selected app data folders prior to wiping or reimaging a system
                .PARAMETER trgPath
                    Specifies a path to backup, all subfolders will be included in the archive.
                .PARAMETER dstPath
                    Specifies a path to place backup, domot include a filename.
                .PARAMETER dstFile
                    Specifies a failename for the backup zip file. If no path is included with
                    the filename than the path defaults to the user's Desktop folder.
                .PARAMETER Preset
                    Preset Pathways and destination file names for commonly used app data you want to backup. Paths and file names are supplied or automatically filled in.
                    1 = TeamsBackgrounds
                .EXAMPLE
                    C:\PS> 
                    <Description of example>
                .NOTES
                    Author: Chuck Mella
                    Date:   February 01, 2022    
            #>
    Param
    (
        [Parameter(HelpMessage = "Path to be backed up.")]
        [String]$trgPath,
        [Parameter(HelpMessage = "Path to backed file.")]
        [String]$dstPath,
        [Parameter(HelpMessage = "Filename for backup archive (Default path is Desktop if no path supplied)")]
        [String]$dstFile,
        [Parameter(HelpMessage = "1 = TeamsBackgrounds")]
        [Int]$Preset,
        [Parameter(HelpMessage = "Shows a What-If")]
        [Switch]$Test
    )
    $runDate = Get-Date -f yyyy-MM-dd
    # Error Check
    If (([string]::IsNullOrEmpty($trgPath)) -and ($null -eq $Preset)) { throw "No Preset or Folderpath supplied"; Break }
    If (([string]::IsNullOrEmpty($dstFile)) -and ($null -eq $Preset)) { throw "No Preset or Destination supplied"; Break }
    If (!([string]::IsNullOrEmpty($dstPath))) { $dstFile = $null }
    # Parse BU Folder
    # Actions under Presets if $trgPath is null
    # Parse Destination Folder
    If ($dstFile -match '\\') { $trgFilePath = $dstFile -replace "\\+[^\\]+$" }
    ElseIf (!([string]::IsNullOrEmpty($dstPath))) { $trgFilePath = $dstPath }
    Else { $trgFilePath = [system.Environment]::GetFolderPath('Desktop') }
    # Parse Destination Filename
    $trgFileName = $dstFile.split('\')[-1]
    # Process chosen Preset
    Switch ($Preset) {
        1 {
            # Teams Backgrounds
            $action = "Proceed"
            If ([string]::IsNullOrEmpty($trgPath)) { $trgPath = "$env:userprofile\AppData\Roaming\Microsoft\Teams\Backgrounds" }
            If ([string]::IsNullOrEmpty($trgFileName)) { $trgFileName = "TeamsBkgrnds_$runDate.zip" }
            Else { $trgFileName = $trgFileName.split('.')[0] + '_' + $runDate + ".zip" }
            $trgFile = $trgFilePath + '\' + $trgFileName
        }
        default { 
            $action = "No Actions"
        }
    }
    # Perform archiving
    If ($action -eq "Proceed") {
        If ($Test.IsPresent) {
            Try {
                Compress-Archive $trgPath -DestinationPath $trgFile -CompressionLevel Optimal -Force -ErrorAction Stop -WhatIf
            }
            Catch { "If Ooops" }
        }
        Else {
            Try {
                Compress-Archive $trgPath -DestinationPath $trgFile -CompressionLevel Optimal -Force -ErrorAction Stop
                II  $trgFile
            }
            Catch { "Else Ooops" }
        }
    }
    Else { Write-Warning "No Actions Taken" }
}
# Backup-DataFolder -Preset 1 -dstPath $trgFolder
#endregion
#region - Local Security Policy
<#
        secedit /export /cfg C:\secpol.cfg
        (Get-Content C:\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\secpol.cfg
        secedit /configure /db C:\windows\security\local.sdb /cfg C:\secpol.cfg /areas SECURITYPOLICY
        Remove-Item -Path C:\secpol.cfg -Force -Confirm:$false
    #>
Function Parse-SecPol($CfgFile) { 
    secedit /export /cfg "$CfgFile" | out-null
    $obj = New-Object psobject
    $index = 0
    $contents = Get-Content $CfgFile -raw
    [regex]::Matches($contents, "(?<=\[)(.*)(?=\])") | ForEach-Object {
        $title = $_
        [regex]::Matches($contents, "(?<=\]).*?((?=\[)|(\Z))", [System.Text.RegularExpressions.RegexOptions]::Singleline)[$index] | ForEach-Object {
            $section = new-object psobject
            $_.value -split "\r\n" | ? { $_.length -gt 0 } | ForEach-Object {
                $value = [regex]::Match($_, "(?<=\=).*").value
                $name = [regex]::Match($_, ".*(?=\=)").value
                $section | add-member -MemberType NoteProperty -Name $name.tostring().trim() -Value $value.tostring().trim() -ErrorAction SilentlyContinue | out-null
            }
            $obj | Add-Member -MemberType NoteProperty -Name $title -Value $section
        }
        $index += 1
    }
    return $obj
}
Function Set-SecPol($Object, $CfgFile) {
    $SecPool.psobject.Properties.GetEnumerator() | ForEach-Object {
        "[$($_.Name)]"
        $_.Value | ForEach-Object {
            $_.psobject.Properties.GetEnumerator() | ForEach-Object {
                "$($_.Name)=$($_.Value)"
            }
        }
    } | out-file $CfgFile -ErrorAction Stop
    secedit /configure /db c:\windows\security\local.sdb /cfg "$CfgFile" /areas SECURITYPOLICY
}
$SecPool = Parse-SecPol -CfgFile ./Test.cgf
## Update Password Policy
$SecPool.'System Access'.PasswordComplexity = 1
$SecPool.'System Access'.MinimumPasswordLength = 14
$SecPool.'System Access'.MaximumPasswordAge = 60
$SecPool.'System Access'.MinimumPasswordAge = 5
$SecPool.'System Access'.PasswordHistorySize = 5
## Account Account Policies
$SecPool.'System Access'.LockoutBadCount = 5
$SecPool.'System Access'.LockoutDuration = 30
$SecPool.'System Access'.ResetLockoutCount = 5
## Enable AUdit Events -Success and Failure
$SecPool.'Event Audit'.AuditSystemEvents = 3
$SecPool.'Event Audit'.AuditLogonEvents = 3
$SecPool.'Event Audit'.AuditPrivilegeUse = 3
$SecPool.'Event Audit'.AuditPolicyChange = 3
$SecPool.'Event Audit'.AuditAccountLogon = 3
$SecPool.'Event Audit'.AuditAccountManage = 3
Set-SecPol -Object $SecPool -CfgFile ./Test.cfg
#endregion
#region - New Event View for Scripting
$dirviews = "$env:ProgramData\Microsoft\Event viewer\Views"
$xm1Data = (Dec64 'PD94bWwgdmVyc2lvbj0ibC5PIj8+DQogIDxWaWV3ZXJjb25maWc+DQogICAgPFF1ZXJ5Y29uZmlnPiANCiAgICAgIDxRdWVyeVBhcmFtcz4gDQogICAgICAgIDxTaW1wbGU+DQogICAgICAgICAgPENoYW5uZWw+QXBwbGljYXRpb248L0NoYW5uZWw+IA0KICAgICAgICAgIDxSZWxhdGl2ZVRpbWVJaW5mbz5PPC9SZWxhdGl2ZVRpbWVJbmZvPiANCiAgICAgICAgICA8U291cmNlPnBzc2NyaXB0aW5nPC9Tb3VyY2U+DQogICAgICAgICAgPEJ5c291cmNlPlRydWU8L0J5c291cmNlPiANCiAgICAgICAgPC9TaW1wbGU+IA0KICAgICAgPC9RdWVyeVBhcmFtcz4NCiAgICAgIDxRdWVyeU5vZGU+DQogICAgICAgIDxOYW1lPkF1dG9tYXRpb24gc2NyaXB0aW5nPC9OYW1lPg0KICAgICAgICA8RGVzY3JpcHRpb24+QXV0b21hdGVkIHNjcmlwdGluZyBFdmVudHM8L0Rlc2NyaXB0aW9uPg0KICAgICAgICA8UXVlcnlMaXN0Pg0KICAgICAgICAgIDxRdWVyeSBJZD0gIjAiPiANCiAgICAgICAgICA8U2VsZWN0IFBhdGg9IkFwcGxpY2F0aW9uIj4qW1N5c3RlbVtQcm92aWRlcltATmFtZT0ncHNzY3JpcHRpbmcnXV1dPC9TZWxlY3Q+IA0KICAgICAgICAgIDwvUXVlcnk+DQogICAgICAgIDwvUXVlcnlMaXN0PiANCiAgICAgIDwvUXVlcnlOb2RlPg0KICAgIDwvUXVlcnljb25maWc+DQogIDwvVmlld2VyY29uZmlnPg==')
$latestview = Get-ChildItem $dirviews -Filter "*View_*.xml" | Sort LastwriteTime -Descending | Select-Object -First 1
If ($null -eq $latestview ) { $newview = $dirviews + "\" + "view_O.xml" }
Else { $newview = $dirviews + "\" + "view_" + ([int]($latestview.Name -replace 'View_' -replace '.xml') + 1) + ".xml" }
$xm1Data | Set-Content $newview
Get-ChildItem $dirviews -Filter "*view_*.xml"
#endregion
# shutdown.exe /r /t 00
#region - RunAsTesting
($shell = New-object -ComObject shell.Application).shellExecute( 'cmd.exe', '/c pnputil /scan-devices&&pause', '', 'RunAs', 1)
#endregion
#region - AdRdrTESTING
#region - DL Latest Adobe Reader
#rv ftp'~
$lc1Path = $updPath
$ftpFolderurl = "ftp ://ftp.adobe.com/pub/adobe/reader/win/AcrobatDC/"
#connect to ftp, and get directory listing
$ftpRequest = [System.Net.FtpWebRequest]::create("$ftpFolderurl ")
$ftpRequest.Method = [system.Net.WebRequestMethods+Ftp]::ListDirectory
$ftpResponse = $ftpRequest.GetResponse()
$Responsestream = $ftpResponse.GetResponsestream()
$ftpReader = New-Object System.IO.StreamReader -ArgumentList $Responsestream
$DirList = $ftpReader.ReadToEnd()
#from Directory Listing get last entry in list of any numeric version
$Latestupdate = $DirList -split '[\n]' | Where-Object { $_ -match 'A\d' } | Sort-Object | Select-Object -Last 1
# build file name & download url for latest file
$LatestFile = "AcroRdrocupd" + $Latestupdate + "_MUI. msp"
$DownloadURL = "$ftpFolderurl$Latestupdate/ $LatestFile"
# download the file
(New-object system.Net.webclient).DownloadFile($DownloadURL, $LatestFile)
(New-object System.Net.Webclient).DownloadFile($DownloadURL, ($lc1Path + '\ ' + $LatestFile))
#endregion
#region - Idea 1
$t = "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/"
$r = Invoke-webRequest -uri $t
$r.ParsedHtml.body.getElementsByTagName('Div')
#endregion
#endregion
#region - Logging
#region - Get-TSEvents.ps1
# v-waalmo@microsoft.com amended this script to allow it to run as stand alone by copying the needed functions from other scritps
# Running it alone will export all Event Logs on the system to a folder named EventLogs as EVTX, CSV, and TXT
# Date: 2019-02-19 - Last Edit: 2019-02-20
Function Get-TSEvents {
    <#
                 TS_GetEvents.ps1
                 Version 2.3.5
                 Date: 05-13-2013 - Last_Edit: 2018-06-16
                 Author: Andre Teixeira - andret@microsoft.com
                 Description: This script is used to export machine event logs in different formats, such as EVT(X), CSV and TXT
            #>
    PARAM
    (
        $ComputerName = $Env:computername,
        $EventLogNames = "", # v-waalmo: This was "AllWMI" in original version
        $OutputFormats = "",
        $ExclusionList = "", 
        $Days = "", 
        $EventLogAdvisorAlertXMLs = "",
        $SectionDescription = "Event Logs",
        $Prefix = $null,
        $Suffix = $null,
        $Query = $Null,
        $After,
        $Before,
        [switch] $DisableRootCauseDetection
    )
    $OSVersion = [Environment]::OSVersion.Version
    Function Write-DiagProgress ($Activity, $Status) {
        trap [Exception] {
            #Ignore any error like - when the file is locked
            continue
        }
        #On ServerCore, $Activity go to WriteDiagProgress.txt. Discart $status
        if ($null -ne $Activity) {
            $Activity + ": " + $Status | Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8" -ErrorAction Continue
            "   Write-DiagProgress: " + $Activity + ": " + $Status
        }
        else {
            ""	| Out-File ($OutputFolder + "\WriteDiagProgress.txt") -Encoding "UTF8"
        }
    }
    Function RunCMD([string]$commandToRun, 
        $filesToCollect = $null, 
        [string]$fileDescription = "", 
        [string]$sectionDescription = "", 
        [boolean]$collectFiles = $true,
        [switch]$useSystemDiagnosticsObject,
        [string]$Verbosity = "Informational",
        [switch]$NoFileExtensionsOnDescription,
        [switch]$BackgroundExecution,
        [boolean]$RenameOutput = $false,
        [switch]$DirectCommand,
        [Scriptblock] $PostProcessingScriptBlock) {
        trap [Exception] {
            WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[RunCMD (commandToRun = $commandToRun) (filesToCollect = $filesToCollect) (fileDescription $fileDescription) (sectionDescription = $sectionDescription) (collectFiles $collectFiles)]" -InvokeInfo $MyInvocation
            $Error.Clear()
            continue
        }
        if ($useSystemDiagnosticsObject.IsPresent) {
            $StringToAdd = " (Via System.Diagnostics.Process)"
        }
        else {
            $StringToAdd = ""
        }
        if ($null -eq $filesToCollect) {
            $collectFiles = $false
        }
        if (($BackgroundExecution.IsPresent) -and ($collectFiles -eq $false)) {
            "[RunCMD] Warning: Background execution will be ignored since -collectFiles is false" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
        }
        if ($BackgroundExecution.IsPresent) {
            $StringToAdd += " (Background Execution)"
        }
        $StringToAdd += " (Collect Files: $collectFiles)"
        "[RunCMD] Running Command" + $StringToAdd + ":`r`n `r`n                      $commandToRun`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -ShortFormat
        # A note: if CollectFiles is set to False, background processing is not allowed
        # This is to avoid problems where multiple background commands write to the same file
        if (($BackgroundExecution.IsPresent -eq $false) -or ($collectFiles -eq $false)) {    
            "--[Stdout-Output]---------------------" | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
            if ($useSystemDiagnosticsObject.IsPresent) {
                if ($DirectCommand.IsPresent) {
                    if ($commandToRun.StartsWith("`"")) {
                        $ProcessName = $commandToRun.Split("`"")[1]
                        $Arguments = ($commandToRun.Split("`"", 3)[2]).Trim()
                    } 
                    elseif ($commandToRun.Contains(".exe")) {
                        # 2. No quote found - try to find a .exe on $commandToRun
                        $ProcessName = $commandToRun.Substring(0, $commandToRun.IndexOf(".exe") + 4)
                        $Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe") + 5, $commandToRun.Length - $commandToRun.IndexOf(".exe") - 5)
                    }
                    else {
                        $ProcessName = "cmd.exe" 
                        $Arguments = "/c `"" + $commandToRun + "`""
                    }
                    $process = ProcessCreate -Process $ProcessName -Arguments $Arguments
                }
                else {
                    $process = ProcessCreate -Process "cmd.exe" -Arguments ("/s /c `"" + $commandToRun + "`"")
                }
                $process.WaitForExit()
                $StdoutOutput = $process.StandardOutput.ReadToEnd() 
                if ($null -ne $StdoutOutput) {
                    ($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
                }
                else {
                    '(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
                }
                $ProcessExitCode = $process.ExitCode
                if ($ProcessExitCode -ne 0) {
                    "[RunCMD] Process exited with error code " + ("0x{0:X}" -f $process.ExitCode) + " when running command line:`r`n             " + $commandToRun | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow'
                    $ProcessStdError = $process.StandardError.ReadToEnd()
                    if ($null -ne $ProcessStdError) {
                        "--[StandardError-Output]--------------" + "`r`n" + $ProcessStdError + "--[EndOutput]-------------------------" + "`r`n" | WriteTo-StdOut -InvokeInfo $MyInvocation -Color 'DarkYellow' -NoHeader
                    }
                }
            } 
            else {
                if ($null -ne $commandToRun) {
                    $StdoutOutput = Invoke-Expression $commandToRun
                    if ($null -ne $StdoutOutput) {
                        ($StdoutOutput | Out-String) | WriteTo-StdOut -InvokeInfo $MyInvocation -NoHeader
                    }
                    else {
                        '(No stdout output generated)' | WriteTo-StdOut -InvokeInfo $InvokeInfo -Color 'Gray' -ShortFormat -NoHeader
                    }
                    $ProcessExitCode = $LastExitCode
                    if ($LastExitCode -gt 0) {
                        "[RunCMD] Warning: Process exited with error code " + ("0x{0:X}" -f $ProcessExitCode) | writeto-stdout -InvokeInfo $MyInvocation -Color 'DarkYellow'
                    }
                }
                else {
                    '[RunCMD] Error: a null -commandToRun argument was sent to RunCMD' | writeto-stdout -InvokeInfo $MyInvocation -IsError
                    $ProcessExitCode = 99
                }
            }
            "--[Finished-Output]-------------------`r`n" | writeto-stdout -InvokeInfo $MyInvocation -NoHeader -ShortFormat
            if ($collectFiles -eq $true) {    
                "[RunCMD] Collecting Output Files... " | writeto-stdout -InvokeInfo $MyInvocation -ShortFormat
                if ($noFileExtensionsOnDescription.isPresent) {
                    CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -noFileExtensionsOnDescription -renameOutput $renameOutput -InvokeInfo $MyInvocation
                }
                else {
                    CollectFiles -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -Verbosity $Verbosity -renameOutput $renameOutput -InvokeInfo $MyInvocation
                }
            }
            #RunCMD returns exit code only if -UseSystemDiagnosticsObject is used
            if ($useSystemDiagnosticsObject.IsPresent) {
                return $ProcessExitCode
            }
        } 
        else {
            #Background Process
            # Need to separate process name from $commandToRun:
            # 1. Try to identify a quote:
            if ($commandToRun.StartsWith("`"")) {
                $ProcessName = $commandToRun.Split("`"")[1]
                $Arguments = ($commandToRun.Split("`"", 3)[2]).Trim()
            } 
            elseif ($commandToRun.Contains(".exe")) {
                # 2. No quote found - try to find a .exe on $commandToRun
                $ProcessName = $commandToRun.Substring(0, $commandToRun.IndexOf(".exe") + 4)
                $Arguments = $commandToRun.Substring($commandToRun.IndexOf(".exe") + 5, $commandToRun.Length - $commandToRun.IndexOf(".exe") - 5)
            }
            else {
                $ProcessName = "cmd.exe" 
                $Arguments = "/c `"" + $commandToRun + "`""
            }
            if ($noFileExtensionsOnDescription.isPresent) {
                $process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -CollectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock 
            }
            else {
                $process = BackgroundProcessCreate -ProcessName $ProcessName -Arguments $Arguments -filesToCollect $filesToCollect -fileDescription $fileDescription -sectionDescription $sectionDescription -collectFiles $collectFiles -Verbosity $Verbosity -renameOutput $renameOutput -noFileExtensionsOnDescription -TimeoutMinutes 15 -PostProcessingScriptBlock $PostProcessingScriptBlock
            }
        }
    }
    Filter WriteTo-ErrorDebugReport
    (
        [string] $ScriptErrorText, 
        [System.Management.Automation.ErrorRecord] $ErrorRecord = $null,
        [System.Management.Automation.InvocationInfo] $InvokeInfo = $null,
        [switch] $SkipWriteToStdout
    ) {
        trap [Exception] {
            $ExInvokeInfo = $_.Exception.ErrorRecord.InvocationInfo
            if ($null -ne $ExInvokeInfo) { $line = ($_.Exception.ErrorRecord.InvocationInfo.Line).Trim() }
            else { $Line = ($_.InvocationInfo.Line).Trim() }
            if (-not ($SkipWriteToStdout.IsPresent)) {
                "[WriteTo-ErrorDebugReport] Error: " + $_.Exception.Message + " [" + $Line + "].`r`n" + $_.StackTrace | WriteTo-StdOut
            }
            continue
        }
        if (($ScriptErrorText.Length -eq 0) -and ($null -eq $ErrorRecord)) { $ScriptErrorText = $_ }
        if (($null -ne $ErrorRecord) -and ($null -eq $InvokeInfo)) {
            if ($null -ne $ErrorRecord.InvocationInfo) { $InvokeInfo = $ErrorRecord.InvocationInfo }
            elseif ($null -ne $ErrorRecord.Exception.ErrorRecord.InvocationInfo) { $InvokeInfo = $ErrorRecord.Exception.ErrorRecord.InvocationInfo }
            if ($null -eq $InvokeInfo) { $InvokeInfo = $MyInvocation }
        }
        elseif ($null -eq $InvokeInfo) { $InvokeInfo = $MyInvocation }
        $Error_Summary = New-Object PSObject
        if (($null -ne $InvokeInfo.ScriptName) -and ($InvokeInfo.ScriptName.Length -gt 0)) {
            $ScriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
        }
        elseif (($null -ne $InvokeInfo.InvocationName) -and ($InvokeInfo.InvocationName.Length -gt 1)) { $ScriptName = $InvokeInfo.InvocationName }
        elseif ($null -ne $MyInvocation.ScriptName) { $ScriptName = [System.IO.Path]::GetFileName($MyInvocation.ScriptName) }
        $Error_Summary_TXT = @()
        if (-not ([string]::IsNullOrEmpty($ScriptName))) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Script" -Value $ScriptName 
        }
        if ($null -ne $InvokeInfo.Line) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value ($InvokeInfo.Line).Trim()
            $Error_Summary_TXT += "Command: [" + ($InvokeInfo.Line).Trim() + "]"
        }
        elseif ($null -ne $InvokeInfo.MyCommand) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Command" -Value $InvokeInfo.MyCommand.Name
            $Error_Summary_TXT += "Command: [" + $InvokeInfo.MyCommand.Name + "]"
        }
        if ($null -ne $InvokeInfo.ScriptLineNumber) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Line Number" -Value $InvokeInfo.ScriptLineNumber
        }
        if ($null -ne $InvokeInfo.OffsetInLine) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Column  Number" -Value $InvokeInfo.OffsetInLine
        }
        if (-not ([string]::IsNullOrEmpty($ScriptErrorText))) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Additional Info" -Value $ScriptErrorText
        }
        if ($null -ne $ErrorRecord.Exception.Message) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Error Text" -Value $ErrorRecord.Exception.Message
            $Error_Summary_TXT += "Error Text: " + $ErrorRecord.Exception.Message
        }
        if ($null -ne $ErrorRecord.ScriptStackTrace) {
            $Error_Summary | Add-Member -MemberType NoteProperty -Name "Stack Trace" -Value $ErrorRecord.ScriptStackTrace
        }
        $Error_Summary | Add-Member -MemberType NoteProperty -Name "Custom Error" -Value "Yes"
        if ($ScriptName.Length -gt 0) { $ScriptDisplay = "[$ScriptName]" }
        $Error_Summary | ConvertTo-Xml | 
        update-diagreport -id ("ScriptError_" + (Get-Random)) -name "Script Error $ScriptDisplay" -verbosity "Debug"
        if (-not ($SkipWriteToStdout.IsPresent)) {
            "[WriteTo-ErrorDebugReport] An error was logged to Debug Report: " + [string]::Join(" / ", $Error_Summary_TXT) | 
            WriteTo-StdOut -InvokeInfo $InvokeInfo -ShortFormat -IsError
        }
        $Error_Summary | Format-List * | Out-String | WriteTo-StdOut -DebugOnly -IsError
    }
    function WriteTo-StdOut {
        param
        (
            $ObjectToAdd,
            [switch]$ShortFormat,
            [switch]$IsError,
            $Color,
            [switch]$DebugOnly,
            [switch]$PassThru,
            [System.Management.Automation.InvocationInfo] $InvokeInfo = $MyInvocation,
            [string]$AdditionalFileName = $null,
            [switch]$noHeader
        )
        BEGIN {
            $WhatToWrite = @()
            if ($null -ne $ObjectToAdd) { $WhatToWrite += $ObjectToAdd } 
            if (($Debug) -and ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host")) {
                if ($null -eq $Color) { $Color = $Host.UI.RawUI.ForegroundColor }
                elseif ($Color -isnot [ConsoleColor]) { $Color = [Enum]::Parse([ConsoleColor], $Color) }
                $scriptName = [System.IO.Path]::GetFileName($InvokeInfo.ScriptName)
            }
            $ShortFormat = $ShortFormat -or $global:ForceShortFormat
        }
        PROCESS {
            if ($_ -ne $null) {
                if ($_.GetType().Name -ne "FormatEndData") { $WhatToWrite += $_ | Out-String }
                else {
                    $WhatToWrite = "Object not correctly formatted. The object of type Microsoft.PowerShell.Commands.Internal.Format.FormatEntryData is not valid or not in the correct sequence."
                }
            }
        }
        END {
            if ($ShortFormat) { $separator = " " }
            else { $separator = "`r`n" }
            $WhatToWrite = [string]::Join($separator, $WhatToWrite)
            while ($WhatToWrite.EndsWith("`r`n")) { $WhatToWrite = $WhatToWrite.Substring(0, $WhatToWrite.Length - 2) }
            if (($Debug) -and ($Host.Name -ne "Default Host") -and ($Host.Name -ne "Default MSH Host")) {
                $output = "[$([DateTime]::Now.ToString(`"s`"))] [$($scriptName):$($MyInvocation.ScriptLineNumber)]: $WhatToWrite"
                if ($IsError.Ispresent) { $Host.UI.WriteErrorLine($output) }
                else {
                    if ($null -eq $Color) { $Color = $Host.UI.RawUI.ForegroundColor }
                    $output | Write-Host -ForegroundColor $Color
                }
                if ($null -eq $global:DebugOutLog) { $global:DebugOutLog = Join-Path $Env:TEMP "$([Guid]::NewGuid().ToString(`"n`")).txt" }
                $output | Out-File -FilePath $global:DebugOutLog -Append -Force 
            }
            elseif (-not $DebugOnly) {
                [System.Threading.Monitor]::Enter($global:m_WriteCriticalSection)
                trap [Exception] {
                    WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
                    continue
                }
                Trap [System.IO.IOException] {
                    # An exection in this location indicates either that the file is in-use or user do not have permissions. Wait .5 seconds. Try again
                    Start-Sleep -Milliseconds 500
                    WriteTo-ErrorDebugReport -ErrorRecord $_ -ScriptErrorText "[Writeto-Stdout]: $WhatToWrite" -InvokeInfo $MyInvocation -SkipWriteToStdout
                    continue
                }
                if ($ShortFormat) {
                    if ($NoHeader.IsPresent) {
                        $WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
                        if ($AdditionalFileName.Length -gt 0) {
                            $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
                        }
                    }
                    else {
                        "[" + (Get-Date -Format "T") + " " + $ComputerName + " *" + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " *" + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
                        if ($AdditionalFileName.Length -gt 0) {
                            "[" + (Get-Date -Format "T") + " " + $ComputerName + " *" + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " *" + $InvokeInfo.ScriptLineNumber.ToString().PadLeft(4) + "] $WhatToWrite" | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
                        }
                    }
                }
                else {
                    if ($NoHeader.IsPresent) {
                        "`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
                        if ($AdditionalFileName.Length -gt 0) {
                            "`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
                        }
                    }
                    else {
                        "`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $StdOutFileName -append -ErrorAction SilentlyContinue 
                        if ($AdditionalFileName.Length -gt 0) {
                            "`r`n[" + (Get-Date) + " " + $ComputerName + " - From " + [System.IO.Path]::GetFileName($InvokeInfo.ScriptName) + " Line: " + $InvokeInfo.ScriptLineNumber + "]`r`n" + $WhatToWrite | Out-File -FilePath $AdditionalFileName -append -ErrorAction SilentlyContinue 
                        }
                    }
                }
                [System.Threading.Monitor]::Exit($global:m_WriteCriticalSection)
            }
            if ($PassThru) { return $WhatToWrite }
        }
    }
    Import-LocalizedData -BindingVariable GetEventsStrings
    Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status $GetEventsStrings.ID_ExportingLogs
    if ($EventLogNames -eq "") {
        # v-waalmo: Show list of events to select from
        $EventLogNames = wevtutil.exe el | Out-GridView -Title "Select event logs to export" -OutputMode Multiple
    }
    $DisplayToAdd = ''
    if (-not (Test-Path($PWD.Path + "\EventLogs"))) { [void]( mkdir ($PWD.Path + "\EventLogs")) }
    $OutputPath = $PWD.Path + "\EventLogs"
    if (($OSVersion.Major -lt 6) -and ($EventLogNames -eq "AllEvents")) { $EventLogNames = "AllWMI" } #Pre-WinVista
    if ($Days -ne "") {
        $Days = "/days:$Days"
        $DisplayToAdd = " ($Days days)"
        if ($null -ne $Query) { "WARNING: Query argument cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -IsError -ShortFormat -InvokeInfo $MyInvocation }
        if (($null -ne $After) -or ($null -ne $Before) ) { "WARNING: -After or -Before arguments cannot be used in conjunction with -Days and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation }
    }
    elseif ($null -ne $Query) {
        $Query = "`"/query:$Query`""
        if (($null -ne $After) -or ($null -ne $Before)) { "WARNING: -After or -Before arguments cannot be used in conjunction with -Query and will be ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation }
    }
    elseif (($null -ne $After) -and ($null -ne $Before) -and ($Before -le $After)) {
        "WARNING: -Before argument contains [$Before] and cannot be earlier than -After argument: [$After] and therefore it will ignored." | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
        $After = $null
    }
    if ((($null -ne $After) -or ($null -ne $Before)) -and ($OSVersion.Major -ge 6)) {
        if (($null -ne $After) -and ($null -eq ($After -as [DateTime]))) {
            "-After argument type is [" + $After.GetType() + "] and contains value [$After]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
            $After = $null
        }
        if (($null -ne $Before) -and ($null -eq ($Before -as [DateTime]))) {
            "-Before argument type is [" + $Before.GetType() + "] and contains value [$Before]. This value cannot be converted to [datetime] and will be ignored" | WriteTo-StdOut -IsError
            $Before = $null
        }
        if (($null -ne $After) -or ($null -ne $Before)) {
            $DisplayToAdd = " (Filtered)"
            $TimeRange = @()
            if ($null -ne $Before) {
                $BeforeLogString = "[Before: $Before $($Before.Kind.ToString())]"
                if ($Before.Kind -ne [System.DateTimeKind]::Utc) { $Before += [System.TimeZoneInfo]::ConvertTimeToUtc($Before) }
                $TimeRange += "@SystemTime <= '" + $Before.ToString("o") + "'"
            }
            if ($null -ne $After) {
                $AfterLogString = "[After: $After $($After.Kind.ToString())]"
                if ($After.Kind -ne [System.DateTimeKind]::Utc) { $After += [System.TimeZoneInfo]::ConvertTimeToUtc($After) }
                $TimeRange += "@SystemTime >= '" + $After.ToString("o") + "'"
            }
            "-Before and/ or -After arguments to TS_GetEvents were used: $BeforeLogString $AfterLogString" | WriteTo-StdOut
            $Query = "*[System[TimeCreated[" + [string]::Join(" and ", $TimeRange) + "]]]"
            $Query = "`"/query:$Query`""
        }
    }
    elseif ((($null -ne $After) -or ($null -ne $Before)) -and ($OSVersion.Major -lt 6)) {
        "WARNING: Arguments -After or -Before arguments are supported only on Windows Vista or newer Operating Systems and therefore it will ignored" | WriteTo-StdOut -ShortFormat -InvokeInfo $MyInvocation
        $After = $null
        $Before = $null
    }
    switch ($EventLogNames) {
        "AllEvents" {
            #Commented line below since Get-WinEvent requires .NET Framework 3.5 *which is not always installed on server media
            #$EventLogNames = Get-WinEvent -ListLog * | Where-Object {$_.RecordCount -gt 0} | Select-Object LogName
            $EventLogNames = wevtutil.exe el
        }
        "AllWMI" {
            $EventLogList = Get-EventLog -List | Where-Object { $_.Entries.Count -gt 0 } | Select-Object @{Name = "LogName"; Expression = { $_.Log } }
            $EventLogNames = @()
            $EventLogList | ForEach-Object { $EventLogNames += $_.LogName }
        }
    }
    if ($OutputFormats -eq "") { $OutputFormatCMD = "/TXT /CSV /evtx /evt" } 
    else { ForEach ($OutputFormat in $OutputFormats) { $OutputFormatCMD += "/" + $OutputFormat + " " } }
    $EventLogAdvisorXMLCMD = ""
    if (($EventLogAdvisorAlertXMLs -ne "") -or ($null -ne $Global:EventLogAdvisorAlertXML)) {
        $EventLogAdvisorXMLFilename = Join-Path -Path $PWD.Path -ChildPath "EventLogAdvisorAlerts.XML"
        "<?xml version='1.0'?>" | Out-File $EventLogAdvisorXMLFilename
        if ($EventLogAdvisorAlertXMLs -ne "") {
            ForEach ($EventLogAdvisorXML in $EventLogAdvisorAlertXMLs) {
                #Save Alerts to disk, then, use file as command line for GetEvents script
                $EventLogAdvisorXML | Out-File $EventLogAdvisorXMLFilename -append
            }
        }
        if ($null -ne $Global:EventLogAdvisorAlertXML) {
            if (Test-Path $EventLogAdvisorXMLFilename) {
                "[GenerateEventLogAdvisorXML] $EventLogAdvisorXMLFilename already exists. Merging content."
                [xml] $EventLogAdvisorXML = Get-Content $EventLogAdvisorXMLFilename
                ForEach ($GlobalSectionNode in $Global:EventLogAdvisorAlertXML.SelectNodes("/Alerts/Section")) {
                    $SectionName = $GlobalSectionNode.SectionName
                    $SectionElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[SectionName = `'$SectionName`']")
                    if ($null -eq $SectionElement) {
                        $SectionElement = $EventLogAdvisorXML.CreateElement("Section")						
                        $X = $EventLogAdvisorXML.SelectSingleNode('Alerts').AppendChild($SectionElement)
                        $SectionNameElement = $EventLogAdvisorXML.CreateElement("SectionName")
                        $X = $SectionNameElement.set_InnerText($SectionName)						
                        $X = $SectionElement.AppendChild($SectionNameElement)
                        $SectionPriorityElement = $EventLogAdvisorXML.CreateElement("SectionPriority")
                        $X = $SectionPriorityElement.set_InnerText(30)
                        $X = $SectionElement.AppendChild($SectionPriorityElement)
                    }
                    ForEach ($GlobalSectionAlertNode in $GlobalSectionNode.SelectNodes("Alert")) {
                        $EventLogName = $GlobalSectionAlertNode.EventLog
                        $EventLogSource = $GlobalSectionAlertNode.Source
                        $EventLogId = $GlobalSectionAlertNode.ID
                        $ExistingAlertElement = $EventLogAdvisorXML.SelectSingleNode("/Alerts/Section[Alert[(EventLog = `'$EventLogName`') and (Source = `'$EventLogSource`') and (ID = `'$EventLogId`')]]")
                        if ($null -eq $ExistingAlertElement) {
                            $AlertElement = $EventLogAdvisorXML.CreateElement("Alert")
                            $X = $AlertElement.Set_InnerXML($GlobalSectionAlertNode.Get_InnerXML())
                            $X = $SectionElement.AppendChild($AlertElement)
                        }
                        else {
                            "WARNING: An alert for event log [$EventLogName], Event ID [$EventLogId], Source [$EventLogSource] was already been queued by another script." | WriteTo-StdOut -ShortFormat
                        }
                    }
                }
                $EventLogAdvisorXML.Save($EventLogAdvisorXMLFilename)
            }
            else { $Global:EventLogAdvisorAlertXML.Save($EventLogAdvisorXMLFilename) }
        }
        $EventLogAdvisorXMLCMD = "/AlertXML:$EventLogAdvisorXMLFilename /GenerateScriptedDiagXMLAlerts "
    }
    if ($SectionDescription -eq "") { $SectionDescription = $GetEventsStrings.ID_EventLogFiles }
    if ($null -ne $Prefix) { $Prefix = "/prefix:`"" + $ComputerName + "_evt_" + $Prefix + "`"" }
    if ($null -ne $Suffix) { $Suffix = "/suffix:`"" + $Suffix + "`"" }
    ForEach ($EventLogName in $EventLogNames) {
        if ($ExclusionList -notcontains $EventLogName) {
            $ExportingString = $GetEventsStrings.ID_ExportingLogs
            Write-DiagProgress -Activity $GetEventsStrings.ID_EVENTLOG -Status ($ExportingString + ": " + $EventLogName)
            $CommandToExecute = "cscript.exe //E:vbscript GetEvents.VBS `"$EventLogName`" /channel $Days $OutputFormatCMD $EventLogAdvisorXMLCMD `"$OutputPath`" /noextended $Query $Prefix $Suffix"
            $OutputFiles = $OutputPath + "\" + $Computername + "_evt_*.*"
            $FileDescription = $EventLogName.ToString() + $DisplayToAdd
            RunCmD -commandToRun $CommandToExecute -sectionDescription $SectionDescription -filesToCollect $OutputFiles -fileDescription $FileDescription
            <# v-waalmo removed the following lines (I don't know why they exist)
                $EventLogFiles = Get-ChildItem $OutputFiles
                if ($EventLogFiles -ne $null) 
                {
                    $EventLogFiles | Remove-Item
                }
                #>
        }
    }
    $EventLogAlertXMLFileName = $Computername + "_EventLogAlerts.XML"
    if (($DisableRootCauseDetection.IsPresent -ne $true) -and (test-path $EventLogAlertXMLFileName)) {	
        [xml] $XMLDoc = Get-Content -Path $EventLogAlertXMLFileName
        if ($null -ne $XMLDoc) { $Processed = $XMLDoc.SelectSingleNode("//Processed").InnerXML }
        if ($null -eq $Processed) {
            #Check if there is any node that does not contain SkipRootCauseDetection. In this case, set root cause detected to 'true'
            if ($null -eq $XMLDoc.SelectSingleNode("//Object[not(Property[@Name=`"SkipRootCauseDetection`"])]")) {
                Update-DiagRootCause -id RC_GetEvents -Detected $true
                if ($null -ne $XMLDoc) {
                    [System.Xml.XmlElement] $rootElement = $XMLDoc.SelectSingleNode("//Root")
                    [System.Xml.XmlElement] $element = $XMLDoc.CreateElement("Processed")
                    $element.innerXML = "True"
                    $rootElement.AppendChild($element)
                    $XMLDoc.Save($EventLogAlertXMLFileName)	
                }
            }
        }
    }
}
Get-TSEvents -OutputFormats 'evtx' -EventLogNames "AllWMI" -After '4/22/2022'
#endregion
#region - Get-TSEvents.psd1 
ConvertFrom-StringData "id_eventlog=Event Logs`nid_exportinglogs=Exporting Event Log`nid_eventlogfiles=Event Log Files"
#endregion
#region - LogSnag.ps1
<#
            Parameter Set: LogName
            Get-EventLog [-LogName] <String> [[-InstanceId] <Int64[]> ] 
            [-After <DateTime> ] [-AsBaseObject] [-Before <DateTime> ] 
            [-ComputerName <String[]> ] [-EntryType <String[]> ] 
            [-Index <Int32[]> ] [-Message <String> ] [-Newest <Int32> ] 
            [-Source <String[]> ] [-UserName <String[]> ] [<CommonParameters>]
        #>
#First we need to define the start date (the date after which we will get events). This date is calculated as today minus 7 days:
$now = get-date
$startdate = $now.adddays(-7)
#Now we can read warning and error events from a log for the last week:
$el = get-eventlog -ComputerName Serv1 -log System -After $startdate -EntryType Error, Warning
#Let's check the result. Just type $el in the console. Yes, we can see events from the event log.
#But how will we export the event log? Windows PowerShell doesn't have cmdlets to export to Excel. But it supports export to CSV file. Let's try it now:
$el | export-csv eventlog.csv
#Yes, it works, but multi-line descriptions ruined the output file.
#Maybe export to XML will help?
$el | export-clixml eventlog.xml
#But how to display it in clear way? Excel understands XML files, but I have no idea how to interpret it:
#PowerShell Log to XML
#I guess we can make an XML transformation to convert this XML into more readable file, but I'm not an XML guru, but I have a more or less useful solution. We can solve our problem if we just export to CSV only several event properties (without event description):
$el | Select-Object EntryType, TimeGenerated, Source, EventID | Export-CSV eventlog.csv -NoTypeInfo
#Now we can read eventlog.csv in Excel without problems.
#Putting all together
#It's time to write the PowerShell script.
#Brief: we will read recent (7 days) error and warning events from Application and System event logs, join them, sort them by time and export to CSV format.
#
#  This script exports consolidated and filtered event logs to CSV
#  Author: Michael Karsyan, FSPro Labs, eventlogxp.com (c) 2016
#
Set-Variable -Name EventAgeDays -Value 7     #we will take events for the latest 7 days
Set-Variable -Name CompArr -Value @("SERV1", "SERV2", "SERV3", "SERV4")   # replace it with your server names
Set-Variable -Name LogNames -Value @("Application", "System")  # Checking app and system logs
Set-Variable -Name EventTypes -Value @("Error", "Warning")  # Loading only Errors and Warnings
Set-Variable -Name ExportFolder -Value "C:\TEST\"
$el_c = @()   #consolidated error log
$now = get-date
$startdate = $now.adddays(-$EventAgeDays)
$ExportFile = $ExportFolder + "el" + $now.ToString("yyyy-MM-dd---hh-mm-ss") + ".csv"  # we cannot use standard delimiteds like ":"
foreach ($comp in $CompArr) {
    foreach ($log in $LogNames) {
        Write-Host Processing $comp\$log
        $el = get-eventlog -ComputerName $comp -log $log -After $startdate -EntryType $EventTypes
        $el_c += $el  #consolidating
    }
}
$el_sorted = $el_c | Sort-Object TimeGenerated    #sort by time
Write-Host Exporting to $ExportFile
$el_sorted | Select-Object EntryType, TimeGenerated, Source, EventID, MachineName | Export-CSV $ExportFile -NoTypeInfo  #EXPORT
Write-Host Done!
#Scheduling the task
#To run the script, we should run this command:
PowerShell.exe -ExecutionPolicy ByPass -File export-logs.ps1
#We can open Windows scheduler GUI to make this task, or use PowerShell console:
#Microsoft recommends this way to schedule a PowerShell script:
$Trigger = New-JobTrigger -Weekly -At "7:00AM" -DaysOfWeek "Monday"
Register-ScheduledJob -Name "Export Logs" -FilePath "C:\Test\export-logs.ps1" -Trigger $Trigger
#But this may miswork, because it adds to Windows Task Scheduler the following action:
powershell.exe -NoLogo -NonInteractive -WindowStyle Hidden -Command "Import-Module PSScheduledJob; $jobDef = [Microsoft.PowerShell.ScheduledJob.ScheduledJobDefinition]::LoadFromStore('Export Logs', 'C:\Users\Michael\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs'); $jobDef.Run()"
#If your policy prevents running PoweShell scripts, our export script won't run because powershell parameters miss -ExecutionPolicy option.
#That's why I will use ScriptBlock instead of FilePath. This code does the trick:
$trigger = New-JobTrigger -Weekly -At "7:00AM" -DaysOfWeek "Monday"
$action = "PowerShell.exe -ExecutionPolicy ByPass -File c:\test\export-logs.ps1"
$sb = [Scriptblock]::Create($action)
Register-ScheduledJob -Name "Export Logs" -ScriptBlock $sb -Trigger $trigger
#Note that to run Register-ScheduledJob cmdlet, you need to start PowerShell elevated.
#That's all. Now you should have a task that runs every Monday at 7:00, collects events from your servers and exports them to CSV files.
#Conclusion
#As you can see, the problem of exporting events to Excel can be solved without third-party tools. This method is somewhat limited, but it works.
#endregion
#endregion
#region - Purge-DHCPData.ps1
Function Purge-DHCPData {
    #requires -runasadministrator
    Param
    (
        $DhcpServer,
        $scopeid,
        [Switch]$infoOnly
    )
    #requires -modules dhcpserver
    If ((Get-Module -ListAvailable).Name -notcontains 'DhcpServer') {
        Write-Warning 'DhcpServer module not detected: EXITING'; BREAK
    }
    If ([String]::IsNullOrEmpty($DhcpServer)) {
        $DhcpServer = (Get-DhcpServerInDC | Out-GridView -Title 'Select DHCP Server' -PassThru).DnsName
    }
    If ([String]::IsNullOrEmpty($scopeid)) {
        $scopeid = (Get-DhcpServerv4Scope -ComputerName $DhcpServer | Out-GridView -Title 'Select DHCP Scope' -PassThru).ScopeId.IPAddressToString 
    }
    $result = Get-DhcpServerv4Lease -ComputerName $DhcpServer -ScopeId $scopeid
    Switch ($infoOnly.IsPresent -eq $true) {
        $true {
            If ($host.name -eq 'ConsoleHost') { $result }
            ElseIf ($host.name -match 'ISE') { $result | Out-GridView -Title "DHCP Entries for Scope [$scopeid]" -PassThru }
        }
        $false {
            foreach ($object in $result) {
                if ( $object.leaseExpiryTime -le (Get-Date) -and $object.AddressState -notmatch 'Reservation' ) {
                    $object.hostname
                    Remove-DhcpServerv4Lease -ComputerName $DhcpServer -IPAddress ($object.IPAddress).IPAddressToString -Verbose
                }
            }
        }
    }
}
Purge-DHCPData -computername "FabconDC01" -scopeid "192.168.0.0"
#endregion
#region - Server 2019 Ping Fix
# Server 2019 Ping fix (Disabled by default)
New-NetFirewallRule -DisplayName 'Allow Inbound ICMPv4' -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -RemoteAddress LocalSubnet -Action Allow
New-NetFirewallRule -DisplayName 'Allow Inbound ICMPv6' -Direction Inbound -Protocol ICMPv6 -IcmpType 8 -RemoteAddress LocalSubnet -Action Allow
New-NetFirewallRule -DisplayName 'Allow Inbound SQL' -Direction Inbound -Protocol TCP -RemoteAddress LocalSubnet -Action Allow -LocalPort 1433
New-NetFirewallRule -DisplayName 'Allow Outbound SQL' -Direction Outbound -Protocol TCP -RemoteAddress LocalSubnet -Action Allow -LocalPort 1433
New-NetFirewallRule -DisplayName 'Allow Outbound WSUS 8530' -Direction Outbound -Protocol TCP -RemoteAddress LocalSubnet -Action Allow -RemotePort 8530
New-NetFirewallRule -DisplayName 'Allow Outbound WSUS 8531' -Direction Outbound -Protocol TCP -RemoteAddress LocalSubnet -Action Allow -RemotePort 8531
#endregion
#region - VM Drive permission fix (Hyper-V)
icacls "V:\Hyper-V\o_FABCONLOGO1\Virtual Hard Disks\FABCONLOGO1.VHDX" /GRANT "NT VIRTUAL MACHINE\D01F0902-88A4-412B-ABA0-7E232BC8FBB6":(F)
icacls "V:\Hyper-V\o_FABCONWS03\Virtual Hard Disks\FABCONWS03.VHDX" /GRANT "NT VIRTUAL MACHINE\D87A16CD-4523-4379-9118-FEA1804C52C6":(F)
icacls "V:\Hyper-V\o_FABCONWS09\Virtual Hard Disks\FABCONWS09.VHDX" /GRANT "NT VIRTUAL MACHINE\D87A16CD-4523-4379-9118-FEA1804C52C6":(F)
icacls "V:\Hyper-V\o_FABCONWS03\Virtual Hard Disks\FABCONWS03.VHDX" /GRANT "NT VIRTUAL MACHINE\6392DE07-8434-4444-915C-AF61780142B2":(F)
icacls "V:\Hyper-V\o_FABCONWS11\Virtual Hard Disks\FABCONWS11.VHDX" /GRANT "NT VIRTUAL MACHINE\F92B709A-4B52-4985-9F71-DAF9023A6277":(F)
icacls "V:\Hyper-V\o_FABCONWS05\Virtual Hard Disks\FABCONWS05.VHDX" /GRANT "NT VIRTUAL MACHINE\09F658B3-781E-4226-8786-F044C4A59C38":(F)
'
    diskpart
    sel disk 0
    list vol
    sel vol 
    format fs=fat32  quick
    assign letter=a
    exit
    bcdboot c:\windows /s a: /f uefi
    '
#endregion
#region - AcctLockouts
#region - Get-AccountLockoutLocation
Search-ADAccount -LockedOut
#region - Get-ADUserLastLogon
function Get-ADUserLastLogon {
    # .SYNOPSIS
    # Get-ADUserLastLogon gets the last logon timestamp of an Active Directory user.
    # .DESCRIPTION
    # Each domain controller is queried separately to calculate the last logon from all results of all DCs.
    # .PARAMETER
    # UserLogonName
    # Provide the user logon name (samaccountname) of the user.
    # .EXAMPLE
    # Get-ADUserLastLogon -UserLogonName s.stollane
    # .NOTES
    # Author: Patrick Gruenauer
    # Web:
    # https://sid-500.com
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        $UserLogonName
    )
    $resultlogon = @()
    Import-Module ActiveDirectory
    $ds = dsquery user -samid $UserLogonName
    If ($ds) {
        $getdc = (Get-ADDomainController -Filter *).Name
        foreach ($dc in $getdc) {
            Try {
                $user = Get-ADUser $UserLogonName -Server $dc -Properties lastlogon -ErrorAction Stop
                $resultlogon += New-Object -TypeName PSObject -Property ([ordered]@{
                        'User'      = $user.Name
                        'DC'        = $dc
                        'LastLogon' = [datetime]::FromFileTime($user.'lastLogon')
                    })
            }
            Catch {
                ''
                Write-Warning "No reports from $($dc)!"
            }
        }
        $resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' } | Sort-Object LastLogon -Descending | Select-Object -First 1 | Format-Table -AutoSize
        If ($null -EQ ($resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' })) {
            ''
            Write-Warning "No reports for user $($user.name). Possible reason: No first login."
        }
    }
    else 
    { throw 'User not found. Check entered username.' }
}
Get-ADUserLastLogon -UserLogonName chuck.mella
#endregion
#region - Get-AccountLockoutLocation
Function Get-AccountLockoutLocation {
    <#
          .Synopsis
          Returns the ComputerName that originated an account lockout for the specified user.
          .DESCRIPTION
          Scans specified Domain Controller Eventlogs for EventID nnnn and returns the
          ComputerName that originated an account lockout for the specified user.
          .PARAMETER UserName <REQUIRED>
          Text - The username (SamAccountName) to search for. Do not prefix with the domain name.
          .PARAMETER DCs <OPTIONAL>
          Array - Narrows search to only the specified Domain Controller(s).
          -DCs 'DC001'
          -DCs 'DC001','DC002','DC006'
          .PARAMETER allDCs <OPTIONAL>
          Switch - Forces search of all Domain Controllers. Any specified Domain controller(s)
          will be ignored
          -allDCs
          .EXAMPLE  Find-PCLockingAcct Joe.User DC0002
          Search specified DC and return Computername if found.
          Output
          -----------
          <Object> ( DC, Time, User, Computer}
          <String> 'No data' - Only if username not found.
          .EXAMPLE Find-PCLockingAcct Joe.User -allDCs
          Search all DCs and return Computername if found.
          Output
          -----------
          <Object> ( DC, Time, User, Computer}
          <String> 'No data' - Only if username not found.
      #>
    Param
    (
        [Parameter(Mandatory = $true)]$UserName,
        [array]$DCs,
        [switch]$allDCs
    )
    # Use ADSI (LDAP) to Collect all domain controllers
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.Filter = '(objectCategory=computer)'
    $Searcher.SearchRoot = "LDAP://ou=domain controllers,$(([ADSI]'').distinguishedname)"
    $ADCs = $Searcher.FindAll() | Select-Object @{n = 'DC'; e = { $_.Properties.cn } } | Select-Object -exp DC
    # Strip domain from UserName
    $UserName = $UserName -replace '^\w+[^\\]+\\' -replace '\@+[^\@]+$'
    # Setup Event Query
    $eQry = ('<QueryList>' + [Environment]::NewLine + '  <Query Id="0" Path="Security">' + [Environment]::NewLine + `
            '    <Select Path="Security">*[System[(EventID=4740)]]</Select>' + [Environment]::NewLine + '  </Query>' + `
            [Environment]::NewLine + '</QueryList>')
    $arrEvents = New-Object System.Collections.ArrayList
    # Select Domain Controller(s)
    If ($null -eq $DCs) { $DCs = $ADCs }
    If ($allDCs) { $DCs = $ADCs }
    # Poll DC Eventlogs for EventID 4740
    Foreach ($DC in $DCs) {
        Try {
            $evts = $(Get-WinEvent -MaxEvents 5 -ComputerName $DC -FilterXML $eQry -ErrorAction Stop) | 
            Select-Object -Property @{name = 'DC'; exp = { $DC } }, TimeCreated, Message
            $evts | ForEach-Object { $null = $arrEvents.Add($_) }
        }
        Catch { Write-Warning "No matching events for user [$username] found on [$DC]." }
    }
    # Find event for specified user.
    If ($null -eq $arrEvents -or $arrEvents.Count -eq 0) { Write-Warning "No Events found: EXITING"; BREAK }
    Else {
        $trgevt = $arrEvents | Where-Object { $_.Message -match $UserName } | Sort-Object | Select-Object -First 1
        # Find CompterName that invoked Account lockout
        $Computer = (($trgevt.Message.Split([char]13) | Where-Object { $_ -match 'Caller Computer Name' }).Split([char]09)[-1]).Trim()
        If ([string]::IsNullOrEmpty($Computer)) { Return "No Data" }
        Else { Return [psCustomObject]@{'DC' = $DC; 'Time' = $evts.TimeCreated; 'User' = $UserName; 'Location' = $Computer } }
        #Find-PCLockingAcct 'bh-sbuss' -dcs '300003-svr0246','300074-svr0246','600075-svr0246'
    }
}
Get-AccountLockoutLocation -UserName chuck.mella -DCs fabcondc02
#endregion
#region - Get-AccountLockoutStatus
# https://thesysadminchannel.com/get-account-lock-out-source-powershell/
#requires -Module ActiveDirectory
Function Get-AccountLockoutStatus {
    <#
          .Synopsis
          This will iterate through all your domain controllers by default and checks for event 4740 in event viewer. To use this, you must dot source the file and call the function.
          For updated help and examples refer to -Online version.
          .DESCRIPTION
          This will go through all domain controllers by default and check to see if there are event ID for lockouts and display the information in table with Username, Time, Computername and CallerComputer.
          For updated help and examples refer to -Online version.
          .NOTES   
          Name: Get-AccountLockoutStatus
          Author: theSysadminChannel
          Version: 1.01
          DateCreated: 2017-Apr-09
          DateUpdated: 2017-Apr-09
          .LINK
          https://thesysadminchannel.com/get-account-lock-out-source-powershell -
          .PARAMETER ComputerName
          By default all domain controllers are checked. If a ComputerName is specified, it will check only that.
          .PARAMETER Username
          If a username is specified, it will only output events for that username.
          .PARAMETER DaysFromToday
          This will set the number of days to check in the event logs.  Default is 3 days.
          .EXAMPLE
          Get-AccountLockoutStatus
          Description:
          Will generate a list of lockout events on all domain controllers.
          .EXAMPLE
          Get-AccountLockoutStatus -ComputerName DC01, DC02
          Description:
          Will generate a list of lockout events on DC01 and DC02.
          .EXAMPLE
          Get-AccountLockoutStatus -Username Username
          Description:
          Will generate a list of lockout events on all domain controllers and filter that specific user.
          .EXAMPLE
          Get-AccountLockoutStatus -DaysFromToday 2
          Description:
          Will generate a list of lockout events on all domain controllers going back only 2 days.
      #>
    [CmdletBinding()]
    param(
        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [string[]]     $ComputerName = (Get-ADDomainController -Filter * |  Select-Object -ExpandProperty Name),
        [Parameter()]
        [string]       $Username,
        [Parameter()]
        [int]          $DaysFromToday = 3
    )
    BEGIN {
        $Object = @()
    }
    PROCESS {
        Foreach ($Computer in $ComputerName) {
            try {
                $EventID = Get-WinEvent -ComputerName $Computer -FilterHashtable @{Logname = 'Security'; ID = 4740; StartTime = (Get-Date).AddDays(-$DaysFromToday) } -EA 0
                Foreach ($Event in $EventID) {
                    $Properties = @{Computername = $Computer
                        Time                     = $Event.TimeCreated
                        Username                 = $Event.Properties.value[0]
                        CallerComputer           = $Event.Properties.value[1]
                    }
                    $Object += New-Object -TypeName PSObject -Property $Properties | Select-Object ComputerName, Username, Time, CallerComputer
                }
            }
            catch {
                $ErrorMessage = $Computer + " Error: " + $_.Exception.Message
            }
            finally {
                if ($Username) {
                    Write-Output $Object | Where-Object { $_.Username -eq $Username }
                }
                else {
                    Write-Output $Object
                }
                $Object = $null
            }
        }
    }      
    END {}
}
Get-AccountLockoutStatus -ComputerName fabcondc02 -Username chuck.mella
#endregion
#region - windows-track-down-an-account-lockout-sourc
# https://social.technet.microsoft.com/wiki/contents/articles/52327.windows-track-down-an-account-lockout-source-and-the-reason-with-powershell.aspx
Import-Module ActiveDirectory
$UserName = Read-Host "Please enter username"
#Get main DC
$PDC = (Get-ADDomainController -Filter * | Where-Object { $_.OperationMasterRoles -contains "PDCEmulator" })
#Get user info
$UserInfo = Get-ADUser -Identity $UserName
#Search PDC for lockout events with ID 4740
$LockedOutEvents = Get-WinEvent -ComputerName $PDC.HostName -FilterHashtable @{LogName = 'Security'; Id = 4740 } -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending
#Parse and filter out lockout events
Foreach ($Event in $LockedOutEvents) {
    If ($Event | Where-Object { $_.Properties[2].value -match $UserInfo.SID.Value }) {
        $Event | Select-Object -Property @(
            @{Label = 'User'; Expression = { $_.Properties[0].Value } }
            @{Label = 'DomainController'; Expression = { $_.MachineName } }
            @{Label = 'EventId'; Expression = { $_.Id } }
            @{Label = 'LockoutTimeStamp'; Expression = { $_.TimeCreated } }
            @{Label = 'Message'; Expression = { $_.Message -split "`r" | Select-Object -First 1 } }
            @{Label = 'LockoutSource'; Expression = { $_.Properties[1].Value } }
        )
    }
}
#endregion
#region - AutomatingADirectoryAccountLockoutSearch
# Only get event logs from the DCs that show a lockout count            
$DCs = $report |            
Where-Object { $_.badPwdCount -gt 0 } |            
Select-Object -ExpandProperty DC -Unique            
$Milliseconds = $Hours * 3600000            
# Script block for remote event log filter and XML event data extraction            
# Logon audit failure events            
#   Event 4625 is bad password in client log            
#   Event 4771 is bad password in DC log            
#   Event 4740 is lockout in DC log            
$sb = {            
    [xml]$FilterXML = (Dec64 'DQo8UXVlcnlMaXN0Pg0KICAgIDxRdWVyeSBJZD0iMCIgUGF0aD0iU2VjdXJpdHkiPg0KICAgICAgICA8U2VsZWN0IFBhdGg9IlNlY3VyaXR5Ij4NCiAgICAgICAgICAgICpbU3lzdGVtWyhFdmVudElEPTQ3NDAgb3IgRXZlbnRJRD00NzcxKSBhbmQgVGltZUNyZWF0ZWRbdGltZWRpZmYoQFN5c3RlbVRpbWUpICZsdDs9ICRVc2luZzpNaWxsaXNlY29uZHNdXV0kVXNpbmc6VXNlckZpbHRlclhNTA0KICAgICAgICA8L1NlbGVjdD4NCiAgICA8L1F1ZXJ5Pg0KPC9RdWVyeUxpc3Q+DQo=')
    Try {            
        $Events = Get-WinEvent -FilterXml $FilterXML -ErrorAction Stop
        ForEach ($Event in $Events) {
            # Convert the event to XML
            $eventXML = [xml]$Event.ToXml()
            # Iterate through each one of the XML message properties
            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) {
                # Append these as object properties
                Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                    -Name  $eventXML.Event.EventData.Data[$i].name `
                    -Value $eventXML.Event.EventData.Data[$i].'#text'
            } #for
        } #FE
        $Events | Select-Object *
    } #Try
    Catch {
        If ($_.Exception -like "*No events were found that match criteria*") {
            Write-Warning "[$(hostname)] No events found"
        }
        Else { $_ }
    } #Catch
}
# Clear out the local job queue            
Get-Job | Remove-Job            
# Load up the local job queue with event log queries to each DC            
Write-Verbose "Querying lockout events on DCs [$DCs]."            
$null = Invoke-Command -ScriptBlock $sb -ComputerName $DCs -AsJob      <##>
#endregion
#endregion
#region 
Get-EventLog 'security' | Where-Object { $_.message -like "*shook*" -AND $_.message.contains("Source Network Address") } 
$ComDN = "(&(objectCategory=computer)(objectClass=computer)(cn=$env:computername))" 
New-PSSession vandc050900-130 
Enter-PSSession WinRM1 
Get-aduserlas 
#endregion 
Search-ADAccount -LockedOut 
#region - Get-ADUserLastLogon 
function Get-ADUserLastLogon { 
    # .SYNOPSIS 
    # Get-ADUserLastLogon gets the last logon timestamp of an Active Directory user. 
    # .DESCRIPTION 
    # Each domain controller is queried separately to calculate the last logon from all results of all DCs. 
    # .PARAMETER 
    # UserLogonName 
    # Provide the user logon name (samaccountname) of the user. 
    # .EXAMPLE 
    # Get-ADUserLastLogon -UserLogonName s.stollane 
    # .NOTES 
    # Author: Patrick Gruenauer 
    # Web: 
    # https://sid-500.com 
    [CmdletBinding()] 
    param 
    ( 
        [Parameter(Mandatory = $true)] 
        $UserLogonName 
    ) 
    $resultlogon = @() 
    Import-Module ActiveDirectory 
    $ds = dsquery user -samid $UserLogonName 
    If ($ds) { 
        $getdc = (Get-ADDomainController -Filter *).Name 
        foreach ($dc in $getdc) { 
            Try { 
                $user = Get-ADUser $UserLogonName -Server $dc -Properties lastlogon -ErrorAction Stop 
                $resultlogon += New-Object -TypeName PSObject -Property ([ordered]@{ 
                        'User'      = $user.Name 
                        'DC'        = $dc 
                        'LastLogon' = [datetime]::FromFileTime($user.'lastLogon') 
                    }) 
            } 
            Catch { 
                '' 
                Write-Warning "No reports from $($dc)!" 
            } 
        } 
        $resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' } | Sort-Object LastLogon -Descending | Select-Object -First 1 | Format-Table -AutoSize 
        If ($null -EQ ($resultlogon | Where-Object { $_.lastlogon -NotLike '*1601*' })) { 
            '' 
            Write-Warning "No reports for user $($user.name). Possible reason: No first login." 
        } 
    } 
    else  
    { throw 'User not found. Check entered username.' } 
} 
Get-ADUserLastLogon -UserLogonName sammie.davis 
#endregion 
#region - Get-AccountLockoutLocation 
Function Get-AccountLockoutLocation { 
    <# 
              .Synopsis 
                  Returns the ComputerName that originated an account lockout for the specified user. 
              .DESCRIPTION 
                  Scans specified Domain Controller Eventlogs for EventID nnnn and returns the 
                  ComputerName that originated an account lockout for the specified user. 
              .PARAMETER UserName <REQUIRED> 
                Text - The username (SamAccountName) to search for. Do not prefix with the domain name. 
              .PARAMETER DCs <OPTIONAL> 
                  Array - Narrows search to only the specified Domain Controller(s). 
                  -DCs 'DC001' 
                  -DCs 'DC001','DC002','DC006' 
              .PARAMETER allDCs <OPTIONAL> 
                  Switch - Forces search of all Domain Controllers. Any specified Domain controller(s)
                  will be ignored 
                  -allDCs 
              .EXAMPLE  Find-PCLockingAcct Joe.User DC0002 
                  Search specified DC and return Computername if found. 
                  Output 
                  ----------*
                  <Object> ( DC, Time, User, Computer} 
                  <String> 'No data' - Only if username not found. 
              .EXAMPLE Find-PCLockingAcct Joe.User -allDCs 
                  Search all DCs and return Computername if found. 
                  Output 
                  ----------*
                  <Object> ( DC, Time, User, Computer} 
                  <String> 'No data' - Only if username not found. 
          #> 
    Param 
    ( 
        [Parameter(Mandatory = $true)]$UserName, 
        [array]$DCs, 
        [switch]$allDCs 
    ) 
    # Use ADSI (LDAP) to Collect all domain controllers 
    $Searcher = New-Object DirectoryServices.DirectorySearcher 
    $Searcher.Filter = '(objectCategory=computer)' 
    $Searcher.SearchRoot = "LDAP://ou=domain controllers,$(([ADSI]'').distinguishedname)" 
    $ADCs = $Searcher.FindAll() | Select-Object @{n = 'DC'; e = { $_.Properties.cn } } | Select-Object -exp DC 
    # Strip domain from UserName 
    $UserName = $UserName -replace '^\w+[^\\]+\\' -replace '\@+[^\@]+$' 
    # Setup Event Query 
    $eQry = ('<QueryList>' + [Environment]::NewLine + '  <Query Id="3" Path="Security">' + [Environment]::NewLine + `
        '    <Select Path="Security">*[System[(EventID=4740)]]</Select>' + [Environment]::NewLine + '  </Query>' + `
        [Environment]::NewLine + '</QueryList>') 
    $arrEvents = New-Object System.Collections.ArrayList 
    # Select Domain Controller(s) 
    If ($null -eq $DCs) { $DCs = $ADCs } 
    If ($allDCs) { $DCs = $ADCs } 
    # Poll DC Eventlogs for EventID 4740 
    Foreach ($DC in $DCs) { 
        Try { 
            $evts = $(Get-WinEvent -MaxEvents 5 -ComputerName $DC -FilterXML $eQry -ErrorAction Stop) |  
            Select-Object -Property @{name = 'DC'; exp = { $DC } }, TimeCreated, Message 
            $evts | ForEach-Object { $null = $arrEvents.Add($_) } 
        } 
        Catch { Write-Warning "No matching events for user [$username] found on [$DC]." } 
    } 
    # Find event for specified user. 
    If ($null -eq $arrEvents -or $arrEvents.Count -eq 0) { Write-Warning "No Events found: EXITING"; BREAK } 
    Else { 
        $trgevt = $arrEvents | Where-Object { $_.Message -match $UserName } | Sort-Object | Select-Object -First 1 
        # Find CompterName that invoked Account lockout 
        $Computer = (($trgevt.Message.Split([char]13) | Where-Object { $_ -match 'Caller Computer Name' }).Split([char]09)[-1]).Trim() 
        If ([string]::IsNullOrEmpty($Computer)) { Return "No Data" } 
        Else { Return [psCustomObject]@{'DC' = $DC; 'Time' = $evts.TimeCreated; 'User' = $UserName; 'Location' = $Computer } } 
        #Find-PCLockingAcct 'bh-sbuss' -dcs '300003-svr0246','300074-svr0246','600075-svr0246' 
    } 
} 
Get-AccountLockoutLocation -UserName sammie.davis -allDCs 
#endregion 
#region - Get-AccountLockoutStatus 
# https://thesysadminchannel.com/get-account-lock-out-source-powershell/ 
#requires -Module ActiveDirectory 
Function Get-AccountLockoutStatus { 
    <# 
          .Synopsis 
          This will iterate through all your domain controllers by default and checks for event 4740 in event viewer. To use this, you must dot source the file and call the function. 
          For updated help and examples refer to -Online version. 
          .DESCRIPTION 
          This will go through all domain controllers by default and check to see if there are event ID for lockouts and display the information in table with Username, Time, Computername and CallerComputer. 
          For updated help and examples refer to -Online version. 
          .NOTES    
          Name: Get-AccountLockoutStatus 
          Author: theSysadminChannel 
          Version: 1.01 
          DateCreated: 2017-Apr-09 
          DateUpdated: 2017-Apr-09 
          .LINK 
          https://thesysadminchannel.com/get-account-lock-out-source-powershell *
          .PARAMETER ComputerName 
          By default all domain controllers are checked. If a ComputerName is specified, it will check only that. 
          .PARAMETER Username 
          If a username is specified, it will only output events for that username. 
          .PARAMETER DaysFromToday 
          This will set the number of days to check in the event logs.  Default is 3 days. 
          .EXAMPLE 
          Get-AccountLockoutStatus 
          Description: 
          Will generate a list of lockout events on all domain controllers. 
          .EXAMPLE 
          Get-AccountLockoutStatus -ComputerName DC01, DC02 
          Description: 
          Will generate a list of lockout events on DC01 and DC02. 
          .EXAMPLE 
          Get-AccountLockoutStatus -Username Username 
          Description: 
          Will generate a list of lockout events on all domain controllers and filter that specific user. 
          .EXAMPLE 
          Get-AccountLockoutStatus -DaysFromToday 2 
          Description: 
          Will generate a list of lockout events on all domain controllers going back only 2 days. 
      #> 
    [CmdletBinding()] 
    param( 
        [Parameter( 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            Position = 0)] 
        [string[]]     $ComputerName = (Get-ADDomainController -Filter * |  Select-Object -ExpandProperty Name), 
        [Parameter()] 
        [string]       $Username, 
        [Parameter()] 
        [int]          $DaysFromToday = 3 
    ) 
    BEGIN { 
        $Object = @() 
    } 
    PROCESS { 
        Foreach ($Computer in $ComputerName) { 
            try { 
                $EventID = Get-WinEvent -ComputerName $Computer -FilterHashtable @{Logname = 'Security'; ID = 4740; StartTime = (Get-Date).AddDays(-$DaysFromToday) } -EA 0 
                Foreach ($Event in $EventID) { 
                    $Properties = @{Computername = $Computer 
                        Time                     = $Event.TimeCreated 
                        Username                 = $Event.Properties.value[0] 
                        CallerComputer           = $Event.Properties.value[1] 
                    } 
                    $Object += New-Object -TypeName PSObject -Property $Properties | Select-Object ComputerName, Username, Time, CallerComputer 
                } 
            }
            catch { 
                $ErrorMessage = $Computer + " Error: " + $_.Exception.Message 
            }
            finally { 
                if ($Username) { 
                    Write-Output $Object | Where-Object { $_.Username -eq $Username } 
                }
                else { 
                    Write-Output $Object 
                } 
                $Object = $null 
            } 
        } 
    }       
    END {} 
} 
Get-AccountLockoutStatus -ComputerName vandc050900-130, vandc060900-130 -Username sammie.davis 
#endregion 
#region - windows-track-down-an-account-lockout-sourc 
# https://social.technet.microsoft.com/wiki/contents/articles/52327.windows-track-down-an-account-lockout-source-and-the-reason-with-powershell.aspx 
Import-Module ActiveDirectory 
$UserName = Read-Host "Please enter username" 
#Get main DC 
$PDC = (Get-ADDomainController -Filter * | Where-Object { $_.OperationMasterRoles -contains "PDCEmulator" }) 
#Get user info 
$UserInfo = Get-ADUser -Identity $UserName 
#Search PDC for lockout events with ID 4740 
$LockedOutEvents = Get-WinEvent -ComputerName $PDC.HostName -FilterHashtable @{LogName = 'Security'; Id = 4740 } -ErrorAction Stop | Sort-Object -Property TimeCreated -Descending 
#Parse and filter out lockout events 
Foreach ($Event in $LockedOutEvents) { 
    If ($Event | Where-Object { $_.Properties[2].value -match $UserInfo.SID.Value }) { 
        $Event | Select-Object -Property @( 
            @{Label = 'User'; Expression = { $_.Properties[0].Value } } 
            @{Label = 'DomainController'; Expression = { $_.MachineName } } 
            @{Label = 'EventId'; Expression = { $_.Id } } 
            @{Label = 'LockoutTimeStamp'; Expression = { $_.TimeCreated } } 
            @{Label = 'Message'; Expression = { $_.Message -split "`r" | Select-Object -First 1 } } 
            @{Label = 'LockoutSource'; Expression = { $_.Properties[1].Value } } 
        ) 
    }
} 
#endregion 
#region - AutomatingADirectoryAccountLockoutSearch 
# Only get event logs from the DCs that show a lockout count             
$DCs = $report | Where-Object { $_.badPwdCount -gt 0 } | Select-Object -ExpandProperty DC -Unique             
$Milliseconds = $Hours * 3600000             
# Script block for remote event log filter and XML event data extraction             
# Logon audit failure events             
#   Event 4625 is bad password in client log             
#   Event 4771 is bad password in DC log             
#   Event 4740 is lockout in DC log             
$sb = {             
    [xml]$FilterXML = (Dec64 'DQo8UXVlcnlMaXN0Pg0KICAgIDxRdWVyeSBJZD0iMCIgUGF0aD0iU2VjdXJpdHkiPg0KICAgICAgICA8U2VsZWN0IFBhdGg9IlNlY3VyaXR5Ij4gDQogICAgICAgICAgICAqW1N5c3RlbVsoRXZlbnRJRD00NzQwIG9yIEV2ZW50SUQ9NDc3MSkgYW5kIFRpbWVDcmVhdGVkW3RpbWVkaWZmKEBTeXN0ZW1UaW1lKSAmbHQ7PSAkVXNpbmc6TWlsbGlzZWNvbmRzXV1dJFVzaW5nOlVzZXJGaWx0ZXJYTUwNCiAgICAgICAgPC9TZWxlY3Q+DQogICAgPC9RdWVyeT4NCjwvUXVlcnlMaXN0PiANCg==') 
    Try {             
        $Events = Get-WinEvent -FilterXml $FilterXML -ErrorAction Stop 
        ForEach ($Event in $Events) { 
            # Convert the event to XML 
            $eventXML = [xml]$Event.ToXml() 
            # Iterate through each one of the XML message properties 
            For ($i = 0; $i -lt $eventXML.Event.EventData.Data.Count; $i++) { 
                # Append these as object properties 
                Add-Member -InputObject $Event -MemberType NoteProperty -Force `
                    -Name  $eventXML.Event.EventData.Data[$i].name `
                    -Value $eventXML.Event.EventData.Data[$i].'#text' 
            }
        }
        $Events | Select-Object * 
    }
    Catch { 
        If ($_.Exception -like "*No events were found that match criteria*") { Write-Warning "[$(hostname)] No events found" } 
        Else { $_ } 
    }
} 
# Clear out the local job queue             
Get-Job | Remove-Job             
# Load up the local job queue with event log queries to each DC             
Write-Verbose "Querying lockout events on DCs [$DCs]."             
$null = Invoke-Command -ScriptBlock $sb -ComputerName $DCs -AsJob      <##> 
#endregion 
#endregion
