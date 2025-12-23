#region - Reset WSUS Client

    $wsusServices = '(wuauserv|cryptSvc|bits|msiserver)'
    Get-Service | Where Name -Match $wsusServices | Stop-Service -Force -Verbose
    'C:\Windows\SoftwareDistribution','C:\Windows\System32\catroot2' | %{ Rename-Item $_ ($_ + '.old') -Force -Verbose }
    Get-Service | Where Name -Match $wsusServices | Start-Service -Force -Verbose
#endregion
#region - Get WMI Class
    function Find-WmiClass
    {
        param([Parameter(Mandatory)]$Keyword)
        Write-Progress -Activity "Finding WMI Classes" -Status "Searching"

    Get-WmiObject -Class * -List |
        Where-Object {
        $containsMember = ((@($_.Properties. Name) -like "*$Keyword*").Count -gt 0) -or ((@($_.Methods. Name) -like "*$Keyword*").Count -gt 0)
        $containsClassName = $_.Name -like "*$Keyword*" -and $_.Properties.Count -gt 2 -and $_. Name -notlike 'Win32_Perf*'
        $containsMember -or $containsClassName
        }

    #find all WMI classes...
    # that contain the search keyword
    Write-Progress -Activity "Find WMI Classes" -Completed
    }

    $classes = Find-WmiClass 'bios'

    $classes | Out-GridView -Title "Select WMI Class" -OutputMode Single |
        ForEach-Object { Get-CimInstance -Class $_.Name | Select-Object -Property * | Out-GridView -Title "Instances"}
#endregion
#region - WSUS Client Reset
    Write-Host -f yellow 'Simple Script to reset Windows updates components by Your Windows Guide.'

    $wsusServices = '(wuauserv|cryptSvc|bits|appidsvc|msiserver)'
    $wSvcs = ($wsusServices -replace '\(' -replace '\)').Split('|')
    Get-Service | Where Name -Match $wsusServices | Stop-Service -Force -Verbose
    If ((Get-Service | Where Name -Match $wsusServices ).Status -contains 'Running')
    {
        Write-Host -f Red "Not all services stopped, EXITING:`n$(Get-Service | Where Name -Match $wsusServices | Select Name,Status | Out-String)"
    }

    # Deleting *.qmgr files
    GCI $env:AllUsersProfile\Microsoft\Network\Downloader -Filter 'qmgr*.dat' | Remove-Item -Force -Confirm:$false -Verbose
    GCI $env:AllUsersProfile\'Application Data'\Microsoft\Network\Downloader -Filter 'qmgr*.dat' | Remove-Item -Force -Confirm:$false -Verbose

    # Removing Windows update cache files....
    # Files
    ForEach ($file in @("$env:SystemRoot\winsxs\pending.xml.bak","$env:SystemRoot\WindowsUpdate.log.bak"))
    {
        If (Test-Path $file -PathType Leaf) { Remove-Item $file -Force -Confirm:$false -Verbose }
        If (Test-Path ($file = $file -Replace '.bak') -PathType Leaf)
        {
            # $file = "C:\temp\file.txt"
            # ($FileSecurity = [System.Security.AccessControl.FileSecurity]::new()).SetOwner([System.Security.Principal.NTAccount]::New($env:username))
            # [System.IO.File]::SetAccessControl($file, $FileSecurity)
            takeown /f $file  
            attrib -r -s -h /s /d $file  
            Rename-Item $file ($file  + '.bak')
        }
    }
 
    # Folders
    ForEach ($dir in @("$env:SystemRoot\SoftwareDistribution.bak","$env:SystemRoot\system32\Catroot2.bak"))
    {
        If (Test-Path $dir -PathType Container) { Remove-Item $dir -Recurse -Force -Confirm:$false -Verbose }
        If (Test-Path ($dir = $dir -Replace '.bak') -PathType Container)
        {
            attrib -r -s -h /s /d $dir
            Rename-Item $dir ($dir  + '.bak')
        }
    }

    # Resetting Update services security descriptors
    $acls = [Ordered]@{
        1 = 'A;;CCLCSWLOCRRC;;;AU'
        2 = 'A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA'
        3 = 'A;;CCDCLCSWRPWPDTLCRSDRCWDWO;;;SO'
        4 = 'A;;CCLCSWRPWPDTLOCRRC;;;SY'
        5 = 'AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;WD'}
    ($wSvcs -notmatch '(appidsvc|msiserver)') + 'trustedinstaller' | %{
        $myArgs = 'sdset {0} {1}' -f $_,"D:($($acls.1))($($acls.2))($($acls.3))($($acls.4))S:($($acls.5))"
        Start-Process -FilePath sc.exe -ArgumentList $myArgs
        }

    # Re-registering Windows update files
      $trgDLLs = @('atl.dll','urlmon.dll','mshtml.dll','shdocvw.dll','browseui.dll','jscript.dll','vbscript.dll',
                 'scrrun.dll','msxml.dll','msxml3.dll','msxml6.dll','actxprxy.dll','softpub.dll','wintrust.dll',
                 'dssenh.dll','rsaenh.dll','gpkcsp.dll','sccbase.dll','slbcsp.dll','cryptdlg.dll','oleaut32.dll',
                 'ole32.dll','shell32.dll','initpki.dll','wuapi.dll','wuaueng.dll','wuaueng1.dll','wucltui.dll',
                 'wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll')
    SL $env:SystemRoot\system32\re*
      $trgDLLs | %{ regsvr32.exe /s $_ }

    # Resetting Winsock and Proxy
    netsh winsock reset
    netsh winsock reset proxy

    # Resetting the services as automatic
      $wsusSvcs = 'wuauserv,auto
                 bits,delayed-auto
                 cryptsvc,auto
                 TrustedInstaller,demand
                 DcomLaunch,auto' | ConvertFrom-Csv -Delim ',' -Header Svc,Start
    ForEach ($svc in $wsusSvcs)
    {
        $myArgs = 'config "{0}" start={1}' -f $svc.Svc,$svc.Start
        "Start-Process -FilePath sc.exe -ArgumentList $myArgs"
    }

    # Start
    # Starting services
    Get-Service | Where Name -Match '(wuauserv|bits|appidsvc|cryptsvc)' | Start-Service -Force -Verbose

    Write-Host -f yellow 'Task completed sucessfully! Please restart your computer and check for the updates again.'
    PAUSE
#endregion