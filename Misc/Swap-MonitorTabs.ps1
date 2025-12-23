Function Send-Tab
{
    Param
    (
        $trgwinTitle ='chrome',# 'vandc06'
        $keycombo = '%a'
    )
    # https://WGSVR/NmConsole/#discover
    (Get-host).UI.Rawur.windowTitle = "Monitor Tabs"
    Clear-Host
    Write-Host "cycling Monitor Tabs... "
    # Load all required control assembies
        [Void][System.Reflection.Assembly]::LoadwithPartialName('System.Windows.Forms')
        [Void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.visualBasic')
        # $wshell = New-Object -ComObject 'wscript.shell'
        ## Add-Type -AssemblyName UIAutomationclient
        # Load all titled processses and select target process.
    $CurrentApps = Get-Process -ea SilentlyContinue | Where-Object {$_.MainwindowTitle -ne ''}
    $trgProcess = $CurrentApps | where MainwindoWTitle -match $trgwinTitle
    $ExplorerwinTitles = (New-Object -ComObject 'shell.application').windows() | Select LocationName
    # select Proper Tab in browser
        Do
        {
            $trgProcess = Get-Process -ea silentlycontinue | where-Object {$_.MainwindowTltle -match '(chromeledge)' }
            [Microsoft.VisualBasic.Interaction]::AppActivate(($trgProcess).MainwindowTitle)
                If ($trgProcess.MainwindowTitle -notmatch 'Whatsup Gold' )
            {
            [System.windows.Forms.sendKeys]::sendwait("A{PgUp}") # "%{ScrollLock}" "%{capsLock}" "%{NumLock}"
            }
        } until ($trgProcess.MainwindowTitle -match 'whatsUp Gold' )
        # select various items in browser
        Do
        {
            $cntrl = 23
            $cntr2 = 23
            Do
            {
                [Microsoft.VisualBasic.Interaction]::AppActivate(($trgProcess).MainwindowTitle)
                [System.windows.Forms.sendKeys]::sendwait("{PgUp}") # "%{scrollLock}" "%{CapsLock}" "%{NumLock}"
                [Void](('CapsLock','NumLock','scroll' ) | %{ [System.windows.Forms.control]::IsKeyLocked($_) })
                # $wshell.AppActivate($trgProcess.Id);sleep 1;
                $wshell.sendKeys($keycombo) #"%{TAB}"
                ## $ae = [System.windows.Automation.AutomationElement]::FromHandle($trgProcess.MainwindowHandle)

                ## $wp = $ae.GetcurrentPattern([System.windows.Automation.windowPatternidentifiers]::Pattern)
                ## $wp.current.windowvisualstate = 'Minimized'
                sleep -Milliseconds 2000
                $cntrl --
            } until ($cntr1 -le 0)
            Do
            {
                [Microsoft.visualBasic.rnteraction]::AppActivate(($trgProcess).MainwindowTitle)
                [system.windows.Forms.sendKeys]::sendwait("{PgDn}") # "%{scrollLock}" "%{capsLock}" "%{NumLock}"
                [void](('CapsLock' ,'NumLock','Scroll') | %{[System.windows.Forms.control]::IsKeyLocked($_) })
                # $wshell.AppActivate($trgProcess.rd);sleep 1;
                $wshell.sendKeys($keycombo) #"%{TAB}"
                ## $ae = [system.windows.Automation.AutomationElement]::FromHandle($trgProcess.MainwindowHandle)
                ## $wp = $ae.GetcurrentPattern([system.Windows.Automation.windowPatternrdentifiers]::Pattern)
                ## $wp.current.windowvisualstate = 'Minimized'
                sleep -Milliseconds 2000
                $cntr2 --
            } until ($cntr2 -le 0)
        } while ($true)
    # Powershell -windowstyle Min -NoLogo -NoProfile -ExecutionPolicy ByPass -Encryptedcommand {} -command {} -File 'Path'
}
