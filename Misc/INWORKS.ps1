Function search-google {
    $query = 'https://www.google.com/search?q='
    $args | ForEach-Object { $query = $query + "$_+" }
    $url = $query.Substring(0, $query.Length - 1)
    Start-Process "$url"
}

Set-Alias glg search-google
glg nightstand, 2 drawer,  pull out tray, counter  height,  LED lights, cpap storage -inurl:amzon.com




Function Search-GoogleV2
{
    [CmdletBinding()]
    [Alias("glg")]
    $query = 'https://www.google.com/search?q='
    $args | ForEach-Object { $query = $query + "$_+" }
    $url = $query.Substring(0, $query.Length - 1)
    Start-Process "$url"
}



Function DecText($a)
{
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($a)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    return $UnsecurePassword
}

function Remove-comObjects ($reflist)
{
    foreach ($ref in $Reflist)
    {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) | out-null
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($ref) | out-null
            Remove-Variable $ref -Force | Out-Null
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

$x = 'LDAP://OU=E,OU=D,OU=C,OU=B,OU=A,DC=nae,DC=3,DC=2,DC=1'
$a = [adsisearcher]“”
    $a.Filter = "(&(objectClass=user))"
    $a.SearchRoot = $x
    $a.FindAll() | Select-Object @{n='User';e={[string]$_.Properties.name}},
                          @{n='ECPI';e={($_.Properties.userprincipalname).substring(0,10)}},
                          @{n='PIV';e={($_.Properties.userprincipalname).substring(10,6)}},
                          @{n='Expiration';e={[datetime]::FromFileTime([string]$_.Properties.accountexpires)}} | Where-Object ECPI |  Sort-Output User | Out-GridView -Title 'ASD Account PIVs & Expirations'



    ($a = [adsisearcher]“(&(objectClass=computer))”).SearchRoot = $x
    $wks = ($a.FindAll() | Select-Object @{n='Workstation';e={$_.Properties.cn}}).Workstation | Sort-Object
    $S = ForEach ($wk in $wks){ "$WK Pingable: $((Test-NetConnection -ComputerName $wk).PingSucceeded)" }
    $rslt = ($S = $s -replace ' Pingable') | ConvertFrom-Csv -Delimiter ':' -Header Computer,Pingable
    $rslt | Where-Object Pingable -eq $True
    $rslt | Where-Object Pingable -eq $false



Import-Module ActiveDirectory

function Get-LastLogonEvents
{
    $dcs = Get-ADDomainController -Filter {Name -like "*"}
    $users = Get-ADUser -Filter *
    $time = 0
    foreach($user in $users)
    {
        foreach($dc in $dcs)
        {
            $hostname = $dc.HostName
            $currentUser = Get-ADUser $user.SamAccountName | Get-ADObject -Server $hostname -Properties lastLogon
            if($currentUser.LastLogon -gt $time)
            {
                $time = $currentUser.LastLogon
            }
            $dt = [DateTime]::FromFileTime($time)
            Write-Host $currentUser "last logged on at:" $dt
            $time = 0
        }
    }
}
Get-LastLogonEvents













Function Global:Dec64 { param ($a)$b = [Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a)); Return $b }
Function Global:Enc64 { param ($a)$b = [Convert]::ToBase64String($a.ToCharArray()); Return $b }

#region - wsus
    # To force a WSUS server to synchronize now:
    (Get-WsusServer).GetSubscription().StartSynchronization()
    (Get-WsusServer).GetSubscription().GetLastSynchronizationInfo()
#endregion
#region - stop screensaver
    Function Global:Dec64 { param ($a) $b = [Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a)); Return $b }
    Function Global:Enc64 { param ($a) $b = [Convert]::ToBase64String($a.ToCharArray());Return $b }

    (Dec64 'ICAgICMgQ29uc29sZSAtIE1vdmUtTW91c2UgLXNlY3MgMTAgLUxvb3BJbmZpbml0ZSAkdHJ1ZQ0KICAgICMgSVNFIC0gTW92ZS1Nb3VzZSAteHkgMSAtc2VjcyA1IC1Mb29wSW5maW5pdGUgJHRydWUgLURpc3BsYXlQb3NpdGlvbiAkdHJ1ZQ0KICAgIFBhcmFtICgNCiAgICAgICAgW3VpbnQxNl0keHkgPSAxLA0KICAgICAgICBbaW50MzJdJHNlY3MgPSA1LA0KICAgICAgICBbYm9vbGVhbl0kTG9vcEluZmluaXRlID0gJGZhbHNlLA0KICAgICAgICBbYm9vbGVhbl0kRGlzcGxheVBvc2l0aW9uID0gJGZhbHNlDQogICAgICAgICkNCiAgICBCZWdpbiB7DQogICAgICAgIEZ1bmN0aW9uIERlYzY0IHsgUGFyYW0oJGEpICRiID0gW1N5c3RlbS5UZXh0LkVuY29kaW5nXTo6QVNDSUkuR2V0U3RyaW5nKFtTeXN0ZW0uQ29udmVydF06OkZyb21CYXNlNjRTdHJpbmcoJGEpKTtSZXR1cm4gJGIgfQ0KICAgICAgICAkdHlwZWRlZiA9IERlYzY0ICdkWE5wYm1jZ1UzbHpkR1Z0TGxKMWJuUnBiV1V1U1c1MFpYSnZjRk5sY25acFkyVnpPdzBLRFFwdVlXMWxjM0JoWTJVZ1VHOVRTQTBLZXcwS0lDQWdJSEIxWW14cFl5QnpkRw0KICAgICAgICAgICAgRjBhV01nWTJ4aGMzTWdUVzkxYzJVTkNpQWdJQ0I3RFFvZ0lDQWdJQ0FnSUZ0RWJHeEpiWEJ2Y25Rb0luVnpaWEl6TWk1a2JHd2lLVjBOQ2lBZ0lDQWdJQ0FnYzNSaGRHbGpJR1Y0ZEdWeWJpQjJiMg0KICAgICAgICAgICAgbGtJRzF2ZFhObFgyVjJaVzUwS0dsdWRDQmtkMFpzWVdkekxDQnBiblFnWkhnc0lHbHVkQ0JrZVN3Z2FXNTBJR1IzUkdGMFlTd2dhVzUwSUdSM1JYaDBjbUZKYm1adktUc05DZzBLSUNBZ0lDQWdJQw0KICAgICAgICAgICAgQndjbWwyWVhSbElHTnZibk4wSUdsdWRDQk5UMVZUUlVWV1JVNVVSbDlOVDFaRklEMGdNSGd3TURBeE93MEtEUW9nSUNBZ0lDQWdJSEIxWW14cFl5QnpkR0YwYVdNZ2RtOXBaQ0JOYjNabFZHOG9hVw0KICAgICAgICAgICAgNTBJSGdzSUdsdWRDQjVLUTBLSUNBZ0lDQWdJQ0I3RFFvZ0lDQWdJQ0FnSUNBZ0lDQnRiM1Z6WlY5bGRtVnVkQ2hOVDFWVFJVVldSVTVVUmw5TlQxWkZMQ0I0TENCNUxDQXdMQ0F3S1RzTkNpQWdJQw0KICAgICAgICAgICAgQWdJQ0FnZlEwS0lDQWdJSDBOQ24wPScNCiAgICAgICAgQWRkLVR5cGUgLVR5cGVEZWZpbml0aW9uICR0eXBlZGVmDQogICAgICAgIH0gI0JlZ2luDQogICAgUHJvY2VzcyB7DQogICAgICAgIElmICgkTG9vcEluZmluaXRlKXsNCiAgICAgICAgICAgICRpID0gMQ0KICAgICAgICAgICAgV2hpbGUgKCR0cnVlKSB7DQogICAgICAgICAgICAgICAgSWYgKCREaXNwbGF5UG9zaXRpb24peyBXcml0ZS1Ib3N0ICIkKFtTeXN0ZW0uV2luZG93cy5Gb3Jtcy5DdXJzb3JdOjpQb3NpdGlvbi5YKSwkKFtTeXN0ZW0uV2luZG93cy5Gb3Jtcy5DdXJzb3JdOjpQb3NpdGlvbi5ZKSIgfSAjSWYNCiAgICAgICAgICAgICAgICBJZiAoKCRpICUgMikgLWVxIDApeyBbUG9TSC5Nb3VzZV06Ok1vdmVUbygkeHksJHh5KSA7ICRpKysgfSAjSWYNCiAgICAgICAgICAgICAgICBFbHNlIHsgW1BvU0guTW91c2VdOjpNb3ZlVG8oLSR4eSwtJHh5KSA7ICRpLS0gfSAjRWxzZQ0KICAgICAgICAgICAgICAgIFN0YXJ0LVNsZWVwIC1TZWNvbmRzICRzZWNzDQogICAgICAgICAgICAgICAgfSAjV2hpbGUNCiAgICAgICAgICAgIH0gI0lmDQogICAgICAgIEVsc2Ugew0KICAgICAgICAgICAgSWYgKCREaXNwbGF5UG9zaXRpb24peyBXcml0ZS1Ib3N0ICIkKFtTeXN0ZW0uV2luZG93cy5Gb3Jtcy5DdXJzb3JdOjpQb3NpdGlvbi5YKSwkKFtTeXN0ZW0uV2luZG93cy5Gb3Jtcy5DdXJzb3JdOjpQb3NpdGlvbi5ZKSIgfSAjSWYNCiAgICAgICAgICAgIFtQb1NILk1vdXNlXTo6TW92ZVRvKCR4eSwkeHkpDQogICAgICAgICAgICB9ICNFbHNlDQogICAgICAgIH0gI1Byb2Nlc3MNCg==') | Clip

    Function Move-Mouse
    {
        # Console - Move-Mouse -secs 10 -LoopInfinite $true
        # ISE - Move-Mouse -xy 1 -secs 5 -LoopInfinite $true -DisplayPosition $true
        Param (
            [uint16]$xy = 1,
            [int32]$secs = 5,
            [boolean]$LoopInfinite = $false,
            [boolean]$DisplayPosition = $false
            )
        Begin {
            Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
            $typedef = (Dec64 'dXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KDQpuYW1lc3BhY2UgUG9TSA0Kew0KICAgIHB1YmxpYyBzdGF0aWMgY2xhc3MgTW91c2UNCiAgICB7DQogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0NCiAgICAgICAgc3RhdGljIGV4dGVybiB2b2lkIG1vdXNlX2V2ZW50KGludCBkd0ZsYWdzLCBpbnQgZHgsIGludCBkeSwgaW50IGR3RGF0YSwgaW50IGR3RXh0cmFJbmZvKTsNCg0KICAgICAgICBwcml2YXRlIGNvbnN0IGludCBNT1VTRUVWRU5URl9NT1ZFID0gMHgwMDAxOw0KDQogICAgICAgIHB1YmxpYyBzdGF0aWMgdm9pZCBNb3ZlVG8oaW50IHgsIGludCB5KQ0KICAgICAgICB7DQogICAgICAgICAgICBtb3VzZV9ldmVudChNT1VTRUVWRU5URl9NT1ZFLCB4LCB5LCAwLCAwKTsNCiAgICAgICAgfQ0KICAgIH0NCn0=')
            Add-Type -TypeDefinition $typedef
            } #Begin
        Process {
            If ($LoopInfinite){
                $i = 1
                While ($true) {
                    If ($DisplayPosition){
                        Write-Host "$([System.Windows.Forms.Cursor]::Position.X),$([System.Windows.Forms.Cursor]::Position.Y)" } #If
                    If (($i % 2) -eq 0){ [PoSH.Mouse]::MoveTo($xy,$xy) ; $i++ } #If
                    Else { [PoSH.Mouse]::MoveTo(-$xy,-$xy) ; $i-- } #Else
                    Start-Start-Sleep -Seconds $secs
                    } #While
                } #If
            Else {
                If ($DisplayPosition){ Write-Host "$([System.Windows.Forms.Cursor]::Position.X),$([System.Windows.Forms.Cursor]::Position.Y)" } #If
                [PoSH.Mouse]::MoveTo($xy,$xy)
                } #Else
            } #Process
    }

    Function Send-ShellPeriod
    {
        param($minutes = 60)

        $myshell = New-Object -com "Wscript.Shell"

        for ($i = 0; $i -lt $minutes; $i++) {
          Start-Start-Sleep -Seconds 60
          $myshell.sendkeys(".")
        }
    }

    Function Toggle-ScrollLock
    {
        Clear-Host
         Write-Output  "Keep-alive with Scroll Lock..."

        $WShell = New-Object -com "Wscript.Shell"

        while ($true)
        {
            # Some people get success using $WShell.sendkeys("SCROLLLOCK") instead of $WShell.sendkeys("{SCROLLLOCK}")
            $WShell.sendkeys("{SCROLLLOCK}")
            Start-Start-Sleep -Milliseconds 100
            $WShell.sendkeys("{SCROLLLOCK}")
            Start-Start-Sleep -Seconds 240
        }
    }

    Function Stay-Awake
    {
        <# Stay Awake by Frank Poth 2019-04-16 #>
        (Get-Host).UI.RawUI.WindowTitle = "Stay Awake"

        [System.Console]::BufferWidth  = [System.Console]::WindowWidth  = 40
        [System.Console]::BufferHeight = [System.Console]::WindowHeight = 10

        $shell = New-Object -ComObject WScript.Shell
        $start_time = Get-Date -UFormat %s <# Get the date in MS #>
        $current_time = $start_time
        $elapsed_time = 0
        Write-Host "I am awake!"
        Start-Start-Sleep -Seconds 5
        $count = 0

        while($true)
        {
            $shell.sendkeys("{NUMLOCK}{NUMLOCK}") <# Fake some input! #>
            if ($count -eq 8)
            {
                $count = 0
                Clear-Host
            }


            if ($count -eq 0)
            {
                $current_time = Get-Date -UFormat %s
                $elapsed_time = $current_time - $start_time
                Write-Host "I've been awake for "([System.Math]::Round(($elapsed_time / 60), 2))" minutes!"
            }
            else { Write-Host "Must stay awake..." }
            $count ++
            Start-Start-Sleep -Seconds 2.5
        }
        # The part that matters is $shell.sendkeys("{NUMLOCK}{NUMLOCK}") This registers 
        # two presses on the numlock key and fools the shell into thinking input was 
        # entered. I wrote this today after searching through various scripts that didn't 
        # work for me. Hope it helps someone!
    }

    Function Start-KillIdle
    {
        <#
            I created a PS script to check idle time and jiggle the mouse to prevent 
            the screensaver. There are two parameters you can control how it works:

                $checkIntervalInSeconds:
                    The interval in seconds to check if the idle time exceeds the limit

                $preventIdleLimitInSeconds:
                    The idle time limit in seconds. If the idle time exceeds the idle time 
                    limit, jiggle the mouse to prevent the screensaver
    
            Here we go. Save the script in preventIdle.ps1. For preventing the 4-min screensaver,
            I set $checkIntervalInSeconds = 30 and $preventIdleLimitInSeconds = 180.
        #>
        Param
        (
            $checkIntervalInSeconds = 30,
            $preventIdleLimitInSeconds = 180
        )
        Add-Type (Dec64 'dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLkRpYWdub3N0aWNzOw0KdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KDQpuYW1lc3BhY2UgUEludm9rZS5XaW4zMiB7DQoNCiAgICBwdWJsaWMgc3RhdGljIGNsYXNzIFVzZXJJbnB1dCB7DQoNCiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIFNldExhc3RFcnJvcj1mYWxzZSldDQogICAgICAgIHByaXZhdGUgc3RhdGljIGV4dGVybiBib29sIEdldExhc3RJbnB1dEluZm8ocmVmIExBU1RJTlBVVElORk8gcGxpaSk7DQoNCiAgICAgICAgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXQ0KICAgICAgICBwcml2YXRlIHN0cnVjdCBMQVNUSU5QVVRJTkZPIHsNCiAgICAgICAgICAgIHB1YmxpYyB1aW50IGNiU2l6ZTsNCiAgICAgICAgICAgIHB1YmxpYyBpbnQgZHdUaW1lOw0KICAgICAgICB9DQoNCiAgICAgICAgcHVibGljIHN0YXRpYyBEYXRlVGltZSBMYXN0SW5wdXQgew0KICAgICAgICAgICAgZ2V0IHsNCiAgICAgICAgICAgICAgICBEYXRlVGltZSBib290VGltZSA9IERhdGVUaW1lLlV0Y05vdy5BZGRNaWxsaXNlY29uZHMoLUVudmlyb25tZW50LlRpY2tDb3VudCk7DQogICAgICAgICAgICAgICAgRGF0ZVRpbWUgbGFzdElucHV0ID0gYm9vdFRpbWUuQWRkTWlsbGlzZWNvbmRzKExhc3RJbnB1dFRpY2tzKTsNCiAgICAgICAgICAgICAgICByZXR1cm4gbGFzdElucHV0Ow0KICAgICAgICAgICAgfQ0KICAgICAgICB9DQoNCiAgICAgICAgcHVibGljIHN0YXRpYyBUaW1lU3BhbiBJZGxlVGltZSB7DQogICAgICAgICAgICBnZXQgew0KICAgICAgICAgICAgICAgIHJldHVybiBEYXRlVGltZS5VdGNOb3cuU3VidHJhY3QoTGFzdElucHV0KTsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KDQogICAgICAgIHB1YmxpYyBzdGF0aWMgZG91YmxlIElkbGVTZWNvbmRzIHsNCiAgICAgICAgICAgIGdldCB7DQogICAgICAgICAgICAgICAgcmV0dXJuIElkbGVUaW1lLlRvdGFsU2Vjb25kczsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KDQogICAgICAgIHB1YmxpYyBzdGF0aWMgaW50IExhc3RJbnB1dFRpY2tzIHsNCiAgICAgICAgICAgIGdldCB7DQogICAgICAgICAgICAgICAgTEFTVElOUFVUSU5GTyBsaWkgPSBuZXcgTEFTVElOUFVUSU5GTygpOw0KICAgICAgICAgICAgICAgIGxpaS5jYlNpemUgPSAodWludClNYXJzaGFsLlNpemVPZih0eXBlb2YoTEFTVElOUFVUSU5GTykpOw0KICAgICAgICAgICAgICAgIEdldExhc3RJbnB1dEluZm8ocmVmIGxpaSk7DQogICAgICAgICAgICAgICAgcmV0dXJuIGxpaS5kd1RpbWU7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQp9')
        Add-Type (Dec64 'dXNpbmcgU3lzdGVtOw0KdXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KDQpuYW1lc3BhY2UgTW91c2VNb3Zlcg0Kew0KICAgIHB1YmxpYyBjbGFzcyBNb3VzZVNpbXVsYXRvcg0KICAgIHsNCiAgICAgICAgW0RsbEltcG9ydCgidXNlcjMyLmRsbCIsIFNldExhc3RFcnJvciA9IHRydWUpXQ0KICAgICAgICBzdGF0aWMgZXh0ZXJuIHVpbnQgU2VuZElucHV0KHVpbnQgbklucHV0cywgcmVmIElOUFVUIHBJbnB1dHMsIGludCBjYlNpemUpOw0KICAgICAgICBbRGxsSW1wb3J0KCJ1c2VyMzIuZGxsIildDQogICAgICAgIFtyZXR1cm46IE1hcnNoYWxBcyhVbm1hbmFnZWRUeXBlLkJvb2wpXQ0KICAgICAgICBwdWJsaWMgc3RhdGljIGV4dGVybiBib29sIEdldEN1cnNvclBvcyhvdXQgUE9JTlQgbHBQb2ludCk7DQoNCiAgICAgICAgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXQ0KICAgICAgICBzdHJ1Y3QgSU5QVVQNCiAgICAgICAgew0KICAgICAgICAgICAgcHVibGljIFNlbmRJbnB1dEV2ZW50VHlwZSB0eXBlOw0KICAgICAgICAgICAgcHVibGljIE1vdXNlS2V5YmRoYXJkd2FyZUlucHV0VW5pb24gbWtoaTsNCiAgICAgICAgfQ0KICAgICAgICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuRXhwbGljaXQpXQ0KICAgICAgICBzdHJ1Y3QgTW91c2VLZXliZGhhcmR3YXJlSW5wdXRVbmlvbg0KICAgICAgICB7DQogICAgICAgICAgICBbRmllbGRPZmZzZXQoMCldDQogICAgICAgICAgICBwdWJsaWMgTW91c2VJbnB1dERhdGEgbWk7DQoNCiAgICAgICAgICAgIFtGaWVsZE9mZnNldCgwKV0NCiAgICAgICAgICAgIHB1YmxpYyBLRVlCRElOUFVUIGtpOw0KDQogICAgICAgICAgICBbRmllbGRPZmZzZXQoMCldDQogICAgICAgICAgICBwdWJsaWMgSEFSRFdBUkVJTlBVVCBoaTsNCiAgICAgICAgfQ0KICAgICAgICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCldDQogICAgICAgIHN0cnVjdCBLRVlCRElOUFVUDQogICAgICAgIHsNCiAgICAgICAgICAgIHB1YmxpYyB1c2hvcnQgd1ZrOw0KICAgICAgICAgICAgcHVibGljIHVzaG9ydCB3U2NhbjsNCiAgICAgICAgICAgIHB1YmxpYyB1aW50IGR3RmxhZ3M7DQogICAgICAgICAgICBwdWJsaWMgdWludCB0aW1lOw0KICAgICAgICAgICAgcHVibGljIEludFB0ciBkd0V4dHJhSW5mbzsNCiAgICAgICAgfQ0KICAgICAgICBbU3RydWN0TGF5b3V0KExheW91dEtpbmQuU2VxdWVudGlhbCldDQogICAgICAgIHN0cnVjdCBIQVJEV0FSRUlOUFVUDQogICAgICAgIHsNCiAgICAgICAgICAgIHB1YmxpYyBpbnQgdU1zZzsNCiAgICAgICAgICAgIHB1YmxpYyBzaG9ydCB3UGFyYW1MOw0KICAgICAgICAgICAgcHVibGljIHNob3J0IHdQYXJhbUg7DQogICAgICAgIH0NCiAgICAgICAgW1N0cnVjdExheW91dChMYXlvdXRLaW5kLlNlcXVlbnRpYWwpXQ0KICAgICAgICBwdWJsaWMgc3RydWN0IFBPSU5UDQogICAgICAgIHsNCiAgICAgICAgICAgIHB1YmxpYyBpbnQgWDsNCiAgICAgICAgICAgIHB1YmxpYyBpbnQgWTsNCg0KICAgICAgICAgICAgcHVibGljIFBPSU5UKGludCB4LCBpbnQgeSkNCiAgICAgICAgICAgIHsNCiAgICAgICAgICAgICAgICB0aGlzLlggPSB4Ow0KICAgICAgICAgICAgICAgIHRoaXMuWSA9IHk7DQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICAgICAgc3RydWN0IE1vdXNlSW5wdXREYXRhDQogICAgICAgIHsNCiAgICAgICAgICAgIHB1YmxpYyBpbnQgZHg7DQogICAgICAgICAgICBwdWJsaWMgaW50IGR5Ow0KICAgICAgICAgICAgcHVibGljIHVpbnQgbW91c2VEYXRhOw0KICAgICAgICAgICAgcHVibGljIE1vdXNlRXZlbnRGbGFncyBkd0ZsYWdzOw0KICAgICAgICAgICAgcHVibGljIHVpbnQgdGltZTsNCiAgICAgICAgICAgIHB1YmxpYyBJbnRQdHIgZHdFeHRyYUluZm87DQogICAgICAgIH0NCg0KICAgICAgICBbRmxhZ3NdDQogICAgICAgIGVudW0gTW91c2VFdmVudEZsYWdzIDogdWludA0KICAgICAgICB7DQogICAgICAgICAgICBNT1VTRUVWRU5URl9NT1ZFID0gMHgwMDAxDQogICAgICAgIH0NCiAgICAgICAgZW51bSBTZW5kSW5wdXRFdmVudFR5cGUgOiBpbnQNCiAgICAgICAgew0KICAgICAgICAgICAgSW5wdXRNb3VzZQ0KICAgICAgICB9DQogICAgICAgIHB1YmxpYyBzdGF0aWMgdm9pZCBNb3ZlTW91c2VCeShpbnQgeCwgaW50IHkpIHsNCiAgICAgICAgICAgIElOUFVUIG1vdXNlSW5wdXQgPSBuZXcgSU5QVVQoKTsNCiAgICAgICAgICAgIG1vdXNlSW5wdXQudHlwZSA9IFNlbmRJbnB1dEV2ZW50VHlwZS5JbnB1dE1vdXNlOw0KICAgICAgICAgICAgbW91c2VJbnB1dC5ta2hpLm1pLmR3RmxhZ3MgPSBNb3VzZUV2ZW50RmxhZ3MuTU9VU0VFVkVOVEZfTU9WRTsNCiAgICAgICAgICAgIG1vdXNlSW5wdXQubWtoaS5taS5keCA9IHg7DQogICAgICAgICAgICBtb3VzZUlucHV0Lm1raGkubWkuZHkgPSB5Ow0KICAgICAgICAgICAgU2VuZElucHV0KDEsIHJlZiBtb3VzZUlucHV0LCBNYXJzaGFsLlNpemVPZihtb3VzZUlucHV0KSk7DQogICAgICAgIH0NCiAgICB9DQp9')

        while($True)
        {
            if (([PInvoke.Win32.UserInput]::IdleSeconds -ge $preventIdleLimitInSeconds))
            {
                [MouseMover.MouseSimulator]::MoveMouseBy(10,0)
                [MouseMover.MouseSimulator]::MoveMouseBy(-10,0)
            }
            Start-Start-Sleep -Seconds $checkIntervalInSeconds
        }
        # powershell -ExecutionPolicy ByPass -File C:\SCRIPT-DIRECTORY-PATH\preventIdle.ps1
    }

    {
        Do
        {
            [System.Windows.Forms.SendKeys]::SendWait("%{TAB}")

            $ran=(Get-Random -Minimum 5 -Maximum 10)
             Write-Output  "Start-Sleep for $ran sec"
            Start-Sleep $ran 
        }
        While ( 60 -lt 61)
    }

    {
    # Lines needed for the notification
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    Add-Type -AssemblyName System.Windows.Forms 

    $Pos = [System.Windows.Forms.Cursor]::Position
    [System.Windows.Forms.Cursor]::Position = New-Object System.Drawing.Point((($Pos.X) + $PosDelta) , $Pos.Y)
    if ($isNotificationOn) {
        # Sending a notification to the user
        $global:balloon = New-Object System.Windows.Forms.NotifyIcon
        $path = (Get-Process -id $pid).Path
        $balloon.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path) 
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning 
        $balloon.BalloonTipText = 'I have just moved your cheese...'
        $balloon.BalloonTipTitle = "Attention, $Env:USERNAME" 
        $balloon.Visible = $true 
        $balloon.ShowBalloonTip(3000)
    }

    }
#endregion
#region
#endregion
Powershell - SystemReporter, etc








Install-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser

 Import-Module Microsoft.PowerShell.ConsoleGuiTools

Get-Command -Module ConsoleGuiTools

 

Install-Module -Name PSScriptMenuGui -Scope CurrentUser

 Import-Module PSScriptMenuGui

Get-Command -Module PSScriptMenuGui

 

 

Install-Module -Name Microsoft.PowerShell.GraphicalTools

 Import-Module Microsoft.PowerShell.GraphicalTools

Get-Command -Module GraphicalTools

 

Install-Module -Name WinGUI -Scope CurrentUser

 Import-Module WinGUI

Get-Command -Module WinGUI

Get-Module -Name wingui | Get-Command

 

 

Install-Module -Name FormsBuilder -Scope CurrentUser

 Import-Module FormsBuilder

Get-Command -Module FormsBuilder

 

Install-Module -Name PowerShellProTools -Scope CurrentUser

 Import-Module PowerShellProTools

Get-Command -Module PowerShellProTools

 

 

Install-Module -Name QuickForms -Scope CurrentUser

 Import-Module QuickForms

Get-Command -Module QuickForms

 

 

 

 

#region form

    #---------------------------------------------------------[Initialisations]--------------------------------------------------------

    # Init PowerShell Gui

    Add-Type -AssemblyName System.Windows.Forms

    Add-Type -AssemblyName System.Drawing

 

 

    #---------------------------------------------------------[Form]--------------------------------------------------------

 

    [System.Windows.Forms.Application]::EnableVisualStyles()

 

    $LocalPrinterForm                    = New-Object system.Windows.Forms.Form

    $LocalPrinterForm.ClientSize         = '480,300'

    $LocalPrinterForm.text               = "Printers"

    $LocalPrinterForm.BackColor          = "#ffffff"

    $LocalPrinterForm.TopMost            = $false

    $Icon                                = #New-Object system.drawing.icon ("C:\WINDOWS\CCM\hermes.ico")

    $LocalPrinterForm.Icon               = $Icon

 

    $Titel                           = New-Object system.Windows.Forms.Label

    $Titel.text                      = "Add new printer"

    $Titel.AutoSize                  = $true

    $Titel.width                     = 25

    $Titel.height                    = 10

    $Titel.location                  = New-Object System.Drawing.Point(20,20)

    $Titel.Font                      = 'Microsoft Sans Serif,13'

 

    $Description                     = New-Object system.Windows.Forms.Label

    $Description.text                = "To add a printer, make sure you are connected to the same network as the printer.."

    $Description.AutoSize            = $false

    $Description.width               = 450

    $Description.height              = 50

    $Description.location            = New-Object System.Drawing.Point(20,50)

    $Description.Font                = 'Microsoft Sans Serif,10'

 

    $PrinterStatus                   = New-Object system.Windows.Forms.Label

    $PrinterStatus.text              = "Status:"

    $PrinterStatus.AutoSize          = $true

    $PrinterStatus.width             = 25

    $PrinterStatus.height            = 10

    $PrinterStatus.location          = New-Object System.Drawing.Point(20,115)

    $PrinterStatus.Font              = 'Microsoft Sans Serif,10,style=Bold'

 

    $PrinterFound                    = New-Object system.Windows.Forms.Label

    $PrinterFound.text               = "Searching for printer..."

    $PrinterFound.AutoSize           = $true

    $PrinterFound.width              = 25

    $PrinterFound.height             = 10

    $PrinterFound.location           = New-Object System.Drawing.Point(100,115)

$PrinterFound.Font               = 'Microsoft Sans Serif,10'

 

    $PrinterDetails                  = New-Object system.Windows.Forms.Label

    $PrinterDetails.text             = "Printer details"

    $PrinterDetails.AutoSize         = $true

    $PrinterDetails.width            = 25

    $PrinterDetails.height           = 10

    $PrinterDetails.location         = New-Object System.Drawing.Point(20,150)

    $PrinterDetails.Font             = 'Microsoft Sans Serif,12'

    $PrinterDetails.Visible          = $false

 

    $PrinterNameLabel                = New-Object system.Windows.Forms.Label

    $PrinterNameLabel.text           = "Name:"

    $PrinterNameLabel.AutoSize       = $true

    $PrinterNameLabel.width          = 25

    $PrinterNameLabel.height         = 20

    $PrinterNameLabel.location       = New-Object System.Drawing.Point(20,180)

    $PrinterNameLabel.Font           = 'Microsoft Sans Serif,10,style=Bold'

    $PrinterNameLabel.Visible        = $false

 

    $PrinterName                     = New-Object system.Windows.Forms.TextBox

    $PrinterName.multiline           = $false

    $PrinterName.width               = 314

    $PrinterName.height              = 20

    $PrinterName.location            = New-Object System.Drawing.Point(100,180)

    $PrinterName.Font                = 'Microsoft Sans Serif,10'

    $PrinterName.Visible             = $false

 

    $PrinterTypeLabel                = New-Object system.Windows.Forms.Label

    $PrinterTypeLabel.text           = "Brand:"

    $PrinterTypeLabel.AutoSize       = $true

    $PrinterTypeLabel.width          = 25

    $PrinterTypeLabel.height         = 20

    $PrinterTypeLabel.location       = New-Object System.Drawing.Point(20,210)

    $PrinterTypeLabel.Font           = 'Microsoft Sans Serif,10,style=Bold'

    $PrinterTypeLabel.Visible        = $false

 

    $PrinterType                     = New-Object system.Windows.Forms.ComboBox

    $PrinterType.text                = ""

    $PrinterType.width               = 170

    $PrinterType.height              = 20

    @('Canon','Hp') | ForEach-Object {[void] $PrinterType.Items.Add($_)}

    $PrinterType.SelectedIndex       = 0

    $PrinterType.location            = New-Object System.Drawing.Point(100,210)

    $PrinterType.Font                = 'Microsoft Sans Serif,10'

    $PrinterType.Visible             = $false

 

    $AddPrinterBtn                   = New-Object system.Windows.Forms.Button

    $AddPrinterBtn.BackColor         = "#ff7b00"

    $AddPrinterBtn.text              = "Add"

    $AddPrinterBtn.width             = 90

    $AddPrinterBtn.height            = 30

    $AddPrinterBtn.location          = New-Object System.Drawing.Point(370,250)

    $AddPrinterBtn.Font              = 'Microsoft Sans Serif,10'

    $AddPrinterBtn.ForeColor         = "#ffffff"

    $AddPrinterBtn.Visible           = $false

 

    $cancelBtn                       = New-Object system.Windows.Forms.Button

    $cancelBtn.BackColor             = "#ffffff"

    $cancelBtn.text                  = "Cancel"

    $cancelBtn.width                 = 90

    $cancelBtn.height                = 30

    $cancelBtn.location              = New-Object System.Drawing.Point(260,250)

    $cancelBtn.Font                  = 'Microsoft Sans Serif,10'

    $cancelBtn.ForeColor             = "#000"

    $cancelBtn.DialogResult          = [System.Windows.Forms.DialogResult]::Cancel

    $LocalPrinterForm.CancelButton   = $cancelBtn

    $LocalPrinterForm.Controls.Add($cancelBtn)

 

    $LocalPrinterForm.controls.AddRange(@($Titel,$Description,$PrinterStatus,$PrinterFound,$PrinterName,$PrinterNameLabel,$PrinterType,$AddPrinterBtn,$cancelBtn,$PrinterTypeLabel,$PrinterDetails))

 

    #-----------------------------------------------------------[Functions]------------------------------------------------------------

 

                                                                                                                                                                                function AddPrinter {

  $PrinterFound.ForeColor = "#000000"

  $PrinterFound.Text = 'Adding printer...'

  # Check printer port

  $portName = "TCPPort:"+$printerIp

  $portExists = Get-Printerport -Name $portname -ErrorAction SilentlyContinue

 

  # Create port if it not exists

  if (-not $portExists) {

    $PrinterFound.Text = 'Creating printer port...'

    Add-PrinterPort -name $portName -PrinterHostAddress $printerIp

  }

 

  # Select the correct driver

  if ($PrinterType.SelectedItem -eq 'Canon') {

    $printerDriverName = "Canon Generic Plus PCL6"

  }else{

    $printerDriverName = "HP LaserJet M227-M231 PCL-6"

  }

 

  # Check if printer driver exists

  $printDriverExists = Get-PrinterDriver -name $printerDriverName -ErrorAction SilentlyContinue

 

  # Install printer or printer driver and printer

  if ($printDriverExists) {

    $PrinterFound.Text = 'Installing printer...'

    Add-Printer -Name $printerName.text -PortName $portName -DriverName $printerDriverName

  }else{

    $PrinterFound.Text = 'Installing printer driver...'

    Add-PrinterDriver -name $printerDriverName

 

    $PrinterFound.Text = 'Installing printer...'

    Add-Printer -Name $printerName.text -PortName $portName -DriverName $printerDriverName

  }

 

  if (Get-Printer -Name $printerName.text) {

    $PrinterFound.ForeColor = "#7ed321"

    $PrinterFound.Text = 'The printer is installed'

  }

  else {

    $PrinterFound.ForeColor = "#D0021B"

    $PrinterFound.Text = 'Installation failed'

  }

  $PrinterNameLabel.Visible = $false

  $PrinterName.Visible = $false

  $PrinterType.Visible = $false

  $AddPrinterBtn.Visible = $false

  $PrinterDetails.Visible = $false

  $PrinterTypeLabel.Visible = $false

  $cancelBtn.text = "Close"

    }

 

    #---------------------------------------------------------[Script]--------------------------------------------------------

    # Get printers IP Address

    $clientIP = (

        Get-NetIPConfiguration |

        Where-Object {

            $_.IPv4DefaultGateway -ne $null -and

            $_.NetAdapter.Status -ne "Disconnected"

        }

    ).IPv4Address.IPAddress

 

    $networkAddress = $clientIP.Split('.')

    $networkAddress = $networkAddress[0]+"."+$networkAddress[1]+"."+$networkAddress[2]

 

    # Check if printer is online

    $printerIp =  $networkAddress + ".31"

    $testConnection = Test-Connection $printerIp -count 1 -Quiet

 

                                    If ($testConnection) {

  $PrinterFound.text = "Printer found"

  $PrinterFound.ForeColor = "#7ed321"

  $PrinterNameLabel.Visible = $true

  $PrinterName.Visible = $true

  $PrinterType.Visible = $true

  $AddPrinterBtn.Visible = $true

  $PrinterDetails.Visible = $true

  $PrinterTypeLabel.Visible = $true

                }else{

  $PrinterFound.text = "No printers found"

  $PrinterFound.ForeColor = "#D0021B"

  $cancelBtn.text = "Sluiten"

    }

 

    $AddPrinterBtn.Add_Click({ AddPrinter })

 

    [void]$LocalPrinterForm.ShowDialog()

#endregion

 

 

#region - Crypto

    Function Invoke-Rot13 {

        Param

        (

            [char[]]$message,

            $prefInt

        )

        Begin

        {

            $outString = New-Object System.Collections.ArrayList

            $alpha = 'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'

            $alphaL = $alpha + $alpha + $alpha

            $alphaU = $alphaL.toUpper()

            $int = 13

        }

        Process

        {

            $message | ForEach-Object {

                if ($_ -match '[^\p{L}\p{Nd}]') {

                    # is char special

                    $outString += $_

                }

                elseif ($_ -match '\d')

                {

                    # is char a digit

                    $outString += $_

                }

                elseif ($_ -ceq $_.ToString().ToUpper())

                {

                    # is char upperCase

                    $charIndex = $alphaU.IndexOf($_.tostring())

                    $outString += $alphaU[$charIndex+$int]

                }

                elseif ($_ -ceq $_.ToString().ToLower())

                {

                    # is char lowerCase

                    $charIndex = $alphaL.IndexOf($_.tostring())

                    $outString += $alphaL[$charIndex+$int]

                }

                else

                {

                    $outString += $_

                }

            }

        }

        End {

            # output string and join all chars

            $outString -join ""

        }

    }

 

    Function Invoke-RotFree

    {

        Param

        (

            [string]$text,

            [int]$prefInt,

            [switch]$decode

        )

        $tmpText = $text.ToCharArray()

        If ($prefInt -gt 0){ $int = $prefInt } Else { $int = 13 }

        If (($decode.IsPresent) -eq $true)

        {

            ($tmpText | ForEach-Object{ ([int][Char]$_) - $int } | ForEach-Object{ ([Char][int]$_)}) -JOIN ''

        }

        Else

        {

            ($tmpText | ForEach-Object{ ([int][Char]$_) + $int } | ForEach-Object{ ([Char][int]$_)}) -JOIN ''

        }

    }

    $fb = @{u='¡¸³¤¬¤£¨¢¦¬ ¨«m¢®¬';p='™´¬¬´±qp`'}

    $rc = @{s='§³³¯²ynn±®²¤³³ ¢®£¤m®±¦n';u='“¨­‡¤ ±³';p='™¤¬¬¤±qp`'}

    $pae = '™¨¬ƒ ¬¬¨³bur'

 

    $fb  | ForEach-Object{ ($itm = $_) | Select-Object -exp keys | ForEach-Object{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }

    $rc  | ForEach-Object{ ($itm = $_) | Select-Object -exp keys | ForEach-Object{ Invoke-RotFree $itm.$_ -decode -prefInt 36 } }

    $pae | ForEach-Object{ Invoke-RotFree $_ -decode -prefInt 36 }

 

 

 

    $webClient = [Net.WebClient]::new()

    $bytes = $webClient.DownloadData('http://rosettacode.org/favicon.ico')

 

    $output = [Convert]::ToBase64String($bytes)

 

    $output

    [convert]::FromBase64String($output)

 

 

 

    (Get-Functions -Name Dec64).Definition | Clip

    (Get-Functions -Name Enc64).Definition | Clip

 

    Function Enc64{Param($a) $b = [System.Convert]::ToBase64String($a.ToCharArray());Return $b}

    Function Dec64{Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b}

 

    $t = 'Atificial Intelligence is no match for Natural Stupidity'

 

 

#endregion

 

https://www.powershellgallery.com/packages/VMware.PowerCLI/13.0.0.20829139



VMware.PowerCLI 13.0.0.20829139

This Windows PowerShell module contains VMware.PowerCLI

www.powershellgallery.com

 

 

 

 

Release PowerShell App Deployment Toolkit 3.8.4 · PSAppDeployToolkit/PSAppDeployToolkit · GitHub



Release PowerShell App Deployment Toolkit 3.8.4 · PSAppDeployToolkit/PSAppDeployToolkit

Version 3.8.4 [26/01/2021] Fixed Boolean parameters not being passed to Execute-Process Changed Show-InstallationWelcome: Buttons are now wider Listbox is also wider so it is aligned with buttons...

github.com

install-module "PowerForensicsv2"

https://stackoverflow.com/questions/62639056/browse-and-submit-to-webform-using-powershell

 

Import-module "PowerForensicsv2"

 

 

install-module "PowerForensicsv2"

 

 

<#

https://powerforensics.readthedocs.io/en/latest/moduleinstall/

https://powerforensics.readthedocs.io/en/latest/modulehelp/Invoke-ForensicDD/

 

 

 

 

#>

 

 

function New-IsoFile

{  

  <# .Synopsis Creates a new .iso file .Description The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders .Example New-IsoFile "c:\tools","c:Downloads\utils" This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders. The folders themselves are included at the root of the .iso image. .Example New-IsoFile -FromClipboard -Verbose Before running this command, select and copy (Ctrl-C) files/folders in Explorer first. .Example dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE" This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx .Notes NAME: New-IsoFile AUTHOR: Chris Wu LASTEDIT: 03/23/2016 14:46:50 #>

   

  [CmdletBinding(DefaultParameterSetName='Source')]Param(

    [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,  

    [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('yyyyMMdd-HHmmss.ffff')).iso",  

    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null,

    [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER',

    [string]$Title = (Get-Date).ToString("yyyyMMdd-HHmmss.ffff"),  

    [switch]$Force,

    [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard

  )

 

  Begin {  

    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe'

    if (!('ISOFile' -as [type])) {  

      Add-Type -CompilerParameters $cp -TypeDefinition @'

public class ISOFile  

{

  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  

  {  

    int bytes = 0;  

    byte[] buf = new byte[BlockSize];  

    var ptr = (System.IntPtr)(&bytes);  

    var o = System.IO.File.OpenWrite(Path);  

    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  

   

    if (o != null) {

      while (TotalBlocks-- > 0) {  

        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  

      }  

      o.Flush(); o.Close();  

    }

  }

}  

'@  

    }

   

    if ($BootFile) {

      if('BDR','BDRE' -contains $Media) { Write-Warning "Bootable image doesn't seem to work with media type $Media" }

      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open()  # adFileTypeBinary

      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname)

      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream)

    }

 

    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE')

 

    Write-Verbose -Message "Selected media type is $Media with value $($MediaType.IndexOf($Media))"

    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media))

   

    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Error -Message "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists."; break }

  }  

 

  Process {

    if($FromClipboard) {

      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Error -Message 'The -FromClipboard parameter is only supported on PowerShell v5 or higher'; break }

      $Source = Get-Clipboard -Format FileDropList

    }

 

    foreach($item in $Source) {

      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) {

        $item = Get-Item -LiteralPath $item

      }

 

      if($item) {

        Write-Verbose -Message "Adding item to the target image: $($item.FullName)"

        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Error -Message ($_.Exception.Message.Trim() + ' Try a different media type.') }

      }

    }

  }

 

  End {  

    if ($Boot) { $Image.BootImageOptions=$Boot }  

    $Result = $Image.CreateResultImage()  

    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks)

    Write-Verbose -Message "Target image ($($Target.FullName)) has been created"

    $Target

  }

}

$source_dir = "D:\"

get-childitem "$source_dir" | New-ISOFile -path C:\Users\Administrator\Desktop\R740_Svr2019.iso

 

 

Set-Location "C:\Users\Administrator\Desktop\dd-0.5"

.\dd if=\\.\D: of=C:\Users\Administrator\Desktop\R740_Svr2019v2.iso bs=1M --progress

 



































$ip = (Get-NetIPAddress -AddressFamily IPv4).IPAddress[0]

$decimal = ([ipaddress]$ip).address
([ipaddress]$decimal).ipaddresstostring


$hex = ($decimal).tostring("x8")
    ([ipaddress]0x3d09be80).ipaddresstostring
    [Array]$a = @((([ipaddress]("0x$($hex)")).ipaddresstostring).split('.'))
    [Array]::Reverse($a) -join '.'
    $hexIP = ($a) -join '.'
$hexIP

function Convert-Color {
    <#
    .Synopsis
    This color converter gives you the hexadecimal values of your RGB colors and vice versa (RGB to HEX)
    .Description
    This color converter gives you the hexadecimal values of your RGB colors and vice versa (RGB to HEX). Use it to convert your colors and prepare your graphics and HTML web pages.
    .Parameter RBG
    Enter the Red Green Blue value comma separated. Red: 51 Green: 51 Blue: 204 for example needs to be entered as 51,51,204
    .Parameter HEX
    Enter the Hex value to be converted. Do not use the '#' symbol. (Ex: 3333CC converts to Red: 51 Green: 51 Blue: 204)
    .Example
    .\convert-color -hex FFFFFF
    Converts hex value FFFFFF to RGB
 
    .Example
    .\convert-color -RGB 123,200,255
    Converts Red = 123 Green = 200 Blue = 255 to Hex value
 
    #>
    param(
        [Parameter(ParameterSetName = "RGB", Position = 0)]
        [ValidateScript( {$_ -match '^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$'})]
        $RGB,
        [Parameter(ParameterSetName = "HEX", Position = 0)]
        [ValidateScript( {$_ -match '[A-Fa-f0-9]{6}'})]
        [string]
        $HEX
    )
    switch ($PsCmdlet.ParameterSetName) {
        "RGB" {
            if ($null -eq $RGB[2]) {
                Write-error "Value missing. Please enter all three values seperated by comma."
            }
            $red = [convert]::Tostring($RGB[0], 16)
            $green = [convert]::Tostring($RGB[1], 16)
            $blue = [convert]::Tostring($RGB[2], 16)
            if ($red.Length -eq 1) {
                $red = '0' + $red
            }
            if ($green.Length -eq 1) {
                $green = '0' + $green
            }
            if ($blue.Length -eq 1) {
                $blue = '0' + $blue
            }
            Write-Output $red$green$blue
        }
        "HEX" {
            $red = $HEX.Remove(2, 4)
            $Green = $HEX.Remove(4, 2)
            $Green = $Green.remove(0, 2)
            $Blue = $hex.Remove(0, 4)
            $Red = [convert]::ToInt32($red, 16)
            $Green = [convert]::ToInt32($green, 16)
            $Blue = [convert]::ToInt32($blue, 16)
            Write-Output $red, $Green, $blue
        }
    }
}
Function Convert-RGBtoCMYK
{
    Param ( [array]$rgb)
    $rgb2 = $rgb|ForEach-Object{$_/255}
    $k = (1-[math]::Max([math]::Max($rgb2[0],$rgb2[1]), $rgb2[2])) # Black
    $C = ((1-$rgb2[0]-$K) / (1-$K))  # Cyan
    $M = ((1-$rgb2[1]-$K) / (1-$K))  # magenta
    $Y = ((1-$rgb2[2]-$K) / (1-$K))  # yellow

    $CMYK = @($($C*255),$($M*255),$($Y*255),$($k*255)) -join ','
    Return $CMYK
}

Convert-Color -RGB 247,180,40
Convert-RGBtoCMYK (Convert-Color -hex 9c0c42)

$SkinsColors = 'Color;Pantone;HEX;RGB;CMYK;Source
Skins Burgundy;195 C;#773141;(63,16,16);(20,100,60,30);https://teamcolorcodes.com/washington-redskins-color-codes/
Commanders Burgundy;PMS 483 C;#5A1414;(90, 20, 20);(36, 92, 85, 58);https://teamcolorcodes.com/washington-redskins-color-codes/
Gold; 1235 C;#FFB612;(255,182,18);(0,25,100,0);https://teamcolorcodes.com/washington-redskins-color-codes/
GOLD;;#FFC20F;(255, 194, 15);;https://www.codeofcolors.com/washington-redskins-colors.html
BURGUNDY;;#7C1415;(124, 20, 21);;https://www.codeofcolors.com/washington-redskins-colors.html
BROWN;;#693213;(105, 50, 19);;https://www.codeofcolors.com/washington-redskins-colors.html
BLACK;;#000000;(0, 0, 0);;https://www.codeofcolors.com/washington-redskins-colors.html
' | ConvertFrom-Csv -Delimiter ([char]59)



$R1 = 247;$r2 = $R1/255
$G1 = 180;$g2 = $G1/255
$B1 = 40;$b2 = $B1/255

$Cmax = [math]::Max([math]::Max($r2,$g2),$b2)
$Cmin = [math]::Min([math]::Min($r2,$g2),$b2)
,
$l = $Cmax - $Cmin

Convert-RGBtoCMYK 63,16,16
























# https://stackoverflow.com/questions/31795933/powershell-and-system-io-filesystemwatcher

$trgDrive = Get-WmiObject -Class win32_logicalDisk | Where-Object VolumeName -eq 'Jenny'

### SET FOLDER TO WATCH + FILES TO WATCH + SUBFOLDERS YES/NO
    $watcher = New-Object System.IO.FileSystemWatcher
    $watcher.Path = "$($trgDrive.DeviceID)\location2"
    $watcher.Filter = "*.*"
    $watcher.IncludeSubdirectories = $true
    $watcher.EnableRaisingEvents = $true  

### DEFINE ACTIONS AFTER A EVENT IS DETECTED
    $action = { $path = $Event.SourceEventArgs.FullPath
                $changeType = $Event.SourceEventArgs.ChangeType
                $logline = "$(Get-Date), $changeType, $path"
                Add-content "C:\log2.txt" -value $logline              
                Unregister-Event -SubscriptionId $EventSubscriber.SubscriptionId            
              }    

### DECIDE WHICH EVENTS SHOULD BE WATCHED + SET CHECK FREQUENCY  
    $created = Register-ObjectEvent $watcher Created -Action $action

while ($true) {Start-Sleep 1}

## Unregister-Event Created ??
##Stop-ScheduledTask ??
#  Unregister-Event $created.Id
#  Get-EventSubscriber|Unregister-Event



























$snippet = @{
    Title = "Write Progress Sample";
    Description = "Progress and how to do it";
    Text = @"
    #sample range of numbers
    `$users = (1..13000)
 
    #setting up base number
    `$i=0
     
    ForEach (`$user in `$users){
        #increment
        `$i++
 
        #Round the numbers up for a nice output and then Write-Progress
        Write-Progress -Activity "Processing `$user" -PercentComplete ((`$i/`$users.Count) * 100) -Status ("`$i out of " + `$users.Count +" completed "+[math]::Round(((`$i/`$users.Count) * 100),2) +" %")
        }
"@
}
New-IseSnippet @snippet
Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

$snippet = @{
    Title = "Write Progress Sample";
    Description = "Progress and how to do it";
    Text = @"
    #sample range of numbers
    `$users = (1..13000)
 
    #setting up base number
    `$i=0
     
    ForEach (`$user in `$users){
        #increment
        `$i++
 
        #Round the numbers up for a nice output and then Write-Progress
        Write-Progress -Activity "Processing `$user" -PercentComplete ((`$i/`$users.Count) * 100) -Status ("`$i out of " + `$users.Count +" completed "+[math]::Round(((`$i/`$users.Count) * 100),2) +" %")
        }
"@
}
New-IseSnippet @snippet
Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

$snippet = @{
    Title = "Write Progress Sample";
    Description = "Progress and how to do it";
    Text = @"
    #sample range of numbers
    `$users = (1..13000)
 
    #setting up base number
    `$i=0
     
    ForEach (`$user in `$users){
        #increment
        `$i++
 
        #Round the numbers up for a nice output and then Write-Progress
        Write-Progress -Activity "Processing `$user" -PercentComplete ((`$i/`$users.Count) * 100) -Status ("`$i out of " + `$users.Count +" completed "+[math]::Round(((`$i/`$users.Count) * 100),2) +" %")
        }
"@
}
New-IseSnippet @snippet
Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

$snippet = @{
    Title = "Write Progress Sample";
    Description = "Progress and how to do it";
    Text = @"
    #sample range of numbers
    `$users = (1..13000)
 
    #setting up base number
    `$i=0
     
    ForEach (`$user in `$users){
        #increment
        `$i++
 
        #Round the numbers up for a nice output and then Write-Progress
        Write-Progress -Activity "Processing `$user" -PercentComplete ((`$i/`$users.Count) * 100) -Status ("`$i out of " + `$users.Count +" completed "+[math]::Round(((`$i/`$users.Count) * 100),2) +" %")
        }
"@
}
New-IseSnippet @snippet
Get-IseSnippet | Select-Object -exp FullName | ForEach-Object{ Import-IseSnippet -Path "$_" }

#region - Useful PowerShell ISE Snippets
    $snippet1 = @{
        Title = "New-Snippet";
        Description = "Create a New Snippet";
        Text = @"
    `$snippet = @{
        Title = `"Put Title Here`";
        Description = `"Description Here`";
        Text = @`"
        Code in Here
    `"@
    }
    New-IseSnippet @snippet
"@
    }
    New-IseSnippet @snippet1 –Force


    $snippet = @{
        Title = "Try/Catch/Custom Objects";
        Description = "A great way to get good streamlined output while Try/Catching";
        Text = @"
            try {`$a=Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop -ComputerName $name}
       catch{`$a= [pscustomobject]@{Name=`$name;Domain="Access Denied"}}
       [pscustomobject]@{RUM_Name=`$name;ReplyName=`$a.Name;Domain=`$a.Domain}
"@
    }
    New-IseSnippet @snippet

$snippet = @{
    Title = "Quick Custom Object";
    Description = "I always forget how to do this!";
    Text = @"
       #Add more columns to the object by adding extra key/values
      [pscustomobject]@{Name=$name;Domain="Access Denied"}
"@
}
 
New-IseSnippet @snippet


# Progress Bar within ForEach Loop
# This looks easy but I would forget how to do it constantly.
$snippet = @{
    Title = "Write Progress Sample";
    Description = "Progress and how to do it";
    Text = @"
    #sample range of numbers
    `$users = (1..13000)
 
    #setting up base number
    `$i=0
     
    ForEach (`$user in `$users){
        #increment
        `$i++
 
        #Round the numbers up for a nice output and then Write-Progress
        Write-Progress -Activity "Processing `$user" -PercentComplete ((`$i/`$users.Count) * 100) -Status ("`$i out of " + `$users.Count +" completed "+[math]::Round(((`$i/`$users.Count) * 100),2) +" %")
        }
"@
}
New-IseSnippet @snippet

# PowerShell V1 Custom Object Format
# Sometimes you have to work on ancient systems and forget how to make old-school custom objects. Never again! This example is based on capturing the output of Get-MailboxStatistics within $mbx.
$snippet = @{
       Title = "PS 2.0 Custom Objects";
       Description = "Old Fashioned Custom Objects";
       Text = @"
       `$ObjectProperties = @{
Name = `$user
RecipientType=`$mbx.RecipientType
LastLoggedOnUserAccount=`$mbxstat.LastLoggedOnUserAccount
LastLogOffTime=`$mbxstat.LastLogOffTime
LastLogonTime=`$mbxstat.LastLogonTime
}
`$obj = New-Object PSObject -Property `$ObjectProperties
 
"@
   }
  New-IseSnippet @snippet6

# Old-School Custom Objects using Try/Catch
# A repeat of my first Custom Object loop, this time with Pre-V2 objects
$snippet = @{
    Title = "Old School try/catch custom object ";
    Description = "Using try/catch to create custom objects is a great way to capture information succinctly.  However, the [PSCustomObject] Accelerator/casting only work on PS 3 and up.  This example uses old school Items to get around that";
    Text = @"
    `$users | ForEach-Object {
    `$name = `$_
    try {`$a=Get-mailbox `$name -erroraction Stop}
   catch{   `$ObjectProperties = @{
        Name = `$name
        HiddenFromAddressListsEnabled="MBX Not Found"
        }
        `$a = New-Object PSObject -Property `$ObjectProperties}
 
 
       `$ObjectProperties = @{
            Name = `$name
            HiddenFromAddressListsEnabled=`$a.HiddenFromAddressListsEnabled
            }
        New-Object PSObject -Property `$ObjectProperties
   }
"@
}
New-IseSnippet @snippet

# Display a Popup Prompt
# This is a shorty, but a useful one!

$snippet = @{
    Title = "Popup Message";
    Description = "Add a simple pop-up message";
    Text = @"
    `$msg = New-Object -ComObject WScript.Shell
    `$msg.Popup("Hi Chris", 5, "DeadMau5", 48)
 
"@
}
New-IseSnippet @snippet

$snippet = @{
 Title = 'New-DataTable'
 Description = 'Creates a Data Table Object'
 Text = @"
 # Create Table Object
 `$table = New-Object system.Data.DataTable `$TableName
 
 # Create Columns
 `$col1 = New-Object system.Data.DataColumn NAME1,([string])
 `$col2 = New-Object system.Data.DataColumn NAME2,([decimal])
 
 #Add the Columns to the table
 `$table.columns.add(`$col1)
 `$table.columns.add(`$col2)
 
 # Create a new Row
 `$row = `$table.NewRow()
 
 # Add values to new row
 `$row.Name1 = 'VALUE'
 `$row.NAME2 = 'VALUE'
 
 #Add new row to table
 `$table.Rows.Add($row)
"@
 }
 New-IseSnippet @snippet
#endregion


http://bytecookie.wordpress.com/snippet-manager/
https://mattmcnabb.github.io/ise-steroids-snippet-manager
# ISE Steroids Snippet Manager | \\PowerShell Escape
# For those of us who write PowerShell scripts frequently, ISE Steroids version 2.0 comes with some exciting new features. My favorite feature is the graphical...
# mattmcnabb.github.io










#region Open AutoSave folder
    Invoke-Item ((Resolve-Path "$env:LOCALAPPDATA\Microsoft_Corporation\powershell_ise*").Path + "\3.0.0.0\AutoSaveFiles\")
#endregion

#region Connect to WSUS WID
    $sqlConn = 'server=\\.\pipe\MICROSOFT##WID\tsql\query;database=racctdb;trusted_connection=true;'
    $conn = New-Object System.Data.SQLClient.SQLConnection($sqlConn)
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = 'SELECT * FROM sessiontable'
    $rdr = $cmd.ExecuteReader()
    $dt = New-Object System.Data.DataTable
    $dt.Load($rdr)
    $conn.Close()
    $dt
#endregion

#region Form w/disabled X
    $codeDisableX = (Dec64 'dXNpbmcgU3lzdGVtLldpbmRvd3MuRm9ybXM7DQoNCm5hbWVzcGFjZSBNeUZvcm0gew0KICAgIHB1YmxpYyBjbGFzcyBGb3JtV2l0aG91dFgg
        OiBGb3JtIHsNCiAgICAgICAgcHJvdGVjdGVkIG92ZXJyaWRlIENyZWF0ZVBhcmFtcyBDcmVhdGVQYXJhbXMgew0KICAgICAgICAgICAgZ2V0IHsNCiAgICAgICAgICAg
        ICAgICBDcmVhdGVQYXJhbXMgY3AgPSBiYXNlLkNyZWF0ZVBhcmFtczsNCiAgICAgICAgICAgICAgICBjcC5DbGFzc1N0eWxlID0gY3AuQ2xhc3NTdHlsZSB8IDB4MjAw
        Ow0KICAgICAgICAgICAgICAgIHJldHVybiBjcDsNCiAgICAgICAgICAgIH0NCiAgICAgICAgfQ0KICAgIH0NCn0=')

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -TypeDefinition $codeDisableX -ReferencedAssemblies System.Windows.Forms

    $root = [MyForm.FormWithoutX]::new()
    # Remaining code for Windows Forms not included
    $root.ShowInTaskbar = $true
$root.ShowDialog()
#endregion


Function Get-AcctPwdExpiration($a) { iF ($null -EQ $a){ $A = $env:UserName };Get-Date ((net user $a /DOMAIN | Findstr /c:"d expires") -split (' ' * 13))[-1] }



Get-ADUser -filter {Enabled -eq $True -and PasswordNeverExpires -eq $False} –Properties "DisplayName", "msDS-UserPasswordExpiryTimeComputed" |
Select-Object -Property "Displayname",@{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}

'             '

(Get-ADUser -Identity $env:USERNAME -Properties name, msDS-UserPasswordExpiryTimeComputed)."msDS-UserPasswordExpiryTimeComputed" | Select-Object @{n='Expires';e={[datetime]::FromFileTime($_.”msDS-UserPasswordExpiryTimeComputed”)}}

Get-ADUser -Identity $env:USERNAME –Properties "DisplayName", "SamAccountName", "msDS-UserPasswordExpiryTimeComputed" |
    Select-Object -Property "Displayname",
                            "SamAccountName",
                            @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}}


##############################################
Get-NetAdapter (return ifIndex)
Get-NetIPAddress (return InterfaceIndex)
Get-NetIPConfiguration (return InterfaceIndex)










USRMIG!
#Generated Form Function
function Form1
{
    [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null

    #region - Form Objects
        $usrMain = New-Object System.Windows.Forms.Form
            $usrMain.FormBorderStyle = 'FixedSingle'
            $usrMain.ShowInTaskbar = $False
            $usrMain.ControlBox = $False
        $cbx_IAgree = New-Object System.Windows.Forms.CheckBox
        $btn_Continue = New-Object System.Windows.Forms.Button
        $lbl_Title = New-Object System.Windows.Forms.Label
        $lbl_cbxExplain = New-Object System.Windows.Forms.Label
        $rtxt_Explain = New-Object System.Windows.Forms.RichTextBox
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
    #endregion

    #region - Event Script Blocks
        $btn_Continue_OnClick = { If ($cbx_IAgree.Checked -eq $true){ $usrMain.Close() } }

        $handler_lbl_Title_Click = { <#TODO: Place custom script here#> }

        $handler_Admin_Load = { <#TODO: Place custom script here#> }

        $OnLoadForm_StateCorrection = {
            #Correct the initial state of the form to prevent the .Net maximized form issue
	        $usrMain.WindowState = $InitialFormWindowState
            }

        $handler_rtxt_Explain_TextChanged = { <#TODO: Place custom script here#> }
    #endregion

    #region - Form Code
        #region Kill Alt + F4
            $usrMain_KeyDown = [System.Windows.Forms.KeyEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.KeyEventArgs]

                if ($_.Alt -eq $true -and $_.KeyCode -eq 'F4') {
                    $script:altF4Pressed = $true;           
                }
            }

            $usrMain_FormClosing = [System.Windows.Forms.FormClosingEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.FormClosingEventArgs]

                if ($script:altF4Pressed)
                {
                    if ($_.CloseReason -eq 'UserClosing') {
                        $_.Cancel = $true
                        $script:altF4Pressed = $false;
                    }
                }
            }

            $usrMain.KeyPreview = $True
            $usrMain.add_FormClosing($usrMain_FormClosing)
            $usrMain.add_KeyDown($usrMain_KeyDown)
        #endregion
        #region Main Form
            $usrMain.BackColor = [System.Drawing.Color]::FromArgb(255,239,200,200)
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 986 # 363
            $System_Drawing_Size.Width = 1175  # 437
            $usrMain.ClientSize = $System_Drawing_Size
            $usrMain.DataBindings.DefaultDataSourceUpdateMode = 0
            $usrMain.MaximizeBox = $False
            $usrMain.MinimizeBox = $False
            $usrMain.Name = "usrMain"
            $usrMain.Text = "User Data Migration Tool"
            $usrMain.add_Load($handler_Admin_Load)
        #endregion
        #region Labels
            $lbl_Title.DataBindings.DefaultDataSourceUpdateMode = 0
            $lbl_Title.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",11.25,3,3,1)

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 449
            $System_Drawing_Point.Y = 20
            $lbl_Title.Location = $System_Drawing_Point
            $lbl_Title.Name = "lbl_Title"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 31
            $System_Drawing_Size.Width = 203
            $lbl_Title.Size = $System_Drawing_Size
            $lbl_Title.TabIndex = 4
            $lbl_Title.Text = "Explanation"
            $lbl_Title.add_Click($handler_lbl_Title_Click)

            $usrMain.Controls.Add($lbl_Title)

            $lbl_cbxExplain.DataBindings.DefaultDataSourceUpdateMode = 0

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 770
            $System_Drawing_Point.Y = 860
            $lbl_cbxExplain.Location = $System_Drawing_Point
            $lbl_cbxExplain.Name = "lbl_cbxExplain"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 30
            $System_Drawing_Size.Width = 234
            $lbl_cbxExplain.Size = $System_Drawing_Size
            $lbl_cbxExplain.TabIndex = 3
            $lbl_cbxExplain.Text = "Check 'I Agree' to continue..."

            $usrMain.Controls.Add($lbl_cbxExplain)
        #endregion
        #region Checkbox
            $cbx_IAgree.DataBindings.DefaultDataSourceUpdateMode = 0

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 1000
            $System_Drawing_Point.Y = 860
            $cbx_IAgree.Location = $System_Drawing_Point
            $cbx_IAgree.Name = "cbx_IAgree"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 24
            $System_Drawing_Size.Width = 104
            $cbx_IAgree.Size = $System_Drawing_Size
            $cbx_IAgree.TabIndex = 0
            $cbx_IAgree.Text = "I Agree"
            $cbx_IAgree.UseVisualStyleBackColor = $True

            $usrMain.Controls.Add($cbx_IAgree)
        #endregion
        #region RichTextBox
            $rtxt_Explain.DataBindings.DefaultDataSourceUpdateMode = 0
            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 42
            $System_Drawing_Point.Y = 57
            $rtxt_Explain.Location = $System_Drawing_Point
            $rtxt_Explain.Name = "rtxt_Explain"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 791 # 224
            $System_Drawing_Size.Width = 1070  # 354
            $rtxt_Explain.Size = $System_Drawing_Size
            $rtxt_Explain.TabIndex = 2
            $rtxt_Explain.Text = "Compared to the Windows copy command, Xcopy is much more efficient in copying files and directories. In addition, Xcopy has more options that make it more customizable and lets you control the file copy behavior.

                        Benefits
                        There are several benefits or advantages of using Xcopy that you will learn as you progress in this guide. But below are some of the benefits of using Xcopy.

                        Faster copy operation on large sets of files and directories.
                        Simplifies application deployment.
                        Can replicate the source directory structure as is.
                        Copy files while retaining the owner and access control list (ACL) information.
                        Copy and overwrite read-only files.
                        Can exclude files based on the file name, extension, or path.
                        Can identify updated files, which is useful for differential backups.
                        Integrate and use with scripts."
            $rtxt_Explain.Font = [system.drawing.font]'Times New Roman, 24pt, style=Bold,Italic'

            $rtxt_Explain.add_TextChanged($handler_rtxt_Explain_TextChanged)

            $UsrMain.Controls.Add($rtxt_Explain)
        #endregion
        #region Button
            $btn_Continue.DataBindings.DefaultDataSourceUpdateMode = 0

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 970
            $System_Drawing_Point.Y = 900
            $btn_Continue.Location = $System_Drawing_Point
            $btn_Continue.Name = "btn_Continue"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 37
            $System_Drawing_Size.Width = 105
            $btn_Continue.Size = $System_Drawing_Size
            $btn_Continue.TabIndex = 1
            $btn_Continue.Text = "Continue"
            $btn_Continue.UseVisualStyleBackColor = $True
            $btn_Continue.add_Click($btn_Continue_OnClick)

            $usrMain.Controls.Add($btn_Continue)
        #endregion
    #endregion

    #Save the initial state of the form
        $InitialFormWindowState = $usrMain.WindowState
    #Init the OnLoad event to correct the initial state of the form
        $usrMain.add_Load($OnLoadForm_StateCorrection)

    #Show the Form
        $usrMain.ShowDialog()| Out-Null
}

#Call the Function
Form1

function Form2
{
    [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null

    #region - Form Objects
        $UsrProg = New-Object System.Windows.Forms.Form
        $progressBar2 = New-Object System.Windows.Forms.ProgressBar
        $label7 = New-Object System.Windows.Forms.Label
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
    #endregion Generated Form Objects

    #region - Event Script Blocks
        $OnLoadForm_StateCorrection =
        {
            #Correct the initial state of the form to prevent the .Net maximized form issue
            $UsrProg.WindowState = $InitialFormWindowState
        }
    #endregion

    #region - Form Code
        #region Kill Alt + F4
            $UsrProg_KeyDown=[System.Windows.Forms.KeyEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.KeyEventArgs]

                if ($_.Alt -eq $true -and $_.KeyCode -eq 'F4') {
                    $script:altF4Pressed = $true;           
                }
            }

            $UsrProg_FormClosing=[System.Windows.Forms.FormClosingEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.FormClosingEventArgs]

                if ($script:altF4Pressed)
                {
                    if ($_.CloseReason -eq 'UserClosing') {
                        $_.Cancel = $true
                        $script:altF4Pressed = $false;
                    }
                }
            }

            $UsrProg.KeyPreview = $True
            $UsrProg.add_FormClosing($UsrProg_FormClosing)
            $UsrProg.add_KeyDown($UsrProg_KeyDown)
        #endregion
        #region Main Form
            $UsrProg.BackColor = [System.Drawing.Color]::FromArgb(255,240,240,240)
            $System_Drawing_Size = New-Object System.Drawing.Size
            $UsrProg.Location.X = 253
            $UsrProg.Location.Y = 313
            $System_Drawing_Size.Height = 200
            $System_Drawing_Size.Width = 913
            $UsrProg.ClientSize = $System_Drawing_Size
            $UsrProg.DataBindings.DefaultDataSourceUpdateMode = 0
            $UsrProg.MaximizeBox = $False
            $UsrProg.MinimizeBox = $False
            $UsrProg.Name = "UsrProg"
            $UsrProg.Text = "Data Transfer Progress"
            $UsrProg.add_Load($handler_Admin_Load)
        #endregion
        #region Progress Bar
            $progressBar2.DataBindings.DefaultDataSourceUpdateMode = 0
            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 43
            $System_Drawing_Point.Y = 73
            $progressBar2.Location = $System_Drawing_Point
            $progressBar2.Name = "progressBar2"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 65
            $System_Drawing_Size.Width = ($UsrProg.Width - ($progressBar2.Location.X * 2.5))
            $progressBar2.Size = $System_Drawing_Size
            $progressBar2.TabIndex = 0
            $progressBar2.Value = 62

            $UsrProg.Controls.Add($progressBar2)
        #endregion
        #region Label
            $label7.DataBindings.DefaultDataSourceUpdateMode = 0
            $label7.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",11.25,3,3,1)

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 44
            $System_Drawing_Point.Y = 21
            $label7.Location = $System_Drawing_Point
            $label7.Name = "label7"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 31
            $System_Drawing_Size.Width = 203
            $label7.Size = $System_Drawing_Size
            $label7.TabIndex = 11
            $label7.Text = "Current Progress"
            $label7.add_Click($handler_label7_Click)

            $UsrProg.Controls.Add($label7)
        #endregion
    #endregion

    #Save the initial state of the form
        $InitialFormWindowState = $UsrProg.WindowState
    #Init the OnLoad event to correct the initial state of the form
        $UsrProg.add_Load($OnLoadForm_StateCorrection)

    #Show the Form
        $UsrProg.ShowDialog()| Out-Null

}

Form2

function Form3
{
    [reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
    [reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null

    #region - Form Objects
        $UsrDone = New-Object System.Windows.Forms.Form
        $btn_Close = New-Object System.Windows.Forms.Button
        $rtxt_Summary = New-Object System.Windows.Forms.RichTextBox
        $lbl_Title = New-Object System.Windows.Forms.Label
        $InitialFormWindowState = New-Object System.Windows.Forms.FormWindowState
    #endregion Generated Form Objects

    #region - Event Script Blocks
        $btn_Close_OnClick = { $usrDone.Close() }
        $OnLoadForm_StateCorrection =
        {
            #Correct the initial state of the form to prevent the .Net maximized form issue
            $UsrDone.WindowState = $InitialFormWindowState
        }
    #endregion

    #region - Form Code
        #region Kill Alt + F4
            $UsrDone_KeyDown=[System.Windows.Forms.KeyEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.KeyEventArgs]

                if ($_.Alt -eq $true -and $_.KeyCode -eq 'F4') {
                    $script:altF4Pressed = $true;           
                }
            }

            $UsrDone_FormClosing=[System.Windows.Forms.FormClosingEventHandler]{
                #Event Argument: $_ = [System.Windows.Forms.FormClosingEventArgs]

                if ($script:altF4Pressed)
                {
                    if ($_.CloseReason -eq 'UserClosing') {
                        $_.Cancel = $true
                        $script:altF4Pressed = $false;
                    }
                }
            }

            $UsrDone.KeyPreview = $True
            $UsrDone.add_FormClosing($UsrDone_FormClosing)
            $UsrDone.add_KeyDown($UsrDone_KeyDown)
        #endregion
        #region Main Form
            $UsrDone.BackColor = [System.Drawing.Color]::FromArgb(255,240,240,240)
            $System_Drawing_Size = New-Object System.Drawing.Size
            $UsrDone.Location.X = 266
            $UsrDone.Location.Y = 298
            $System_Drawing_Size.Height = 750
            $System_Drawing_Size.Width = 1109
            $UsrDone.ClientSize = $System_Drawing_Size
            $UsrDone.DataBindings.DefaultDataSourceUpdateMode = 0
            $UsrDone.MaximizeBox = $False
            $UsrDone.MinimizeBox = $False
            $UsrDone.Name = "UsrDone"
            $UsrDone.Text = "Job Summary"
            $UsrDone.add_Load($handler_Admin_Load)
        #endregion
        #region Labels
            $lbl_Title.DataBindings.DefaultDataSourceUpdateMode = 0
            $lbl_Title.Font = New-Object System.Drawing.Font("Microsoft Sans Serif",11.25,3,3,1)

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 449
            $System_Drawing_Point.Y = 20
            $lbl_Title.Location = $System_Drawing_Point
            $lbl_Title.Name = "lbl_Title"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 31
            $System_Drawing_Size.Width = 203
            $lbl_Title.Size = $System_Drawing_Size
            $lbl_Title.TabIndex = 4
            $lbl_Title.Text = "Summary"
            $lbl_Title.add_Click($handler_lbl_Title_Click)

            $usrDone.Controls.Add($lbl_Title)
        #endregion
        #region RichTextBox
            $rtxt_Summary.DataBindings.DefaultDataSourceUpdateMode = 0
            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 42
            $System_Drawing_Point.Y = 57
            $rtxt_Summary.Location = $System_Drawing_Point
            $rtxt_Summary.Name = "rtxt_Summary"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 600 # 224
            $System_Drawing_Size.Width = ($UsrDone.Width - ($rtxt_Summary.Location.X * 2.5))
            $rtxt_Summary.Size = $System_Drawing_Size
            $rtxt_Summary.TabIndex = 2
            $rtxt_Summary.Text = "Compared to the Windows copy command, Xcopy is much more efficient in copying files and directories. In addition, Xcopy has more options that make it more customizable and lets you control the file copy behavior.

                        Benefits
                        There are several benefits or advantages of using Xcopy that you will learn as you progress in this guide. But below are some of the benefits of using Xcopy.

                        Faster copy operation on large sets of files and directories.
                        Simplifies application deployment.
                        Can replicate the source directory structure as is.
                        Copy files while retaining the owner and access control list (ACL) information.
                        Copy and overwrite read-only files.
                        Can exclude files based on the file name, extension, or path.
                        Can identify updated files, which is useful for differential backups.
                        Integrate and use with scripts."
            $rtxt_Summary.Font = [system.drawing.font]'Times New Roman, 24pt, style=Bold,Italic'
 
            $rtxt_Summary.add_TextChanged($handler_rtxt_Summary_TextChanged)

            $UsrDone.Controls.Add($rtxt_Summary)
        #endregion
        #region Button
            $btn_Close.DataBindings.DefaultDataSourceUpdateMode = 0

            $System_Drawing_Point = New-Object System.Drawing.Point
            $System_Drawing_Point.X = 970
            $System_Drawing_Point.Y = 675
            $btn_Close.Location = $System_Drawing_Point
            $btn_Close.Name = "btn_Close"
            $System_Drawing_Size = New-Object System.Drawing.Size
            $System_Drawing_Size.Height = 37
            $System_Drawing_Size.Width = 105
            $btn_Close.Size = $System_Drawing_Size
            $btn_Close.TabIndex = 0
            $btn_Close.Text = "Close"
            $btn_Close.UseVisualStyleBackColor = $True
            $btn_Close.add_Click($btn_Close_OnClick)

            $usrDone.Controls.Add($btn_Close)
        #endregion
    #endregion

    #Save the initial state of the form
        $InitialFormWindowState = $UsrDone.WindowState
    #Init the OnLoad event to correct the initial state of the form
        $UsrDone.add_Load($OnLoadForm_StateCorrection)

    #Show the Form
        $UsrDone.ShowDialog()| Out-Null

}

Form3







function Copy-ItemWithProgress
{
    <#
    .SYNOPSIS
    RoboCopy with PowerShell progress.

    .DESCRIPTION
    Performs file copy with RoboCopy. Output from RoboCopy is captured,
    parsed, and returned as Powershell native status and progress.

    .PARAMETER Source
    Directory to copy files from, this should not contain trailing slashes

    .PARAMETER Destination
    DIrectory to copy files to, this should not contain trailing slahes

    .PARAMETER FilesToCopy
    A wildcard expresion of which files to copy, defaults to *.*

    .PARAMETER RobocopyArgs
    List of arguments passed directly to Robocopy.
    Must not conflict with defaults: /ndl /TEE /Bytes /NC /nfl /Log

    .PARAMETER ProgressID
    When specified (>=0) will use this identifier for the progress bar

    .PARAMETER ParentProgressID
    When specified (>= 0) will use this identifier as the parent ID for progress bars
    so that they appear nested which allows for usage in more complex scripts.

    .OUTPUTS
    Returns an object with the status of final copy.
    REMINDER: Any error level below 8 can be considered a success by RoboCopy.

    .EXAMPLE
    C:\PS> .\Copy-ItemWithProgress c:\Src d:\Dest

    Copy the contents of the c:\Src directory to a directory d:\Dest
    Without the /e or /mir switch, only files from the root of c:\src are copied.

    .EXAMPLE
    C:\PS> .\Copy-ItemWithProgress '"c:\Src Files"' d:\Dest /mir /xf *.log -Verbose

    Copy the contents of the 'c:\Name with Space' directory to a directory d:\Dest
    /mir and /XF parameters are passed to robocopy, and script is run verbose

    .LINK
    https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress

    .NOTES
    By Keith S. Garner (KeithGa@KeithGa.com) - 6/23/2014
    With inspiration by Trevor Sullivan @pcgeek86
    Tweaked by Justin Marshall - 02/20/2020

    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Source,
        [Parameter(Mandatory=$true)]
        [string]$Destination,
        [Parameter(Mandatory=$false)]
        [string]$FilesToCopy="*.*",
        [Parameter(Mandatory = $true,ValueFromRemainingArguments=$true)] 
        [string[]] $RobocopyArgs,
        [int]$ParentProgressID=-1,
        [int]$ProgressID=-1
    )

    #handle spaces and trailing slashes
    $SourceDir = '"{0}"' -f ($Source -replace "\\+$","")
    $TargetDir = '"{0}"' -f ($Destination -replace "\\+$","")


    $ScanLog  = [IO.Path]::GetTempFileName()
    $RoboLog  = [IO.Path]::GetTempFileName()
    $ScanArgs = @($SourceDir,$TargetDir,$FilesToCopy) + $RobocopyArgs + "/ndl /TEE /bytes /Log:$ScanLog /nfl /L".Split(" ")
    $RoboArgs = @($SourceDir,$TargetDir,$FilesToCopy) + $RobocopyArgs + "/ndl /TEE /bytes /Log:$RoboLog /NC".Split(" ")

    # Launch Robocopy Processes
    write-verbose ("Robocopy Scan:`n" + ($ScanArgs -join " "))
    write-verbose ("Robocopy Full:`n" + ($RoboArgs -join " "))
    $ScanRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $ScanArgs
    try
    {
        $RoboRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $RoboArgs
        try
        {
            # Parse Robocopy "Scan" pass
            $ScanRun.WaitForExit()
            $LogData = get-content $ScanLog
            if ($ScanRun.ExitCode -ge 8)
            {
                $LogData|out-string|Write-Error
                throw "Robocopy $($ScanRun.ExitCode)"
            }
            $FileSize = [regex]::Match($LogData[-4],".+:\s+(\d+)\s+(\d+)").Groups[2].Value
            write-verbose ("Robocopy Bytes: $FileSize `n" +($LogData -join "`n"))
            #determine progress parameters
            $ProgressParms=@{}
            if ($ParentProgressID -ge 0) {
                $ProgressParms['ParentID']=$ParentProgressID
            }
            if ($ProgressID -ge 0) {
                $ProgressParms['ID']=$ProgressID
            } else {
                $ProgressParms['ID']=$RoboRun.Id
            }
            # Monitor Full RoboCopy
            while (!$RoboRun.HasExited)
            {
                $LogData = get-content $RoboLog
                $Files = $LogData -match "^\s*(\d+)\s+(\S+)"
                if ($null -ne $Files )
                {
                    $copied = ($Files[0..($Files.Length-2)] | ForEach-Object {$_.Split("`t")[-2]} | Measure-Object -sum).Sum
                    if ($LogData[-1] -match "(100|\d?\d\.\d)\%")
                    {
                        write-progress Copy -ParentID $ProgressParms['ID'] -percentComplete $LogData[-1].Trim("% `t") $LogData[-1]
                        $Copied += $Files[-1].Split("`t")[-2] /100 * ($LogData[-1].Trim("% `t"))
                    }
                    else
                    {
                        write-progress Copy -ParentID $ProgressParms['ID'] -Complete
                    }
                    write-progress ROBOCOPY  -PercentComplete ($Copied/$FileSize*100) $Files[-1].Split("`t")[-1] @ProgressParms
                }
            }
        } finally {
            if (!$RoboRun.HasExited) {Write-Warning "Terminating copy process with ID $($RoboRun.Id)..."; $RoboRun.Kill() ; }
            $RoboRun.WaitForExit()
            # Parse full RoboCopy pass results, and cleanup
            (get-content $RoboLog)[-11..-2] | out-string | Write-Verbose
            remove-item $RoboLog
            write-output ([PSCustomObject]@{ ExitCode = $RoboRun.ExitCode })

        }
    } finally {
        if (!$ScanRun.HasExited) {Write-Warning "Terminating scan process with ID $($ScanRun.Id)..."; $ScanRun.Kill() }
        $ScanRun.WaitForExit()

        remove-item $ScanLog
    }
}


function Copy-File {
    # ref: https://stackoverflow.com/a/55527732/3626361
    param([string]$From, [string]$To)

    try {
        $job = Start-BitsTransfer -Source $From -Destination $To `
            -Description "Moving: $From => $To" `
            -DisplayName "Backup" -Asynchronous

        # Start stopwatch
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Progress -Activity "Connecting..."

        while ($job.JobState.ToString() -ne "Transferred") {
            switch ($job.JobState.ToString()) {
                "Connecting" {
                    break
                }
                "Transferring" {
                    $pctcomp = ($job.BytesTransferred / $job.BytesTotal) * 100
                    $elapsed = ($sw.elapsedmilliseconds.ToString()) / 1000

                    if ($elapsed -eq 0) {
                        $xferrate = 0.0
                    }
                    else {
                        $xferrate = (($job.BytesTransferred / $elapsed) / 1mb);
                    }

                    if ($job.BytesTransferred % 1mb -eq 0) {
                        if ($pctcomp -gt 0) {
                            $secsleft = ((($elapsed / $pctcomp) * 100) - $elapsed)
                        }
                        else {
                            $secsleft = 0
                        }

                        Write-Progress -Activity ("Copying file '" + ($From.Split("\") | Select-Object -last 1) + "' @ " + "{0:n2}" -f $xferrate + "MB/s") `
                            -PercentComplete $pctcomp `
                            -SecondsRemaining $secsleft
                    }
                    break
                }
                "Transferred" {
                    break
                }
                Default {
                    throw $job.JobState.ToString() + " unexpected BITS state."
                }
            }
        }

        $sw.Stop()
        $sw.Reset()
    }
    finally {
        Complete-BitsTransfer -BitsJob $job
        Write-Progress -Activity "Completed" -Completed
    }
}

Function Copy-FilesBitsTransfer(
        [Parameter(Mandatory=$true)][String]$sourcePath, 
        [Parameter(Mandatory=$true)][String]$destinationPath, 
        [Parameter(Mandatory=$false)][bool]$createRootDirectory = $true)
{
    $item = Get-Item $sourcePath
    $itemName = Split-Path $sourcePath -leaf
    if (!$item.PSIsContainer){ #Item Is a file

        $clientFileTime = Get-Item $sourcePath | Select-Object LastWriteTime -ExpandProperty LastWriteTime

        if (!(Test-Path -Path $destinationPath\$itemName)){
            Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy Template file" -Confirm:$false
            if (!$?){
                return $false
            }
        }
        else{
            $serverFileTime = Get-Item $destinationPath\$itemName | Select-Object LastWriteTime -ExpandProperty LastWriteTime

            if ($serverFileTime -lt $clientFileTime)
            {
                Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy Template file" -Confirm:$false
                if (!$?){
                    return $false
                }
            }
        }
    }
    else{ #Item Is a directory
        if ($createRootDirectory){
            $destinationPath = "$destinationPath\$itemName"
            if (!(Test-Path -Path $destinationPath -PathType Container)){
                if (Test-Path -Path $destinationPath -PathType Leaf){ #In case item is a file, delete it.
                    Remove-Item -Path $destinationPath
                }

                New-Item -ItemType Directory $destinationPath | Out-Null
                if (!$?){
                    return $false
                }

            }
        }
        Foreach ($fileOrDirectory in (Get-Item -Path "$sourcePath\*"))
        {
            $status = Copy-FilesBitsTransfer $fileOrDirectory $destinationPath $true
            if (!$status){
                return $false
            }
        }
    }

    return $true
}
