Function Get-MyLastLogon([Array]$users=$env:username)
{
    foreach ($user in $users) {
        $usr = Get-ADUser -Identity $user -Properties LastLogon,LastLogonTimeStamp
        $lastLogDate = [DateTime]::FromFileTime($usr.LastLogon).ToLocalTime()
        $lastRplDate = [DateTime]::FromFileTime($usr.LastLogonTimeStamp).ToLocalTime()
        $reportDate  = [DateTime](($lastLogDate,$lastRplDate | Measure-Object -Maximum).Maximum)
        $usr | Select-Object @{n='UserName';e={$_.Name}},
                              @{n='CurrentDC';e={$lastLogDate}},
                              @{n='AllDCs';e={$lastRplDate}},
                              @{n='Days.Hrs:Min:Sec';e={([DateTime]::Now - $reportDate).ToString()}}
    }
}

# Example
    Get-MyLastLogon 'adminUser','User'
