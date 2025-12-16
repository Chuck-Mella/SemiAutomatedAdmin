Function Get-MyPwdAge([Array]$users=$env:username,[Switch]$lcl)
{
    foreach ($user in $users) {
        If ($lcl){ $usr = Get-LocalUser -Name $user }
        Else { $usr = Get-ADUser -Identity $user -Properties PasswordLastSet }
        $usr | Select-Object @{n='UserName';e={$_.Name}},
                              @{n='saMAcct';e={$_.SamAccountName}},
                              @{n='Pwd Date';e={$_.PasswordLastSet}},
                              @{n='Pwd Age (Days)';e={((New-TimeSpan -Start $_.PasswordLastSet -End (Get-Date)).Days)}}
    }
}
Get-MyPwdAge 'adminUser','User'
Get-MyPwdAge -users LocalAccount -lcl
