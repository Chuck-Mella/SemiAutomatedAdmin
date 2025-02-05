# Exit if OS not server OR if task already exists
    If ((gwmi win32_operatingsystem).ProductType -eq 1 ){ EXIT }
    If ( [Bool ] (Get-scheduledTask | where TaskName -Match 'server Event capture' ) -eq $true){ EXIT }
# Limit to East coast servers
    $ADComputer = $($cmp = [ADSISearcher] "(&(objectclass=computer))" ;
    $cmp.FindAll() | where { $_.Properties.samaccountname -match $env:computerName })
    If ( $ADComputer.Path -NOTmatch 'East|AD-E' ){ EXIT }
