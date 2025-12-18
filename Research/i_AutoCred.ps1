Function Scramble
{
    Param ($i,$x)
    
    $r = ($x.ToCharArray() | %{[int]$_ +$i})
    ("@($($r -join ','))") | Set-Clipboard
    $vmAcl = ConvertTo-SecureString (($r |
                ForEach-Object{ [Char]($_ -$i) }) -join '') -AsPlainText -Force
    Return $vmAcl
}

$apwd = Scramble 26 'WellHidden!!0'
$credential = (New-object system.Management.Automation.Pscredential('Administrator',$apwd))

$credential.GetNetworkCredential().password


@(113,127,134,134,98,131,126,126,127,136,59,59,74)
