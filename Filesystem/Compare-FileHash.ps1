Param
(
    $location = (Get-location),
    $File1,
    $File2,
    [ValidateSet('SHA1','SHA256','SHA384','SHA512','MACTripleDES','MD5','RIPEMD160')]$alg = 'SHA256'

)

SL $location
$Comp1 = Get-filehash -literalpath $File1 -algorithm $alg | Select -Exp Hash
$Comp2 = Get-filehash -literalpath $File2 -algorithm $alg | Select -Exp Hash

If ($comp1 -eq $Comp2){  Write-Host -f green "[$alg] Hashes Match`n`tHash: $Comp1" }
Else {  Write-Host -f y "[$alg] Hashes Do Not Match`n`tFile1: $Comp1`n`tFile2: $Comp2" }

function Compare-FileHash
{
    Param
    (
        [ValidateSet('SHA1','SHA256','SHA384','SHA512','MACTripleDES','MD5','RIPEMD160')]$alg = 'SHA256',
        $File1,
        $File2
    )
}
