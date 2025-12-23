$currdomain = ([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
$sysScripts = "\\$currdomain\sysvol\$currdomain\scripts\PSScripts" 

Function Save-Creds
{
    Param ($user='domain\svcAcct',$it)
    $keyfile = "$sysScripts\Key$it.bin" 
    $a = Get-credential -Message 'Enter PWD' -userName $user
    $aesKey = New-object Byte[] 32

    [System.Security.Cryptography.RNGCryptoServiceProvider]::create().GetBytes($aesKey)
    $aesKey | Out-File $keyfile
    $a.password | ConvertFrom-SecureString -Key $aesKey | Out-File $keyfile -Append
} # save-creds -it 24
