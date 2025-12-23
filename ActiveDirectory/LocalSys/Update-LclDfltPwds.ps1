Param
(
    $key,
    [switch]$Force
)
# Marshal Data
    $curDomain = ([DirectoryServices.ActiveDirectory.Domain]::GetcurrentDomain()).Name
    $keyFile = "\\$curDomain\SYSVOL\$curDomain\scripts\PSScripts_GPO\key$key.bin"
    $aesKey = (GC $keyFile)[0..31]
    $aessalt = (GC $keyFile)[-1]
    $pwd = $aessalt | ConvertTo-SecureString -Key $aesKey
# Get Local Admin Group Members
    $admGroup = Get-LocalGroupMember -Group Administrators
#Get all ENABLED local accounts
    $lclAccts = Get-LocalUser | where { $_.enabled -eq $true }
# select ADMIN accounts only
    $admAccts = $lc1Accts | where { $admGroup.name -contains "$env:computerName\$($_.Name)" }
# Modify Password(s)
ForEach ($acct in $admAccts)
{
    If (( New-Timespan (Get-date $acct.PasswordLastset) (Get-date)).Days -ge 364){ $acct | Set-LocalUser -Password $pwd }
    If ($Force.IsPresent -eq $true) { $acct | Set-Localuser -Password $pwd }
}
