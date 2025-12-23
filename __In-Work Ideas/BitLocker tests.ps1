# https://theitbros.com/config-active-directory-store-bitlocker-recovery-keys/
Get-ADComputer 'fabconhv01'| Get-ADObject -properties * | Select-Object distinguishedname, ms-FVE-KeyPackage, ms-FVE-RecoveryGuid, ms-FVE-RecoveryInformation, ms-FVE-RecoveryPassword, ms-FVE-VolumeGuid 

Get-ADObject -SearchBase ((GET-ADRootDSE).SchemaNamingContext) -Filter {Name -like 'ms-FVE-*'}
Install-WindowsFeature BitLocker -IncludeAllSubFeature -IncludeManagementTools

# UPDATE GPOS

gpupdate /force

manage-bde -status c:

$trg = manage-bde -protectors -get c:
$trg | gm

# Get current BitLocker ID for the encrypted volume (CMD):
manage-bde -protectors -get c:
# Now, you can send the BitLocker recovery key to the AD by specifying an ID obtained in the previous step:
manage-bde -protectors -adbackup c: -id '{64BBFA76-C12C-410A-A2C1-572048ED3499}'


Get-PSDrive | gm

$BitVolume = Get-BitLockerVolume -MountPoint $env:SystemDrive
$RecoveryKey = $BitVolume.KeyProtector | Where-Object { $_.KeyProtectorType -eq 'RecoveryPassword' }
Backup-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $RecoveryKey.KeyProtectorID
# BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $RecoveryKey.KeyProtectorID



$ADComputer = 'fabcondc01'
$DN = Get-ADComputer $ADComputer | Select-Object -ExpandProperty DistinguishedName
$ADobj = get-adobject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $DN -Properties 'msFVE-RecoveryPassword' | Select-Object Name,msFVE-RecoveryPassword
[Ordered]@{
    Computer = $ADComputer
    RecoveryPassword = $ADobj.'msFVE-RecoveryPassword'
    Date = Get-Date -Date ($ADobj.Name ).Split('{')[0]
    BitlockerKeyID = (($ADobj.Name ).Split('{')[1]).TrimEnd('}')
}
#OR 
Get-ADComputer 'fabconhv01' |Get-ADObject -properties * | Select-Object * distinguishedname, msFVE-REcoveryPassword, whencreated

