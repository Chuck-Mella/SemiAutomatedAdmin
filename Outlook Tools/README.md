# Backup or restore Outlook email signatures

## Backup-OutlookSignatures.ps1
Compresses all signature files from the user's profile folders and saves the resultant zip file to a folder "Outlook-sigBUs" created in  the user's Documents folder.

## Restore-OutlookSignatures.ps1
Restores all signature files from a backup file (created by Backup-OutlookSignatures) to the user's profile folders.

## New-SSDgtlSigntr.ps1
Creates a new Self-Signed certificate and places it in the user's Trusted Root certificate store. Certificate is purposed for signing documents and emails. the certificate life time is one year. If a valid certificate (not expired) with the same subject is found, the script exits. If it is expired (or not present) then a new certificate will be created.
