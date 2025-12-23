#region - INWORK - Mass install Certs
    $certificatePath = "C:\path\to\your\certificate.cer"
    $certStore = "Cert:\LocalMachine\Root"

    # Get a list of computers
    $computers = Get-Content "C:\path\to\computers.txt"

    foreach ($computer in $computers) {
        Invoke-Command -ComputerName $computer -ScriptBlock {
            param ($certificatePath, $certStore)
            Import-Certificate -FilePath $certificatePath -CertStoreLocation $certStore
        } -ArgumentList $certificatePath, $certStore
    }
#endregion


