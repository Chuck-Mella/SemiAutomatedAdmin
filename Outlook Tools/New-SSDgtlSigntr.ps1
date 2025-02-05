#create self-signed cert if missing or expired
# select Cert Store and create subject from user AD info
    $test = $false
    $certstore = 'cert:\Currentuser\My'
    If ($(whoami) -match $env:computerName)
    {
        $user = $env:userName
        $sbj = "C=US, E=$env:userName,OU=AD, O=Assessments Division, CN=[$env:computerName]Local Admin"
    }
    Else
    {
        $user = $($usr = [ADSISearcher]"(&(objectclass=user))" ; $usr.FindAll() | where { $_.Properties.samaccountname -match $env:userName })
        $sbj = "C=US, E=$($user.Properties.mail),OU=AD, O=Assessments Division, CN=$($user.Properties.givenname) $($user.Properties.sn) "
    }
    $certdata = [Ordered]@{
        subject = $sbj
        certstoreLocation = $certstore
        Keyusage = 'Digitalsignature'
        Type = 'custom'
        FriendlyName = 'My Signature'
        NotBefore = (Get-Date).AddYears(0)
        NotAfter = (Get-Date).AddYears(1)
        }

#Test for existing cert
    $chkcert = Get-ChildItem $certstore -Recurse | Where-Object -Property subject -eq -value "$sbj" # | select-object *
    # create cert if missing
    If ($chkcert -eq $null )
    {
        $nwcert = New-SelfSignedCertificate @certdata
    }
# update cert if old
    If ($chkcert -ne $null )
    {
        #Test for expired cert
        $expcert = New-Object System.Collections.ArrayList
        $chkcert.count
        #select cert with most recent expiration date
        ForEach ($cert in $chkcert) { [void]$expcert.Add((Get-Date $cert.GetExpirationDateString())) }
        $expDate = (Get-Date ($expcert | sort | select -Unique -Last 1))
        #If Expired, update
        If ($expDate -lt (Get-Date).AddYears(0)){ $nwcert = New-SelfSignedCertificate @certdata }
    }
    Function New-Expiredcert
    {
        $certdata.NotBefore, $certdata.NotAfter = (Get-Date).AddYears(-1),(GetDate).AddHours(-1)
        Return New-SelfSignedCertificate @certdata
    }
    # New*Expiredcert
    Function Copy-SSC2Trusted
    {
        # copy new cert to Trusted Root Store
        $nwcert = Get-ChildItem $certstore | Where-Object -Property subject -eq -value "$sbj"
        $rootstore = [System.Security.Cryptography.X509Certificates.X509Store]::new('Root','Currentuser')
        $rootstore.open('readwrite')
        $rootstore.Add($nwcert)
        $rootstore.close()
    }
    # copy-SSC2Trusted
