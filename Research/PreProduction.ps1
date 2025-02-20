#region - Pre-Production Code
    # shutdown /r /t (5 * 3600)
    Disable-StaleAccounts
    {
        Param
        (
            $daysInactive = 25,
            $noLogins = 30,
            $fqdn = (([DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name -replace '^','dc=' -replace '\.',',dc='),
            $sBase = "OU=Users\, AD-East,$fqdn",
            $dBase = "OU=Disabled Accounts,$fqdn"
        )

        <# 
            https://timclevenger.com/2020/05/26/automatically-disable-inactive-users-in-active-directory/
        
            disableUsers.ps1  
            Set msDS-LogonTimeSyncInterval (days) to a sane number.  By
            default lastLogonDate only replicates between DCs every 9-14 
            days unless this attribute is set to a shorter interval.
 
            Also, make sure to create the EventLog source before running, or
            comment out the Write-EventLog lines if no event logging is
            needed.  Only needed once on each machine running this script.
            New-EventLog -LogName Application -Source "DisableUsers.ps1"
 
            Remove "-WhatIf"s before putting into production.
        #> 
        # load modules and build working variables
            Import-Module ActiveDirectory
            $diDate = (Get-Date).AddDays(-($daysInactive))
            $nlDate = (Get-Date).AddDays(-($noLogins))
 
        # Identify and disable users who have not logged in in x days
            $inactiveAccts = Get-ADUser -SearchBase $sBase -Filter {Enabled -eq $TRUE} `
                -Properties lastLogonDate, whenCreated, distinguishedName, CanonicalName | 
                Where-Object {($_.lastLogonDate -lt $diDate) -and ($_.lastLogonDate -ne $NULL)}

 
            $inactiveAccts | %{
                Disable-ADAccount $_ -WhatIf
                Set-ADUser -Identity $_.SamAccountName -Description ("Account disabled for inactivity ($daysInactive days) by $env:USERNAME on $(Get-Date)") -WhatIf
                Get-ADUser -Identity | Move-ADAccount $_ -WhatIf
                }
 
        # Identify and disable users who were created x days ago and never logged in.
            $unusedAccts = Get-ADUser -SearchBase $sBase -Filter {Enabled -eq $TRUE} `
                -Properties lastLogonDate, whenCreated, distinguishedName, CanonicalName | 
                Where-Object {($_.whenCreated -lt $nlDate) -and (-not ($_.lastLogonDate -ne $NULL))}
 
 
            $unusedAccts | %{
                Disable-ADAccount $_ -WhatIf
                Set-ADUser -Identity $_.SamAccountName -Description ("Account disabled for non-use inactivity ($noLogins days) by $env:USERNAME on $(Get-Date)") -WhatIf
                Get-ADUser -Identity | Move-ADAccount $_ -WhatIf
                }

        # Format results
            # Log Prep
                $msg = "Admin:$env:UserName`nAttempted to disable users below for NEVER logging in after <NUM> days have passed.`n`n<RSLT>`n`nAccounts moved to the '$dBase' OU."

                $src,$log = 'psAdminScripting','Application'
                If (!([System.Diagnostics.EventLog]::SourceExists($src)))
                { [System.Diagnostics.EventLog]::CreateEventSource($src,$log) }

            # Format Evt Msg
                $rsltDI = ($inactiveAccts | Select SamAccountName,@{n='OU';e={$_.CanonicalName -replace '\/+{^\/]+$'}}) | Sort OU
                $rsltNL = ($unusedAccts | Select SamAccountName,@{n='OU';e={$_.CanonicalName -replace '\/+{^\/]+$'}}) | Sort OU

                $msgDI = $msg -replace 'NEVER','not'-replace '<NUM>',$daysInactive -replace '<RSLT>',$rsltDI
                $msgNL = $msg -replace '<NUM>',$noLogins -replace '<RSLT>',$rsltNL

            # Write results to Evt Msg
                Write-EventLog -Source $src -EventId 9091 -LogName $log -Message $msgDI
                Write-EventLog -Source $src -EventId 9092 -LogName $log -Message $msgDI
    }

    Function Reset-LclPwdChngDate($rng=60)
    {
        $chkDate = (Get-Date).AddDays(-$rng)
        $trgAccts = Get-LocalUser | Where PasswordLastSet -le $chkDate
        ForEach ($acct in $trgAccts)
        {
            $usr = [ADSI]"WinNT://$env:ComputerName/$($acct.Name),user"
            $usr.PasswordExpired = 1
            $usr.SetInfo()
            $usr.PasswordExpired = 0
            $usr.SetInfo()
        }
        Get-LocalUser | Where PasswordLastSet -ge $chkDate | Select Name,Enabled,PasswordLastSet
    }

    #region - Certifitcate Store Checks
        [ValidateSet('CurrentUser','LocalMachine')]$Store = 'CurrentUser' 
        $certStore = "Cert:\$Store"
        $chkCert = Get-ChildItem $certStore -Recurse | where Subject -Match -Value "Ca 6" # | select *


        $instPath = 'path to certificatew'

        gci $instPath

        Get-PfxCertificate '\\path\cert.p7b'

        Function Copy-SSC2Trusted
        {
            # Copy new Cert to Trusted Root store
                Param ([ValidateSet('CurrentUser','LocalMachine')]$Store,$sbj)
                $certStore = "Cert:\$Store"
                $nwCert = Get-ChildItem $certStore -Recurse | where -Property Subject -eq -Value $sbj
                $rootStore - [System.Security.Cryptography.X509Certificates.X509Store]::new('Root',$Store)
                $rootStore.Open('ReadWrite')
                $rootStore.Add($nwCert)
                $rootStore.Close()
        }
        Copy-SSC2Trusted -Store CurrentUser -sbj "Ca 6"
    #endregion

    #region - New Segregated Admin Accounts
        $curDomain = ( [Directoryservices.ActiveDirectory.Domain]::Getcurrentoomain()).Name
        $fDom = $curDomain =replace '^','dc=' -replace '\.',',dc='
        New-AdGroup -Name "Server Admins" -Description "Designated administrators for domain member servers." -GroupCategory Security -GroupScope Global -Path "OU=DomainGroups.$fDom"
        New-AdGroup -Name "Workstation Admins" -Description "Designated administrators for domain workstations." -GroupCategory Security -GroupScope Global -Path "OU=DomainGroups.$fDom"
        New-AdGroup -Name "Application Admins" -Description "Designated administrators for domain applications." -GroupCategory Security -GroupScope Global -Path "OU=DomainGroups.$fDom"
    
        Function New-AdmAcct
        {
            Param
            (
                $usr = 'Joe Admin',
                [ValidateSet('Ent','Dom','Svr','Wks','App')]$admRole = 'App',
                $dfltPwd = ('Password1234561!' | ConvertTo-SecureString -AsPlainText -Force),
                $admOU = "OU=Administrators,OU=IT Administration"
                # $admOU = "OU=IT Administration"
            )
            $curDomain = ( [Directoryservices.ActiveDirectory.Domain]::Getcurrentoomain()).Name
            $fDom = $curDomain =replace '^','dc=' -replace '\.',',dc='

            $dfltRoles = "Ent,Enterprise,EA`nDom,Domain,DA`nSvr,Server,SA`nWks,Workstation,WA`nApp,Application,AA`n" | ConvertFrom-Csv -Header role,desc,init
            $trgRole = $dfltRoles | Where Role -eq $admRole

            $obj = [Ordered]@{
                AccountExpirationDate = (Get-Date).AddYears(1)
                AccountPassword = $dfltPwd
                Company = 'Adminium'
                Division = 'Support'
                Department = 'IT'
                Office = 'Shelbyville'
                OfficePhone = '800-800-8888'
                GivenName = $usr.split(' ')[0]
                SurName = $usr.split(' ')[1]
                Description = $trgRole.desc + " Administrator"
                DisplayName = "$($usr.split(' ')[1]), $($usr.split(' ')[0]) $($trgRole.desc) Administrator"
                Name = "$($usr.split(' ')[1]), $($usr.split(' ')[0]) $($trgRole.desc) Administrator"
                SamAccountName = "Admin$(($usr.split(' ')[0])[0])$(($usr.split(' ')[1])[0]).$($trgRole.init)"
                UserPrincipalName = "Admin$(($usr.split(' ')[0])[0])$(($usr.split(' ')[1])[0]).$($trgRole.init)@$curDom"
                Path = "OU=$($trgRole.desc),$admOU,$fDom"
            }

            New-AdUser @obj -PassThru | Set-AdUser -ChangePasswordAtLogon:$true -Enabled:$true
            Add-ADGroupMember -Identity "$($trgRole.desc) Admins" -Members $obj.SamAccountName
        }

        $admins = @('Joe Admin','John Admin','Jill Admin','Joan Admin','Vince Admin','')
        $admins = $admins[4]
        $roles = @('Ent','Dom','Svr','Wks','App')
        $roles = $roles[2]

        ForEach ($admin in $admins){ ForEach ($role in $roles){ New-AdmAcct -usr $admin -admRole $role } }

    #endregion

    #region _ Close DiscBurn (In-Work)
        $drives = New-Object -ComObject 'IMAPI2.MsftDiscMaster2'
        $recorder = New-Object -ComObject 'IMAPI2.MsftDiscRecorder2'
        $recorder.InitializeDiscRecorder($drives[0])  # Choose a drive here

        $disc = New-Object -ComObject 'IMAPI2.MsftDiscFormat2Data'
        $disc.ClientName = 'PowerShell Recorder'
        $disc.Recorder = $recorder
        $disc.ForceMediaToBeClosed = $true  # Finalize the next session

        $image = New-Object -ComObject 'IMAPI2FS.MsftFileSystemImage'

        if (!$disc.IsCurrentMediaSupported($recorder)) {
            throw 'Disc is not writeable.'
        } elseif ($disc.MediaHeuristicallyBlank) {
            $image.ChooseImageDefaults($recorder)
        } else {
            $image.MultisessionInterfaces = $disc.MultisessionInterfaces
            $image.ImportFileSystem() > $null
        }
    #endregion

    #region - Cert Ideas
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
        Add-Type -TypeDefinition (Dec64 'dXNpbmcgU3lzdGVtLk5ldDsNCnVzaW5nIFN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuWDUwOUNlcnRpZmljYXRlczsNCnB1YmxpYyBjbGFzcyBUcnVzdEFsbENlcnRzUG9saWN5IDogSUNlcnRpZmljYXRlUG9saWN5DQp7DQogICAgcHVibGljIGJvb2wgQ2hlY2tWYWxpZGF0aW9uUmVzdWx0KFNlcnZpY2VQb2ludCBzcCwgWDUwOUNlcnRpZmljYXRlIGNlcnQsIFdlYlJlcXVlc3QgcmVxLCBpbnQgY2VydFByb2JsZW0pDQogICAgew0KICAgICAgICByZXR1cm4gdHJ1ZTsNCiAgICB9DQp9')
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
    #endregion

    #region - Repeat txt search
        [regex]::matches('AAAAAAAABBBAAAAAAABBBAAAAA',('B'*3)).count #-match '(.)\1{55,}'
    #endregion

    #region - shares
        Get-smbshare -cimsession FILESVR_A | Get-smbshareAccess
        Get-smbshare -cimsession FILESVR_B | Get-smbshareAccess
        Get-smbshare -cimsession FILESVR_C | Get-smbshareAccess
        Get-smbshare -cimsession FILESVR_D | Get-smbshareAccess
    #endregion
#endregion
