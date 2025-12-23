        #region - send warning messages to VM Users
            # Kill script on weekends
              If ((Get-Date).Dayofweek -match '(Saturday|sunday)'){ EXIT }
            $OUVMs = $($cmp = [adsisearcher]'(&(objectclass=computer))';$cmp.FindAll() | ?{($_.path -match 'Windows (10|11) Instant Clones').Properties.cn}
            # $OUVMs = $($cmp = [adsisearcher]'(&(objectclass=computer))';$cmp.FindAll()).Properties.cn
            $VMS = $OUVMs | Sort
            # $VMS = $OUVMs -match '^Win' | Sort

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(15*60)","/SERVER:$vm","*","JWICS is shutting down in 30 Minutes." }
            Start-Sleep -Seconds (15*60-5)

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(5*60)","/SERVER:$vm","*","JWICS is shutting down in 15 Minutes." }
            Start-Sleep -Seconds (5*60-2)

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(5*60)","/SERVER:$vm","*","JWICS is shutting down in 10 Minutes." }
            Start-Sleep -Seconds (5*60-2)

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(5*60)","/SERVER:$vm","*","JWICS is shutting down in 5 Minutes." }
            Start-Sleep -Seconds (4*60)

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(1*60)","/SERVER:$vm","*","JWICS is shutting down in 1 Minute." }
            Start-Sleep -Seconds (1*60)

            ForEach ($vm in $VMs)
            { Start-Process -Filepath 'MSG.exe' -ArgumentList "/TIME:$(.1*60)","/SERVER:$vm","*","JWICS shutting down." }
        #endregion
