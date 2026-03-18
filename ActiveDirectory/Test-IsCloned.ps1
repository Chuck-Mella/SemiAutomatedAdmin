Function Test-IsCloned
{
    Param ($userSam)

    Import-Module ActiveDirectory

    try {
        $user = Get-ADUser -Identity $userSam -Properties whenCreated, SIDHistory, memberOf, lastLogonTimestamp

        Write-Host "Account: $($user.SamAccountName)"
        Write-Host "Created: $($user.whenCreated)"
        Write-Host "SIDHistory Count: $($user.SIDHistory.Count)"
        Write-Host "Groups: $($user.memberOf.Count)"
        Write-Host "Last Logon: $([DateTime]::FromFileTime($user.lastLogonTimestamp))"

        if ($user.SIDHistory.Count -gt 0) {
            Write-Host "⚠ Possible cloned/migrated account (SIDHistory present)" -ForegroundColor Yellow
        }
        elseif ($user.memberOf.Count -gt 0 -and $user.whenCreated -gt (Get-Date).AddDays(-1)) {
            Write-Host "ℹ Recently created with memberships — may be cloned from a template" -ForegroundColor Cyan
        }
        else {
            Write-Host "✓ Likely created from scratch" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
    }
}

Test-IsCloned -userSam <USERNAME>
 
