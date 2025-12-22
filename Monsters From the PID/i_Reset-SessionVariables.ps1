    # Set Variable RESET point
        New-Variable -Force -Name MyStartupVariables -Value (Get-Variable | ForEach-Object{$_.Name}) -Scope Global

    Function Reset-SessionVariables
    {
        Param ( $stVar = (Get-Variable MyStartupVariables).Name )
        $varCheck = (Get-Variable | Where {$_.Name -ne $stVar} | ForEach-Object{$_.Name })
        $killList = (Compare $varCheck $MyStartupVariables | Where SideIndicator -eq '<=').InputObject
        $killList | %{ Remove-Variable -Verbose -Force -Name $_ -Confirm:$false }
    }
        


        $MyStartupVariables.count
        $varCheck.count


