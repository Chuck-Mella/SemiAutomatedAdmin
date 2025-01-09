        Function Convert-Watt2Lumen
        {
            Param 
            (
                [Parameter(Mandatory=$true)][int]$power,
                [ValidateSet('LED','CFL','Halogen','Incandescent','Metal Halide')]$Source = 'Incandescent'
            )
            $tblConvert = "LED,80`nCFL,70`nHalogen,20`nIncandescent,15`nMetal Halide,60" | ConvertFrom-Csv -delim ',' -Header BulbType,Refactor
            $Lumens = [int]($tblConvert| Where BulbType -eq $Source).Refactor * $power
            Return $Lumens
        }
        Function Convert-Lumen2Watt
        {
            Param
            (
                [Parameter(Mandatory=$true)][int]$lumens,
                [ValidateSet('LED','CFL','Halogen','Incandescent','Metal Halide')]$Source = 'Incandescent'
            )
            $tblConvert = "LED,80`nCFL,70`nHalogen,20`nIncandescent,15`nMetal Halide,60" | ConvertFrom-Csv -delim ',' -Header BulbType,Refactor
            $Watts = $lumens / [int]($tblConvert| Where BulbType -eq $Source).Refactor
            Return [int]$Watts
        }
