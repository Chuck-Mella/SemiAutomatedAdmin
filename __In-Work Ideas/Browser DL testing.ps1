            Install-Module -Name PowerHTML
            Import-Module -Name PowerHTML
            Get-Command -Module PowerHTML
            ConvertFrom-Html -URI $urlAdobe1

            $urlAdobe1 = Invoke-WebRequest -Uri "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC" -UseBasicParsing
            $urlAdobe1 = Invoke-RestMethod -Uri "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC" -UseBasicParsing
            $urlAdobe2 = "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC/continuous/dccontinuoussep2023.html#dccontinuousseptwentytwentythree"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Trace-Command -Name metadata,parameterbinding,cmdlet -Expression {
    Invoke-WebRequest -Uri "https://www.adobe.com/devnet-docs/acrobatetk/tools/ReleaseNotesDC" -OutFile C:\temp\azcopy.zip
} -PSHost

            ####################################################################################

            function Download-7zip {
                # SET VARIABLES
                $initialURL = "http://www.7-zip.org/download.html"
                $folderName = "7zip"
                $filenamePrefix = "7zip64"
                $filenameExtension = "msi"
                $defaultVersion = "0"
                ###############

                # MIGHT NEED CUSTOMIZATION DEPENDING ON CRAWL METHOD
                $program = (Invoke-WebRequest -Uri "$initialURL" ).Links | Where-Object {($_.href -like "*x64.msi")} | Select-Object href
                $programURL = $program[0]
                $programSTRING = "$programURL"

                $programVERSION = $programSTRING -replace("@{href=a/7z","") -replace("-x64.msi}","")
                $programDOWNLOAD = $programSTRING -replace("@{href=","http://www.7-zip.org/") -replace("}","")
                ####################################################
    
                # NO CHANGES NEEDED
                $programFILENAME = ".\$folderName\$filenamePrefix-$programVERSION.$filenameExtension"
                $programREAD = Get-ChildItem ".\$folderName\" -name | Sort-Object -Descending | Select-Object -First 1
                if ($programREAD.length -eq 0) {
                    $programREADVERSION = "$defaultVersion"
                } else {
                    $programREADVERSION = $programREAD -replace("$filenamePrefix-","") -replace(".$filenameExtension","")
                }
                downloadProgram $programREADVERSION $programVERSION $programDOWNLOAD $programFILENAME
                ###################   
            }

