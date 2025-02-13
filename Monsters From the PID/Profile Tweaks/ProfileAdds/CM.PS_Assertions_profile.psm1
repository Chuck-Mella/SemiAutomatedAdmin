# Folder Existence
    filter Assert-FolderExists
    {
        $exists = Test-Path -Path $_ -PathType Container
        if (!$exists)
        { 
            Write-Warning "$_ did not exist. Folder created."
            $null = New-Item -Path $_ -ItemType Directory 
        }
        #  https://powershell.one/code/10.html
    }  
