# 1. Define your script block
    $scriptBlock = {
        $source = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Bookmarks"
        $destination = ("$([Environment]::GetFolderPath('Desktop'))\EdgeFavorites_Backup_{0:yyyyMMdd_HHmm}.json" -f (Get-Date))
        Copy-Item -Path $source -Destination $destination -Force
    }

# 2. Convert to String and then to Unicode Bytes
    $scriptString = $scriptBlock.ToString()
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($scriptString)

# 3. Encode to Base64
    $encodedCommand = [Convert]::ToBase64String($bytes)

# Run BU
    IEX "powershell.exe -EncodedCommand `"$encodedCommand`"" 

# Output for use in CMD or another PowerShell session
    "powershell.exe -EncodedCommand `"$encodedCommand`"" | Set-Clipboard
