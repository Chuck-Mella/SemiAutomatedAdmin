$basPath = "C:\Users\CAMELLA\OneDrive - Work\Documents\Desktop"
$zipTool = "$basPath\7z2600-extra\7za.exe"
$src     = "$basPath\Copilots"
$dest    = "$basPath\Copilots.7z"
$pass    = "PlainTextPassword"

& $zipTool a -tzip $dest $src -p$pass -mem=AES256
