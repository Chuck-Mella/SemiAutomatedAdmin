#region - Create 'Kill NIC' desktop icon
	$WScriptShell = New-Object -ComObject WScript.Shell
	# $ShortcutFile = [Environment]::GetFolderPath('CommonDesktopDirectory') + "\Kill NIC.lnk"
	$ShortcutFile = [Environment]::GetFolderPath('Desktop') + "\Kill NIC.lnk"
	$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
	$Shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
	$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& {Get-NetAdapter | Where Status -eq 'Up' | Where Name -NotMatch '^v' | Disable-NetAdapter -Confirm:`$false}`""
	$Shortcut.IconLocation = "$env:SystemRoot\System32\inetcpl.cpl,44"
	$Shortcut.Save()
#endregion
#region - Create 'Ressurect NIC' desktop icon
	$WScriptShell = New-Object -ComObject WScript.Shell
	# $ShortcutFile = [Environment]::GetFolderPath('CommonDesktopDirectory') + "\Resurrect NIC.lnk"
	$ShortcutFile = [Environment]::GetFolderPath('Desktop') + "\Resurrect NIC.lnk"
	$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)
	$Shortcut.TargetPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
	$Shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"& {Get-NetAdapter | Where LinkSpeed -NotMatch '^0' | Where Status -eq 'Disabled' | Enable-NetAdapter -Confirm:`$false}`""
	$Shortcut.IconLocation = "$env:SystemRoot\System32\inetcpl.cpl,40"
	$Shortcut.Save()
#endregion
