# Import PowerShell Module from a Remote Computer (PSRemoting)
    $rmServer = 'ServerName'

# Version A
    $session = New-PSSession -ComputerName $rmServer
    # To display a list of modules installed on a remote computer:
        Get-Module -PSSession $session –ListAvailable
    # To import the specified PowerShell module to your computer:
        Import-Module -PSsession $session -Name SqlServer
    # Don’t forget to close the session when you finish:
        Remove-PSSession $session



# Version B
    # Connect to a remote computer using the Invoke-Command and import the PowerShell module you want:
        $session = New-PSSession -ComputerName $rmServer
        Invoke-Command {Import-Module SqlServer} -Session $session
    # Export module cmdlets from the remote session to the local module:
        Export-PSSession -Session $s -CommandName *-Sql* -OutputModule RemoteSQLServer -AllowClobber
    # The command creates a new RemoteSQLServer PowerShell module on your computer (in C:\Program Files\WindowsPowerShell\Modules). The cmdlet files themselves are not copied.
    # Close the session:
        Remove-PSSession $session

Import-Module RemoteSQLServer

# All SQL module cmdlets will be available without establishing an explicit connection to the remote computer. 
# Try to query the MS SQL database using the Invoke-Sqlcmd command. 
# All MSSQL commands are available until you close your PowerShell console or remove the module.
