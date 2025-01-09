    #region - ODBC
        <#
            Working with ODBC Connections in Powershell
             February 12, 2017  Anders Rødland  Powershell, SQL Server
            This post explains how to work with ODBC connections in Powershell. Powershell 4 introduced new cmdlets that make it very easy to create and manage ODBC connections. We use the .NET assembly system.data.odbc.odbcconnection to use ODBC connections present on the system to query the database.

            ODBC connections in Powershell 4.0 and higher
            Powershell 4 introduced these 4 cmdlets to create, manage and remove ODBC connections. If you for some reason still are on Powershell 3.0, I recommend you to upgrade to Powershell 5.0 which is the newest version at the time of this blog post. Managing ODBC connections in Powershell 3 or older is not fun and requires you to either modify registry or use an .exe file to manage them for you.

            Add-OdbcDsn
            Get-OdbcDsn
            Remove-OdbcDsn
            Set-OdbcDsn
            Add a new ODBC connection with Powershell

            Use the the cmdlet Add-OdbcDsn to create a new ODBC connection. The example code creates a new ODBC connection named MyPayroll.

            Add-OdbcDsn -Name "MyPayroll" -DriverName "SQL Server Native Client 10.0" -DsnType "System" -SetPropertyValue @("Server=MyServer", "Trusted_Connection=Yes", "Database=Payroll")
            Get an ODBC connection with Powershell

            Use the the cmdlet Get-OdbcDsn to get a Powershell object of an ODBC connection. The following code example returns an object containing the 32-bit ODBC configuration named MyPayroll.

            Get-OdbcDsn -Name "MyPayroll" -DsnType "System" -Platform "32-bit"
            Change properties on an ODBC conenction with Powershell

            Use the cmdlet Set-OdbcDsn to change the properties of an existing ODBC connection. The following code example change the ODBC connection named MyPayroll to use the database Payroll.

            Set-OdbcDsn -Name "MyPayroll" -DsnType "System" -SetPropertyValue "Database=Payroll"
 

            Testing an ODBC connection with Powershell
            This is the source code for the function Test-ODBCConnection which test if the ODBC connection can connect to the database. The function returns $true if a successful connection is made, and $false if it cannot connect. It will print an error message to the console if there is an error somewhere, like the ODBC connection do not exist.
        #>
        Function Test-ODBCConnection {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory=$True,
                            HelpMessage="DSN name of ODBC connection")]
                            [string]$DSN
            )
            $conn = new-object system.data.odbc.odbcconnection
            $conn.connectionstring = "(DSN=$DSN)"
    
            try {
                if (($conn.open()) -eq $true) {
                    $conn.Close()
                    $true
                }
                else {
                    $false
                }
            } catch {
                Write-Host $_.Exception.Message
                $false
            }
        }
        # You can download this script from Microsoft Technet Gallery: https://gallery.technet.microsoft.com/Test-ODBCConnection-522fefaf

        # Query ODBC connection to get data with Powershell
        function Get-ODBC-Data
        {
           param
           (
               [string]$query=$(throw 'query is required.'),
               [string]$dsn
           )
           $conn = New-Object System.Data.Odbc.OdbcConnection
           $conn.ConnectionString = "DSN=$dsn;"
           $conn.open()
           $cmd = New-object System.Data.Odbc.OdbcCommand($query,$conn)
           $ds = New-Object system.Data.DataSet
           $null = (New-Object system.Data.odbc.odbcDataAdapter($cmd)).fill($ds)
           $conn.close()
           $ds.Tables[0]
        }
 

        # Query ODBC connection to set data with Powershell
        function Set-ODBC-Data
        {
          param
          (
              [string]$query=$(throw 'query is required.'),
              [string]$dsn
          )
          $conn = New-Object System.Data.Odbc.OdbcConnection
          $conn.ConnectionString= "DSN=$dsn;"
          $cmd = new-object System.Data.Odbc.OdbcCommand($query,$conn)
          $conn.open()
          $cmd.ExecuteNonQuery()
          $conn.close()
        }
    #endregion
