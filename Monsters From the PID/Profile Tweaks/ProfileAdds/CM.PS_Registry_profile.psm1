Function New-RegDrive {
    Param ( $Hive = 'HKU' )
    Switch ($Hive){
        'HKU' { $Root = 'HKEY_USERS'}
        }
    If ([string]::IsNullOrEmpty($Root)){ Write-Warning 'Reg Root not found.'; Break }
    If ((Get-PSDrive -PSProvider Registry).Name -notcontains $Hive){
        New-PSDrive -PSProvider Registry -Name $Hive -Root $Root | Out-Null
        (Get-PSDrive -PSProvider Registry) | Select-Object Name,Root,CurrentLocation
        }
    } #New-RegDrive

Function Export-Registry {
    <#
        .Synopsis
            Export registry item properties.

        .Description
            Export item properties for a give registry key. The default is to write results to the pipeline
            but you can export to either a CSV or XML file. Use -NoBinary to omit any binary registry values.

        .Parameter Path
            The path to the registry key to export.

        .Parameter ExportType
            The type of export, either CSV or XML.

        .Parameter ExportPath
            The filename for the export file.

        .Parameter NoBinary
            Do not export any binary registry values

        .Example
        PS C:\> Export-Registry "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ExportType xml -exportpath c:\files\WinLogon.xml
    
        .Example
        PS C:\> "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MobileOptionPack","HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 10" | export-registry
  
        .Example
        PS C:\> dir hklm:\software\microsoft\windows\currentversion\uninstall | export-registry -ExportType Csv -ExportPath "C:\work\uninstall.csv" -NoBinary
    
        .Notes
        NAME: Export-Registry
        VERSION: 2.0
        AUTHOR: Jeffery Hicks
        LASTEDIT: 01/25/2011 10:18:33
    
        Learn more with a copy of Windows PowerShell 2.0: TFM (SAPIEN Press 2010)
    
        .Link
        Http://jdhitsolutions.com/blog
    
        .Link
        Get-ItemProperty
        Export-CSV
        Export-CliXML
    
        .Inputs
        [string[]]
        .Outputs
        [object]
    #>
    [cmdletBinding()]
    Param(
        [Parameter(Position=0,Mandatory=$True,
        HelpMessage="Enter a registry path using the PSDrive format.",
        ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [ValidateScript({(Test-Path $_) -AND ((Get-Item $_).PSProvider.Name -match "Registry")})]
        [Alias("PSPath")] [string[]]$Path,
        [Parameter()] [ValidateSet("csv","xml")] [string]$ExportType,
        [Parameter()] [string]$ExportPath,
        [switch]$NoBinary
        )
    Begin {
        Write-Verbose -Message "$(Get-Date) Starting $($myinvocation.mycommand)"
        #initialize an array to hold the results
        $data=@()
        } #Begin
    Process {
        #go through each pipelined path
        ForEach ($item in $path) {
            Write-Verbose "Getting $item"
            $regItem=Get-Item -Path $item
            #get property names
            $properties= $RegItem.Property
            Write-Verbose "Retrieved $(($properties | measure-object).count) properties"
            If (-not ($properties)){
                #no item properties were found so create a default entry
                $value=$Null
                $PropertyItem="(Default)"
                $RegType="String"
                #create a custom object for each entry and add it the temporary array
                $data+=New-Object -TypeName PSObject -Property @{
                    "Path"=$item
                    "Name"=$propertyItem
                    "Value"=$value
                    "Type"=$regType
                    "Computername"=$env:computername
                    }
                }       
            Else {
                #enumrate each property getting itsname,value and type
                ForEach ($property in $properties) {
                    Write-Verbose "Exporting $property"
                    $value=$regItem.GetValue($property,$null,"DoNotExpandEnvironmentNames")
                    #get the registry value type
                    $regType=$regItem.GetValueKind($property)
                    $PropertyItem=$property
                    #create a custom object for each entry and add it the temporary array
                    $data+=New-Object -TypeName PSObject -Property @{
                        "Path"=$item
                        "Name"=$propertyItem
                        "Value"=$value
                        "Type"=$regType
                        "Computername"=$env:computername
                        }
                    } #foreach
                } #else
            }#Foreach 
        } #Process
    End {
        #make sure we got something back
        if ($data) {
            #filter out binary if specified
            if ($NoBinary) {
                Write-Verbose "Removing binary values"
                $data=$data | Where-Object {$_.Type -ne "Binary"}
                }
            #export to a file both a type and path were specified
            If ($ExportType -AND $ExportPath) {
                Write-Verbose "Exporting $ExportType data to $ExportPath"
                Switch ($exportType) {
                    "csv" { $data | Export-CSV -Path $ExportPath -noTypeInformation }
                    "xml" { $data | Export-CLIXML -Path $ExportPath }
                    } #switch
                } #if $exportType
            ElseIf ( ($ExportType -AND (-not $ExportPath)) -OR ($ExportPath -AND (-not $ExportType)) )
                { Write-Warning "You forgot to specify both an export type and file." }
            Else  { $data } #write data to the pipeline  
            } #if $#data
        else {
            Write-Verbose "No data found"
            Write-Output "No data found"
            }
        #exit the function
        Write-Verbose -Message "$(Get-Date) Ending $($myinvocation.mycommand)"
        } #End
    } #Export-Registry

Function New-RegKey {
	<#
	.SYNOPSIS
	        Creates a new registry key on local or remote machines.

	.DESCRIPTION
	        Use New-RegKey to create a new registry key on local or remote machines.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key.  

	.PARAMETER Name
	        The name of the new key to create. 

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.
       		
	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		New-RegKey -ComputerName SERVER1,SERVER2 -Key $Key -Name NewSubKey -PassThru

		ComputerName Hive            Key                       SubKeyCount ValueCount
		------------ ----            ---                       ----------- ----------
		SERVER1      LocalMachine    SOFTWARE\MyCompany\New... 0           0		
		SERVER2      LocalMachine    SOFTWARE\MyCompany\New... 0           0		


		Description
		-----------
		The command creates new regitry key on two remote computers. 
		When PassThru is present the command returns the registry key custom object.
		
	.EXAMPLE
		Get-Content servers.txt | New-RegKey -Key $Key -Name NewSubKey -PassThru | Set-RegString -Value TestValue -Data TestData -Force -PassThru

		ComputerName Hive            Key                  Value       Data     Type
		------------ ----            ---                  -----       ----     ----
		SERVER1      LocalMachine    SOFTWARE\MyCompan... TestValue   TestData String
		SERVER2      LocalMachine    SOFTWARE\MyCompan... TestValue   TestData String
		SERVER3      LocalMachine    SOFTWARE\MyCompan... TestValue   TestData String


		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file. The names are piped into
		New-RegKey which creates the key in the remote computers. 
		The result of New-RegKey is piped into Set-RegString which creates a new String value under the new key and sets its data.

	.OUTPUTS
		PSFanatic.Registry.RegistryKey (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry
	.LINK
		Get-RegKey
		Remove-RegKey
		Test-RegKey

	#>
	[OutputType('PSFanatic.Registry.RegistryKey')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	Param ( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(Mandatory=$true,Position=3,ValueFromPipelineByPropertyName=$true)]
		[string]$Name,
		
		[switch]$Ping,
		[switch]$PassThru
	    ) 
	Process {
	    Write-Verbose "Enter process block..."
	    	
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				
				
				Write-Verbose "Creating new Key."
				$new = $subKey.CreateSubKey($Name)	

				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry key custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Key="$Key\$Name"
						Name=$Name
						SubKeyCount=$new.SubKeyCount
						ValueCount=$new.ValueCount						
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryKey')
					$pso				
				}					
					
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Test-RegKey {

	<#
	.SYNOPSIS
	        Determines if a registry key exists.

	.DESCRIPTION
	        Use Test-RegKey to determine if a registry key exists.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the registry key, if found. 
 
	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		Test-RegKey -ComputerName SERVER1 -Key $Key
		
		True


		Description
		-----------
		The command checks if the MyCompany key exists on SERVER1. 
		If the Value was found the result is True, else False.		
	
	.EXAMPLE
		Get-Content servers.txt | Test-RegValue -Key $Key -PassThru

		ComputerName Hive            Key                  Value              Data   Type
		------------ ----            ---                  -----              ----   ----
		SERVER1      LocalMachine    SOFTWARE\Microsof... PowerShellVersion  1.0    String
		SERVER2      LocalMachine    SOFTWARE\Microsof... PowerShellVersion  1.0    String
		SERVER3      LocalMachine    SOFTWARE\Microsof... PowerShellVersion  1.0    String

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file. The computer names are piped into
		Test-RegValue. If the Value was found and PassThru is specidied, the result is the registry value custom object.

	.OUTPUTS
		System.Boolean
		PSFanatic.Registry.RegistryValue (PSCustomObject)
		
	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegKey
		New-RegKey
		Remove-RegKey
	#>
	

	[OutputType('System.Boolean','PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,
	
		[switch]$Ping,
		
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)
				
				if($subKey)
				{		
					Write-Verbose "Registry sub key: $subKey has been found"					
					
					if($PassThru)
					{
						Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
						Write-Verbose "Create PSFanatic registry key custom object."

						$pso = New-Object PSObject -Property @{
							ComputerName=$c
							Hive=$Hive
							Key=$Key
							SubKeyCount=$subKey.SubKeyCount
							ValueCount=$subKey.ValueCount						
						}

						Write-Verbose "Adding format type name to custom object."
						$pso.PSTypeNames.Clear()
						$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryKey')
						$pso					
					}
					else
					{
						$true
					}
				}
				else
				{
					Write-Verbose "Registry sub key: $subKey cannot be found"
					$false
				}

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				#Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function New-RegSubKey {
    # Description: Create the registry key
    # Return Value: True/false respectively
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)][Alias("CN","__SERVER","IPAddress","server")] 
            [string[]]$ComputerName = (& HostName),	
        [string]$hive,
        [string]$keyName
        )
    $hives = [Enum]::GetNames([Microsoft.Win32.RegistryHive])
    If ($hives -notcontains $hive){ Write-Error "Invalid hive value"; Return }
    $regHive = [Microsoft.Win32.RegistryHive]$hive;
    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($regHive,$server);
    [void]$regKey.CreateSubKey($keyName);
    If ($?){ $true } Else { $false }
    }

Function Test-RegSubKey {
    # Description: Test the existence of the registry key
    # Return Value: True/false respectively
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)][Alias("CN","__SERVER","IPAddress","server")] 
            [string[]]$ComputerName = (& HostName),	
        [string]$hive,
        [string]$keyName
        )
    $hives = [enum]::getnames([Microsoft.Win32.RegistryHive])
    If ($hives -notcontains $hive){ Throw "Invalid hive value" }
    $regHive = [Microsoft.Win32.RegistryHive]$hive
    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($regHive,$server)
    $subKey = $regKey.OpenSubKey($keyName);
    If (!$subKey){ Return $false } Else { Return $true }
    # Test-RegSubKey -Hive 'LocalMachine' -keyName 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    }

Function Test-RegValue {
    <#
        Description:
            Test the existence of the registry value or key
        Return Value:
            True/false respectively
    #>
    Param (
        [Parameter(Position=0,ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)][Alias("CN","__SERVER","IPAddress","server")] 
            [string[]]$ComputerName = (& HostName),	
        [string]$valueName,
        [string]$hive,
        [string]$Type,
        [string]$key
        )
    $ErrorActionPreference = 'Stop'
    Try { $test = Get-RegValue -ValueName $valueName -Hive $hive -Type $Type -Key $key } Catch { $test = $null }
    If (!($test.Value -eq $valueName)){$false} Else {$true}
    # Test-RegValue -ValueName "LocalAccountTokenFilterPolicy" -Hive 'LocalMachine' -Type DWord -Key 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    }

Function Get-RegMultiString {

	<#
	.SYNOPSIS
	        Retrieves an array of null-terminated strings (REG_MULTI_SZ) from local or remote computers.

	.DESCRIPTION
	        Use Get-RegMultiString to retrieve an array of null-terminated strings (REG_MULTI_SZ) from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.


	.EXAMPLE	
		$Key = "SYSTEM\CurrentControlSet\services\LanmanServer\Shares"
		Get-RegMultiString -Key $Key -Value Drivers

		ComputerName Hive         Key                                                   Value   Data
		------------ ----         ---                                                   -----   ----
		COMPUTER1    LocalMachine SYSTEM\CurrentControlSet\services\LanmanServer\Shares Drivers {CSCFlags=0, MaxUses=429496729...


		Description
		-----------
		The command gets the flags of the Drivers system shared folder from the local computer.
		The name of ComputerName parameter, which is optional, is omitted.		
		
	.EXAMPLE	
		"DC1","DC2" | Get-RegString -Key $Key -Value Sysvol -Ping
		
		ComputerName Hive         Key                                                   Value  Data
		------------ ----         ---                                                   -----  ----
		DC1          LocalMachine SYSTEM\CurrentControlSet\services\LanmanServer\Shares Sysvol {CSCFlags=256, MaxUses=429496...
		DC2          LocalMachine SYSTEM\CurrentControlSet\services\LanmanServer\Shares Sysvol {CSCFlags=256, MaxUses=429496...

		Description
		-----------
		The command gets the flags of the Sysvol system shared folder from two DC computers. 
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Get-RegString -Key $Key -Value Sysvol
		
		ComputerName Hive         Key                                                   Value  Data
		------------ ----         ---                                                   -----  ----
		DC1          LocalMachine SYSTEM\CurrentControlSet\services\LanmanServer\Shares Sysvol {CSCFlags=256, MaxUses=429496...
		DC2          LocalMachine SYSTEM\CurrentControlSet\services\LanmanServer\Shares Sysvol {CSCFlags=256, MaxUses=429496...

		Description
		-----------
		The command uses the Get-Content cmdlet to get the DC names from a text file.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegMultiString
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	

	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",

		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$Ping
	) 
	

	process
	{
 	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)	
		
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)	
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				
				
				Write-Verbose "Get value name : [$Value]"
				$rv = $subKey.GetValue($Value,-1)
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					Write-Verbose "Create PSFanatic registry value custom object."
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegMultiString {

	<#
	.SYNOPSIS
	        Sets or creates an array of null-terminated strings (REG_MULTI_SZ) on local or remote computers.

	.DESCRIPTION
	        Use Set-RegMultiString to set or create an array of null-terminated strings (REG_MULTI_SZ) on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
	        The data to set the registry value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.
	       		
	.EXAMPLE	  
		$Key = "SOFTWARE\MyCompany"
		Set-RegMultiString -Key $Key -Value MultiString -Data @("Power","Shell","Rocks!")	
		
		Description
		-----------
		The command sets or creates a multiple string registry value MultiString on the local computer MyCompany key.
		The name of ComputerName parameter, which is optional, is omitted. 		
		
	.EXAMPLE	
		"SERVER1","SERVER1","SERVER3" | Set-RegMultiString -Key $Key -Value MultiString -Data @("Power","Shell","Rocks!") -Ping		
		
		Description
		-----------
		The command sets or creates a multiple string registry value MultiString on three remote computers.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Set-RegMultiString -Key $Key -Value MultiString -Data -Force -PassThru

		ComputerName Hive         Key                Value       Data                   Type
		------------ ----         ---                -----       ----                   ----
		SERVER1      LocalMachine SOFTWARE\MyCompany MultiString {Power, Shell, Rocks!} MultiString
		SERVER2      LocalMachine SOFTWARE\MyCompany MultiString {Power, Shell, Rocks!} MultiString
		SERVER3      LocalMachine SOFTWARE\MyCompany MultiString {Power, Shell, Rocks!} MultiString

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file. 
		It Sets or Creates a registry MultiString value named MultiString on three remote computers.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.	

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegMultiString
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(Mandatory=$true,Position=4)]		
		[string[]]$Data,
		
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Multiple String value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::MultiString)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$subKey.GetValue($Value)
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}				
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegQWord {

	<#
	.SYNOPSIS
	        Retrieves a 64-bit binary number registry value (REG_QWORD) from local or remote computers.

	.DESCRIPTION
	        Use Get-RegQWord to retrieve a 64-bit binary number registry value (REG_QWORD) from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER AsHex
	        Returnes the value in HEX notation.
	       
	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.
			
	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		Get-RegQWord -ComputerName SERVER1 -Hive LocalMachine -Key $Key -Value SystemLastStartTime

		ComputerName Hive            Key                  Value                Data                Type
		------------ ----            ---                  -----                ----                ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime  129057765227436584  QWord


		Description
		-----------
	   	The command gets the SystemLastStartTime value from SERVER1 server.	   
	   
	.EXAMPLE	   
		Get-RegQWord -ComputerName SERVER1 -Key $Key -Value QWordValue

		ComputerName Hive            Key                  Value                Data                Type
		------------ ----            ---                  -----                ----                ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime  129057765227436584  QWord


		Description
		-----------
	   	The command gets the SystemLastStartTime value from SERVER1 server. 
	   	You can omit the -Hive parameter (which is optional), if the registry Hive the key resides in is LocalMachine (HKEY_LOCAL_MACHINE).

	.EXAMPLE
		Get-RegQWord -CN SERVER1,SERVER2 -Key $Key -Value QWordValue -AsHex

		ComputerName Hive            Key                  Value                Data               Type
		------------ ----            ---                  -----                ----               ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime  0x1ca815a8be31a28  QWord
		SERVER2      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime  0x1ca815a8be31a28  QWord


		Description
		-----------
	   	This command gets the SystemLastStartTime value from SERVER1 and SERVER2.
	   	The command uses the ComputerName parameter alias 'CN' to specify a collection of computer names. 
	   	When the AsHex Switch Parameter is used, the value's data returnes in HEX notation.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry
	
	.LINK
		Set-RegQWord
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$AsHex,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				
				
				Write-Verbose "Get value name : [$Value]"
				$rv = $subKey.GetValue($Value,-1)
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					if($AsHex)
					{
						Write-Verbose "Parameter [AsHex] is present, return value as HEX."
						$rv = "0x{0:x}" -f $rv
					}
					else
					{
						Write-Verbose "Parameter [AsHex] is not present, return value as INT."
					}


					Write-Verbose "Create PSFanatic registry value custom object."
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso
				}

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegQWord {

	<#
	.SYNOPSIS
	   	Sets or creates a 64-bit binary number (REG_QWORD) on local or remote computers.

	.DESCRIPTION
	        Use Set-RegQWord to set or create a 64-bit binary number (REG_QWORD) on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
	        The data to set the registry value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.
	       		
	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		Set-RegQWord -Key $Key -Value SystemLastStartTime -Data (Get-Date).Ticks

		ComputerName Hive            Key                  Value                     Data                 Type
		------------ ----            ---                  -----                     ----                 ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime       633981970786684203   QWord

		
		Description
		-----------
		The command sets the registry SystemLastStartTime QWord value on the local computer.		
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE
		Get-RegQWord -ComputerName "SERVER1","SERVER1","SERVER3" -Key $Key -Value SystemLastStartTime -Ping | Where-Object {$_.Data -eq 129057765227436584} | Set-RegQWord -Data (Get-Date).Ticks -Force -PassThru
				
		ComputerName Hive            Key                  Value                     Data                 Type
		------------ ----            ---                  -----                     ----                 ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime       633981970786684203   QWord
		SERVER2      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime       633981970786684203   QWord
		SERVER3      LocalMachine    SOFTWARE\MyCompany   SystemLastStartTime       633981970786684203   QWord

				
		Description
		-----------
		The command gets the registry SystemLastStartTime QWord value from three remote computers. 
		The result is piped to the Where-Object cmdlet and filters those who don not meet the Where-Object criteria.
		The Results of Where-Object are piped to Set-RegQWord which sets the SystemLastStartTime value to the current date time ticks (Int64).
		
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.				

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry
	
	.LINK
		Get-RegQWord
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(
			Mandatory=$true,
			Position=4,
			HelpMessage="The data to set the registry value."
		)]
		[string]$Data,
		
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		

				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry QWord Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::QWord)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$subKey.GetValue($Value)
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegString{

	<#
	.SYNOPSIS
		Retrieves a registry string (REG_SZ) value from local or remote computers.

	.DESCRIPTION
		Use Get-RegString to retrieve a registry string (REG_SZ) value from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
		The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.
	       
	.EXAMPLE	  
		Get-RegString -Hive LocalMachine -Key SOFTWARE\Microsoft\DataAccess -Value FullInstallVer

		ComputerName Hive         Key                           Value          Data           Type
		------------ ----         ---                           -----          ----           ----
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 6.1.7600.16385 String
		
		
		Description
		-----------
		The command gets the installed version of Microsoft Data Access Components (MDAC) from the local computer.
		The name of ComputerName parameter, which is optional, is omitted.		
		
	.EXAMPLE	
		"SERVER1","SERVER2","SERVER3" | Get-RegString -Key SOFTWARE\Microsoft\DataAccess -Value FullInstallVer -Ping
		
		ComputerName Hive         Key                           Value          Data        Type
		------------ ----         ---                           -----          ----        ----
		SERVER1      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.3959.0 String
		SERVER2      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.3959.0 String
		SERVER3      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.1830.0 String

		Description
		-----------
		The command gets the installed version of Microsoft Data Access Components (MDAC) from remote computers. 
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Get-RegString -Key SOFTWARE\Microsoft\DataAccess -Value FullInstallVer
		
		ComputerName Hive         Key                           Value          Data        Type
		------------ ----         ---                           -----          ----        ----
		SERVER1      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.3959.0 String
		SERVER2      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.3959.0 String
		SERVER3      LocalMachine SOFTWARE\Microsoft\DataAccess FullInstallVer 2.82.1830.0 String

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file.

	.EXAMPLE	
		Get-RegString -Hive LocalMachine -Key SOFTWARE\Microsoft\DataAccess -Value FullInstallVer | Test-RegValue -ComputerName SERVER1,SERVER2 -Ping
		True
		True

		Description
		-----------
		This command gets the installed version of Microsoft Data Access Components (MDAC) from the local computer.
		The output is piped to the Test-RegValue Function to check if the value exists on two remote computers.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.		

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegString
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
	    	
	    	
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				
				
				Write-Verbose "Get value name : [$Value]"
				$rv = $subKey.GetValue($Value,-1)
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegString {

	<#
	.SYNOPSIS
	        Sets or creates a string (REG_SZ) registry value on local or remote computers.

	.DESCRIPTION
	        Use Set-RegString to set or create registry string (REG_SZ) value on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
	        The data to set the registry value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.	       		

	.EXAMPLE	  
		$Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
		Set-RegString -Key $Key -Value Notepad -Data "notepad.exe"		
		
		Description
		-----------
		The command Sets or Creates a registry value named Notepad on the local computer RunOnce key.
		The name of ComputerName parameter, which is optional, is omitted. 		
		
	.EXAMPLE	
		"SERVER1","SERVER1","SERVER3" | Set-RegString -Key $Key -Value Notepad -Data "notepad.exe" -Ping		
		
		Description
		-----------
		The command sets or creates a registry value named Notepad on three remote computers local computer's RunOnce key.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Set-RegString -Key $Key -Value Notepad -Data "notepad.exe" -Force -PassThru

		ComputerName Hive         Key                                           Value   Data        Type
		------------ ----         ---                                           -----   ----        ----
		SERVER1      LocalMachine SOFTWARE\Microsoft\Windows\CurrentVersion\Run Notepad notepad.exe String
		SERVER2      LocalMachine SOFTWARE\Microsoft\Windows\CurrentVersion\Run Notepad notepad.exe String
		SERVER3      LocalMachine SOFTWARE\Microsoft\Windows\CurrentVersion\Run Notepad notepad.exe String

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file. 
		It Sets or Creates a registry String value named Notepad on three remote computers.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.				
		
	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegString
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",

		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(
			Mandatory=$true,
			Position=4,
			HelpMessage="The data to set the registry value."
		)]
		[string]$Data,
		
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
 	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)	

				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry String Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::String)
				}	
				
				
				if($PassThru)
				{					
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$subKey.GetValue($Value)
						Type=$subKey.GetValueKind($Value)
					}

					
					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}				
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Remove-RegKey {
	<#
	.SYNOPSIS
	        Deletes the specified registry key from local or remote computers.

	.DESCRIPTION
	        Use Remove-RegKey to delete the specified registry key from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	    .PARAMETER Recurse
	        Deletes the specified subkey and any child subkeys recursively.

	.EXAMPLE
		$Key= "SOFTWARE\MyCompany\NewSubKey"
		Test-RegKey -Key $Key -ComputerName SERVER1,SERVER2 -PassThru | Remove-RegKey -Force
		
		Description
		-----------
		The command checks if the NewSubKey key exists on SERVER1 and SERVER2. When using the PassThru parameter, each key, if found, it emitted to the pipeline.
		Each key found that is piped into Remove-RegKey is deleted whether it it empty or has any subkeys or values.		

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
	
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegKey
		New-RegKey
		Test-RegKey
		
	#>
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
	Param ( 
		[Parameter( Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer." )]		
		[Alias("CN","__SERVER","IPAddress")] [string[]]$ComputerName="",		
		[Parameter( Position=1, ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'." )]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		[Parameter( Mandatory=$true, Position=2, ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to remove." )]
		[string]$Key,
		[switch]$Ping,
		[switch]$Force,
		[switch]$Recurse
	    ) 
    Process {
        Write-Verbose "Enter process block..."
		ForEach($c in $ComputerName) {	
		    Try {				
				if ($c -eq "") {
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
                    }
				if ($Ping) {
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					if ( !(Test-Connection -ComputerName $c -Count 1 -Quiet)) {
						Write-Warning "[$c] doesn't respond to ping."
						return
					    }
				    }
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				if ($Force -or $PSCmdlet.ShouldProcess($c,"Remove Registry Key '$Hive\$Key'")) {		
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					if ($Recurse) {
						Write-Verbose "Parameter [Recurse] is present, deleting key and sub items."
						$reg.DeleteSubKeyTree($Key)
					    }
					else {
						Write-Verbose "Parameter [Recurse] is not present, deleting key."
						$reg.DeleteSubKey($Key,$True)
					    }
				    }			
				Write-Verbose "Closing remote registry connection on: [$c]."
				$reg.close()
			    }
		    Catch { Write-Error $_ }
		    } 
		Write-Verbose "Exit process block..."
	    }
    } #Remove-RegKey

Function Remove-RegValue {

	<#
	.SYNOPSIS
	        Deletes the specified registry value from local or remote computers.

	.DESCRIPTION
	        Use Remove-RegValue to delete the specified registry value from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value to delete.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.
	       		
	.EXAMPLE
		$Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
		Test-RegValue -Key $Key -Value NoDriveTypeAutorun -ComputerName SERVER1,SERVER2 -PassThru | Remove-RegValue -Force
		
		Description
		-----------
		The command checks if the NoDriveTypeAutorun key value on SERVER1 and SERVER2. When using the PassThru parameter, each value, if found, it emitted to the pipeline.
		Each value found that is piped into Remove-RegValue is deleted without any confirmations.		

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegValue
		Test-RegValue
	#>
	
	
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,
		
		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to remove."
		)]
		[string]$Value,
		
		[switch]$Force,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				
				
				if($Force -or $PSCmdlet.ShouldProcess($c,"Remove Registry Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.DeleteValue($Value,$true)
				}			
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$reg.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegKey {

	<#
	.SYNOPSIS
	        Gets the registry keys on local or remote computers.

	.DESCRIPTION
	        Use Get-RegKey to get registry keys on local or remote computers
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Name
	        The name of the registry key, Wildcards are permitted.
		
	.PARAMETER Recurse
	   	Gets the registry values of the specified registry key and its sub keys.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.
      		
	.EXAMPLE	   
		Get-RegKey -Key SOFTWARE\Microsoft\PowerShell\1 -Name p* 

		ComputerName Hive         Key                                                      SubKeyCount ValueCount
		------------ ----         ---                                                      ----------- ----------
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine         0           6
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns        5           0
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PSConfigurationProviders 1           0

	   	
	   	Description
	   	-----------
	   	Gets all keys from the PowerShell subkey on the local computer with names starts with the letter 'p'.

	.EXAMPLE
		Get-RegKey -Key SOFTWARE\Microsoft\PowerShell\1 -Name p* -Recurse

		ComputerName Hive         Key                                                            SubKeyCount ValueCount
		------------ ----         ---                                                            ----------- ----------
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine               0           6
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns              5           0
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns\PowerGUI_Pro 0           7
		COMPUTER1    LocalMachine SOFTWARE\Microsoft\PowerShell\1\PSConfigurationProviders       1           0

	   	Description
	   	-----------
	   	Gets all keys and subkeys from the PowerShell subkey on the local computer with names starts with the letter 'p'.

	.EXAMPLE
		Get-RegKey -ComputerName SERVER1 -Key SOFTWARE\Microsoft\PowerShell\1 -Name p* | Get-RegValue

		ComputerName Hive            Key                  Value                     Data                 Type
		------------ ----            ---                  -----                     ----                 ----
		SERVER1      LocalMachine    SOFTWARE\Microsof... ApplicationBase           C:\Windows\System... String
		SERVER1      LocalMachine    SOFTWARE\Microsof... PSCompatibleVersion       1.0, 2.0             String
		SERVER1      LocalMachine    SOFTWARE\Microsof... RuntimeVersion            v2.0.50727           String
		SERVER1      LocalMachine    SOFTWARE\Microsof... ConsoleHostAssemblyName   Microsoft.PowerSh... String
		SERVER1      LocalMachine    SOFTWARE\Microsof... ConsoleHostModuleName     C:\Windows\System... String
		SERVER1      LocalMachine    SOFTWARE\Microsof... PowerShellVersion         2.0                  String

	   	Description
	   	-----------
	   	Gets all keys and subkeys from the PowerShell subkey on the remote server SERVER1 with names starts with the letter 'p'.
	   	Pipe the results to Get-RegValue to get all value types under these keys.

	.OUTPUTS
		PSFanatic.Registry.RegistryKey (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		New-RegKey
		Remove-RegKey
		Test-RegKey

	#>
		

	[OutputType('PSFanatic.Registry.RegistryKey')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		

		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",

		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,
		
		[Parameter(
			Mandatory=$false,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]	
		[string]$Name="*",		
	
		[switch]$Ping,
		
		[switch]$Recurse
	) 

	begin
	{
		Write-Verbose "Enter begin block..."
	
		Function Recurse($Key){
		
			Write-Verbose "Start recursing, key is [$Key]"

			try
			{
			
				$subKey = $reg.OpenSubKey($key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				
			
				foreach ($k in $subKey.GetSubKeyNames())
				{							
					if($k -like $Name)
					{
						$child = $subKey.OpenSubKey($k)
						$pso = New-Object PSObject -Property @{
							ComputerName=$c
							Hive=$Hive
							Key="$Key\$k"								
							ValueCount=$child.ValueCount
							SubKeyCount=$child.SubKeyCount
						}

						Write-Verbose "Recurse: Adding format type name to custom object."
						$pso.PSTypeNames.Clear()
						$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryKey')
						$pso
					}
						
					Recurse "$Key\$k"		
				}
				
			}
			catch
			{
				Write-Error $_
			}
			
			Write-Verbose "Ending recurse, key is [$Key]"
		}
		
		Write-Verbose "Exit begin block..."
	}
	

	process
	{


	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}
				
				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
	
								
				if($Recurse)
				{
					Write-Verbose "Parameter [Recurse] is present, calling Recurse Function."
					Recurse $Key
				}
				else
				{					
				
					Write-Verbose "Open remote subkey: [$Key]."			
					$subKey = $reg.OpenSubKey($Key)
					
					if(!$subKey)
					{
						Throw "Key '$Key' doesn't exist."
					}
					
					Write-Verbose "Start get remote subkey: [$Key] keys."
					foreach ($k in $subKey.GetSubKeyNames())
					{
						if($k -like $Name)
						{						
							$child = $subKey.OpenSubKey($k)
							$pso = New-Object PSObject -Property @{
								ComputerName=$c
								Hive=$Hive
								Key="$Key\$k"								
								ValueCount=$child.ValueCount
								SubKeyCount=$child.SubKeyCount
							}

							Write-Verbose "Recurse: Adding format type name to custom object."
							$pso.PSTypeNames.Clear()
							$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryKey')
							$pso
						}
					}				
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$reg.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
	
		Write-Verbose "Exit process block..."
	}
}

Function Global:Get-RegValue{

	<#
	.SYNOPSIS
	        Sets the default value (REG_SZ) of the registry key on local or remote computers.

	.DESCRIPTION
	        Use Get-RegValue to set the default value (REG_SZ) of the registry key on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value, Wildcards are permitted.

	    .PARAMETER Type

	   	A collection of data types of registry values, from the RegistryValueKind enumeration.
	   	Possible values:

		- Binary
		- DWord
		- ExpandString
		- MultiString
		- QWord
		- String
		
		When the parameter is not specified all types are returned, Wildcards are permitted.
		
	    .PARAMETER Recurse
	   	Gets the registry values of the specified registry key and its sub keys.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.
       		
	.EXAMPLE	   
		Get-RegValue -Key SOFTWARE\Microsoft\PowerShell\1 -Recurse

		ComputerName Hive            Key                  Value                     Data                 Type
		------------ ----            ---                  -----                     ----                 ----
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... Install                   1                    DWord
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... PID                       89383-100-0001260... String
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... Install                   1                    DWord
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... ApplicationBase           C:\Windows\System... String
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... PSCompatibleVersion       1.0, 2.0             String
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... RuntimeVersion            v2.0.50727           String
		(...)
		
		
		Description
		-----------
		Gets all values of the PowerShell subkey on the local computer regardless of their type.		

	.EXAMPLE
		"SERVER1" | Get-RegValue -Key SOFTWARE\Microsoft\PowerShell\1 -Type String,DWord -Recurse -Ping

		ComputerName Hive            Key                  Value                     Data                 Type
		------------ ----            ---                  -----                     ----                 ----
		SERVER1      LocalMachine    SOFTWARE\Microsof... Install                   1                    DWord
		SERVER1      LocalMachine    SOFTWARE\Microsof... PID                       89383-100-0001260... String
		SERVER1      LocalMachine    SOFTWARE\Microsof... Install                   1                    DWord
		SERVER1      LocalMachine    SOFTWARE\Microsof... ApplicationBase           C:\Windows\System... String
		SERVER1      LocalMachine    SOFTWARE\Microsof... PSCompatibleVersion       1.0, 2.0             String
		(...)
	
		Description
		-----------
		Gets all String and DWord values of the PowerShell subkey and its subkeys from remote computer SERVER1, ping the remote server first.				

	.EXAMPLE
		Get-RegValue -ComputerName SERVER1 -Key SOFTWARE\Microsoft\PowerShell -Type MultiString -Value t* -Recurse

		ComputerName Hive            Key                  Value  Data                 Type
		------------ ----            ---                  -----  ----                 ----
		SERVER1      LocalMachine    SOFTWARE\Microsof... Types  {virtualmachinema... MultiString
		SERVER1      LocalMachine    SOFTWARE\Microsof... Types  {C:\Program Files... MultiString

		Description
		-----------
		Gets all MultiString value names, from the subkey and its subkeys, that starts with the 't' letter from remote computer SERVER1.				

	.OUTPUTS
		System.Boolean
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
	
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegValue
		Test-RegValue
		Remove-RegValue	

	#>	
	

	[OutputType('System.Boolean','PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		

		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",

		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,
		
		[Parameter(
			Mandatory=$false,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]	
		[string]$Value="*",		

		[Parameter(
			Mandatory=$false,
			Position=4,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The data type of the registry value."
		)]
		[ValidateSet("String","ExpandString","Binary","DWord","MultiString","QWord")]
		[string[]]$Type="*",
		
		[switch]$Ping,
		
		[switch]$Recurse
	) 

	begin
	{
		Write-Verbose "Enter begin block..."
	
		Function Recurse($Key){
		
			Write-Verbose "Start recursing, key is [$Key]"

			try
			{
			
				$subKey = $reg.OpenSubKey($key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				

				foreach ($v in $subKey.GetValueNames())
				{
					$vk = $subKey.GetValueKind($v)
					
					foreach($t in $Type)
					{	
						if($v -like $Value -AND $vk -like $t)
						{						
							$pso = New-Object PSObject -Property @{
								ComputerName=$c
								Hive=$Hive
								Value=if(!$v) {"(Default)"} else {$v}
								Key=$Key
								Data=$subKey.GetValue($v)
								Type=$vk
							}

							Write-Verbose "Recurse: Adding format type name to custom object."
							$pso.PSTypeNames.Clear()
							$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
							$pso
						}
					}
				}
				
				foreach ($k in $subKey.GetSubKeyNames())
				{
					Recurse "$Key\$k"		
				}
				
			}
			catch
			{
				Write-Error $_
			}
			
			Write-Verbose "Ending recurse, key is [$Key]"
		}
		
		Write-Verbose "Exit begin block..."
	}
	

	process
	{


	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}
				
				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
	
								
				if($Recurse)
				{
					Write-Verbose "Parameter [Recurse] is present, calling Recurse Function."
					Recurse $Key
				}
				else
				{					
				
					Write-Verbose "Open remote subkey: [$Key]."			
					$subKey = $reg.OpenSubKey($Key)
					
					if(!$subKey)
					{
						Throw "Key '$Key' doesn't exist."
					}
					
					Write-Verbose "Start get remote subkey: [$Key] values."
					foreach ($v in $subKey.GetValueNames())
					{						
						$vk = $subKey.GetValueKind($v)
						
						foreach($t in $Type)
						{					
							if($v -like $Value -AND $vk -like $t)
							{														
								$pso = New-Object PSObject -Property @{
									ComputerName=$c
									Hive=$Hive
									Value= if(!$v) {"(Default)"} else {$v}
									Key=$Key
									Data=$subKey.GetValue($v)
									Type=$vk
								}

								Write-Verbose "Adding format type name to custom object."
								$pso.PSTypeNames.Clear()
								$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
								$pso
							}
						}
					}				
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$reg.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
	
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegValueKind {
    # Description: Get the registry value type (e.g, string,dword etc)
    # Return Value: None
    Param(
        [Parameter(Position=0,ValueFromPipeline=$true, 
            ValueFromPipelineByPropertyName=$true)][Alias("CN","__SERVER","IPAddress","server")] 
            [string[]]$ComputerName = (& HostName),	
        [string]$hive = 'LocalMachine',
        [string]$keyName,
        [string]$valueName
        )
    $hives = [enum]::getnames([Microsoft.Win32.RegistryHive])
    If ($hives -notcontains $hive){ Throw "Invalid hive value"; Return }
    $regHive = [Microsoft.Win32.RegistryHive]$hive;
    $regKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($regHive,$server);
    $subKey = $regKey.OpenSubKey($keyName);
    If (!$subKey){ Throw "The specified registry key does not exist."; Return }
    $regVal=$subKey.GetValueKind($valueName);
    If (!$regVal){ Throw "The specified registry value does not exist."; Return }
    Else { $regVal }
    # Get-RegValueKind -ValueName "LocalAccountTokenFilterPolicy" -Hive 'LocalMachine' -keyName 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    }

Function Get-RegExpandString{

	<#
	.SYNOPSIS
	        Retrieves a null-terminated string that contains unexpanded references to environment variables (REG_EXPAND_SZ) from local or remote computers.

	.DESCRIPTION
	        Use Get-RegExpandString to retrieve a null-terminated string that contains unexpanded references to environment variables (REG_EXPAND_SZ) from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER ExpandEnvironmentNames
	        Expands values containing references to environment variables using data from the local environment.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.EXAMPLE
		$Key = "SOFTWARE\Microsoft\Windows\CurrentVersion"
		Get-RegExpandString -Key $Key -Value ProgramFilesPath

		ComputerName Hive            Key                  Value             Data            Type
		------------ ----            ---                  -----             ----            ----
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... ProgramFilesPath  %ProgramFiles%  ExpandString
		

		Description
		-----------
		The command gets the registry ProgramFilesPath ExpandString value from the local computer. 
		The returned value contains unexpanded references to environment variables.
		
	.EXAMPLE
		Get-RegExpandString -Key $Key -Value ProgramFilesPath -ComputerName SERVER1,SERVER2,SERVER3 -ExpandEnvironmentNames -Ping

		ComputerName Hive            Key                  Value             Data              Type
		------------ ----            ---                  -----             ----              ----
		SERVER1      LocalMachine    SOFTWARE\Microsof... ProgramFilesPath  C:\Program Files  ExpandString
		SERVER2      LocalMachine    SOFTWARE\Microsof... ProgramFilesPath  C:\Program Files  ExpandString
		SERVER3      LocalMachine    SOFTWARE\Microsof... ProgramFilesPath  C:\Program Files  ExpandString
		
		
		Description
		-----------
		The command gets the registry ProgramFilesPath ExpandString value from three remote computers. 
		When the ExpandEnvironmentNames Switch parameter is used, the data of the value is expnaded based on the environment variables data from the local environment.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegExpandString
		Get-RegValue
		Remove-RegValue
		Test-RegValue

	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$ExpandEnvironmentNames,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)	

				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				
				if($ExpandEnvironmentNames)
				{
					Write-Verbose "Parameter [ExpandEnvironmentNames] is present, expanding value of environamnt strings."
					Write-Verbose "Get value name : [$Value]"
					$rv = $subKey.GetValue($Value,-1)
				}
				else
				{
					Write-Verbose "Parameter [ExpandEnvironmentNames] is not present, environamnt strings are not expanded."
					Write-Verbose "Get value name : [$Value]"
					$rv = $subKey.GetValue($Value,-1,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
				}
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					Write-Verbose "Create PSFanatic registry value custom object."
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso
				}

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegExpandString{

	<#
	.SYNOPSIS
		Sets or creates a string (REG_EXPAND_SZ) registry value on local or remote computers.

	.DESCRIPTION
		Use Set-RegExpandString to set or create registry string (REG_EXPAND_SZ) value on local or remote computers.
	       
	.PARAMETER ComputerName
		An array of computer names. The default is the local computer.

	.PARAMETER Hive
		The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
		Possible values:

		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
		The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
		The data to set the registry value.

	.PARAMETER ExpandEnvironmentNames
		Expands values (from the local environment) containing references to environment variables.

	.PARAMETER Force
		Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
		Use ping to test if the machine is available before connecting to it. 
		If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
		Passes the newly custom object to the pipeline. By default, this Function does not generate any output.


	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		Set-RegExpandString -ComputerName SERVER1,SERVER2,SERVER3 -Key $Key -Value SystemDir -Data %WinDir%\System32 -Force -PassThru -ExpandEnvironmentNames

		ComputerName Hive            Key                  Value      Data                 Type
		------------ ----            ---                  -----      ----                 ----
		COMPUTER1    LocalMachine    SOFTWARE\MyCompany   SystemDir  C:\Windows\System32  ExpandString
		
		
		Description
		-----------
		The command sets the registry SystemDir ExpandString value on three remote servers.
		The returned value contains an expanded value based on local environment variables.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.	

	.EXAMPLE
		"SERVER1","SERVER2","SERVER3" | Set-RegExpandString -Key $Key -Value SystemDir -Data %WinDir%\System32 -Ping -Force -PassThru

		ComputerName Hive            Key                  Value      Data              Type
		------------ ----            ---                  -----      ----              ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   SystemDir  %WinDir%\System32 ExpandString
		SERVER2      LocalMachine    SOFTWARE\MyCompany   SystemDir  %WinDir%\System32 ExpandString
		SERVER3      LocalMachine    SOFTWARE\MyCompany   SystemDir  %WinDir%\System32 ExpandString


		Description
		-----------
		The command sets the registry SystemDir ExpandString value on three remote servers.
		The returned value is not expanded.
		
	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry
	
	.LINK
		Get-RegExpandString
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateScript({ [Enum]::GetNames([Microsoft.Win32.RegistryHive]) -contains $_	})]
		[string]$Hive="LocalMachine",

		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(
			Mandatory=$true,
			Position=4,
			HelpMessage="The data to set the registry value."
		)]
		[string]$Data,
		
		[switch]$ExpandEnvironmentNames,
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)				
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				
				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry Expand String Value '$Hive\$Key\$Value'"))
				{
					Write-Verbose "Parameter [ExpandEnvironmentNames] is present, expanding value of environamnt strings."
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::ExpandString)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					if($ExpandEnvironmentNames){
						Write-Verbose "Parameter [ExpandEnvironmentNames] is present, expanding value of environamnt strings."
						$d = $subKey.GetValue($Value,$Data)
					}
					else
					{
						$d = $subKey.GetValue($Value,$Data,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
					}
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value					
						Key=$Key
						Data=$d
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegDWord{

	<#
	.SYNOPSIS
	        Retrieves a 32-bit binary number (REG_DWORD) registry value from local or remote computers.

	.DESCRIPTION
	        Use Get-RegDWord to retrieve a 32-bit binary number (REG_DWORD) registry value from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER AsHex
	        Returnes the value in HEX notation.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.EXAMPLE
		$Key = "System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
		Get-RegDWord -ComputerName SERVER1 -Hive LocalMachine -Key $Key -Value PortNumber

		ComputerName Hive            Key                  Value       Data  Type
		------------ ----            ---                  -----       ----  ----
		SERVER1      LocalMachine    System\CurrentCon... PortNumber  3389  DWord


		Description
		-----------
	   	The command gets the Terminal Server's listening port from SERVER1 server.	   
	   
	.EXAMPLE	   
		Get-RegDWord -ComputerName SERVER1 -Key $Key -Value PortNumber

		ComputerName Hive            Key                  Value       Data  Type
		------------ ----            ---                  -----       ----  ----
		SERVER1      LocalMachine    System\CurrentCon... PortNumber  3389  DWord


		Description
		-----------
	   	The command gets the Terminal Server's listening port from SERVER1 server. 
	   	You can omit the -Hive parameter (which is optional), if the registry Hive the key resides in is LocalMachine (HKEY_LOCAL_MACHINE).

	.EXAMPLE
		Get-RegDWord -CN SERVER1,SERVER2 -Key $Key -Value PortNumber -AsHex

		ComputerName Hive            Key                  Value       Data   Type
		------------ ----            ---                  -----       ----   ----
		SERVER1      LocalMachine    System\CurrentCon... PortNumber  0xd3d  DWord
		SERVER2      LocalMachine    System\CurrentCon... PortNumber  0xd3d  DWord


		Description
		-----------
	   	This command gets the Terminal Server's listening port from SERVER1 and SERVER2.
	   	The command uses the ComputerName parameter alias 'CN' to specify a collection of computer names. 
	   	When the AsHex Switch Parameter is used, the value's data returnes in HEX notation.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegQWord
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$AsHex,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				
				
				Write-Verbose "Get value name : [$Value]"
				$rv = $subKey.GetValue($Value,-1)
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					if($AsHex)
					{
						Write-Verbose "Parameter [AsHex] is present, return value as HEX."
						$rv = "0x{0:x}" -f $rv
					}
					else
					{
						Write-Verbose "Parameter [AsHex] is not present, return value as INT."
					}
					
					
					Write-Verbose "Create PSFanatic registry value custom object."
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}
					
					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso					
					
				}				

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegDWord{

	<#
	.SYNOPSIS
	        Sets or creates a 32-bit binary number (REG_DWORD) on local or remote computers.

	.DESCRIPTION
	        Use Set-RegDWord to set or create a 32-bit binary number (REG_DWORD) on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
	        The data to set the registry value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.
		
	.EXAMPLE
		$Key = "SYSTEM\CurrentControlSet\Control\Terminal Server"	
		Get-RegDWord -ComputerName "SERVER1","SERVER1","SERVER3" -Key $Key -Value fDenyTSConnections -Ping
				
		Description
		-----------
		The command gets the registry fDenyTSConnections Dword value from three remote computers.		
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE
		Get-RegDWord -ComputerName "SERVER1","SERVER1","SERVER3" -Key $Key -Value fDenyTSConnections -Ping | Where-Object {$_.Data -eq 1} | Set-RegDWord -Data 0 -Force -PassThru
				
		Description
		-----------
		The command gets the registry fDenyTSConnections Dword value from three remote computers. 
		The result is piped to the Where-Object cmdlet and filters the computers that have Rempote Desktop disabled.
		The Results of Where-Object are piped to Set-RegDWord which sets the Dword value to 1 (Enable Rempote Desktop connections).
		
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.				

	.EXAMPLE
		$Key = "SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer"
		Get-Contebt server.txt | Set-RegDWord -Key $Key -Value NoDriveTypeAutorun -Data 0xFF -Force -PassThru -Ping
				
		Description
		-----------
		The command disables Autoplay for all drives on all server names defined in servers.txt with a HEX value of 0xFF (Decimal 255). 
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/

	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegDWord
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(Mandatory=$true,Position=4)]
		[int]$Data,
		
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry DWord Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::DWord)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$subKey.GetValue($Value)
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegDefault {
	<#
	.SYNOPSIS
	        Retrieves registry default string (REG_SZ) value from local or remote computers.

	.DESCRIPTION
	        Use Get-RegDefault to retrieve registry default string (REG_SZ) value from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open. 

	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		"SERVER1","SERVER2","SERVER3" | Set-RegDefault -Key $Key -Ping
		
		ComputerName Hive            Key                  Value      Data            Type
		------------ ----            ---                  -----      ----            ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		SERVER2      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		SERVER3      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		
		Description
		-----------
		Gets the reg default value of the SOFTWARE\MyCompany subkey on three remote computers local machine hive (HKLM) .
		Ping each server before setting the value.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)
		
	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegDefault
		Get-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]."
				$subKey = $reg.OpenSubKey($Key)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
				
				$pso = New-Object PSObject -Property @{
					ComputerName=$c
					Hive=$Hive
					Value="(Default)"
					Key=$Key
					Data=$subKey.GetValue($null)
					Type=$subKey.GetValueKind($Value)
				}
					
				Write-Verbose "Adding format type name to custom object."
				$pso.PSTypeNames.Clear()
				$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
				$pso

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegDefault {

	<#
	.SYNOPSIS
	        Sets the default value (REG_SZ) of the registry key on local or remote computers.

	.DESCRIPTION
	        Use Set-RegDefault to set the default value (REG_SZ) of the registry key on local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Data
	        The data to set in the registry default value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.
	       		
	.EXAMPLE
		$Key = "SOFTWARE\MyCompany"
		"SERVER1","SERVER2","SERVER3" | Set-RegDefault -Key $Key -Data MyDefaultValue -Ping -PassThru -Force
		
		ComputerName Hive            Key                  Value      Data            Type
		------------ ----            ---                  -----      ----            ----
		SERVER1      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		SERVER2      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		SERVER3      LocalMachine    SOFTWARE\MyCompany   (Default)  MyDefaultValue  String		
		
		Description
		-----------
		Set the reg default value of the SOFTWARE\MyCompany subkey on three remote computers local machine hive (HKLM) .
		Ping each server before setting the value and use -PassThru to get the objects back. Use Force to override confirmations.

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegDefault
		Get-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,
	
		[Parameter(
			Mandatory=$true,
			Position=3,
			HelpMessage="The data to set in the registry default value."
		)]
		[AllowEmptyString()]
		[string]$Data,		

		[switch]$Ping,
		[switch]$Force,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)	
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry Default Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting [$Key] default value."
					$subKey.SetValue($null,$Data)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value="(Default)"
						Key=$Key
						Data=$subKey.GetValue($null)
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}
				
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Get-RegBinary {
	<#
	.SYNOPSIS
	        Retrieves a binary data registry value (REG_BINARY) from local or remote computers.

	.DESCRIPTION
	        Use Get-RegBinary to retrieve a binary data registry value (REG_BINARY) from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.EXAMPLE	  
		$Key = "SOFTWARE\Microsoft\Internet Explorer\Registration"
		Get-RegBinary -Key $Key -Value DigitalProductId

		ComputerName Hive            Key                  Value              Data                 Type
		------------ ----            ---                  -----              ----                 ----
		COMPUTER1    LocalMachine    SOFTWARE\Microsof... IE Installed Date  {114, 76, 180, 17... Binary		
		
		Description
		-----------
		The command gets the DigitalProductId binary value from the local computer.
		The name of ComputerName parameter, which is optional, is omitted.		
		
	.EXAMPLE	
		"SERVER1","SERVER2","SERVER3" | Get-RegBinary -Key $Key -Value DigitalProductId -Ping
		
		ComputerName Hive         Key                                               Value            Data              Type
		------------ ----         ---                                               -----            ----              ----
		SERVER1      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary
		SERVER2      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary
		SERVER3      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary

		Description
		-----------
		The command gets the DigitalProductId binary value from remote computers. 
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Get-RegBinary -Key $Key -Value DigitalProductId
		
		ComputerName Hive         Key                                               Value            Data              Type
		------------ ----         ---                                               -----            ----              ----
		SERVER1      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary
		SERVER2      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary
		SERVER3      LocalMachine SOFTWARE\Microsoft\Internet Explorer\Registration DigitalProductId {164, 0, 0, 0...} Binary

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file.

	.EXAMPLE	
		Get-RegString -Hive LocalMachine -Key $Key -Value DigitalProductId | Test-RegValue -ComputerName SERVER1,SERVER2 -Ping
		True
		True

		Description
		-----------
		he command gets the DigitalProductId binary value from the local computer.
		The output is piped to the Test-RegValue Function to check if the value exists on two remote computers.
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.	
	
	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Set-RegBinary
		Get-RegValue
		Remove-RegValue
		Test-RegValue


	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
	
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to get."
		)]
		[string]$Value,
		
		[switch]$Ping
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
				
				Write-Verbose "Open remote subkey: [$Key]"
				$subKey = $reg.OpenSubKey($Key)				

				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."
				}
					
				Write-Verbose "Get value name : [$Value]"
				$rv = $subKey.GetValue($Value,-1)
				
				if($rv -eq -1)
				{
					Write-Error "Cannot find value [$Value] because it does not exist."
				}
				else
				{
					Write-Verbose "Create PSFanatic registry value custom object."
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$rv
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso
				}				

				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}

Function Set-RegBinary {

	<#
	.SYNOPSIS
	        Sets or creates a binary data registry value (REG_BINARY) from local or remote computers.

	.DESCRIPTION
	        Use Set-RegBinary to set or create a binary data registry value (REG_BINARY) from local or remote computers.
	       
	.PARAMETER ComputerName
	    	An array of computer names. The default is the local computer.

	.PARAMETER Hive
	   	The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'.
	   	Possible values:
	   	
		- ClassesRoot
		- CurrentUser
		- LocalMachine
		- Users
		- PerformanceData
		- CurrentConfig
		- DynData	   	

	.PARAMETER Key
	        The path of the registry key to open.  

	.PARAMETER Value
	        The name of the registry value.

	.PARAMETER Data
	        The data to set the registry value.

	.PARAMETER Force
	        Overrides any confirmations made by the command. Even using the Force parameter, the Function cannot override security restrictions.

	.PARAMETER Ping
	        Use ping to test if the machine is available before connecting to it. 
	        If the machine is not responding to the test a warning message is output.

	.PARAMETER PassThru
	        Passes the newly custom object to the pipeline. By default, this Function does not generate any output.

	.EXAMPLE	  
		$Key = "SOFTWARE\MyCompany"		
		Set-RegBinary -Key $Key -Value RegBinary -Data @([char[]]"PowerShell")
		
		Description
		-----------
		The command Sets or Creates a binary registry value named RegBinary on the local computer.
		The name of ComputerName parameter, which is optional, is omitted. 		
		
	.EXAMPLE	
		"SERVER1","SERVER1","SERVER3" | Set-RegBinary -Key $Key -Value RegBinary -Data @([char[]]"PowerShell") -Ping		
		
		Description
		-----------
		The command Sets or Creates a registry value named RegBinary on three remote computers.		
		When the Switch parameter Ping is specified the command issues a ping test to each computer. 
		If the computer is not responding to the ping request a warning message is written to the console and the computer is not processed.

	.EXAMPLE	
		Get-Content servers.txt | Set-RegBinary -Key $Key -Value RegBinary -Data @([char[]]"PowerShell") -Force -PassThru

		ComputerName Hive            Key                  Value     Data                 Type
		------------ ----            ---                  -----     ----                 ----
		SERVER1      LocalMachine    software\mycompany   RegBinary {80, 111, 119, 10... Binary
		SERVER2      LocalMachine    software\mycompany   RegBinary {80, 111, 119, 10... Binary
		SERVER3      LocalMachine    software\mycompany   RegBinary {80, 111, 119, 10... Binary

		Description
		-----------
		The command uses the Get-Content cmdlet to get the server names from a text file. 
		It Sets or Creates a Binary registry value named RegBinary on three remote computers.
		By default, the caller is prompted to confirm each action. To override confirmations, the Force Switch parameter is specified.		
		By default, the command doesn't return any objects back. To get the values objects, specify the PassThru Switch parameter.				

	.OUTPUTS
		PSFanatic.Registry.RegistryValue (PSCustomObject)

	.NOTES
		Author: Shay Levy
		Blog  : http://blogs.microsoft.co.il/blogs/ScriptFanatic/
		
	.LINK
		http://code.msdn.microsoft.com/PSRemoteRegistry

	.LINK
		Get-RegBinary
		Get-RegValue
		Remove-RegValue
		Test-RegValue
	#>
	
	
	[OutputType('PSFanatic.Registry.RegistryValue')]
	[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High',DefaultParameterSetName="__AllParameterSets")]
					
	param( 
		[Parameter(
			Position=0,
			ValueFromPipeline=$true,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="An array of computer names. The default is the local computer."
		)]		
		[Alias("CN","__SERVER","IPAddress")]
		[string[]]$ComputerName="",		
		
		[Parameter(
			Position=1,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The HKEY to open, from the RegistryHive enumeration. The default is 'LocalMachine'."
		)]
		[ValidateSet("ClassesRoot","CurrentUser","LocalMachine","Users","PerformanceData","CurrentConfig","DynData")]
		[string]$Hive="LocalMachine",
		
		[Parameter(
			Mandatory=$true,
			Position=2,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The path of the subkey to open or create."
		)]
		[string]$Key,

		[Parameter(
			Mandatory=$true,
			Position=3,
			ValueFromPipelineByPropertyName=$true,
			HelpMessage="The name of the value to set."
		)]
		[string]$Value,

		[Parameter(Mandatory=$true,Position=4)]
		[byte[]]$Data,
		
		[switch]$Force,
		[switch]$Ping,
		[switch]$PassThru
	) 
	

	process
	{
	    	
	    	Write-Verbose "Enter process block..."
		
		foreach($c in $ComputerName)
		{	
			try
			{				
				if($c -eq "")
				{
					$c=$env:COMPUTERNAME
					Write-Verbose "Parameter [ComputerName] is not present, setting its value to local computer name: [$c]."
					
				}
				
				if($Ping)
				{
					Write-Verbose "Parameter [Ping] is present, initiating Ping test"
					
					if( !(Test-Connection -ComputerName $c -Count 1 -Quiet))
					{
						Write-Warning "[$c] doesn't respond to ping."
						return
					}
				}

				
				Write-Verbose "Starting remote registry connection against: [$c]."
				Write-Verbose "Registry Hive is: [$Hive]."
				$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]$Hive,$c)		
							
				Write-Verbose "Open remote subkey: [$Key] with write access."
				$subKey = $reg.OpenSubKey($Key,$true)
				
				if(!$subKey)
				{
					Throw "Key '$Key' doesn't exist."					
				}				

				if($Force -or $PSCmdlet.ShouldProcess($c,"Set Registry Binary Value '$Hive\$Key\$Value'"))
				{					
					Write-Verbose "Parameter [Force] or [Confirm:`$False] is present, suppressing confirmations."
					Write-Verbose "Setting value name: [$Value]"
					$subKey.SetValue($Value,$Data,[Microsoft.Win32.RegistryValueKind]::Binary)
				}	
				
				
				if($PassThru)
				{
					Write-Verbose "Parameter [PassThru] is present, creating PSFanatic registry custom objects."
					Write-Verbose "Create PSFanatic registry value custom object."
					
					$pso = New-Object PSObject -Property @{
						ComputerName=$c
						Hive=$Hive
						Value=$Value
						Key=$Key
						Data=$subKey.GetValue($Value)
						Type=$subKey.GetValueKind($Value)
					}

					Write-Verbose "Adding format type name to custom object."
					$pso.PSTypeNames.Clear()
					$pso.PSTypeNames.Add('PSFanatic.Registry.RegistryValue')
					$pso				
				}				
				
				Write-Verbose "Closing remote registry connection on: [$c]."
				$subKey.close()
			}
			catch
			{
				Write-Error $_
			}
		} 
		
		Write-Verbose "Exit process block..."
	}
}
