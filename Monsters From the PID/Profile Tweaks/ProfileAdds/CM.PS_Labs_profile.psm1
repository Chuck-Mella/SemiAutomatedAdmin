#region Functions
    function Write-LabInfo([Parameter(Mandatory=$true)]$message){
        Write-Host $message
    }
    Set-Alias -Name WriteInfo -Value 'Write-LabInfo' -Scope Global -Force

    function Write-LabInfoHighlighted([Parameter(Mandatory=$true)]$message){
        Write-Host $message -ForegroundColor Cyan
    }
    Set-Alias -Name WriteInfoHighlighted -Value 'Write-LabInfoHighlighted' -Scope Global -Force

    function Write-LabSuccess([Parameter(Mandatory=$true)]$message){
        Write-Host $message -ForegroundColor Green
    }
    Set-Alias -Name WriteSuccess -Value 'Write-LabSuccess' -Scope Global -Force

    function Write-LabError([Parameter(Mandatory=$true)]$message){
        Write-Host $message -ForegroundColor Red
    }
    Set-Alias -Name WriteError -Value 'Write-LabError' -Scope Global -Force

    function Write-LabErrorAndExit([Parameter(Mandatory=$true)]$message){
        Write-Host $message -ForegroundColor Red
        Write-Host "Press enter to continue ..."
        $exit=Read-Host
        Exit
    }
    Set-Alias -Name WriteErrorAndExit -Value 'Write-LabErrorAndExit' -Scope Global -Force
    
    #Create Unattend for VHD 
    Function CreateUnattendFileVHD{
        param (
            [parameter(Mandatory=$true)]
            [string]
            $Computername,
            [parameter(Mandatory=$true)]
            [string]
            $AdminPassword,
            [parameter(Mandatory=$true)]
            [string]
            $Path,
            [parameter(Mandatory=$true)]
            [string]
            $TimeZone
        )

        if ( Test-Path "$path\Unattend.xml" ) {
            Remove-Item "$Path\Unattend.xml"
        }
        $unattendFile = New-Item "$Path\Unattend.xml" -type File
        $fileContent =  @"
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">

  <settings pass="offlineServicing">
   <component
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        language="neutral"
        name="Microsoft-Windows-PartitionManager"
        processorArchitecture="amd64"
        publicKeyToken="31bf3856ad364e35"
        versionScope="nonSxS"
        >
      <SanPolicy>1</SanPolicy>
    </component>
 </settings>
 <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <ComputerName>$Computername</ComputerName>
        <RegisteredOwner>PFE</RegisteredOwner>
        <RegisteredOrganization>Contoso</RegisteredOrganization>
    </component>
 </settings>
 <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword>
           <Value>$AdminPassword</Value>
           <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE> 
        <SkipUserOOBE>true</SkipUserOOBE> 
      </OOBE>
      <TimeZone>$TimeZone</TimeZone>
    </component>
  </settings>
</unattend>

"@

        Set-Content -path $unattendFile -value $fileContent

        #return the file object
        Return $unattendFile 
    }

#endregion
