If ($isAdmin){ Install-Module SQLServer }

# Add-Type -AssemblyName System.IO.Compression.FileSystem
# [System.IO.Compression.ZipFile]::ExtractToDirectory("$HOME\Downloads\vsts-agent-win-x64-2.175.2.zip", "$PWD")
# ----------------- Az module compatible below
# DQpmdW5jdGlvbiBHZXQtQXpDYWNoZWRBY2Nlc3NUb2tlbigpDQp7DQogICAgJEVycm9yQWN0aW9uUHJlZmVyZW5jZSA9ICdTdG9wJw0KICANCiAgICBpZigtbm90IChHZXQtTW9kdWxlIEF6LkFjY291bnRzKSkgew0KICAgICAgICBJbXBvcnQtTW9kdWxlIEF6LkFjY291bnRzDQogICAgfQ0KICAgICRhelByb2ZpbGUgPSBbTWljcm9zb2Z0LkF6dXJlLkNvbW1hbmRzLkNvbW1vbi5BdXRoZW50aWNhdGlvbi5BYnN0cmFjdGlvbnMuQXp1cmVSbVByb2ZpbGVQcm92aWRlcl06Okluc3RhbmNlLlByb2ZpbGUNCiAgICBpZigtbm90ICRhelByb2ZpbGUuQWNjb3VudHMuQ291bnQpIHsNCiAgICAgICAgV3JpdGUtRXJyb3IgIkVuc3VyZSB5b3UgaGF2ZSBsb2dnZWQgaW4gYmVmb3JlIGNhbGxpbmcgdGhpcyBmdW5jdGlvbi4iICAgIA0KICAgIH0NCiAgDQogICAgJGN1cnJlbnRBenVyZUNvbnRleHQgPSBHZXQtQXpDb250ZXh0DQogICAgJHByb2ZpbGVDbGllbnQgPSBOZXctT2JqZWN0IE1pY3Jvc29mdC5BenVyZS5Db21tYW5kcy5SZXNvdXJjZU1hbmFnZXIuQ29tbW9uLlJNUHJvZmlsZUNsaWVudCgkYXpQcm9maWxlKQ0KICAgIFdyaXRlLURlYnVnICgiR2V0dGluZyBhY2Nlc3MgdG9rZW4gZm9yIHRlbmFudCIgKyAkY3VycmVudEF6dXJlQ29udGV4dC5UZW5hbnQuVGVuYW50SWQpDQogICAgJHRva2VuID0gJHByb2ZpbGVDbGllbnQuQWNxdWlyZUFjY2Vzc1Rva2VuKCRjdXJyZW50QXp1cmVDb250ZXh0LlRlbmFudC5UZW5hbnRJZCkNCiAgICAkdG9rZW4uQWNjZXNzVG9rZW4NCn0NCg0KZnVuY3Rpb24gR2V0LUF6QmVhcmVyVG9rZW4oKQ0Kew0KICAgICRFcnJvckFjdGlvblByZWZlcmVuY2UgPSAnU3RvcCcNCiAgICAoJ0JlYXJlciB7MH0nIC1mIChHZXQtQXpDYWNoZWRBY2Nlc3NUb2tlbikpDQp9DQo=

# ----------------- AzureRM module compatible below

function Get-AzureRmCachedAccessToken()
{
    $ErrorActionPreference = 'Stop'
  
    if(-not (Get-Module AzureRm.Profile)) {
        Import-Module AzureRm.Profile
    }
    $azureRmProfileModuleVersion = (Get-Module AzureRm.Profile).Version
    # refactoring performed in AzureRm.Profile v3.0 or later
    if($azureRmProfileModuleVersion.Major -ge 3) {
        $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
        if(-not $azureRmProfile.Accounts.Count) {
            Write-Error "Ensure you have logged in before calling this function."    
        }
    } else {
        # AzureRm.Profile < v3.0
        $azureRmProfile = [Microsoft.WindowsAzure.Commands.Common.AzureRmProfileProvider]::Instance.Profile
        if(-not $azureRmProfile.Context.Account.Count) {
            Write-Error "Ensure you have logged in before calling this function."    
        }
    }
  
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Tenant.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Tenant.TenantId)
    $token.AccessToken
}

function Get-AzureRmBearerToken()
{
    $ErrorActionPreference = 'Stop'
    ('Bearer {0}' -f (Get-AzureRmCachedAccessToken))
}

<#
Workflow Stop-Start-AzureVM 
{ 
    Param 
    (    
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] 
        [String] 
        $AzureSubscriptionId, 
        [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()] 
        [String] 
        $AzureVMList="All", 
        [Parameter(Mandatory=$true)][ValidateSet("Start","Stop")] 
        [String] 
        $Action 
    ) 
     
    $credential = Get-AutomationPSCredential -Name 'AzureCredential' 
    Login-AzureRmAccount -Credential $credential 
    Select-AzureRmSubscription -SubscriptionId $AzureSubscriptionId 
 
    if($AzureVMList -ne "All") 
    { 
        $AzureVMs = $AzureVMList.Split(",") 
        [System.Collections.ArrayList]$AzureVMsToHandle = $AzureVMs 
    } 
    else 
    { 
        $AzureVMs = (Get-AzureRmVM).Name 
        [System.Collections.ArrayList]$AzureVMsToHandle = $AzureVMs 
 
    } 
 
    foreach($AzureVM in $AzureVMsToHandle) 
    { 
        if(!(Get-AzureRmVM | ? {$_.Name -eq $AzureVM})) 
        { 
            throw " AzureVM : [$AzureVM] - Does not exist! - Check your inputs " 
        } 
    } 
 
    if($Action -eq "Stop") 
    { 
        Write-Output "Stopping VMs"; 
        foreach -parallel ($AzureVM in $AzureVMsToHandle) 
        { 
            Get-AzureRmVM | ? {$_.Name -eq $AzureVM} | Stop-AzureRmVM -Force 
        } 
    } 
    else 
    { 
        Write-Output "Starting VMs"; 
        foreach -parallel ($AzureVM in $AzureVMsToHandle) 
        { 
            Get-AzureRmVM | ? {$_.Name -eq $AzureVM} | Start-AzureRmVM 
        } 
    } 
}
#>

#region AutomatedLabAzureWorkerVMs
  # https://www.powershellgallery.com/packages/AutomatedLabWorker/3.9.0.5/Content/AutomatedLabAzureWorkerVirtualMachines.psm1

    $PSDefaultParameterValues = @{
        '*-Azure*:Verbose' = $false
        '*-Azure*:Warning' = $false
        'Import-Module:Verbose' = $false
        }
    Function New-LWAzureVM
    {
        [Cmdletbinding()]
        Param (
            [Parameter(Mandatory)]
            [AutomatedLab.Machine]$Machine
        )

        Write-LogFunctionEntry
    
        $lab = Get-Lab
    
        $resourceGroupName = $lab.Name
        if ($machine.AzureProperties)
        {
            if ($machine.AzureProperties.ContainsKey('ResourceGroupName'))
            {
                #if the resource group name is provided for the machine, it replaces the default
                $resourceGroupName = $machine.AzureProperties.ResourceGroupName
            }
        }
    
        $machineResourceGroup = $Machine.AzureProperties.ResourceGroupName
        if (-not $machineResourceGroup)
        {
            $machineResourceGroup = (Get-LabAzureDefaultResourceGroup).ResourceGroupName
        }
        Write-Verbose -Message "Target resource group for machine: '$machineResourceGroup'"
    
        if (-not $global:cacheVMs)
        {
            $global:cacheVMs = Get-AzureRmVM -WarningAction SilentlyContinue
        }

        if ($global:cacheVMs | Where-Object {$_.Name -eq $Machine.Name -and $_.ResourceGroupName -eq $resourceGroupName})
        {
            Write-ProgressIndicatorEnd
            Write-ScreenInfo -Message "Machine '$($machine.name)' already exist. Skipping creation of this machine" -Type Warning
            Return $false
        }

        Write-Verbose -Message "Creating container 'automatedlabdisks' for additional disks"
        $storageContext = (Get-AzureRmStorageAccount -Name $lab.AzureSettings.DefaultStorageAccount -ResourceGroupName $machineResourceGroup).Context
        $container = Get-AzureStorageContainer -Name automatedlabdisks -Context $storageContext -ErrorAction SilentlyContinue
        if (-not $container)
        {
            $container = New-AzureStorageContainer -Name automatedlabdisks -Context $storageContext
        }

        Write-Verbose -Message "Scheduling creation Azure machine '$Machine'"

        #random number in the path to prevent conflicts
        $rnd = (Get-Random -Minimum 1 -Maximum 1000).ToString('0000')
        $osVhdLocation = "$($storageContext.BlobEndpoint)/automatedlab1/$($machine.Name)OsDisk$rnd.vhd"
        $lab.AzureSettings.VmDisks.Add($osVhdLocation)
        Write-Verbose -Message "The location of the VM disk is '$osVhdLocation'"

        $adminUserName = $Machine.InstallationUser.UserName
        $adminPassword = $Machine.InstallationUser.Password


    
        #if this machine has a SQL Server role
        if ($Machine.Roles.Name -match 'SQLServer(?<SqlVersion>\d{4})')
        {    
            #get the SQL Server version defined in the role
            $sqlServerRoleName = $Matches[0]
            $sqlServerVersion = $Matches.SqlVersion
        }

        #if this machine has a Visual Studio role
        if ($Machine.Roles.Name -match 'VisualStudio(?<Version>\d{4})')
        {
            $visualStudioRoleName = $Matches[0]        
            $visualStudioVersion = $Matches.Version
        }

        #if this machine has a SharePoint role
        if ($Machine.Roles.Name -match 'SharePoint(?<Version>\d{4})')
        {
            $sharePointRoleName = $Matches[0]
            $sharePointVersion = $Matches.Version
        }
            
        if ($sqlServerRoleName)
        {
            Write-Verbose -Message 'This is going to be a SQL Server VM'
            $pattern = 'SQL(?<SqlVersion>\d{4})(?<SqlIsR2>R2)??(?<SqlServicePack>SP\d)?-(?<OS>WS\d{4}(R2)?)'
                
            #get all SQL images machting the RegEx pattern and then get only the latest one
            $sqlServerImages = $lab.AzureSettings.VmImages |
            Where-Object Offer -Match $pattern | 
            Group-Object -Property Sku, Offer | 
            ForEach-Object {
                $_.Group | Sort-Object -Property PublishedDate -Descending | Select-Object -First 1
            }

            #add the version, SP Level and OS from the ImageFamily field to the image object
            foreach ($sqlServerImage in $sqlServerImages)
            {
                $sqlServerImage.Offer -match $pattern | Out-Null

                $sqlServerImage | Add-Member -Name SqlVersion -Value $Matches.SqlVersion -MemberType NoteProperty -Force
                $sqlServerImage | Add-Member -Name SqlIsR2 -Value $Matches.SqlIsR2 -MemberType NoteProperty -Force
                $sqlServerImage | Add-Member -Name SqlServicePack -Value $Matches.SqlServicePack -MemberType NoteProperty -Force
    
                $sqlServerImage | Add-Member -Name OS -Value (New-Object AutomatedLab.OperatingSystem($Matches.OS)) -MemberType NoteProperty -Force
            }

            #get the image that matches the OS and SQL server version
            $machineOs = New-Object AutomatedLab.OperatingSystem($machine.OperatingSystem)
            $vmImage = $sqlServerImages | Where-Object { $_.SqlVersion -eq $sqlServerVersion -and $_.OS.Version -eq $machineOs.Version } |
            Sort-Object -Property SqlServicePack -Descending | Select-Object -First 1
            $offerName = $vmImageName = $vmImage | Select-Object -ExpandProperty Offer
            $publisherName = $vmImage | Select-Object -ExpandProperty PublisherName
            $skusName = $vmImage | Select-Object -ExpandProperty Skus

            if (-not $vmImageName)
            {
                Write-Warning 'SQL Server image could not be found. The following combinations are currently supported by Azure:'
                foreach ($sqlServerImage in $sqlServerImages)
                {
                    Write-Host $sqlServerImage.Label
                }

                throw "There is no Azure VM image for '$sqlServerRoleName' on operating system '$($machine.OS)'. The machine cannot be created. Cancelling lab setup. Please find the available images above."
            }
        }
        elseif ($visualStudioRoleName)
        {
            Write-Verbose -Message 'This is going to be a Visual Studio VM'

            $pattern = 'VS-(?<Version>\d{4})-(?<Edition>\w+)-VSU(?<Update>\d)-AzureSDK-\d{2,3}-((?<OS>WIN\d{2})|(?<OS>WS\d{4,6}))'
                
            #get all SQL images machting the RegEx pattern and then get only the latest one
            $visualStudioImages = $lab.AzureSettings.VmImages |
            Where-Object Offer -EQ VisualStudio

            #add the version, SP Level and OS from the ImageFamily field to the image object
            foreach ($visualStudioImage in $visualStudioImages)
            {
                $visualStudioImage.Skus -match $pattern | Out-Null

                $visualStudioImage | Add-Member -Name Version -Value $Matches.Version -MemberType NoteProperty -Force
                $visualStudioImage | Add-Member -Name Update -Value $Matches.Update -MemberType NoteProperty -Force
    
                $visualStudioImage | Add-Member -Name OS -Value (New-Object AutomatedLab.OperatingSystem($Matches.OS)) -MemberType NoteProperty -Force
            }

            #get the image that matches the OS and SQL server version
            $machineOs = New-Object AutomatedLab.OperatingSystem($machine.OperatingSystem)
            $vmImage = $visualStudioImages | Where-Object { $_.Version -eq $visualStudioVersion -and $_.OS.Version.Major -eq $machineOs.Version.Major } |
            Sort-Object -Property Update -Descending | Select-Object -First 1
            $offerName = $vmImageName = $vmImage | Select-Object -ExpandProperty Offer
            $publisherName = $vmImage | Select-Object -ExpandProperty PublisherName
            $skusName = $vmImage | Select-Object -ExpandProperty Skus

            if (-not $vmImageName)
            {
                Write-Warning 'Visual Studio image could not be found. The following combinations are currently supported by Azure:'
                foreach ($visualStudioImage in $visualStudioImages)
                {
                    Write-Host $visualStudioImage.Label
                }

                throw "There is no Azure VM image for '$visualStudioRoleName' on operating system '$($machine.OperatingSystem)'. The machine cannot be created. Cancelling lab setup. Please find the available images above."
            }
        }
        elseif ($sharePointRoleName)
        {
            Write-Verbose -Message 'This is going to be a SharePoint VM'

            # AzureRM currently has only one SharePoint offer
        
            $sharePointImages = $lab.AzureSettings.VmImages |
            Where-Object Offer -Match 'SharePoint' |
            Sort-Object -Property PublishedDate -Descending | Select-Object -First 1

            # Add the SP version
            foreach ($sharePointImage in $sharePointImages)
            {
                $sharePointImage | Add-Member -Name Version -Value $sharePointImage.Skus -MemberType NoteProperty -Force
            }

            #get the image that matches the OS and SQL server version
            $machineOs = New-Object AutomatedLab.OperatingSystem($machine.OperatingSystem)
            Write-Warning "The SharePoint 2013 Trial image in Azure does not have any information about the OS anymore, hence this operating system specified is ignored. There is only $($sharePointImages.Count) image available."
        
            #$vmImageName = $sharePointImages | Where-Object { $_.Version -eq $sharePointVersion -and $_.OS.Version -eq $machineOs.Version } |
            $vmImage = $sharePointImages | Where-Object Version -eq $sharePointVersion |
            Sort-Object -Property Update -Descending | Select-Object -First 1

            $offerName = $vmImageName = $vmImage | Select-Object -ExpandProperty Offer
            $publisherName = $vmImage | Select-Object -ExpandProperty PublisherName
            $skusName = $vmImage | Select-Object -ExpandProperty Skus

            if (-not $vmImageName)
            {
                Write-Warning 'SharePoint image could not be found. The following combinations are currently supported by Azure:'
                foreach ($sharePointImage in $sharePointImages)
                {
                    Write-Host $sharePointImage.Label $sharePointImage.ImageFamily
                }

                throw "There is no Azure VM image for '$sharePointRoleName' on operating system '$($Machine.OperatingSystem)'. The machine cannot be created. Cancelling lab setup. Please find the available images above."
            }
        }
        else
        {
            $vmImageName = (New-Object AutomatedLab.OperatingSystem($machine.OperatingSystem)).AzureImageName
            if (-not $vmImageName)
            {
                throw "There is no Azure VM image for the operating system '$($Machine.OperatingSystem)'. The machine cannot be created. Cancelling lab setup."
            }

            $vmImage = $lab.AzureSettings.VmImages |
            Where-Object Skus -eq $vmImageName  |
            Select-Object -First 1

            $offerName = $vmImageName = $vmImage | Select-Object -ExpandProperty Offer
            $publisherName = $vmImage | Select-Object -ExpandProperty PublisherName
            $skusName = $vmImage | Select-Object -ExpandProperty Skus
        }
        Write-Verbose -Message "We selected the SKUs $skusName from offer $offerName by publisher $publisherName"
    
        Write-ProgressIndicator
    
        if ($machine.AzureProperties.RoleSize)
        {
            $roleSize = $lab.AzureSettings.RoleSizes |
            Where-Object { $_.Name -eq $machine.AzureProperties.RoleSize }
            Write-Verbose -Message "Using specified role size of '$($roleSize.Name)'"
        }
        elseif ($machine.AzureProperties.UseAllRoleSizes)
        {
            $DefaultAzureRoleSize = $MyInvocation.MyCommand.Module.PrivateData.DefaultAzureRoleSize
            $roleSize = $lab.AzureSettings.RoleSizes |
            Where-Object { $_.MemoryInMB -ge $machine.Memory -and $_.NumberOfCores -ge $machine.Processors -and $machine.Disks.Count -le $_.MaxDataDiskCount } |
            Sort-Object -Property MemoryInMB, NumberOfCores |
            Select-Object -First 1

            Write-Verbose -Message "Using specified role size of '$($roleSize.InstanceSize)'. VM was configured to all role sizes but constrained to role size '$DefaultAzureRoleSize' by psd1 file"
        }
        else
        {
            switch ($lab.AzureSettings.DefaultRoleSize)
            {
                'A' { $pattern = '^(Standard_A\d{1,2}|Basic_A\d{1,2})' }
                'D' { $pattern = '^Standard_D\d{1,2}' }
                'DS' { $pattern = '^Standard_DS\d{1,2}' }
                'G' { $pattern = '^Standard_G\d{1,2}' }
                'F' { $pattern = '^Standard_F\d{1,2}' }
                default { $pattern = '^(Standard_A\d{1,2}|Basic_A\d{1,2})'}
            }
        
            $roleSize = $lab.AzureSettings.RoleSizes |
            Where-Object Name -Match $pattern |
            Where-Object { $_.MemoryInMB -ge ($machine.Memory / 1MB) -and $_.NumberOfCores -ge $machine.Processors } |
            Sort-Object -Property MemoryInMB, NumberOfCores |
            Select-Object -First 1

            Write-Verbose -Message "Using specified role size of '$($roleSize.Name)' out of role sizes '$pattern'"
        }
    
        if (-not $roleSize)
        {
            throw "Could not find an appropriate role size in Azure $($machine.Processors) cores and $($machine.Memory) MB of memory"
        }
    
        Write-ProgressIndicator
    
        $labVirtualNetworkDefinition = Get-LabVirtualNetworkDefinition

      # List-serialization issues when passing to job. Disks will be added to a hashtable
      $Disks = @{}
        $Machine.Disks | %{$Disks.Add($_.Name,$_.DiskSize)}

        Start-Job -Name "CreateAzureVM ($machineResourceGroup) ($Machine)" -ArgumentList $Machine,
      $Disks,
        $Machine.NetworkAdapters[0].VirtualSwitch.Name,
        $roleSize.Name,
        $vmImageName,
        $osVhdLocation,
        $adminUserName,
        $adminPassword,
        $machineResourceGroup,
        $labVirtualNetworkDefinition,
        $Machine.NetworkAdapters[0].Ipv4Address.IpAddress,
        $storageContext,
        $resourceGroupName,
        $lab.AzureSettings.DefaultLocation.DisplayName,
        $lab.AzureSettings.AzureProfilePath,
        $lab.AzureSettings.DefaultSubscription.SubscriptionName,
        $lab.Name,
        $publisherName,
        $offerName,
        $skusName `
        -ScriptBlock {
            param
            (
                [object]$Machine, #AutomatedLab.Machine
          [object]$Disks,
                [string]$Vnet,
                [string]$RoleSize,
                [string]$VmImageName,
                [string]$OsVhdLocation,
                [string]$AdminUserName,
                [string]$AdminPassword,
                [string]$MachineResourceGroup,
                [object[]]$LabVirtualNetworkDefinition, #AutomatedLab.VirtualNetwork[]
                [object]$DefaultIpAddress, #AutomatedLab.IPAddress
                [object]$StorageContext,
                [string]$ResourceGroupName,
                [string]$Location,
                [string]$SubscriptionPath,
                [string]$SubscriptionName,
                [string]$LabName,
                [string]$PublisherName,
                [string]$OfferName,
                [string]$SkusName
            )

            $VerbosePreference = 'Continue'
        
            Write-Verbose '-------------------------------------------------------'
            Write-Verbose "Machine: $($Machine.name)"
            Write-Verbose "Vnet: $Vnet"
            Write-Verbose "RoleSize: $RoleSize"
            Write-Verbose "VmImageName: $VmImageName"
            Write-Verbose "OsVhdLocation: $OsVhdLocation"
            Write-Verbose "AdminUserName: $AdminUserName"
            Write-Verbose "AdminPassword: $AdminPassword"
            Write-Verbose "ResourceGroupName: $ResourceGroupName"
            Write-Verbose "StorageAccountName: $($StorageContext.StorageAccountName)"
            Write-Verbose "BlobEndpoint: $($StorageContext.BlobEndpoint)"
            Write-Verbose "DefaultIpAddress: $DefaultIpAddress"
            Write-Verbose "Location: $Location"
            Write-Verbose "Subscription file: $SubscriptionPath"
            Write-Verbose "Subscription name: $SubscriptionName"
            Write-Verbose "Lab name: $LabName"
            Write-Verbose "Publisher: $PublisherName"
            Write-Verbose "Offer: $OfferName"
            Write-Verbose "Skus: $SkusName"
            Write-Verbose '-------------------------------------------------------'
        
            Select-AzureRmProfile -Path $SubscriptionPath
            Set-AzureRmContext -SubscriptionName $SubscriptionName
        
            $VerbosePreference = 'Continue'

            $subnet = (Get-AzureRmVirtualNetwork -ResourceGroupName $ResourceGroupName |
            Where-Object { $_.AddressSpace.AddressPrefixes.Contains($Machine.IpAddress[0].ToString()) })[0] |
            Get-AzureRmVirtualNetworkSubnetConfig
        
            Write-Verbose -Message "Subnet for the VM is '$($subnet.Name)'"
        
            Write-Verbose -Message "Calling 'New-AzureVMConfig'"
                             
            $securePassword = ConvertTo-SecureString -String $AdminPassword -AsPlainText -Force
            $cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($AdminUserName, $securePassword)

            $vm =New-AzureRmVMConfig -VMName $Machine.Name -VMSize $RoleSize -ErrorAction Stop
            $vm = Set-AzureRmVMOperatingSystem -VM $vm -Windows -ComputerName $Machine.Name -Credential $cred -ProvisionVMAgent -EnableAutoUpdate -ErrorAction Stop -WinRMHttp
                           
            Write-Verbose "Choosing latest source image for $SkusName in $OfferName"
            $vm = Set-AzureRmVMSourceImage -VM $vm -PublisherName $PublisherName -Offer $OfferName -Skus $SkusName -Version "latest" -ErrorAction Stop

            Write-Verbose -Message "Setting private and dynamic public IP addresses."
            $defaultIPv4Address = $DefaultIpAddress
            $publicIpAddress = New-AzureRmPublicIpAddress -Name "$($Machine.Name.ToLower())pip" -ResourceGroupName $ResourceGroupName -Location $Location -DomainNameLabel "$($LabName.ToLower())-$($Machine.Name.ToLower())" -AllocationMethod Dynamic
            if($publicIpAddress.ProvisioningState -ne 'Succeeded')
            {
                throw "No public IP could be assigned to $($machine.Name). Connections to this machine will not work."
            }

            Write-Verbose -Message "Default IP address is '$DefaultIpAddress'. Public IP is $($publicIpAddress.IpAddress)"
        
            Write-Verbose -Message "Creating new network interface with configured private and public IP and subnet $($subnet.Name)"
            $networkInterface = New-AzureRmNetworkInterface -Name "$($Machine.Name.ToLower())nic0" -ResourceGroupName $ResourceGroupName -Location $Location -Subnet $Subnet -PrivateIpAddress $defaultIPv4Address -PublicIpAddress $publicIpAddress
        
            Write-Verbose -Message 'Adding NIC to VM'
            $vm = Add-AzureRmVMNetworkInterface -VM $vm -Id $networkInterface.Id -ErrorAction Stop

                                   
            $DiskName = "$($machine.Name)_os"
            $OSDiskUri = "$($StorageContext.BlobEndpoint)automatedlabdisks/$DiskName.vhd"
        
            Write-Verbose "Adding OS disk to VM with blob url $OSDiskUri"
            $vm = Set-AzureRmVMOSDisk -VM $vm -Name $DiskName -VhdUri $OSDiskUri -CreateOption fromImage -ErrorAction Stop

            if ($Disks)
            {
                Write-Verbose "Adding $($Disks.Count) data disks"
                $lun = 0
        
                foreach ($Disk in $Disks.GetEnumerator())
                {
            $DataDiskName = $Disk.Key.ToLower()
            $DiskSize = $Disk.Value
            $VhdUri = "$($StorageContext.BlobEndpoint)automatedlabdisks/$DataDiskName.vhd"

                    Write-Verbose -Message "Calling 'Add-AzureRmVMDataDisk' for $DataDiskName with $DiskSize GB on LUN $lun (resulting in uri $VhdUri)"
                    $vm = $vm | Add-AzureRmVMDataDisk -Name $DataDiskName -VhdUri $VhdUri -Caching None -DiskSizeInGB $DiskSize -Lun $lun -CreateOption Empty 
                    $lun++
                }
            }
           
            Write-ProgressIndicator        

            #Add any additional NICs to the VM configuration
            if ($Machine.NetworkAdapters.Count -gt 1)
            {
                Write-Verbose -Message "Adding $($Machine.NetworkAdapters.Count) additional NICs to the VM config"
                foreach ($adapter in ($Machine.NetworkAdapters | Where-Object Ipv4Address -ne $defaultIPv4Address))
                {
                    if ($adapter.Ipv4Address.ToString() -ne $defaultIPv4Address)
                    {
                        $adapterStartAddress = Get-NetworkRange -IPAddress ($adapter.Ipv4Address.AddressAsString) -SubnetMask ($adapter.Ipv4Address.Ipv4Prefix) | Select-Object -First 1
                        $additionalSubnet = (Get-AzureRmVirtualNetwork -ResourceGroupName $ResourceGroupName | Where-Object { $_.AddressSpace.AddressPrefixes.Contains($adapterStartAddress) })[0] |
                        Get-AzureRmVirtualNetworkSubnetConfig

                        Write-Verbose -Message "adapterStartAddress = '$adapterStartAddress'"
                        $vNet = $LabVirtualNetworkDefinition | Where-Object { $_.AddressSpace.AddressAsString -eq $adapterStartAddress }
                        if ($vNet)
                        {
                            Write-Verbose -Message "Adding additional network adapter with Vnet '$($vNet.Name)' in subnet '$adapterStartAddress' with IP address '$($adapter.Ipv4Address.AddressAsString)'"
                            $networkInterface = New-AzureRmNetworkInterface -Name ($adapter.Ipv4Address.AddressAsString) `
                            -ResourceGroupName $ResourceGroupName -Location $Location `
                            -Subnet $additionalSubnet -PrivateIpAddress ($adapter.Ipv4Address.AddressAsString)
        
                            $vm = Add-AzureRmVMNetworkInterface -VM $vm -Id $networkInterface.Id -ErrorAction Stop
                        }
                        else
                        {
                            throw "Vnet could not be determined for network adapter with IP address of '$(Get-NetworkRange -IPAddress ($adapter.Ipv4Address.AddressAsString) -SubnetMask ($adapter.Ipv4Address.Ipv4Prefix)))'"
                        }
                    }
                }
            }

            Write-Verbose -Message 'Calling New-AzureRMVm'
            New-AzureRmVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vm -Tags @{ AutomatedLab = $script:lab.Name; CreationTime = Get-Date } -ErrorAction Stop
        }

        Write-LogFunctionExit
    }

    Function Initialize-LWAzureVM
    {
        [Cmdletbinding()]
        Param (
            [Parameter(Mandatory)]
            [AutomatedLab.Machine[]]$Machine
        )

        $initScript = {
            param
            (
                [Parameter(Mandatory = $true)]
                $MachineSettings
            )

            #region Region Settings Xml
                $regionSettings = (Dec64 'PGdzOkdsb2JhbGl6YXRpb25TZXJ2aWNlcyB4bWxuczpncz0idXJuOmxvbmdob3JuR2xvYmFsaXphdGlvblVuYXR0ZW5kIj4gDQogDQogI
                                          CAgPCEtLSB1c2VyIGxpc3QgLS0+IA0KICAgIDxnczpVc2VyTGlzdD4gDQogICAgPGdzOlVzZXIgVXNlcklEPSJDdXJyZW50IiBDb3B5U2
                                          V0dGluZ3NUb0RlZmF1bHRVc2VyQWNjdD0idHJ1ZSIgQ29weVNldHRpbmdzVG9TeXN0ZW1BY2N0PSJ0cnVlIi8+IA0KICAgIDwvZ3M6VXN
                                          lckxpc3Q+IA0KIA0KICAgIDwhLS0gR2VvSUQgLS0+IA0KICAgIDxnczpMb2NhdGlvblByZWZlcmVuY2VzPiANCiAgICA8Z3M6R2VvSUQg
                                          VmFsdWU9InsxfSIvPiANCiAgICA8L2dzOkxvY2F0aW9uUHJlZmVyZW5jZXM+IA0KIA0KICAgIDwhLS0gc3lzdGVtIGxvY2FsZSAtLT4gD
                                          QogICAgPGdzOlN5c3RlbUxvY2FsZSBOYW1lPSJ7MH0iLz4gDQogDQo8IS0tIHVzZXIgbG9jYWxlIC0tPiANCiAgICA8Z3M6VXNlckxvY2
                                          FsZT4gDQogICAgPGdzOkxvY2FsZSBOYW1lPSJ7MH0iIFNldEFzQ3VycmVudD0idHJ1ZSIgUmVzZXRBbGxTZXR0aW5ncz0idHJ1ZSIvPiA
                                          NCiAgICA8L2dzOlVzZXJMb2NhbGU+IA0KIA0KPC9nczpHbG9iYWxpemF0aW9uU2VydmljZXM+IA==')
            #endregion

            $geoId = 94 #default is US

            $computerName = ($env:ComputerName).ToUpper()
            $tempFile = [System.IO.Path]::GetTempFileName()
            $regsettings = ($MachineSettings."$computerName")[1]
            Write-Verbose -Message "Regional Settings for $computerName`: $regsettings"
            $regionSettings -f ($MachineSettings."$computerName")[0], $geoId | Out-File -FilePath $tempFile
            $argument = 'intl.cpl,,/f:"{0}"' -f $tempFile
            control.exe $argument
            Start-Sleep -Seconds 1
            Remove-Item -Path $tempFile

            Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force

            #Set Power Scheme to High Performance
            powercfg.exe -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

            #Map the Azure lab source drive
            $azureCredential = New-Object pscredential (($MachineSettings."$computerName")[4], (ConvertTo-SecureString -String ($MachineSettings."$computerName")[5] -AsPlainText -Force))

            $azureDrive = New-PSDrive -Name X -PSProvider FileSystem -Root ($MachineSettings."$computerName")[3] -Description 'Azure lab sources' -Persist -Credential $azureCredential -ErrorAction SilentlyContinue
            if(-not $azureDrive)
            {
                Write-Warning "Could not map $(($MachineSettings."$computerName")[3]) as drive X. Post-installations might fail."
            }

            #set the time zone
                $timezone = ($MachineSettings."$computerName")[1]
                Write-Verbose -Message "Time zone for $computerName`: $regsettings"
                tzutil.exe /s $regsettings

                reg.exe add 'HKLM\SOFTWARE\Microsoft\ServerManager\oobe' /v DoNotOpenInitialConfigurationTasksAtLogon /d 1 /t REG_DWORD /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\ServerManager' /v DoNotOpenServerManagerAtLogon /d 1 /t REG_DWORD /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v EnableFirstLogonAnimation /d 0 /t REG_DWORD /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v FilterAdministratorToken /t REG_DWORD /d 0 /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v EnableLUA /t REG_DWORD /d 0 /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' /v IsInstalled /t REG_DWORD /d 0 /f #disable admin IE Enhanced Security Configuration
                reg.exe add 'HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}' /v IsInstalled /t REG_DWORD /d 0 /f #disable user IE Enhanced Security Configuration

            #turn off the Windows firewall
            #netsh.exe advfirewall set domain state off
            #netsh.exe advfirewall set private state off
            #netsh.exe advfirewall set public state off
        
            $disks = ($MachineSettings."$computerName")[2]
            Write-Verbose -Message "Disk count for $computerName`: $disks"
            if ([int]$disks -gt 0)
            {
                $diskpartCmd = 'LIST DISK'

                $disks = $diskpartCmd | diskpart.exe

                foreach ($line in $disks)
                {
                    if ($line -match 'Disk (?<DiskNumber>\d) \s+(Online|Offline)\s+(?<Size>\d+) GB\s+(?<Free>\d+) GB')
                    {
                        $nextDriveLetter = [char[]](67..90) | 
                        Where-Object { (Get-WmiObject -Class Win32_LogicalDisk | 
                        Select-Object -ExpandProperty DeviceID) -notcontains "$($_):"} | 
                        Select-Object -First 1

                        $diskNumber = $Matches.DiskNumber

                        $diskpartCmd = "@ 
                            SELECT DISK $diskNumber 
                            ATTRIBUTES DISK CLEAR READONLY 
                            ONLINE DISK 
                            CREATE PARTITION PRIMARY 
                            ASSIGN LETTER=$nextDriveLetter 
                            EXIT 
                        @"
                        $diskpartCmd | diskpart.exe | Out-Null

                        Start-Sleep -Seconds 2

                        cmd.exe /c "echo y | format $($nextDriveLetter): /q /v:DataDisk$diskNumber"
                    }
        
                }
            }
        }

        Write-LogFunctionEntry
    
        $lab = Get-Lab

        Write-ScreenInfo -Message 'Waiting for all machines to be visible in Azure'
        while ((Get-AzureRmVM -ResourceGroupName $lab.Name -WarningAction SilentlyContinue | Where-Object Name -in $Machine.Name).Count -ne $Machine.Count)
        {        
            Start-Sleep -Seconds 10
            Write-Verbose 'Still waiting for all machines to be visible in Azure'
        }
        Write-ScreenInfo -Message "$($Machine.Count) new machine(s) has been created and now visible in Azure"
        Write-ScreenInfo -Message 'Waiting until all machines have a DNS name in Azure'
        while ((Get-LabMachine).AzureConnectionInfo.DnsName.Count -ne (Get-LabMachine).Count)
        {
            Start-Sleep -Seconds 10
            Write-ScreenInfo -Message 'Still waiting until all machines have a DNS name in Azure'
        }
        Write-ScreenInfo -Message "DNS names found: $((Get-LabMachine).AzureConnectionInfo.DnsName.Count)"

        #refresh the machine list to have also Azure meta date is available
        $Machine = Get-LabMachine -ComputerName $Machine

        #Point out first added machine as staging machine for staging Tools folder and alike
        $stagingMachine = $Machine[0]
    
        #copy AL tools to lab machine and optionally the tools folder
        Write-ScreenInfo -Message "Waiting for machine '$stagingMachine' to be accessible" -NoNewLine
        Wait-LabVM -ComputerName $stagingMachine -ProgressIndicator 15 -ErrorAction Stop
    
        $toolsDestination = "$($stagingMachine.ToolsPath)"
        if ($stagingMachine.ToolsPathDestination)
        {
            $toolsDestination = "$($stagingMachine.ToolsPathDestination)"
        }
    
        if ($Machine | Where-Object {$_.ToolsPath -ne ''})
        {
            #Compress all tools for all machines into one zip file
            $tempFolderPath = [System.IO.Path]::GetTempFileName()
            Remove-Item -Path $tempFolderPath
            $tempFolderPath = "$tempFolderPath.tmp"
        
            New-Item -ItemType Directory -Path "$tempFolderPath.tmp" | Out-Null
        
            $tempFilePath = [System.IO.Path]::GetTempFileName()
            Remove-Item -Path $tempFilePath
            $tempFilePath = $tempFilePath -replace '\.tmp', '.zip'
        
            foreach ($m in $Machine)
            {
                New-Item -ItemType Directory -Path "$tempFolderPath\$($m.Name)" | Out-Null
                if ($m -ne $stagingMachine -and $m.ToolsPath -and $m.ToolsPath -eq $stagingMachine.ToolsPath)
                {
                    New-Item -ItemType File -Path "$tempFolderPath\$($m.Name)\Replica-$($stagingMachine.Name)" | Out-Null
                }
                elseif ($m.ToolsPath)
                {
                    Get-ChildItem -Path "$($m.ToolsPath)" | Copy-Item -Destination "$tempFolderPath\$($m.Name)" -Recurse
                }
            }   
        
            Write-Verbose -Message "Tools destination for staging machine: $($toolsDestination)"
        
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::CreateFromDirectory($tempFolderPath, $tempFilePath) 
        
        
            Write-ScreenInfo -Message "Starting copy of Tools ($([int]((Get-Item $tempfilepath).length/1kb)) KB) to staging machine '$stagingMachine'" -TaskStart
            Send-File -Source $tempFilePath -Destination C:\AutomatedLabTools.zip -Session (New-LabPSSession -ComputerName $stagingMachine)
            Write-ScreenInfo -Message 'Finished' -TaskEnd
        
            Remove-Item -Path $tempFilePath -Force
            Remove-Item -Path $tempFolderPath -Recurse -Force
        
        
            #Expand files on staging machine and create a share for other machines to access
            $job = Invoke-LabCommand -ComputerName $stagingMachine -ActivityName 'Expanding Tools Zip File' -NoDisplay -ArgumentList $toolsDestination -ScriptBlock `
            {
                param
                (
                    [string]$ToolsDestination
                )
        
                if (-not (Test-Path 'C:\AutomatedLabTools'))
                {
                    New-Item -ItemType Directory -Path 'C:\AutomatedLabTools' | Out-Null
                }

                if (-not (Test-Path $ToolsDestination))
                {
                    New-Item -ItemType Directory -Path $ToolsDestination | Out-Null
                }
            
                $shell = New-Object -ComObject Shell.Application
                $shell.namespace('C:\AutomatedLabTools').CopyHere($shell.Namespace('C:\AutomatedLabTools.zip').Items()) 
            
                if (Test-Path "C:\AutomatedLabTools\$(Hostname.exe)")
                {
                    Get-ChildItem -Path "C:\AutomatedLabTools\$(Hostname.exe)" | Copy-Item -Destination $ToolsDestination -Recurse
                }

                $shareClass = [WMICLASS]'WIN32_Share'
                $shareClass.Create('C:\AutomatedLabTools', 'AutomatedLabTools', 0)
            } -AsJob -PassThru
    
            Write-ScreenInfo -Message 'Waiting for Tools to be extracted on staging machine' -NoNewLine
            Wait-LWLabJob -Job $job -ProgressIndicator 5 -Timeout 30 -NoDisplay
    
    
            Write-ScreenInfo -Message 'Waiting for all machines to be accessible' -TaskStart -NoNewLine
            Write-Verbose "Staging machine is '$stagingMachine'"
            $otherMachines = Get-LabMachine | Where-Object Name -ne $stagingMachine
            #if the lab has not just one machine, wait for other machines
            if ($otherMachines)
            {
                Write-Verbose "Other machines are '$($otherMachines -join '. ')'"
                Wait-LabVM -ComputerName $otherMachines -ProgressIndicator 15 -ErrorAction Stop
            }
            Write-ScreenInfo -Message 'All machines are now accessible' -TaskEnd
    
            Write-ScreenInfo -Message 'Starting copy of Tools content to all machines' -TaskStart
    
            if ($otherMachines)
            {
                $jobs = Invoke-LabCommand -ComputerName $otherMachines -NoDisplay -AsJob -PassThru -ActivityName 'Copy tools from staged folder' -ScriptBlock `
                {
                    param
                    (
                        [Parameter(Mandatory = $true)]
                        [string]$Server,
                    
                        [Parameter(Mandatory = $true)]
                        [string]$User,
                    
                        [Parameter(Mandatory = $true)]
                        [string]$Password,
                    
                        [string]$ToolsDestination
                    )
                
                    #Remove-Item -Path C:\Tools -Recurse
                    $backupErrorActionPreference = $ErrorActionPreference
                    $ErrorActionPreference = 'SilentlyContinue'
                
                    net.exe use * "\\$Server\AutomatedLabTools" /user:$Server\$User $Password | Out-Null
                    $ErrorActionPreference = $backupErrorActionPreference
            
                    write-host '3'
                    if (Test-Path "\\$Server\AutomatedLabTools\$(Hostname.exe)\Replica-*")
                    {
                        $source = (Get-Item "\\$Server\AutomatedLabTools\$(Hostname.exe)\Replica-*").Name.Split('-', 2)[1]
                        Copy-Item "\\$Server\AutomatedLabTools\$source" -Destination $ToolsDestination -Recurse
                    }
                    else
                    {
                        Copy-Item "\\$Server\AutomatedLabTools\$(Hostname.exe)" -Destination $ToolsDestination -Recurse
                    }
                    $backupErrorActionPreference = $ErrorActionPreference
                    $ErrorActionPreference = 'SilentlyContinue'
                
                    net.exe use "\\$Server\AutomatedLabTools" /delete /yes | Out-Null
                    $ErrorActionPreference = $backupErrorActionPreference
                
                } -ArgumentList $stagingMachine.NetworkAdapters[0].Ipv4Address.IpAddress, $stagingMachine.InstallationUser.UserName, $stagingMachine.InstallationUser.Password, $toolsDestination
            }
        }
        Write-ScreenInfo -Message 'Finished' -TaskEnd

        Write-ScreenInfo -Message 'Configuring localization and additional disks' -TaskStart -NoNewLine
        $machineSettings = @{}
        foreach ($m in $Machine)
        {
            $machineSettings.Add($m.Name.ToUpper(), @($m.UserLocale, $m.TimeZone, [int]($m.Disks.Count), (Get-LabAzureLabSourcesStorage).Path, (Get-LabAzureLabSourcesStorage).StorageAccountName, (Get-LabAzureLabSourcesStorage).StorageAccountKey))
        }
        $jobs = Invoke-LabCommand -ComputerName $Machine -ActivityName VmInit -ScriptBlock $initScript -UseLocalCredential -ArgumentList $machineSettings -NoDisplay -AsJob -PassThru
        Wait-LWLabJob -Job $jobs -ProgressIndicator 5 -Timeout 30 -NoDisplay
        Write-ScreenInfo -Message 'Finished' -TaskEnd

        Enable-LabVMRemoting -ComputerName $Machine
    
        Write-ScreenInfo -Message 'Stopping all new machines except domain controllers'
        $machinesToStop = $Machine | Where-Object { $_.Roles.Name -notcontains 'RootDC' -and $_.Roles.Name -notcontains 'FirstChildDC' -and $_.Roles.Name -notcontains 'DC' -and $_.IsDomainJoined }
        if ($machinesToStop)
        {
            Stop-LWAzureVM -ComputerName $machinesToStop
            Wait-LabVMShutdown -ComputerName $machinesToStop
        }

        if ($machinesToStop)
        {
            Write-ScreenInfo -Message "$($Machine.Count) new Azure machines was configured. Some machines were stopped as they are not to be domain controllers '$($machinesToStop -join ', ')'"
        }
        else
        {
            Write-ScreenInfo -Message "($($Machine.Count)) new Azure machines was configured"
        }
        
        Write-LogFunctionExit
    }

    Function Remove-LWAzureVM
    {
        Param (
            [Parameter(Mandatory)]
            [string]$ComputerName,

            [switch]$AsJob,

            [switch]$PassThru
        )

        Write-LogFunctionEntry

        $Lab = Get-Lab

        if ($AsJob)
        {
            $job = Start-Job -ScriptBlock {
                param (
                    [Parameter(Mandatory)]
                    [hashtable]$ComputerName,
                    [Parameter(Mandatory)]
                    [string]$SubscriptionPath
                )

                Import-Module -Name Azure*
                Select-AzureRmProfile -Path $SubscriptionPath

                $resourceGroup = ((Get-LabMachine -ComputerName $ComputerName).AzureConnectionInfo.ResourceGroupName)

                $vm = Get-AzureRmVM -ResourceGroupName $resourceGroup -Name $ComputerName -WarningAction SilentlyContinue

                $vm | Remove-AzureRmVM -Force
            } -ArgumentList $ComputerName,$Lab.AzureSettings.AzureProfilePath

            if ($PassThru)
            {
                $job
            }
        }
        else
        {
            $resourceGroup = ((Get-LabMachine -ComputerName $ComputerName).AzureConnectionInfo.ResourceGroupName)
            $vm = Get-AzureRmVM -ResourceGroupName $resourceGroup -Name $ComputerName -WarningAction SilentlyContinue

            $result = $vm | Remove-AzureRmVM -Force
        }

        Write-LogFunctionExit
    }

    Function Start-LWAzureVM
    {
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$ComputerName,

            [int]$DelayBetweenComputers = 0,

            [int]$ProgressIndicator = 15,

            [switch]$NoNewLine
            )

        Write-LogFunctionEntry

        # This is ugly and will likely change in one of the next AzureRM module updates. PowerState is indeed a string literal instead of an Enum
        $azureVms = Get-AzureRmVM -WarningAction SilentlyContinue -Status -ResourceGroupName (Get-LabAzureDefaultResourceGroup).ResourceGroupName
        if (-not $azureVms)
        {
            throw 'Get-AzureRmVM did not return anything, stopping lab deployment. Code will be added to handle this error soon'
        }
        $resourceGroups = (Get-LabMachine -ComputerName $ComputerName).AzureConnectionInfo.ResourceGroupName | Select-Object -Unique
        $azureVms = $azureVms | Where-Object { $_.PowerState -ne 'VM running' -and  $_.Name -in $ComputerName -and $_.ResourceGroupName -in $resourceGroups }

        $retries = 5
        $machinesToJoin = @()

        foreach ($name in $ComputerName)
        {
            $vm = $azureVms | Where-Object Name -eq $name

            do {
                $result = $vm | Start-AzureRmVM -ErrorAction SilentlyContinue
                if ($result.Status -ne 'Succeeded')
                {
                    Start-Sleep -Seconds 10
                }
                $retries--
            }
            until ($retries -eq 0 -or $result.Status -eq 'Succeeded')

            if ($result.Status -ne 'Succeeded')
            {
                throw "Could not start machine '$name'"
            }
            else
            {
                $machine = Get-LabMachine -ComputerName $name
                #if the machine should be domain-joined but has not yet joined and is not a domain controller 
                if ($machine.IsDomainJoined -and -not $machine.HasDomainJoined -and ($machine.Roles.Name -notcontains 'RootDC' -and $machine.Roles.Name -notcontains 'FirstChildDC' -and $machine.Roles.Name -notcontains 'DC'))
                {
                    $machinesToJoin += $machine
                }
            }

            Start-Sleep -Seconds $DelayBetweenComputers
        }

        if ($machinesToJoin)
        {
            Write-Verbose -Message "Waiting for machines '$($machinesToJoin -join ', ')' to come online"
            Wait-LabVM -ComputerName $machinesToJoin -ProgressIndicator $ProgressIndicator -NoNewLine:$NoNewLine

            Write-Verbose -Message 'Start joining the machines to the respective domains'
            Join-LabVMDomain -Machine $machinesToJoin
        }

        Write-LogFunctionExit
    }

    Function Stop-LWAzureVM
    {
        param (
            [Parameter(Mandatory)]
            [string[]]$ComputerName,

            [int]$ProgressIndicator,

            [switch]$NoNewLine,

            [switch]$ShutdownFromOperatingSystem
        )

        Write-LogFunctionEntry

      $lab = Get-Lab
        $azureVms = Get-AzureRmVM -WarningAction SilentlyContinue 
        $resourceGroups = (Get-LabMachine -ComputerName $ComputerName).AzureConnectionInfo.ResourceGroupName | Select-Object -Unique
        $azureVms = $azureVms | Where-Object { $_.Name -in $ComputerName -and $_.ResourceGroupName -in $resourceGroups }

        if ($ShutdownFromOperatingSystem)
        {
            $jobs = @()
            $jobs = Invoke-LabCommand -ComputerName $ComputerName -NoDisplay -AsJob -PassThru -ScriptBlock { shutdown.exe -s -t 0 -f }
            Wait-LWLabJob -Job $jobs -NoDisplay -ProgressIndicator $ProgressIndicator
            $failedJobs = $jobs | Where-Object {$_.State -eq 'Failed'}
            if ($failedJobs)
            {
                Write-ScreenInfo -Message "Could not stop Azure VM(s): '$($failedJobs.Location)'" -Type Error
            }
        }
        else
        {
        $jobs = @() 

            foreach ($name in $ComputerName)
            {
                $vm = $azureVms | Where-Object Name -eq $name 
                $jobs += Start-Job -Name "StopAzureVm_$name" -ScriptBlock {
            param
            (
              [object]$Machine,
              [string]$SubscriptionPath
            )
            Import-Module -Name Azure*
            Select-AzureRmProfile -Path $SubscriptionPath
            $result = $Machine | Stop-AzureRmVM -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Force

            if ($result.Status -ne 'Succeeded')
            {
              Write-Error -Message 'Could not stop Azure VM' -TargetObject $Machine.Name
            }
          } -ArgumentList @($vm, $lab.AzureSettings.AzureProfilePath)
            }

        Wait-LWLabJob -Job $jobs -NoDisplay -ProgressIndicator $ProgressIndicator
            $failedJobs = $jobs | Where-Object {$_.State -eq 'Failed'}
            if ($failedJobs)
            {
          $jobNames = ($failedJobs | foreach {if($_.Name.StartsWith("StopAzureVm_")){($_.Name -split "_")[1]}}) -join ", "
                Write-ScreenInfo -Message "Could not stop Azure VM(s): '$jobNames'" -Type Error
            }

        }
    
        if ($ProgressIndicator -and (-not $NoNewLine))
        {
            Write-ProgressIndicatorEnd
        }

        Write-LogFunctionExit
    }

    Function Wait-LWAzureRestartVM
    {
        param (
            [Parameter(Mandatory)]
            [string[]]$ComputerName,

            [double]$TimeoutInMinutes = 15,

            [int]$ProgressIndicator,

            [switch]$NoNewLine
        )

        #required to suporess verbose messages, warnings and errors
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-LogFunctionEntry

        $start = (Get-Date).ToUniversalTime()

        Write-Verbose -Message "Starting monitoring the servers at '$start'"

        $machines = Get-LabMachine -ComputerName $ComputerName

        $cmd = {
            param (
                [datetime]$Start
            )

            $Start = $Start.ToLocalTime()

            $events = Get-EventLog -LogName System -InstanceId 2147489653 -After $Start -Before $Start.AddMinutes(40)

            $events
        }

        $ProgressIndicatorTimer = (Get-Date)

        do
        {
            $machines = foreach ($machine in $machines)
            {
                if (((Get-Date) - $ProgressIndicatorTimer).TotalSeconds -ge $ProgressIndicator)
                {
                    Write-ProgressIndicator
                    $ProgressIndicatorTimer = (Get-Date)
                }
            
                $events = Invoke-LabCommand -ComputerName $machine -ActivityName WaitForRestartEvent -ScriptBlock $cmd -ArgumentList $start.Ticks -UseLocalCredential -PassThru -Verbose:$false -NoDisplay -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                if (-not $events)
                {
                    $events = Invoke-LabCommand -ComputerName $machine -ActivityName WaitForRestartEvent -ScriptBlock $cmd -ArgumentList $start.Ticks -PassThru -Verbose:$false -NoDisplay -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                }

                if ($events)
                {
                    Write-Verbose -Message "VM '$machine' has been restarted"
                }
                else
                {
                    $machine
                }
            }
        }
        until ($machines.Count -eq 0 -or (Get-Date).ToUniversalTime().AddMinutes(-$TimeoutInMinutes) -gt $start)

        if (-not $NoNewLine)
        {
            Write-ProgressIndicatorEnd
        }
    
        if ((Get-Date).ToUniversalTime().AddMinutes(-$TimeoutInMinutes) -gt $start)
        {
            foreach ($machine in ($machines))
            {
                Write-Error -Message "Timeout while waiting for computers to restart. Computers '$machine' not restarted" -TargetObject $machine
            }
        }
    
        Write-Verbose -Message "Finished monitoring the servers at '$(Get-Date)'"

        Write-LogFunctionExit
    }

    Function Get-LWAzureVMStatus
    {
        param (
            [Parameter(Mandatory)]
            [string[]]$ComputerName
        )

        #required to suporess verbose messages, warnings and errors
        Get-CallerPreference -Cmdlet $PSCmdlet -SessionState $ExecutionContext.SessionState

        Write-LogFunctionEntry

        $result = @{ }
        $azureVms = Get-AzureRmVM -WarningAction SilentlyContinue -Status (Get-LabAzureDefaultResourceGroup).ResourceGroupName
        if (-not $azureVms)
        {
            throw 'Get-AzureRmVM did not return anything, stopping lab deployment. Code will be added to handle this error soon'
        }
        $resourceGroups = (Get-LabMachine).AzureConnectionInfo.ResourceGroupName | Select-Object -Unique
        $azureVms = $azureVms | Where-Object { $_.Name -in $ComputerName -and $_.ResourceGroupName -in $resourceGroups }

        foreach ($azureVm in $azureVms)
        {
            if ($azureVm.PowerState -eq 'VM running')
            {
                $result.Add($azureVm.Name, 'Started')
            }
            elseif ($azureVm.PowerState -eq 'VM stopped' -or $azureVm.PowerState -eq 'VM deallocated')
            {
                $result.Add($azureVm.Name, 'Stopped')
            }
            else
            {
                $result.Add($azureVm.Name, 'Unknown')
            }
        }

        $result

        Write-LogFunctionExit
    }


    Function Get-LWAzureVMConnectionInfo
    {
        param (
            [Parameter(Mandatory)]
            [string[]]$ComputerName
        )

        Write-LogFunctionEntry

        $azureVMs = Get-AzureRmVM -WarningAction SilentlyContinue | Where-Object ResourceGroupName -in (Get-LabAzureResourceGroup).ResourceGroupName | Where-Object Name -in $ComputerName

        foreach ($name in $ComputerName)
        {
            $azureVM = $azureVMs | Where-Object Name -eq $name

            if (-not $azureVM)
            { return } 

            $nic = Get-AzureRmNetworkInterface | Where {$_.virtualmachine.id -eq ($azureVM.Id)}
            $ip = Get-AzureRmPublicIpAddress | where {$_.Id -eq $nic.IpConfigurations.publicipaddress.id}

            # Why are DnsName and HttpsName being used? Seems like it would be the same anyway...
            New-Object PSObject -Property @{
                ComputerName = $name
                DnsName = $ip.DnsSettings.Fqdn
                HttpsName = $ip.DnsSettings.Fqdn
                VIP = $ip.IpAddress
                Port = 5985
                RdpPort = 3389
                ResourceGroupName = $azureVM.ResourceGroupName
            }
        }

        Write-LogFunctionExit
    }

    Function Enable-LWAzureVMRemoting
    {
        param(
            [Parameter(Mandatory, Position = 0)]
            [string[]]$ComputerName,
            [switch]$UseSSL
        )

        if ($ComputerName)
        {
            $machines = Get-LabMachine -All | Where-Object Name -in $ComputerName
        }
        else
        {
            $machines = Get-LabMachine -All
        }

        $script = {
            param ($DomainName, $UserName, $Password)

            $RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'

            Set-ItemProperty -Path $RegPath -Name AutoAdminLogon -Value 1 -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $RegPath -Name DefaultUserName -Value $UserName -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $RegPath -Name DefaultPassword -Value $Password -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $RegPath -Name DefaultDomainName -Value $DomainName -ErrorAction SilentlyContinue

            #Enable-WSManCredSSP works fine when called remotely on 2012 servers but not on 2008 (Access Denied). In case Enable-WSManCredSSP fails
            #the settings are done in the registry directly
            try
            {
                Enable-WSManCredSSP -Role Server -Force | Out-Null
            }
            catch
            {
                New-ItemProperty -Path HKLM:\software\Microsoft\Windows\CurrentVersion\WSMAN\Service -Name auth_credssp -Value 1 -PropertyType DWORD -Force
                New-ItemProperty -Path HKLM:\software\Microsoft\Windows\CurrentVersion\WSMAN\Service -Name allow_remote_requests -Value 1 -PropertyType DWORD -Force
            }
        }

        foreach ($machine in $machines)
        {
            $cred = $machine.GetCredential((Get-Lab))
            try
            {
                Invoke-LabCommand -ComputerName $machine -ActivityName SetLabVMRemoting -NoDisplay -ScriptBlock $script `
                -ArgumentList $machine.DomainName, $cred.UserName, $cred.GetNetworkCredential().Password -ErrorAction Stop
            }
            catch
            {
                if ($UseSSL)
                {
                    Connect-WSMan -ComputerName $machine.AzureConnectionInfo.DnsName -Credential $cred -Port $machine.AzureConnectionInfo.Port -UseSSL -SessionOption (New-WSManSessionOption -SkipCACheck -SkipCNCheck)
                }
                else
                {
                    Connect-WSMan -ComputerName $machine.AzureConnectionInfo.DnsName -Credential $cred -Port $machine.AzureConnectionInfo.Port
                }
                Set-Item -Path "WSMan:\$($machine.AzureConnectionInfo.DnsName)\Service\Auth\CredSSP" -Value $true
                Disconnect-WSMan -ComputerName $machine.AzureConnectionInfo.DnsName
            }
        }
    }
#endregion AutomatedLabAzureWorkerVMs


Function Kill-Bastion
{
    # Kill-Bastion -rsgName "rsg_CamRemWKS" -bstnName "rsg_CamRemWKS-vnet-bastion"
    Param
    (
        $rsgName,
        $bstnName
    )
    Get-AzBastion -ResourceGroupName $rsgName -Name $bstnName | Remove-AzBastion -Verbose
}
