
#region - RemoteSQLSever
    #region - RemoteSQLServer.ps1
    <#
        # Implicit remoting module
        # generated on 10/20/2022 12:34:48 PM
        # by Export-PSSession cmdlet
        # Invoked with the following command line:     Export-PSSession -Session $session -CommandName *-Sql* -OutputModule RemoteSQLServer -AllowClobber
    #>

        
    @{
        GUID = 'eda65b0f-805d-4ae4-9a4d-fbcff54d2a87'
        Description = 'Implicit remoting for http://fabconsql01/wsman'
        ModuleToProcess = @('RemoteSQLServer.psm1')
        FormatsToProcess = @('RemoteSQLServer.format.ps1xml')

        ModuleVersion = '1.0'

        PrivateData = @{
            ImplicitRemoting = $true
        }
    }
    #endregion
    #region - RemoteSQLServer.psm1

    <#
     # Implicit remoting module
     # generated on 10/20/2022 12:34:48 PM
     # by Export-PSSession cmdlet
     # Invoked with the following command line:     Export-PSSession -Session $session -CommandName *-Sql* -OutputModule RemoteSQLServer -AllowClobber

     #>
        
    param(
        <# Optional parameter that can be used to specify the session on which this proxy module works #>    
        [System.Management.Automation.Runspaces.PSSession] $PSSessionOverride,
        [System.Management.Automation.Remoting.PSSessionOption] $PSSessionOptionOverride
    )

    $script:__psImplicitRemoting_versionOfScriptGenerator = [Microsoft.PowerShell.Commands.ExportPSSessionCommand, Microsoft.PowerShell.Commands.Utility, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]::VersionOfScriptGenerator
    if ($script:__psImplicitRemoting_versionOfScriptGenerator.Major -ne 1.0)
    {
        throw 'The module cannot be loaded because it has been generated with an incompatible version of the Export-PSSession cmdlet. Generate the module with the Export-PSSession cmdlet from the current session, and try loading the module again.'
    }


    $script:WriteHost = $executionContext.InvokeCommand.GetCommand('Write-Host', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:WriteWarning = $executionContext.InvokeCommand.GetCommand('Write-Warning', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:WriteInformation = $executionContext.InvokeCommand.GetCommand('Write-Information', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:GetPSSession = $executionContext.InvokeCommand.GetCommand('Get-PSSession', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:NewPSSession = $executionContext.InvokeCommand.GetCommand('New-PSSession', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:ConnectPSSession = $executionContext.InvokeCommand.GetCommand('Connect-PSSession', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:NewObject = $executionContext.InvokeCommand.GetCommand('New-Object', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:RemovePSSession = $executionContext.InvokeCommand.GetCommand('Remove-PSSession', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:InvokeCommand = $executionContext.InvokeCommand.GetCommand('Invoke-Command', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:SetItem = $executionContext.InvokeCommand.GetCommand('Set-Item', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:ImportCliXml = $executionContext.InvokeCommand.GetCommand('Import-CliXml', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:NewPSSessionOption = $executionContext.InvokeCommand.GetCommand('New-PSSessionOption', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:JoinPath = $executionContext.InvokeCommand.GetCommand('Join-Path', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:ExportModuleMember = $executionContext.InvokeCommand.GetCommand('Export-ModuleMember', [System.Management.Automation.CommandTypes]::Cmdlet)
    $script:SetAlias = $executionContext.InvokeCommand.GetCommand('Set-Alias', [System.Management.Automation.CommandTypes]::Cmdlet)

    $script:MyModule = $MyInvocation.MyCommand.ScriptBlock.Module
        
    ##############################################################################

    function Write-PSImplicitRemotingMessage
    {
        param(
            [Parameter(Mandatory = $true, Position = 0)]
            [string]
            $message)
        
        try { & $script:WriteHost -Object $message -ErrorAction SilentlyContinue } catch { }
    }

    function Get-PSImplicitRemotingSessionOption
                                    {
    if ($PSSessionOptionOverride -ne $null)
    {
        return $PSSessionOptionOverride
    }
    else
    {
        return $(& $script:NewPSSessionOption -Culture 'en-US' -UICulture 'en-US' -CancelTimeOut 60000 -IdleTimeOut 7200000 -OpenTimeOut 180000 -OperationTimeOut 180000 -MaximumReceivedObjectSize 209715200 -MaximumRedirection 0 -ProxyAccessType None -ProxyAuthentication Negotiate )
    }
    }

    $script:PSSession = $null

    function Get-PSImplicitRemotingModuleName { $myInvocation.MyCommand.ScriptBlock.File }

    function Set-PSImplicitRemotingSession
                                                                                                            {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowNull()]
        [Management.Automation.Runspaces.PSSession] 
        $PSSession, 

        [Parameter(Mandatory = $false, Position = 1)]
        [bool] $createdByModule = $false)

    if ($PSSession -ne $null)
    {
        $script:PSSession = $PSSession

        if ($createdByModule -and ($script:PSSession -ne $null))
        {
            $moduleName = Get-PSImplicitRemotingModuleName 
            $script:PSSession.Name = 'Session for implicit remoting module at {0}' -f $moduleName
            
            $oldCleanUpScript = $script:MyModule.OnRemove
            $removePSSessionCommand = $script:RemovePSSession
            $script:MyModule.OnRemove = { 
                & $removePSSessionCommand -Session $PSSession -ErrorAction SilentlyContinue
                if ($oldCleanUpScript)
                {
                    & $oldCleanUpScript $args
                }
            }.GetNewClosure()
        }
    }
    }

    if ($PSSessionOverride) { Set-PSImplicitRemotingSession $PSSessionOverride }

    function Get-PSImplicitRemotingSession
                                                                                                                                                                                                                        {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string] 
        $commandName
    )

    $savedImplicitRemotingHash = ''

    if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
    {
        Set-PSImplicitRemotingSession `
            (& $script:GetPSSession `
                -InstanceId b84633f4-4278-4eae-a157-56aecb1ff6e0 `
                -ErrorAction SilentlyContinue )
    }
    if (($script:PSSession -ne $null) -and ($script:PSSession.Runspace.RunspaceStateInfo.State -eq 'Disconnected'))
    {
        # If we are handed a disconnected session, try re-connecting it before creating a new session.
        Set-PSImplicitRemotingSession `
            (& $script:ConnectPSSession `
                -Session $script:PSSession `
                -ErrorAction SilentlyContinue)
    }
    if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
    {
        Write-PSImplicitRemotingMessage ('Creating a new session for implicit remoting of "{0}" command...' -f $commandName)

        Set-PSImplicitRemotingSession `
            -CreatedByModule $true `
            -PSSession ( 
            $( 
                & $script:NewPSSession `
                    -ComputerName 'fabconsql01' `
                    -ApplicationName 'wsman'    -ConfigurationName 'Microsoft.PowerShell' `
                    -SessionOption (Get-PSImplicitRemotingSessionOption) `
                     `
                     `
                    -Authentication Default `
                     `
            )
    )

        if ($savedImplicitRemotingHash -ne '')
        {
            $newImplicitRemotingHash = [string]($script:PSSession.ApplicationPrivateData.ImplicitRemoting.Hash)
            if ($newImplicitRemotingHash -ne $savedImplicitRemotingHash)
            {
                & $script:WriteWarning -Message 'Commands that are available in the new remote session are different than those available when the implicit remoting module was created.  Consider creating the module again by using the Export-PSSession cmdlet.'
            }
        }

        
    }
    if (($script:PSSession -eq $null) -or ($script:PSSession.Runspace.RunspaceStateInfo.State -ne 'Opened'))
    {
        throw 'No session has been associated with this implicit remoting module.'
    }
    return [Management.Automation.Runspaces.PSSession]$script:PSSession
    }

    function Modify-PSImplicitRemotingParameters
                                                                                    {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [hashtable]
        $clientSideParameters,

        [Parameter(Mandatory = $true, Position = 1)]
        $PSBoundParameters,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $parameterName,

        [Parameter()]
        [switch]
        $leaveAsRemoteParameter)
        
    if ($PSBoundParameters.ContainsKey($parameterName))
    {
        $clientSideParameters.Add($parameterName, $PSBoundParameters[$parameterName])
        if (-not $leaveAsRemoteParameter) { 
            $null = $PSBoundParameters.Remove($parameterName) 
        }
    }
    }

    function Get-PSImplicitRemotingClientSideParameters
                                                                                                {
    param(
        [Parameter(Mandatory = $true, Position = 1)]
        $PSBoundParameters,

        [Parameter(Mandatory = $true, Position = 2)]
        $proxyForCmdlet)

    $clientSideParameters = @{}
    $parametersToLeaveRemote = 'ErrorAction', 'WarningAction', 'InformationAction'

    Modify-PSImplicitRemotingParameters $clientSideParameters $PSBoundParameters 'AsJob'
    if ($proxyForCmdlet)
    {
        foreach($parameter in [System.Management.Automation.Cmdlet]::CommonParameters)
        {
            if($parametersToLeaveRemote -contains $parameter)
            {
                Modify-PSImplicitRemotingParameters $clientSideParameters $PSBoundParameters $parameter -LeaveAsRemoteParameter
            }
            else
            {
                Modify-PSImplicitRemotingParameters $clientSideParameters $PSBoundParameters $parameter
            }
        }
    }

    return $clientSideParameters
    }

    ##############################################################################

    & $script:SetItem 'function:script:ConvertFrom-EncodedSqlName' `
                                                                                                                                                                                                                                                                                        {
    param(
    
    [Alias('wv')]
    ${WarningVariable},

    [Alias('iv')]
    ${InformationVariable},

    [Alias('pv')]
    ${PipelineVariable},

    [Alias('vb')]
    [switch]
    ${Verbose},

    [Alias('infa')]
    ${InformationAction},

    [Alias('db')]
    [switch]
    ${Debug},

    [Alias('ov')]
    ${OutVariable},

    [Alias('ob')]
    ${OutBuffer},

    ${SqlName},

    [Alias('ev')]
    ${ErrorVariable},

    [Alias('ea')]
    ${ErrorAction},

    [Alias('wa')]
    ${WarningAction},

    [switch]
    ${AsJob})

    Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'ConvertFrom-EncodedSqlName') `
                            -Arg ('ConvertFrom-EncodedSqlName', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
    Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
    End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

    # .ForwardHelpTargetName ConvertFrom-EncodedSqlName
    # .ForwardHelpCategory Alias
    # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:ConvertTo-EncodedSqlName' `
                                                                                                                                                                                                                                                                                        {
    param(
    
    [Alias('wv')]
    ${WarningVariable},

    [Alias('iv')]
    ${InformationVariable},

    [Alias('pv')]
    ${PipelineVariable},

    [Alias('vb')]
    [switch]
    ${Verbose},

    [Alias('infa')]
    ${InformationAction},

    [Alias('db')]
    [switch]
    ${Debug},

    [Alias('ov')]
    ${OutVariable},

    [Alias('ob')]
    ${OutBuffer},

    ${SqlName},

    [Alias('ev')]
    ${ErrorVariable},

    [Alias('ea')]
    ${ErrorAction},

    [Alias('wa')]
    ${WarningAction},

    [switch]
    ${AsJob})

    Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'ConvertTo-EncodedSqlName') `
                            -Arg ('ConvertTo-EncodedSqlName', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
    Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
    End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

    # .ForwardHelpTargetName ConvertTo-EncodedSqlName
    # .ForwardHelpCategory Alias
    # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Add-SqlAvailabilityDatabase' `
                                                                                                                                                                                                                                                                                                                                {
    param(
    
    [Alias('ea')]
    ${ErrorAction},

    ${Database},

    ${InputObject},

    [Alias('ov')]
    ${OutVariable},

    [Alias('infa')]
    ${InformationAction},

    [Alias('wv')]
    ${WarningVariable},

    [Alias('vb')]
    [switch]
    ${Verbose},

    [Alias('db')]
    [switch]
    ${Debug},

    [Alias('pv')]
    ${PipelineVariable},

    [Alias('cf')]
    [switch]
    ${Confirm},

    [Alias('ev')]
    ${ErrorVariable},

    [Alias('ob')]
    ${OutBuffer},

    [Alias('wa')]
    ${WarningAction},

    [switch]
    ${Script},

    ${Path},

    [Alias('wi')]
    [switch]
    ${WhatIf},

    [Alias('iv')]
    ${InformationVariable},

    [switch]
    ${AsJob})

    Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'Add-SqlAvailabilityDatabase') `
                            -Arg ('Add-SqlAvailabilityDatabase', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
    Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
    End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

    # .ForwardHelpTargetName Add-SqlAvailabilityDatabase
    # .ForwardHelpCategory Cmdlet
    # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Add-SqlAvailabilityGroupListenerStaticIp' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${StaticIp},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Add-SqlAvailabilityGroupListenerStaticIp') `
                                -Arg ('Add-SqlAvailabilityGroupListenerStaticIp', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Add-SqlAvailabilityGroupListenerStaticIp
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Add-SqlFirewallRule' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        ${ManagementPublicPort},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Add-SqlFirewallRule') `
                                -Arg ('Add-SqlFirewallRule', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Add-SqlFirewallRule
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Backup-SqlDatabase' `
    {
        param(
    
        [Alias('wa')]
        ${WarningAction},

        ${UndoFileName},

        [switch]
        ${Restart},

        ${SqlCredential},

        [switch]
        ${FormatMedia},

        ${BlockSize},

        ${MediaDescription},

        ${InputObject},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${Path},

        ${MirrorDevices},

        ${Database},

        [Alias('infa')]
        ${InformationAction},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        ${ExpirationDate},

        ${BackupContainer},

        ${MaxTransferSize},

        [switch]
        ${Script},

        ${BufferCount},

        [Alias('wv')]
        ${WarningVariable},

        [switch]
        ${Checksum},

        ${DatabaseObject},

        [switch]
        ${Initialize},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${DatabaseFile},

        [switch]
        ${NoRewind},

        ${Credential},

        ${ConnectionTimeout},

        [Alias('ea')]
        ${ErrorAction},

        ${LogTruncationType},

        ${ServerInstance},

        [switch]
        ${ContinueAfterError},

        [Alias('ob')]
        ${OutBuffer},

        [switch]
        ${SkipTapeHeader},

        ${BackupSetDescription},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${NoRecovery},

        ${BackupSetName},

        ${BackupAction},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [switch]
        ${PassThru},

        [switch]
        ${CopyOnly},

        [Alias('ev')]
        ${ErrorVariable},

        ${CompressionOption},

        [Alias('iv')]
        ${InformationVariable},

        ${BackupDevice},

        ${EncryptionOption},

        ${RetainDays},

        ${BackupFile},

        [switch]
        ${Incremental},

        ${DatabaseFileGroup},

        [switch]
        ${UnloadTapeAfter},

        ${MediaName},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Backup-SqlDatabase') `
                                -Arg ('Backup-SqlDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Backup-SqlDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Disable-SqlAlwaysOn' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [Alias('pv')]
        ${PipelineVariable},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('infa')]
        ${InformationAction},

        [switch]
        ${NoServiceRestart},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        [switch]
        ${Force},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Disable-SqlAlwaysOn') `
                                -Arg ('Disable-SqlAlwaysOn', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Disable-SqlAlwaysOn
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Enable-SqlAlwaysOn' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [Alias('pv')]
        ${PipelineVariable},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('infa')]
        ${InformationAction},

        [switch]
        ${NoServiceRestart},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        [switch]
        ${Force},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Enable-SqlAlwaysOn') `
                                -Arg ('Enable-SqlAlwaysOn', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Enable-SqlAlwaysOn
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Get-SqlCredential' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        ${Name},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Get-SqlCredential') `
                                -Arg ('Get-SqlCredential', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Get-SqlCredential
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Get-SqlDatabase' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [Alias('pv')]
        ${PipelineVariable},

        ${InputObject},

        ${Name},

        [Alias('infa')]
        ${InformationAction},

        ${ConnectionTimeout},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        ${ServerInstance},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Get-SqlDatabase') `
                                -Arg ('Get-SqlDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Get-SqlDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Get-SqlInstance' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${RetryTimeout},

        ${Name},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        ${MachineName},

        ${ManagementPublicPort},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Get-SqlInstance') `
                                -Arg ('Get-SqlInstance', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Get-SqlInstance
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Get-SqlSmartAdmin' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        ${Name},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        ${DatabaseName},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        ${ServerInstance},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Get-SqlSmartAdmin') `
                                -Arg ('Get-SqlSmartAdmin', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Get-SqlSmartAdmin
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Invoke-Sqlcmd' `
    {
        param(
    
        ${Password},

        [Alias('wa')]
        ${WarningAction},

        ${OutputSqlErrors},

        ${ErrorLevel},

        ${SeverityLevel},

        [switch]
        ${DisableVariables},

        ${Query},

        [switch]
        ${AbortOnError},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        ${MaxBinaryLength},

        [switch]
        ${EncryptConnection},

        [switch]
        ${DedicatedAdministratorConnection},

        [Alias('As')]
        ${OutputAs},

        [Alias('ea')]
        ${ErrorAction},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [switch]
        ${IncludeSqlUserErrors},

        ${ConnectionTimeout},

        ${Username},

        ${ServerInstance},

        ${NewPassword},

        [switch]
        ${SuppressProviderContextWarning},

        [switch]
        ${DisableCommands},

        [Alias('ov')]
        ${OutVariable},

        ${Variable},

        ${ConnectionString},

        ${QueryTimeout},

        ${MaxCharLength},

        [Alias('iv')]
        ${InformationVariable},

        [Alias('wv')]
        ${WarningVariable},

        ${Database},

        ${HostName},

        [Alias('ob')]
        ${OutBuffer},

        [switch]
        ${IgnoreProviderContext},

        ${InputFile},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Invoke-Sqlcmd') `
                                -Arg ('Invoke-Sqlcmd', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Invoke-Sqlcmd
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Join-SqlAvailabilityGroup' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        ${Name},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Join-SqlAvailabilityGroup') `
                                -Arg ('Join-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Join-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlAvailabilityGroup' `
    {
        param(
    
        [switch]
        ${DatabaseHealthTrigger},

        ${Database},

        ${InputObject},

        ${Name},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('ev')]
        ${ErrorVariable},

        ${AutomatedBackupPreference},

        ${HealthCheckTimeout},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [switch]
        ${BasicAvailabilityGroup},

        [Alias('ob')]
        ${OutBuffer},

        ${FailureConditionLevel},

        [Alias('ea')]
        ${ErrorAction},

        [Alias('wa')]
        ${WarningAction},

        ${AvailabilityReplica},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${Script},

        ${Path},

        [switch]
        ${DtcSupportEnabled},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlAvailabilityGroup') `
                                -Arg ('New-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlAvailabilityGroupListener' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        ${Name},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${StaticIp},

        [Alias('ev')]
        ${ErrorVariable},

        ${DhcpSubnet},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${Script},

        ${Path},

        ${Port},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlAvailabilityGroupListener') `
                                -Arg ('New-SqlAvailabilityGroupListener', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlAvailabilityGroupListener
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlAvailabilityReplica' `
    {
        param(
    
        [Alias('wa')]
        ${WarningAction},

        ${ConnectionModeInPrimaryRole},

        ${SessionTimeout},

        ${Path},

        ${AvailabilityMode},

        [Alias('infa')]
        ${InformationAction},

        [Alias('db')]
        [switch]
        ${Debug},

        ${EndpointUrl},

        [Alias('wv')]
        ${WarningVariable},

        [switch]
        ${AsTemplate},

        ${Version},

        [Alias('ea')]
        ${ErrorAction},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [switch]
        ${Script},

        ${BackupPriority},

        ${ConnectionModeInSecondaryRole},

        ${ReadonlyRoutingConnectionUrl},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('ov')]
        ${OutVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${Name},

        [Alias('iv')]
        ${InformationVariable},

        [Alias('pv')]
        ${PipelineVariable},

        ${InputObject},

        ${ReadOnlyRoutingList},

        ${FailoverMode},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('ev')]
        ${ErrorVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlAvailabilityReplica') `
                                -Arg ('New-SqlAvailabilityReplica', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlAvailabilityReplica
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlBackupEncryptionOption' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${EncryptorName},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('ev')]
        ${ErrorVariable},

        ${EncryptorType},

        [switch]
        ${NoEncryption},

        ${Algorithm},

        [Alias('wa')]
        ${WarningAction},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlBackupEncryptionOption') `
                                -Arg ('New-SqlBackupEncryptionOption', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlBackupEncryptionOption
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlCredential' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${Secret},

        ${InputObject},

        ${Name},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('ov')]
        ${OutVariable},

        [Alias('ev')]
        ${ErrorVariable},

        ${Identity},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        ${ProviderName},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlCredential') `
                                -Arg ('New-SqlCredential', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlCredential
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:New-SqlHADREndpoint' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${Encryption},

        ${InputObject},

        ${IpAddress},

        ${Name},

        ${AuthenticationOrder},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${EncryptionAlgorithm},

        ${Certificate},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${Owner},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${Script},

        ${Path},

        ${Port},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'New-SqlHADREndpoint') `
                                -Arg ('New-SqlHADREndpoint', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName New-SqlHADREndpoint
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Remove-SqlAvailabilityDatabase' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Remove-SqlAvailabilityDatabase') `
                                -Arg ('Remove-SqlAvailabilityDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Remove-SqlAvailabilityDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Remove-SqlAvailabilityGroup' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Remove-SqlAvailabilityGroup') `
                                -Arg ('Remove-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Remove-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Remove-SqlAvailabilityReplica' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Remove-SqlAvailabilityReplica') `
                                -Arg ('Remove-SqlAvailabilityReplica', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Remove-SqlAvailabilityReplica
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Remove-SqlCredential' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Remove-SqlCredential') `
                                -Arg ('Remove-SqlCredential', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Remove-SqlCredential
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Remove-SqlFirewallRule' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        ${ManagementPublicPort},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Remove-SqlFirewallRule') `
                                -Arg ('Remove-SqlFirewallRule', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Remove-SqlFirewallRule
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Restore-SqlDatabase' `
    {
        param(
    
        [Alias('wa')]
        ${WarningAction},

        ${MediaName},

        ${StopAtMarkAfterDate},

        [switch]
        ${Restart},

        ${SqlCredential},

        [Alias('ob')]
        ${OutBuffer},

        ${BlockSize},

        ${RelocateFile},

        ${Path},

        [switch]
        ${KeepReplication},

        [switch]
        ${ReplaceDatabase},

        ${RestoreAction},

        [Alias('pv')]
        ${PipelineVariable},

        ${FileNumber},

        ${BufferCount},

        ${Offset},

        [Alias('wv')]
        ${WarningVariable},

        ${DatabaseObject},

        [Alias('ea')]
        ${ErrorAction},

        ${StopBeforeMarkAfterDate},

        [switch]
        ${Partial},

        [switch]
        ${NoRewind},

        ${Credential},

        [switch]
        ${UnloadTapeAfter},

        ${ConnectionTimeout},

        [Alias('ev')]
        ${ErrorVariable},

        ${StopBeforeMarkName},

        ${InputObject},

        ${ServerInstance},

        [switch]
        ${ContinueAfterError},

        [Alias('db')]
        [switch]
        ${Debug},

        ${StopAtMarkName},

        ${ToPointInTime},

        [switch]
        ${Script},

        [switch]
        ${RestrictedUser},

        [Alias('ov')]
        ${OutVariable},

        [switch]
        ${NoRecovery},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${StandbyFile},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${DatabaseFile},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [switch]
        ${PassThru},

        ${MaxTransferSize},

        [Alias('iv')]
        ${InformationVariable},

        ${BackupDevice},

        [switch]
        ${Checksum},

        ${Database},

        ${BackupFile},

        ${DatabaseFileGroup},

        [switch]
        ${ClearSuspectPageTable},

        [Alias('infa')]
        ${InformationAction},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Restore-SqlDatabase') `
                                -Arg ('Restore-SqlDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Restore-SqlDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Resume-SqlAvailabilityDatabase' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Resume-SqlAvailabilityDatabase') `
                                -Arg ('Resume-SqlAvailabilityDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Resume-SqlAvailabilityDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Save-SqlMigrationReport' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${Database},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${Password},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${MigrationType},

        [Alias('infa')]
        ${InformationAction},

        ${Server},

        [Alias('ob')]
        ${OutBuffer},

        ${Schema},

        ${Object},

        ${FolderPath},

        [Alias('ev')]
        ${ErrorVariable},

        ${Username},

        [Alias('wa')]
        ${WarningAction},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Save-SqlMigrationReport') `
                                -Arg ('Save-SqlMigrationReport', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Save-SqlMigrationReport
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlAuthenticationMode' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${SqlCredential},

        [switch]
        ${NoServiceRestart},

        [Alias('db')]
        [switch]
        ${Debug},

        [switch]
        ${ForceServiceRestart},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Mode},

        ${Path},

        ${ManagementPublicPort},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlAuthenticationMode') `
                                -Arg ('Set-SqlAuthenticationMode', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlAuthenticationMode
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlAvailabilityGroup' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${AutomatedBackupPreference},

        ${HealthCheckTimeout},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ob')]
        ${OutBuffer},

        ${FailureConditionLevel},

        ${DatabaseHealthTrigger},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlAvailabilityGroup') `
                                -Arg ('Set-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlAvailabilityGroupListener' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        ${Port},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlAvailabilityGroupListener') `
                                -Arg ('Set-SqlAvailabilityGroupListener', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlAvailabilityGroupListener
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlAvailabilityReplica' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [Alias('iv')]
        ${InformationVariable},

        ${InputObject},

        ${BackupPriority},

        ${ConnectionModeInSecondaryRole},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${FailoverMode},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('db')]
        [switch]
        ${Debug},

        ${ReadOnlyRoutingList},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('ov')]
        ${OutVariable},

        ${ConnectionModeInPrimaryRole},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        ${AvailabilityMode},

        [Alias('ob')]
        ${OutBuffer},

        ${SessionTimeout},

        [Alias('wa')]
        ${WarningAction},

        ${ReadonlyRoutingConnectionUrl},

        [switch]
        ${Script},

        ${Path},

        [Alias('wv')]
        ${WarningVariable},

        ${EndpointUrl},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlAvailabilityReplica') `
                                -Arg ('Set-SqlAvailabilityReplica', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlAvailabilityReplica
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlCredential' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${Secret},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        ${Identity},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlCredential') `
                                -Arg ('Set-SqlCredential', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlCredential
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlHADREndpoint' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${Encryption},

        ${InputObject},

        ${IpAddress},

        [Alias('ov')]
        ${OutVariable},

        ${AuthenticationOrder},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${EncryptionAlgorithm},

        ${Certificate},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        ${Owner},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('ob')]
        ${OutBuffer},

        ${State},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        ${Port},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlHADREndpoint') `
                                -Arg ('Set-SqlHADREndpoint', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlHADREndpoint
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlNetworkConfiguration' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [switch]
        ${Disable},

        [switch]
        ${NoServiceRestart},

        [Alias('db')]
        [switch]
        ${Debug},

        [switch]
        ${ForceServiceRestart},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ob')]
        ${OutBuffer},

        ${Protocol},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        ${ManagementPublicPort},

        ${Port},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlNetworkConfiguration') `
                                -Arg ('Set-SqlNetworkConfiguration', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlNetworkConfiguration
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Set-SqlSmartAdmin' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [Alias('iv')]
        ${InformationVariable},

        ${Path},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('vb')]
        [switch]
        ${Verbose},

        ${SqlCredential},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        ${BackupRetentionPeriodInDays},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        ${DatabaseName},

        [Alias('infa')]
        ${InformationAction},

        [Alias('ob')]
        ${OutBuffer},

        ${EncryptionOption},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${BackupEnabled},

        [Alias('wv')]
        ${WarningVariable},

        ${MasterSwitch},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Set-SqlSmartAdmin') `
                                -Arg ('Set-SqlSmartAdmin', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Set-SqlSmartAdmin
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Start-SqlInstance' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        ${ManagementPublicPort},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Start-SqlInstance') `
                                -Arg ('Start-SqlInstance', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Start-SqlInstance
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Stop-SqlInstance' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AutomaticallyAcceptUntrustedCertificates},

        ${InputObject},

        ${RetryTimeout},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('db')]
        [switch]
        ${Debug},

        ${Credential},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('wa')]
        ${WarningAction},

        ${ServerInstance},

        ${Path},

        ${ManagementPublicPort},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Stop-SqlInstance') `
                                -Arg ('Stop-SqlInstance', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Stop-SqlInstance
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Suspend-SqlAvailabilityDatabase' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Suspend-SqlAvailabilityDatabase') `
                                -Arg ('Suspend-SqlAvailabilityDatabase', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Suspend-SqlAvailabilityDatabase
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Switch-SqlAvailabilityGroup' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        [switch]
        ${AllowDataLoss},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('infa')]
        ${InformationAction},

        [Alias('wv')]
        ${WarningVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${Script},

        ${Path},

        [switch]
        ${Force},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Switch-SqlAvailabilityGroup') `
                                -Arg ('Switch-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Switch-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Test-SqlAvailabilityGroup' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [switch]
        ${NoRefresh},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${AllowUserPolicies},

        ${Path},

        [switch]
        ${ShowPolicyDetails},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

                                                                                                Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'Test-SqlAvailabilityGroup') `
                            -Arg ('Test-SqlAvailabilityGroup', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
                                Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
                                End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

        # .ForwardHelpTargetName Test-SqlAvailabilityGroup
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Test-SqlAvailabilityReplica' `
                                                                                                                                                                                                                                                                                                                                            {
    param(
    
    [Alias('ea')]
    ${ErrorAction},

    ${InputObject},

    [Alias('ov')]
    ${OutVariable},

    [Alias('vb')]
    [switch]
    ${Verbose},

    [Alias('wv')]
    ${WarningVariable},

    [switch]
    ${NoRefresh},

    [Alias('db')]
    [switch]
    ${Debug},

    [Alias('pv')]
    ${PipelineVariable},

    [Alias('infa')]
    ${InformationAction},

    [Alias('cf')]
    [switch]
    ${Confirm},

    [Alias('ev')]
    ${ErrorVariable},

    [Alias('ob')]
    ${OutBuffer},

    [Alias('wa')]
    ${WarningAction},

    [switch]
    ${AllowUserPolicies},

    ${Path},

    [switch]
    ${ShowPolicyDetails},

    [Alias('wi')]
    [switch]
    ${WhatIf},

    [Alias('iv')]
    ${InformationVariable},

    [switch]
    ${AsJob})

    Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'Test-SqlAvailabilityReplica') `
                            -Arg ('Test-SqlAvailabilityReplica', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
    Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
    End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

    # .ForwardHelpTargetName Test-SqlAvailabilityReplica
    # .ForwardHelpCategory Cmdlet
    # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Test-SqlDatabaseReplicaState' `
    {
        param(
    
        [Alias('ea')]
        ${ErrorAction},

        ${InputObject},

        [Alias('ov')]
        ${OutVariable},

        [Alias('vb')]
        [switch]
        ${Verbose},

        [Alias('wv')]
        ${WarningVariable},

        [switch]
        ${NoRefresh},

        [Alias('db')]
        [switch]
        ${Debug},

        [Alias('pv')]
        ${PipelineVariable},

        [Alias('infa')]
        ${InformationAction},

        [Alias('cf')]
        [switch]
        ${Confirm},

        [Alias('ev')]
        ${ErrorVariable},

        [Alias('ob')]
        ${OutBuffer},

        [Alias('wa')]
        ${WarningAction},

        [switch]
        ${AllowUserPolicies},

        ${Path},

        [switch]
        ${ShowPolicyDetails},

        [Alias('wi')]
        [switch]
        ${WhatIf},

        [Alias('iv')]
        ${InformationVariable},

        [switch]
        ${AsJob})

        Begin {
            try {
                $positionalArguments = & $script:NewObject collections.arraylist
                foreach ($parameterName in $PSBoundParameters.BoundPositionally)
                {
                    $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                    $null = $PSBoundParameters.Remove($parameterName)
                }
                $positionalArguments.AddRange($args)

                $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

                $scriptCmd = { & $script:InvokeCommand `
                                @clientSideParameters `
                                -HideComputerName `
                                -Session (Get-PSImplicitRemotingSession -CommandName 'Test-SqlDatabaseReplicaState') `
                                -Arg ('Test-SqlDatabaseReplicaState', $PSBoundParameters, $positionalArguments) `
                                -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                             }

                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
            } catch {
                throw
            }
        }
        Process { 
        try {
            $steppablePipeline.Process($_)
        } catch {
            throw
        }
     }
        End { 
        try {
            $steppablePipeline.End()
        } catch {
            throw
        }
     }

        # .ForwardHelpTargetName Test-SqlDatabaseReplicaState
        # .ForwardHelpCategory Cmdlet
        # .RemoteHelpRunspace PSSession
    }
        
    & $script:SetItem 'function:script:Test-SqlSmartAdmin' `
                                                                                                                                                                                                                                                                                                                                            {
    param(
    
    [Alias('ea')]
    ${ErrorAction},

    ${InputObject},

    [Alias('ov')]
    ${OutVariable},

    [Alias('vb')]
    [switch]
    ${Verbose},

    [Alias('wv')]
    ${WarningVariable},

    [switch]
    ${NoRefresh},

    [Alias('db')]
    [switch]
    ${Debug},

    [Alias('pv')]
    ${PipelineVariable},

    [Alias('infa')]
    ${InformationAction},

    [Alias('cf')]
    [switch]
    ${Confirm},

    [Alias('ev')]
    ${ErrorVariable},

    [Alias('ob')]
    ${OutBuffer},

    [Alias('wa')]
    ${WarningAction},

    [switch]
    ${AllowUserPolicies},

    ${Path},

    [switch]
    ${ShowPolicyDetails},

    [Alias('wi')]
    [switch]
    ${WhatIf},

    [Alias('iv')]
    ${InformationVariable},

    [switch]
    ${AsJob})

    Begin {
        try {
            $positionalArguments = & $script:NewObject collections.arraylist
            foreach ($parameterName in $PSBoundParameters.BoundPositionally)
            {
                $null = $positionalArguments.Add( $PSBoundParameters[$parameterName] )
                $null = $PSBoundParameters.Remove($parameterName)
            }
            $positionalArguments.AddRange($args)

            $clientSideParameters = Get-PSImplicitRemotingClientSideParameters $PSBoundParameters $True

            $scriptCmd = { & $script:InvokeCommand `
                            @clientSideParameters `
                            -HideComputerName `
                            -Session (Get-PSImplicitRemotingSession -CommandName 'Test-SqlSmartAdmin') `
                            -Arg ('Test-SqlSmartAdmin', $PSBoundParameters, $positionalArguments) `
                            -Script { param($name, $boundParams, $unboundParams) & $name @boundParams @unboundParams } `
                         }

            $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
            $steppablePipeline.Begin($myInvocation.ExpectingInput, $ExecutionContext)
        } catch {
            throw
        }
    }
    Process { 
    try {
        $steppablePipeline.Process($_)
    } catch {
        throw
    }
  }
    End { 
    try {
        $steppablePipeline.End()
    } catch {
        throw
    }
  }

    # .ForwardHelpTargetName Test-SqlSmartAdmin
    # .ForwardHelpCategory Cmdlet
    # .RemoteHelpRunspace PSSession
    }
        
    ##############################################################################

    & $script:ExportModuleMember -Function @('ConvertFrom-EncodedSqlName', 'ConvertTo-EncodedSqlName', 'Add-SqlAvailabilityDatabase', 'Add-SqlAvailabilityGroupListenerStaticIp', 'Add-SqlFirewallRule', 'Backup-SqlDatabase', 'Disable-SqlAlwaysOn', 'Enable-SqlAlwaysOn', 'Get-SqlCredential', 'Get-SqlDatabase', 'Get-SqlInstance', 'Get-SqlSmartAdmin', 'Invoke-Sqlcmd', 'Join-SqlAvailabilityGroup', 'New-SqlAvailabilityGroup', 'New-SqlAvailabilityGroupListener', 'New-SqlAvailabilityReplica', 'New-SqlBackupEncryptionOption', 'New-SqlCredential', 'New-SqlHADREndpoint', 'Remove-SqlAvailabilityDatabase', 'Remove-SqlAvailabilityGroup', 'Remove-SqlAvailabilityReplica', 'Remove-SqlCredential', 'Remove-SqlFirewallRule', 'Restore-SqlDatabase', 'Resume-SqlAvailabilityDatabase', 'Save-SqlMigrationReport', 'Set-SqlAuthenticationMode', 'Set-SqlAvailabilityGroup', 'Set-SqlAvailabilityGroupListener', 'Set-SqlAvailabilityReplica', 'Set-SqlCredential', 'Set-SqlHADREndpoint', 'Set-SqlNetworkConfiguration', 'Set-SqlSmartAdmin', 'Start-SqlInstance', 'Stop-SqlInstance', 'Suspend-SqlAvailabilityDatabase', 'Switch-SqlAvailabilityGroup', 'Test-SqlAvailabilityGroup', 'Test-SqlAvailabilityReplica', 'Test-SqlDatabaseReplicaState', 'Test-SqlSmartAdmin')
        
    ##############################################################################

    & $script:SetAlias -Name 'Decode-SqlName' -Value 'ConvertFrom-EncodedSqlName' -Force -Scope script
        
    & $script:SetAlias -Name 'Encode-SqlName' -Value 'ConvertTo-EncodedSqlName' -Force -Scope script
        
    & $script:ExportModuleMember -Alias @('Decode-SqlName', 'Encode-SqlName')
            #endregion
    #region - RemoteSQLServer.Format.ps1xml
        <?xml version="1.0" encoding="utf-8"?>
        <Configuration>
          <ViewDefinitions />
        </Configuration>#endregion
    #endregion
#endregion
