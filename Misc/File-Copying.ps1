    function Copy-ItemWithProgress
    {
        <#
        .SYNOPSIS
        RoboCopy with PowerShell progress.

        .DESCRIPTION
        Performs file copy with RoboCopy. Output from RoboCopy is captured,
        parsed, and returned as Powershell native status and progress.

        .PARAMETER Source
        Directory to copy files from, this should not contain trailing slashes

        .PARAMETER Destination
        DIrectory to copy files to, this should not contain trailing slahes

        .PARAMETER FilesToCopy
        A wildcard expresion of which files to copy, defaults to *.*

        .PARAMETER RobocopyArgs
        List of arguments passed directly to Robocopy.
        Must not conflict with defaults: /ndl /TEE /Bytes /NC /nfl /Log

        .PARAMETER ProgressID
        When specified (>=0) will use this identifier for the progress bar

        .PARAMETER ParentProgressID
        When specified (>= 0) will use this identifier as the parent ID for progress bars
        so that they appear nested which allows for usage in more complex scripts.

        .OUTPUTS
        Returns an object with the status of final copy.
        REMINDER: Any error level below 8 can be considered a success by RoboCopy.

        .EXAMPLE
        C:\PS> .\Copy-ItemWithProgress c:\Src d:\Dest

        Copy the contents of the c:\Src directory to a directory d:\Dest
        Without the /e or /mir switch, only files from the root of c:\src are copied.

        .EXAMPLE
        C:\PS> .\Copy-ItemWithProgress '"c:\Src Files"' d:\Dest /mir /xf *.log -Verbose

        Copy the contents of the 'c:\Name with Space' directory to a directory d:\Dest
        /mir and /XF parameters are passed to robocopy, and script is run verbose

        .LINK
        https://keithga.wordpress.com/2014/06/23/copy-itemwithprogress

        .NOTES
        By Keith S. Garner (KeithGa@KeithGa.com) - 6/23/2014
        With inspiration by Trevor Sullivan @pcgeek86
        Tweaked by Justin Marshall - 02/20/2020

        #>

        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string]$Source,
            [Parameter(Mandatory=$true)]
            [string]$Destination,
            [Parameter(Mandatory=$false)]
            [string]$FilesToCopy="*.*",
            [Parameter(Mandatory = $true,ValueFromRemainingArguments=$true)] 
            [string[]] $RobocopyArgs,
            [int]$ParentProgressID=-1,
            [int]$ProgressID=-1
        )

        #handle spaces and trailing slashes
        $SourceDir = '"{0}"' -f ($Source -replace "\\+$","")
        $TargetDir = '"{0}"' -f ($Destination -replace "\\+$","")


        $ScanLog  = [IO.Path]::GetTempFileName()
        $RoboLog  = [IO.Path]::GetTempFileName()
        $ScanArgs = @($SourceDir,$TargetDir,$FilesToCopy) + $RobocopyArgs + "/ndl /TEE /bytes /Log:$ScanLog /nfl /L".Split(" ")
        $RoboArgs = @($SourceDir,$TargetDir,$FilesToCopy) + $RobocopyArgs + "/ndl /TEE /bytes /Log:$RoboLog /NC".Split(" ")

        # Launch Robocopy Processes
        write-verbose ("Robocopy Scan:`n" + ($ScanArgs -join " "))
        write-verbose ("Robocopy Full:`n" + ($RoboArgs -join " "))
        $ScanRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $ScanArgs
        try
        {
            $RoboRun = start-process robocopy -PassThru -WindowStyle Hidden -ArgumentList $RoboArgs
            try
            {
                # Parse Robocopy "Scan" pass
                $ScanRun.WaitForExit()
                $LogData = get-content $ScanLog
                if ($ScanRun.ExitCode -ge 8)
                {
                    $LogData|out-string|Write-Error
                    throw "Robocopy $($ScanRun.ExitCode)"
                }
                $FileSize = [regex]::Match($LogData[-4],".+:\s+(\d+)\s+(\d+)").Groups[2].Value
                write-verbose ("Robocopy Bytes: $FileSize `n" +($LogData -join "`n"))
                #determine progress parameters
                $ProgressParms=@{}
                if ($ParentProgressID -ge 0) {
                    $ProgressParms['ParentID']=$ParentProgressID
                }
                if ($ProgressID -ge 0) {
                    $ProgressParms['ID']=$ProgressID
                } else {
                    $ProgressParms['ID']=$RoboRun.Id
                }
                # Monitor Full RoboCopy
                while (!$RoboRun.HasExited)
                {
                    $LogData = get-content $RoboLog
                    $Files = $LogData -match "^\s*(\d+)\s+(\S+)"
                    if ($null -ne $Files )
                    {
                        $copied = ($Files[0..($Files.Length-2)] | ForEach-Object {$_.Split("`t")[-2]} | Measure-Object -sum).Sum
                        if ($LogData[-1] -match "(100|\d?\d\.\d)\%")
                        {
                            write-progress Copy -ParentID $ProgressParms['ID'] -percentComplete $LogData[-1].Trim("% `t") $LogData[-1]
                            $Copied += $Files[-1].Split("`t")[-2] /100 * ($LogData[-1].Trim("% `t"))
                        }
                        else
                        {
                            write-progress Copy -ParentID $ProgressParms['ID'] -Complete
                        }
                        write-progress ROBOCOPY  -PercentComplete ($Copied/$FileSize*100) $Files[-1].Split("`t")[-1] @ProgressParms
                    }
                }
            } finally {
                if (!$RoboRun.HasExited) {Write-Warning "Terminating copy process with ID $($RoboRun.Id)..."; $RoboRun.Kill() ; }
                $RoboRun.WaitForExit()
                # Parse full RoboCopy pass results, and cleanup
                (get-content $RoboLog)[-11..-2] | out-string | Write-Verbose
                remove-item $RoboLog
                write-output ([PSCustomObject]@{ ExitCode = $RoboRun.ExitCode })

            }
        } finally {
            if (!$ScanRun.HasExited) {Write-Warning "Terminating scan process with ID $($ScanRun.Id)..."; $ScanRun.Kill() }
            $ScanRun.WaitForExit()

            remove-item $ScanLog
        }
    }


    function Copy-File {
        # ref: https://stackoverflow.com/a/55527732/3626361
        param([string]$From, [string]$To)

        try {
            $job = Start-BitsTransfer -Source $From -Destination $To `
                -Description "Moving: $From => $To" `
                -DisplayName "Backup" -Asynchronous

            # Start stopwatch
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Write-Progress -Activity "Connecting..."

            while ($job.JobState.ToString() -ne "Transferred") {
                switch ($job.JobState.ToString()) {
                    "Connecting" {
                        break
                    }
                    "Transferring" {
                        $pctcomp = ($job.BytesTransferred / $job.BytesTotal) * 100
                        $elapsed = ($sw.elapsedmilliseconds.ToString()) / 1000

                        if ($elapsed -eq 0) {
                            $xferrate = 0.0
                        }
                        else {
                            $xferrate = (($job.BytesTransferred / $elapsed) / 1mb);
                        }

                        if ($job.BytesTransferred % 1mb -eq 0) {
                            if ($pctcomp -gt 0) {
                                $secsleft = ((($elapsed / $pctcomp) * 100) - $elapsed)
                            }
                            else {
                                $secsleft = 0
                            }

                            Write-Progress -Activity ("Copying file '" + ($From.Split("\") | Select-Object -last 1) + "' @ " + "{0:n2}" -f $xferrate + "MB/s") `
                                -PercentComplete $pctcomp `
                                -SecondsRemaining $secsleft
                        }
                        break
                    }
                    "Transferred" {
                        break
                    }
                    Default {
                        throw $job.JobState.ToString() + " unexpected BITS state."
                    }
                }
            }

            $sw.Stop()
            $sw.Reset()
        }
        finally {
            Complete-BitsTransfer -BitsJob $job
            Write-Progress -Activity "Completed" -Completed
        }
    }

    Function Copy-FilesBitsTransfer(
            [Parameter(Mandatory=$true)][String]$sourcePath, 
            [Parameter(Mandatory=$true)][String]$destinationPath, 
            [Parameter(Mandatory=$false)][bool]$createRootDirectory = $true)
    {
        $item = Get-Item $sourcePath
        $itemName = Split-Path $sourcePath -leaf
        if (!$item.PSIsContainer){ #Item Is a file

            $clientFileTime = Get-Item $sourcePath | select LastWriteTime -ExpandProperty LastWriteTime

            if (!(Test-Path -Path $destinationPath\$itemName)){
                Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy Template file" -Confirm:$false
                if (!$?){
                    return $false
                }
            }
            else{
                $serverFileTime = Get-Item $destinationPath\$itemName | select LastWriteTime -ExpandProperty LastWriteTime

                if ($serverFileTime -lt $clientFileTime)
                {
                    Start-BitsTransfer -Source $sourcePath -Destination $destinationPath -Description "$sourcePath >> $destinationPath" -DisplayName "Copy Template file" -Confirm:$false
                    if (!$?){
                        return $false
                    }
                }
            }
        }
        else{ #Item Is a directory
            if ($createRootDirectory){
                $destinationPath = "$destinationPath\$itemName"
                if (!(Test-Path -Path $destinationPath -PathType Container)){
                    if (Test-Path -Path $destinationPath -PathType Leaf){ #In case item is a file, delete it.
                        Remove-Item -Path $destinationPath
                    }

                    $null = New-Item -ItemType Directory $destinationPath
                    if (!$?){
                        return $false
                    }

                }
            }
            Foreach ($fileOrDirectory in (Get-Item -Path "$sourcePath\*"))
            {
                $status = Copy-FilesBitsTransfer $fileOrDirectory $destinationPath $true
                if (!$status){
                    return $false
                }
            }
        }

        return $true
    }