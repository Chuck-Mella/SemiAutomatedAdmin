Function Get-CurrentAV { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct }  

Function Get-OrigWin10ProdKey { Get-CimInstance -ClassName SoftwareLicensingService | Select-Object -ExpandProperty OA3xOriginalProductKey }

Function Move-Mouse
{
	    # Console - Move-Mouse -secs 10 -LoopInfinite $true
    # ISE - Move-Mouse -xy 1 -secs 5 -LoopInfinite $true -DisplayPosition $true
    Param (
        [uint16]$xy = 1,
        [int32]$secs = 5,
        [boolean]$LoopInfinite = $false,
        [boolean]$DisplayPosition = $false
        )
    Begin {
        Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b }
        $typedef = Dec64 'dXNpbmcgU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2VzOw0KDQpuYW1lc3BhY2UgUG9TSA0Kew0KICAgIHB1YmxpYyBzdG
            F0aWMgY2xhc3MgTW91c2UNCiAgICB7DQogICAgICAgIFtEbGxJbXBvcnQoInVzZXIzMi5kbGwiKV0NCiAgICAgICAgc3RhdGljIGV4dGVybiB2b2
            lkIG1vdXNlX2V2ZW50KGludCBkd0ZsYWdzLCBpbnQgZHgsIGludCBkeSwgaW50IGR3RGF0YSwgaW50IGR3RXh0cmFJbmZvKTsNCg0KICAgICAgIC
            Bwcml2YXRlIGNvbnN0IGludCBNT1VTRUVWRU5URl9NT1ZFID0gMHgwMDAxOw0KDQogICAgICAgIHB1YmxpYyBzdGF0aWMgdm9pZCBNb3ZlVG8oaW
            50IHgsIGludCB5KQ0KICAgICAgICB7DQogICAgICAgICAgICBtb3VzZV9ldmVudChNT1VTRUVWRU5URl9NT1ZFLCB4LCB5LCAwLCAwKTsNCiAgIC
            AgICAgfQ0KICAgIH0NCn0='
        Add-Type -TypeDefinition $typedef
        } #Begin
    Process {
        If ($LoopInfinite){
            $i = 1
            While ($true) {
                If ($DisplayPosition){ Write-Host "$([System.Windows.Forms.Cursor]::Position.X),$([System.Windows.Forms.Cursor]::Position.Y)" } #If
                If (($i % 2) -eq 0){ [PoSH.Mouse]::MoveTo($xy,$xy) ; $i++ } #If
                Else { [PoSH.Mouse]::MoveTo(-$xy,-$xy) ; $i-- } #Else
                Start-Sleep -Seconds $secs
                } #While
            } #If
        Else {
            If ($DisplayPosition){ Write-Host "$([System.Windows.Forms.Cursor]::Position.X),$([System.Windows.Forms.Cursor]::Position.Y)" } #If
            [PoSH.Mouse]::MoveTo($xy,$xy)
            } #Else
        } #Process

}

Function Get-BiosType {
    <#
        .Synopsis
           Determines underlying firmware (BIOS) type and returns an integer indicating UEFI, Legacy BIOS or Unknown.
           Supported on Windows 8/Server 2012 or later

        .DESCRIPTION
           This function uses a complied Win32 API call to determine the underlying system firmware type.

        .EXAMPLE
           If (Get-BiosType -eq 1) { # System is running UEFI firmware... }

        .EXAMPLE
            Switch (Get-BiosType) {
                1       {"Legacy BIOS"}
                2       {"UEFI"}
                Default {"Unknown"}
            }

        .OUTPUTS
           Integer indicating firmware type (1 = Legacy BIOS, 2 = UEFI, Other = Unknown)

        .FUNCTIONALITY
           Determines underlying system firmware type

        .NOTES
            Windows 8/Server 2012 or above:
    #>
    [OutputType([UInt32])]
    Param()
Add-Type -Language CSharp -TypeDefinition @'

    using System;
    using System.Runtime.InteropServices;

    public class FirmwareType
    {
        [DllImport("kernel32.dll")]
        static extern bool GetFirmwareType(ref uint FirmwareType);

        public static uint GetFirmwareType()
        {
            uint firmwaretype = 0;
            if (GetFirmwareType(ref firmwaretype))
                return firmwaretype;
            else
                return 0;   // API call failed, just return 'unknown'
        }
    }
'@

    [FirmwareType]::GetFirmwareType()
}

Function Get-BiosFromSetupLog
{
    # Look in the setup logfile to see what bios type was detected (EFI or BIOS)
    (Select-String 'Detected boot environment' C:\Windows\Panther\setupact.log -AllMatches ).line -replace '.*:\s+'
}

Function IsUEFI
{
    <#
        .Synopsis
           Determines underlying firmware (BIOS) type and returns True for UEFI or False for legacy BIOS.

        .DESCRIPTION
           This function uses a complied Win32 API call to determine the underlying system firmware type.

        .EXAMPLE
           If (IsUEFI) { # System is running UEFI firmware... }

        .OUTPUTS
           [Bool] True = UEFI Firmware; False = Legacy BIOS

        .FUNCTIONALITY
           Determines underlying system firmware type
    #>
    [OutputType([Bool])]
    Param ()
Add-Type -Language CSharp -TypeDefinition @'

    using System;
    using System.Runtime.InteropServices;

    public class CheckUEFI
    {
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern UInt32 
        GetFirmwareEnvironmentVariableA(string lpName, string lpGuid, IntPtr pBuffer, UInt32 nSize);

        const int ERROR_INVALID_FUNCTION = 1; 

        public static bool IsUEFI()
        {
            // Try to call the GetFirmwareEnvironmentVariable API.  This is invalid on legacy BIOS.

            GetFirmwareEnvironmentVariableA("","{00000000-0000-0000-0000-000000000000}",IntPtr.Zero,0);

            if (Marshal.GetLastWin32Error() == ERROR_INVALID_FUNCTION)

                return false;     // API not supported; this is a legacy BIOS

            else

                return true;      // API error (expected) but call is supported.  This is UEFI.
        }
    }
'@

    [CheckUEFI]::IsUEFI()
}

Function EFIorLegacy
{
    $d = Confirm-SecureBootUEFI -ErrorVariable ProcessError
    if ($ProcessError -eq $true)
    {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("legacy",0,"BOOTMODE",0x1)
    }
    else
    {
        $wshell = New-Object -ComObject Wscript.Shell
        $wshell.Popup("UEFI",0,"BOOTMODE",0x1) 
    }
}


Function i__HashText($text)
{
    $memoryStream = [System.IO.MemoryStream]::new()
    $streamWriter = [System.IO.StreamWriter]::new($MemoryStream)
    $streamWriter.Write($text)
    $streamWriter.Flush()
    $memoryStream.Position = 0
    $hash = Get-FileHash -InputStream $MemoryStream -Algorithm 'SHA1'
    $memoryStream.Dispose()
    $streamWriter.Dispose()
    $hash.Hash   
} # i__HashText 'Son of a Cow turd!'

Function Get-Win10Version
{
    $winfo = [Environment]::OSVersion.Version| Select-Object Major,Minor,Build,Revision
    $winfo | Add-Member -MemberType NoteProperty -Name 'ReleaseId' -Value (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
    $winfo | Format-Table
}

Function Backup-OutlookSignatures
{
    Param ([switch]$Force, [switch]$Update,$trgFolder)
    $SigFolder = "$env:userprofile\AppData\Roaming\Microsoft\Signatures\*"
    $SigZip = "Signatures BU ($(& Hostname)) $(Get-Date -f yyyy-MM-dd).zip"
    If ($trgFolder -eq $null){ $trgFolder = "$env:OneDriveConsumer\Documents\Outlook SigBUs"}
    If ($Force.IsPresent -eq $true)
    {
        Compress-Archive -Path $SigFolder -DestinationPath ($trgFolder + '\' + $SigZip) -Force
    }
    If ($Update.IsPresent -eq $true)
    {
        Compress-Archive -Path $SigFolder -DestinationPath ($trgFolder + '\' + $SigZip) -Update
    }
    Else
    {
        Compress-Archive -Path $SigFolder -DestinationPath ($trgFolder + '\' + $SigZip)
    }

}

Function Restore-OutlookSignatures
{
    Param
    (
        $SigBUFolder = "$env:OneDriveConsumer\Documents\Outlook SigBUs",
        $SigZip,
        $trgFolder = "$env:userprofile\AppData\Roaming\Microsoft\Signatures"
    )
     If ($SigZip -eq $null)
    {
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
            Filter = 'Compressed (*.zip)|*.zip'
            InitialDirectory = $SigBUFolder
            }
        $result = $FileBrowser.ShowDialog() # Direct actions based on dialog results
        $FileName = $FileBrowser.SafeFileName
        $FilePath = $FileBrowser.FileName
    }
    Else 
    {
        $FilePath = $SigZip
        $FileName = ($SigZip -split '\\')[-1]
    }

    Expand-Archive -LiteralPath $FilePath -DestinationPath $trgFolder -Force -Verbose

    Write-Host "`n`nDone Processing '$FileName'" -f Green
}
