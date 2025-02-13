    Function Get-BatteryStatus
    {
        $path = "$env:temp/battery_report2.html"
        powercfg /batteryreport /output $Path /duration 14
        Start-Process -FilePath $Path -Wait
        Remove-Item -Path $path  
    }

    Function Get-WebDLFile
    {
       Param
       (
           $url,
           $targetFile
       )
       $uri = New-Object "System.Uri" "$url"
       $request = [System.Net.HttpWebRequest]::Create($uri)
       $request.set_Timeout(15000) #15 second timeout
       $response = $request.GetResponse()
       $totalLength = [System.Math]::Floor($response.get_ContentLength()/1024)
       $responseStream = $response.GetResponseStream()
       $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $targetFile, Create
       $buffer = new-object byte[] 10KB

       $count = $responseStream.Read($buffer,0,$buffer.length)
       $downloadedBytes = $count
       while ($count -gt 0)
       {
           $targetStream.Write($buffer, 0, $count)
           $count = $responseStream.Read($buffer,0,$buffer.length)
           $downloadedBytes = $downloadedBytes + $count
           Write-Progress -activity "Downloading file '$($url.split('/') | Select -Last 1)'" -status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes/1024)) / $totalLength)  * 100)
       }
       Write-Progress -activity "Finished downloading file '$($url.split('/') | Select -Last 1)'"

       $targetStream.Flush()
       $targetStream.Close()
       $targetStream.Dispose()
       $responseStream.Dispose()
    }


    Function Get-WebFileDLv1
    {
        Param
        (
            $url,
            $targetFile
        )
        $dlRequest = new-object System.Net.WebClient
        $dlRequest.DownloadFile(“$url”,“$targetFile”)

    }

    Function Get-WebFileDLv2
    {
           Param
           (
               $url,
               $targetFile
           )
        Invoke-WebRequest $url -outfile $targetFile

    }

    $Global:labInfo = (Dec64 'TmFtZSxTaGFyZURpcixiaXRzTUVDTSxiaXRzU0NPTSxDb2RlU291cmNlDQpOZXRjb20sQjpcTmV0Y29tIFNoYXJlc1xTQ09NTGFiMDEsaHR0cHM6Ly9zdGdzeXNtYW5sYWIuYmxvYi5jb3JlLndpbmRvd3MubmV0L3BhY2thZ2VzL1NvdXJjZS1NRUNNMjAxMC56aXA/c3Y9MjAyMC0wNC0wOCZzdD0yMDIxLTA1LTI2VDEzJTNBNDUlM0EwMVomc2U9MjAyMS0wNS0yN1QxMyUzQTQ1JTNBMDFaJnNyPWImc3A9ciZzaWc9OVVvU3FtcUpydkp1bm90R1VSR09adzhabUhMYVJNYjNwS25OTjFzWHNoRSUzRCwsQzpcVXNlcnNcQ2h1Y2tcT25lRHJpdmVcRG9jdW1lbnRzXEdJVCBSZXBvc2l0b3JpZXNcQ29kZSAtIFdvcmtcMDEgLSBOZXRjb20gQ2ZnIE1hbmlmZXN0c1xTeXN0ZW0gQ2VudGVyIEF1dG9tYXRpb24NCg==') | ConvertFrom-csv

    Configuration CopyDSCResource {
        <#
            $srcArticle = 'https://powershellmagazine.com/2013/09/02/copying-powershell-modules-and-custom-dsc-resources-using-dsc/'
    
            In an earlier article, I showed you a custom DSC resource I built for managing hosts file entries, 
            but I did not tell you that the custom DSC resource must exist on the remote system at a predefined 
            path. When using push configuration model for configuration management, without copying the custom 
            DSC resource, you cannot really apply any configuration supported by the resource. In DSC, there 
            is also a pull model for configuration management which eliminates the need for you to take care 
            of copying the DSC resources to remote systems. We will save this for a later article.

            In this article I will show you how to copy the DSC resources from a network share to a set of 
            remote systems using DSC. Before we get started, we need to create a network share and copy all 
            the custom DSC resources.

            Once we copy all the custom DSC resources, we need to assign permissions to the computer accounts 
            that are target nodes for this configuration. This is required because the DSC Local Configuration 
            Manager runs as the SYSTEM account and won’t have access to network resources. In my lab setup, 
            I just have three virtual machines running Windows PowerShell 4.0 for all my DSC-related work. 
            I have added all the computer accounts to the share with Read permission. As I’d mentioned, this 
            is required and without this you will receive an access denied error when you try to copy files 
            from a network share to a remote system. Thanks to Steven Murawski for this tip!

            Now, coming to the actual DSC configuration document, we will use a File resource to perform a copy of a 
            network share contents to a module path for custom DSC resources.
        #>
        param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullOrEmpty()]
            [String[]]$NodeName,
            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [String]$SourcePath,

            [Parameter(Mandatory=$false)]
            [ValidateNotNullOrEmpty()]
            [String]$ModulePath = "$PSHOME\modules\PSDesiredStateConfiguration\PSProviders"
        )

        Node $NodeName {
            File DSCResourceFolder {
                SourcePath = $SourcePath
                DestinationPath = $ModulePath
                Recurse = $true
                Type = "Directory"
            }
        }
        <#

            CopyDSCResource -NodeName DC,SQL,MGMT,MGMT2 -SourcePath "\\helmsdeep\SCOMLab01"

            Once you customize the above configuration document for your requirements, save it as a .ps1 file. 
            Notice the last line in the script where we are specifying the computer names as arguments to 
            the –NodeName parameter and the -SourcePath where all the custom DSC resources are stored.

            We can now build the MOF files by dot-sourcing the configuration document and then apply the configuration 
            using Start-DscConfiguration cmdlet.


            .\demo.ps1
            Start-DscConfiguration -Wait -Verbose -Path .\CopyDSCResource


            Once we complete applying the configuration using the Start-DscConfiguration cmdlet, we can see the 
            custom resource folder in the network share copied to the specified module path.

            Alright, I must admit this is just one way of copying the files from a network share to a remote system. 
            If you have paid enough attention to the attributes available in the File resource, you will ask me a 
            question about the Credential attribute. Yes, this attribute can be used to specify the credentials to 
            access the network share. The Credential attribute eliminates the need for assigning permissions to 
            computer accounts – what is discussed in this article – to access the network shares when applying DSC 
            configuration. However, the Credential attribute comes with its own baggage. 
            Let us save that for a later post! 🙂
        #>
    }



