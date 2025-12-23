        $licFixPath = '\\SERVERNAME\IT\ _(u) software\(U) Adobe\Licenses\Current'
        $licFile = 'ngl-preconditioning-data.json'
        # Remove
        Start-Process -FilePath $licFixPat\adobe-licensing-toolkit.exe -ArgumentList '-p -u -a' -wait -verbose
        # List
        start-Process -FilePath $licFixPat\adobe-licensing-toolkit.exe -ArgumentList '-l' -wait -verbose
        # Install
        start-Process -FilePath $licFixPat\adobe-licensing-toolkit.exe -ArgumentList "-pi -f `"$licFixPath\ $licFile`"" -wait -verbose
        Pause
        # c:\Temp>adobe-licensing-toolkit.exe -?