#region Ftp DL
    $username='test'
    $password='123qwe'
    $ftp='ftp://192.168.2.222'
    $subfolder='/'

    $ftpuri = $ftp + $subfolder
    $uri=[system.URI] $ftpuri
    $ftprequest=[system.net.ftpwebrequest]::Create($uri)
    $ftprequest.Credentials=New-Object System.Net.NetworkCredential($username,$password)
    $ftprequest.Method=[system.net.WebRequestMethods+ftp]::ListDirectory
    $response=$ftprequest.GetResponse()
    $strm=$response.GetResponseStream()
    $reader=New-Object System.IO.StreamReader($strm,'UTF-8')
    $list=$reader.ReadToEnd()
    $lines=$list.Split("`n")
    return $lines


    # DL File
    $file = "C:\test.txt"
    $ftpuri = "ftp://test:123qwe@192.168.2.222/test.txt"
    $webclient = New-Object System.Net.WebClient
    $uri = New-Object System.Uri($ftpuri)
    $webclient.DownloadFile($uri, $file)


    # DL Binary
    $username='test'
    $password='123qwe'
    $ftp='ftp://192.168.2.222'
    $remote_file='https://d1ny9casiyy5u5.cloudfront.net/test.txt'
    $local_file = 'C:\test.txt'

    $ftpuri = $ftp + $remote_file
    $uri=[system.URI] $ftpuri
    $ftprequest=[system.net.ftpwebrequest]::Create($uri)
    $ftprequest.Credentials=New-Object System.Net.NetworkCredential($username,$password)
    $ftprequest.Method=[system.net.WebRequestMethods+ftp]::DownloadFile
    $ftprequest.UseBinary = $true
    $ftprequest.KeepAlive = $false
    $response=$ftprequest.GetResponse()
    $strm=$response.GetResponseStream()
    try
    {
    $targetfile = New-Object IO.FileStream ($local_file,[IO.FileMode]::Create)
    "File created: $local_file"
    [byte[]]$readbuffer = New-Object byte[] 1024
    do{
    $readlength = $strm.Read($readbuffer,0,1024)
    $targetfile.Write($readbuffer,0,$readlength)
    }
    while ($readlength -ne 0)

    $targetfile.close()
    }
    catch
    {
    $_|fl * -Force
    }
#endregion


