($adsi = [adsisearcher]'').Filter = '(&(objectclass=computer))' ;$cmp.FindAll() | ?{ ($_.path -match 'Windows (10|11) Instant Clones').Properties.cn }
$svrList = $adsi.FindAll() | Where { (([adsi]$_.Path).OperatingSystem -match 'Server')}
$wksList = $adsi.FindAll() | Where { (([adsi]$_.Path).OperatingSystem -notmatch 'Server')} | Sort
$xList = $adsi.FindAll() | Where { (([adsi]$_.Path).OperatingSystem -notmatch '(Windows 1|Server)')} | Sort

$wksList = $wksList | Where Path -notmatch '(cn\=i|jmp|\-test)' | Sort

$svrList.Count
$wksList.Count

$sList = ($svrList | Select @{n='name';e={([adsi]$_.Path).cn}}).Name
$wList = ($wksList | Select @{n='name';e={([adsi]$_.Path).cn}}).Name


$wksActive = $wList | %{ iF (Test-Connection -BufferSize 32 -ComputerName $_ -Count 1 -Quiet){ $_ } }
$runList = $sList + $wksActive

65..69 |  %{Ping 7.46.88.$_ -n 2}
