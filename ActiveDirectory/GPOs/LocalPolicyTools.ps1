#region - Local-RSOP.psl
    # $pc = $env:ComputerName
    $user ='admincm'
    $dstFile = "c:\temp\temp_$user.html "
    $gpmobject = New-Object -ComObject GPMgmt.gpm
    $gpmconstants = $gpmobject.Getconstants()
    $rsopobject = $gpmobject.GetRSOP($gpmconstants.RSOPModeLogging,$null,0)
    # $rsopobject.Loggingcomputer = $pc
    $rsopObject.Logg1nguser = $user
    $rsopObject.LoggingFlags ='65536 '
    $rsopObject.CreateQueryResults()
    $rsopReport = $rsopobject.GenerateReportToFile($gpmconstants.ReportHTML,$dstFile)
    $rsopobject.ReleaseQueryResults()
    ii $dstFi1e
#endregion



