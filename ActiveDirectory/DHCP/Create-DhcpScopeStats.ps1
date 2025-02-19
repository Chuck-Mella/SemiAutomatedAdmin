# DHCP Scope Statistics Report
Function Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b  }
$htmlfile = [Environment]::GetFolderPath("Desktop") + '\' + "DHCPData-$(Get-Date -f yyyyMMdd).html" ### The full path to the final HTML file
$htmlfile_temp = [Environment]::GetFolderPath("Desktop") + '\' + "DHCPData-$(Get-Date -f yyyyMMdd)_temp.html" ### The full path to the temporary HTML file
 
### Checking to see if the temp file exists, if it does it will remove it
If (Test-Path $htmlfile_temp) { Remove-Item $htmlfile_temp -Force }

$html_header = (Dec64 'DQo8aHRtbD4NCjxoZWFkPg0KPG1ldGEgaHR0cC1lcXVpdj0nQ29udGVudC1UeXBlJyBjb250ZW50PSd0ZXh0L2h0bWw7IGNoYXJzZXQ9aXNvLTg4NTktMSc+DQo8dGl0bGU+REhDUCBSZXBvcnQ8L3RpdGxlPg0KPFNUWUxFIFRZUEU9J3RleHQvY3NzJz4NCjwvc3R5bGU+DQo8L2hlYWQ+DQo8Ym9keT4NCjx0YWJsZS1sYXlvdXQ6IGZpeGVkPg0KPHRhYmxlIHdpZHRoPScxMDAlJz4NCjx0ciBiZ2NvbG9yPScjMDBCNjI0Jz4NCjx0ZCBjb2xzcGFuPSc3JyBoZWlnaHQ9JzI1JyBhbGlnbj0nY2VudGVyJz48c3Ryb25nPjxmb250IGNvbG9yPScjMDAwMDAwJyBzaXplPSc0JyBmYWNlPSd0YWhvbWEnPkRIQ1AgU2NvcGUgU3RhdGlzdGljcyBSZXBvcnQ8L2ZvbnQ+PGZvbnQgY29sb3I9JyMwMDAwMDAnIHNpemU9JzQnIGZhY2U9J3RhaG9tYSc+ICgwOS8wOS8yMDIyIDEzOjE3OjIzKTwvZm9udD48Zm9udCBjb2xvcj0nIzAwMDAwMCcgc2l6ZT0nMicgZmFjZT0ndGFob21hJz4gPEJSPiBEYXRhIFVwZGF0ZXMgRXZlcnkgRGF5PC9mb250Pg0KPC90cj4NCjwvdGFibGU+DQo8dGFibGUgd2lkdGg9JzEwMCUnPg0KPHRyIGJnY29sb3I9JyNDQ0NDQ0MnPg0KPHRkIGNvbHNwYW49JzcnIGhlaWdodD0nMjAnIGFsaWduPSdjZW50ZXInPjxzdHJvbmc+PGZvbnQgY29sb3I9JyMwMDAwMDAnIHNpemU9JzInIGZhY2U9J3RhaG9tYSc+PHNwYW4gc3R5bGU9YmFja2dyb3VuZC1jb2xvcjojRkZGMjg0PldBUk5JTkc8L3NwYW4+IGF0IDgwJSBJbiBVc2UgICAgICA8c3BhbiBzdHlsZT1iYWNrZ3JvdW5kLWNvbG9yOiNGRjAwMDA+PGZvbnQgY29sb3I9d2hpdGU+Q1JJVElDQUw8L2ZvbnQ+PC9zcGFuPiBhdCA5NSUgSW4gVXNlPC9mb250Pg0KPC90cj4NCjwvdGFibGU+DQo8dGFibGUgd2lkdGg9JzEwMCUnPjx0Ym9keT4NCiAgICA8dHIgYmdjb2xvcj1ibGFjaz4NCiAgICA8dGQgd2lkdGg9JzEwJScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+REhDUCBTZXJ2ZXI8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5TY29wZSBJRDwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDx0ZCB3aWR0aD0nMTAlJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5TY29wZSBuYW1lPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+U2NvcGUgU3RhdGU8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5JbiBVc2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5GcmVlPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+JSBJbiBVc2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5SZXNlcnZlZDwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDx0ZCB3aWR0aD0nOCUnIGhlaWdodD0nMTUnIGFsaWduPSdjZW50ZXInPiA8c3Ryb25nPiA8Zm9udCBjb2xvcj0nd2hpdGUnIHNpemU9JzInIGZhY2U9J3RhaG9tYScgPlN1Ym5ldCBNYXNrPC9mb250Pjwvc3Ryb25nPjwvdGQ+DQogICAgPHRkIHdpZHRoPSc4JScgaGVpZ2h0PScxNScgYWxpZ249J2NlbnRlcic+IDxzdHJvbmc+IDxmb250IGNvbG9yPSd3aGl0ZScgc2l6ZT0nMicgZmFjZT0ndGFob21hJyA+U3RhcnQgb2YgUmFuZ2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5FbmQgb2YgUmFuZ2U8L2ZvbnQ+PC9zdHJvbmc+PC90ZD4NCiAgICA8dGQgd2lkdGg9JzglJyBoZWlnaHQ9JzE1JyBhbGlnbj0nY2VudGVyJz4gPHN0cm9uZz4gPGZvbnQgY29sb3I9J3doaXRlJyBzaXplPScyJyBmYWNlPSd0YWhvbWEnID5MZWFzZSBEdXJhdGlvbjwvZm9udD48L3N0cm9uZz48L3RkPg0KICAgIDwvdHI+DQo8L3RhYmxlPg0K')
$html_header | Out-File $htmlfile_temp ### Writing the HTML header to the temporary file

$DHCP_Servers = Get-DhcpServerInDC | ForEach-Object {$_.DnsName} | Sort-Object -Property DnsName ### Dynamically pulling the DHCP servers in a Active Directory domain
Foreach ($DHCP_Server in $DHCP_Servers)
{
    ### Going through the DHCP servers that were returned one at a time to pull statistics
    $DHCP_Scopes = Get-DhcpServerv4Scope –ComputerName $DHCP_Server | Select-Object ScopeId, Name, SubnetMask, StartRange, EndRange, LeaseDuration, State ### Getting all the dhcp scopes for the given server
    Foreach ($DHCP_Scope in $DHCP_Scopes)
    { ### Going through the scopes returned in a given server
        $DHCP_Scope_Stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DHCP_Server -ScopeId $DHCP_Scope.ScopeId | Select-Object Free, InUse, Reserved, PercentageInUse, ScopeId ### Gathering the scope stats
        $percentinuserounded = ([math]::Round($DHCP_Scope_Stats.PercentageInUse,0)) ### Rounding the percent in use to have no decimals
        ### Color formatting based on how much a scope is in use
        If ($percentinuserounded -ge 95){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#FF0000"> <font color="white">' + $percentinuserounded + '</font></td>'}
        If ($percentinuserounded -ge 80 -and $percentinuserounded -lt 95){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#FFF284"> <font color="black">' + $percentinuserounded + '</font></td>'}
        If ($percentinuserounded -lt 80){$htmlpercentinuse = '<td width="8%" align="center" td bgcolor="#A6CAA9"> <font color="black">' + $percentinuserounded + '</font></td>'}
        ### Changing the cell color if the scope is inactive / active
        If ($DHCP_Scope.State -eq "Inactive"){$htmlScopeState = '<td width="8%" align="center" td bgcolor="#AAAAB2"> <font color="black">' + $DHCP_Scope.State  + '</font></td>'}
        If ($DHCP_Scope.State -eq "Active"){$htmlScopeState = '<td width="8%" align="center">' + $DHCP_Scope.State + '</td>'}
        ### Changing the background color on every other scope so the html is easy to read
        $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 0 ) {$htmlbgcolor = '<tr bgcolor=#F5F5F5>'} } ## Even Number (off-white)
        $htmlwrite_count | ForEach-Object {if($_ % 2 -eq 1 ) {$htmlbgcolor = '<tr bgcolor=#CCCCCC>'} } ## Odd Number (gray)
        #### Creating the HTML row for the given DHCP scope with the detailed stats and information
        $current = "
                <table width='100%'><tbody>
                    $htmlbgcolor
                    <td width='10%' align='center'>$($DHCP_Server.TrimEnd(".local.domain"))</td>
                    <td width='8%' align='center'>$($DHCP_Scope.ScopeId)</td>
                    <td width='10%' align='center'>$($DHCP_Scope.Name)</td>
                    $htmlScopeState
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.InUse)</td>
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.Free)</td>
                    $htmlpercentinuse
                    <td width='8%' align='center'>$($DHCP_Scope_Stats.Reserved)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.SubnetMask)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.StartRange)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.EndRange)</td>
                    <td width='8%' align='center'>$($DHCP_Scope.LeaseDuration)</td>
                    </tr>
                </table>
                "
        $current  | Out-File $htmlfile_temp -Append ### Appending the HTML row to the tempory file
 
        $htmlwrite_count++ ### Incrementing the count by 1 so that the next HTML row is a different color
        Clear-Variable htmlScopeState, htmlpercentinuse, percentinuserounded, DHCP_Scope_Stats -ErrorAction SilentlyContinue
    }
}
Clear-Variable htmlwrite_count



If (Test-Path $htmlfile) { Remove-Item $htmlfile -Force } ### Removing the final html file if it exists
Rename-Item $htmlfile_temp $htmlfile -Force ### Renaming the temp file to the final file
