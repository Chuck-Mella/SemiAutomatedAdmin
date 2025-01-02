
PowerShell Gallery Home
Packages
Publish
Statistics
Documentation
Sign in
Search PowerShell packages:
PowerShellGet, Get-AzVM, etc...
SplitDbxContent 1.0
SplitDbxContent.ps1
1
2
3
4
5
6
7
8
9
10
11
12
13
14
15
16
17
18
19
20
21
22
23
24
25
26
27
28
29
30
31
32
33
34
35
36
37
38
39
40
41
42
43
44
45
46
47
48
49
50
51
52
53
54
55
56
57
58
59
60
61
62
63
64
65
66
67
68
69
70
71
72
<#PSScriptInfo
 
.VERSION 1.0
 
.GUID ec45a3fc-5e87-4d90-b55e-bdea083f732d
 
.AUTHOR Microsoft Secure Boot Team
 
.COMPANYNAME Microsoft
 
.COPYRIGHT Microsoft
 
.TAGS Windows Security
 
.LICENSEURI
 
.PROJECTURI
 
.ICONURI
 
.EXTERNALMODULEDEPENDENCIES
 
.REQUIREDSCRIPTS
 
.EXTERNALSCRIPTDEPENDENCIES
 
.RELEASENOTES
Version 1.0: Original published version.
 
#>

<#
.DESCRIPTION
 Splits a DBX update package into the new DBX variable contents and the signature authorizing the change.
 To apply an update using the output files of this script, try:
 Set-SecureBootUefi -Name dbx -ContentFilePath .\content.bin -SignedFilePath .\signature.p7 -Time 2010-03-06T19:17:21Z -AppendWrite'
.EXAMPLE
.\SplitDbxAuthInfo.ps1 DbxUpdate_x64.bin
#>


# Get file from script input
$file  = Get-Content -Encoding Byte $args[0]

# Identify file signature
$chop = $file[40..($file.Length - 1)]
if (($chop[0] -ne 0x30) -or ($chop[1] -ne 0x82 )) {
    Write-Error "Cannot find signature"
    exit 1
}

# Signature is known to be ASN size plus header of 4 bytes
$sig_length = ($chop[2] * 256) + $chop[3] + 4
$sig = $chop[0..($sig_length - 1)]

if ($sig_length -gt ($file.Length + 40)) {
    Write-Error "Signature longer than file size!"
    exit 1
}

# Build and write signature output file
[System.Byte[]] $sigbytes =  @()
foreach ($i in $sig) {$sigbytes += $i}
Set-Content -Encoding Byte -Path ".\signature.p7" -Value $sigbytes
Write-Output "Successfully created output file .\signature.p7"

# Build and write variable content output file
$content = $chop[$sig_length..($chop.Length - 1)]
[System.Byte[]] $bytes =  @()
foreach ($i in $content) {$bytes += $i}
Set-Content -Encoding Byte -Path ".\content.bin" -Value $bytes
Write-Output "Successfully created output file .\content.bin"
Contact UsTerms of UsePrivacy PolicyGallery StatusFeedbackFAQs© 2022 Microsoft Corporation