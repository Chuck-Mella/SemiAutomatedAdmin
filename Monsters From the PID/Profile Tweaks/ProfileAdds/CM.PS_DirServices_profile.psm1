    Function Get-GrpMembers
    {
        Param
        (
            [Array]$Groups,
            [Array]$Users,
            $gpDom
        )
        #If (!(Get-Reqs -Mdls ActiveDirectory)){BREAK}
        [System.Collections.ArrayList]$rslt = @()
        If  (!(gmo activeDirectory))
        {
            ForEach ($Group in $Groups)
            {
                $a="(&(objectCategory=group)(Name=$Group))"
                $Searcher = New-Object DirectoryServices.DirectorySearcher
                $Searcher.Filter = $a
                $Searcher.SearchRoot = "LDAP://OU=Groups,$gpDom"
                $grp = $Searcher.FindAll()
                $mbrs = ($grp.Properties.member)
                $mbrs = $mbrs|%{($_.Split(",")[0]).Replace("CN=","")}
                ForEach ($mbr in $mbrs)
                {
                    $b="(&(objectCategory=User)(Name=$mbr))"
                    $Searcher = New-Object DirectoryServices.DirectorySearcher
                    $Searcher.Filter = $b
                    $Searcher.SearchRoot = "LDAP://$gpDom"
                    $usr = ($Searcher.FindAll()).Properties
                    $obj = $usr|Select @{name='Group';expression={$Group}},
                        @{name='Name';expression={$usr.name}},
                        @{name='SamAccountName';expression={$usr.samaccountname}},
                        @{name='SID';expression={
                            ((New-Object System.Security.Principal.NTAccount($usr.samaccountname)).Translate(
                            [System.Security.Principal.SecurityIdentifier])).Value}},
                        @{name='DistinguishedName';expression={$usr.distinguishedname}}
                    $rslt.Add($obj)|Out-Null
                }
            }
        }
        Else
        {
            ForEach ($Group in $Groups)
            {
                $obj = (Get-ADGroupMember -Identity $Group|Select @{name='Group';expression={$Group}},Name,SamAccountName,SID,DistinguishedName)
                $rslt.Add($obj)|Out-Null
            }
        }
        $rslt | ft -auto
    } #Get-GrpMembers
    # USAGE: Get-GrpMembers Administrators

    Function Get-NTUSERDAT
    {
	    <# 
   	    .Synopsis 
    	    Mounts the NTUSER.DAT file as a PSDrive using the registry provider

	    .Description
		    Without any arguments the current users file is loaded, but a single 
		    profile can be specified or the -All switch can be given to load all 
		    profiles on the machine. If the -Dismount command is given it will 
		    unload the drive and registry hive; also, if given in conjuntion with
		    -All, then all profiles on the machine will be dismounted. If the 
		    username contains a period it will be stripped. The [gc]::collect() 
		    command is also given to clean up the registry after dismount.

   	    .Example 
    	    Get-NTUSERDAT

	    .Example
		    Get-NTUSERDAT -User <username>

	    .Example
		    Get-NTUSERDAT -All

	    .Example 
		    Get-NTUSERDAT -User <username> -Dismount

	    .Example 
		    Get-NTUSERDAT -Dismount -All 

   	    .Notes 
    	    NAME: Get-NTUSERDAT.ps1 
    	    AUTHOR: Paul Brown 
    	    LASTEDIT: 12/17/2015 10:57:41 
    	    KEYWORDS: 

   	    .Link 
    	    https://gallery.technet.microsoft.com/scriptcenter/site/search?f%5B0%5D.Type=User&f%5B0%5D.Value=PaulBrown4
	    #Requires -Version 2.0 
	    #> 
	    [cmdletbinding()]
	    Param
        (
	        [Parameter (
                Mandatory=$false,
                Position=0,
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true
            )]
            [array]$User = $Env:USERNAME,
            [switch]$All,
            [switch]$Dismount
	    )
	    If ($All)
        {
		    $User = $(Get-ChildItem "$($env:systemdrive)\Users\").Name
	    }
	    If (-not $Dismount)
        {
		    Foreach ($name in $User)
            {
			    Try
                {
				    $newname = $($name.replace(".",""))
				    $hive = "HKLM\$newname"
				    $path = "$($env:systemdrive)\Users\$name\ntuser.dat"
				    reg load  $hive $path
				    New-PSDrive -Name $newname -PSProvider Registry -Root $hive -Scope Global
			    }
                Catch
                {
			    }
		    }
	    }
        Else
        {
		    Foreach ($name in $User)
            {
			    Try
                {
				    $newname = $($name.replace(".",""))
				    Remove-PSDrive -Name $newname
				    reg unload "HKLM\$newname"
				
				    [GC]::Collect()
			    }
                Catch
                {
			    }
		    }
	    }
    }

#region LDAP
    ([String](([adsi]"LDAP://RootDSE").Properties).ServerName)
#endregion

#region - GroupMbr fn_ADTools research & txt2csv 
    # Audit-ADGroups, Get-ADGrpMembers, Get-ADMemberOf, Get-CurrUserGroups, Get-EffectivePSO, Get-ExtendedRights, Get-IADGroup
#endregion
