# ASCII
    Function Global:Dec64 { Param($a) $b = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($a));Return $b };
    Function Global:Enc64 { Param($a) $b = [System.Convert]::ToBase64String($a.ToCharArray());Return $b };
# Unicode
    Function Global:Enc64v2 { Param($a) $b = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($a));Return $b };
    Function Global:Dec64v2 { Param($a) $b = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($a));Return $b };
    
