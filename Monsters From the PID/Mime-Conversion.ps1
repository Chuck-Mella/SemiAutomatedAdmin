    #region - Mime Converstion
        Function ConvertTo-Mime($File){ ([Convert]::ToBase64String((Get-Content $File -Encoding Byte -Raw))) | sc "$File.enc.txt"}
        Function convertFrom-Mime($File){ $data= ([Convert]::FromBase64String((Get-Content $File))); [IO.File]::writeAllBytes(($File -replace '.enc.txt'),$data)}
        function Get-MimeType()
        {
          param($extension = $null);
          $mimeType = $null;
          if ( $null -ne $extension )
          {
            $drive = Get-PSDrive HKCR -ErrorAction SilentlyContinue;
            if ( $null -eq $drive )
            {
              $drive = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
            }
            $mimeType = (Get-ItemProperty HKCR:$extension)."Content Type";
          }
          $mimeType;
        }
        Get-MimeType -extension .zip
    #endregion
