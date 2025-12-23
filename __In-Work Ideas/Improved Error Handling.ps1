#region - Improved Error Handling
    Try {}
    Catch {
        $errTemp = $_
        Switch ($errTemp.Exception.GetType().FullName)
        {
            'System.InvalidOperationException'{ "This Happened: $($errTemp.Exception.Message)" }
            'System.ArgumentException'{ "This Happened: $($errTemp.Exception.Message)" }
            default { "Something Else Happened: $($errTemp.Exception.GetType().FullName)" }
        }
        }
#endregion


