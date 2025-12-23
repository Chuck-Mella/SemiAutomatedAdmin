#region psWeb
    Add-Type -AssemblyName System.Web
    [System.Web.HttpUtility]::HtmlEncode('Österreich heißt so.')
    [System.Web.HttpUtility]::UrlEncode("www.google.com")

    # ...
    $ClientID = '<Your Value Here From Registered Application>'
    $client_Secret = '<Your Registered Application client_secret>'

    # If ClientId or Client_Secret has special characters, UrlEncode before sending request
    $clientIDEncoded = [System.Web.HttpUtility]::UrlEncode($ClientID)
    $client_SecretEncoded = [System.Web.HttpUtility]::UrlEncode($client_Secret)
    # ...
#endregion


