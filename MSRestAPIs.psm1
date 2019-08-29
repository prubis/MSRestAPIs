New-Variable -Option Constant -Name APIClientId -Value "1950a258-227b-4e31-a9cf-717495945fc2"
New-Variable -Option Constant -Name RedirectURI -Value "urn:ietf:wg:oauth:2.0:oob"
New-Variable -Option Constant -Name AuthenticationEndpoint -Value "https://login.windows.net"

# PromptBehaviour:
# Always 	
#  The user will be prompted for credentials even if there is a token that meets the requirements already in the cache.
# Auto 	
#  Acquire token will prompt the user for credentials only when necessary. If a token that meets the requirements is already cached then the user will not be prompted.
# Never 	
#  The user will not be prompted for credentials. If prompting is necessary then the AcquireToken request will fail.
# RefreshSession 	
# Re-authorizes (through displaying webview) the resource usage, making sure that the resulting access token contains updated claims. If user logon cookies are available, the user will not be asked for credentials again and the logon dialog will dismiss automatically.
New-Variable -Option Constant -Name AuthenticationPromptBehaviour -Value "Auto"


Function Get-MicrosoftAPIAuthorisationToken {
    <#
    .Synopsis
    Returns a Java Web Token (JWT), usable as authorisation headers when calling Microsoft APIs. Each token is good for only one API endpoint, which must be specified when calling Get-MicrosoftAPIAuthorisationToken.
    .Description
    The MS REST APIs need you to present your authorisation token when calling them. This function connects to the Azure AD API and requests a token, which it then wraps appropriately such that can be passed as a -Headers parameter to e.g. Invoke-RestMethod.
    
    This function allows interactive user logins, and automated service principal logins that use either a secret or a certificate. The certificate must exist in the caller's personal certificate store.
    .Parameter UserName
    A valid Azure AD User Principal Name (UPN) such as alice@contoso.onmicrosoft.com .
    .Parameter TenantName
    e.g. 'contoso.onmicrosoft.com'
    .Parameter API
    This is the REST API endpoint you wish to access. The ones I know about are:
    
        https://graph.windows.net         Azure AD Graph API ("legacy", now)
        https://graph.microsoft.com       Microsoft Graph API
        https://management.azure.com      Azure REST API
        https://consumption.azure.com     Supposedly the EA portal, or similar functionality.
        
    There may be other API endpoints, which I don't know about. If you need to use one not in this list, you must edit this function.
    .Parameter ApplicationId
    Service Principal's AppId, if connecting as a Service Principal.
    .Parameter ApplicationSecret
    Service Principal's secret, if connecting as a Service Principal using a secret. The secret must be passed as a secure string.
    .Parameter CertificateThumbprint
    Service Principal's certificate's private key's thumbprint, if connecting as a Service Principal using a certificate. The certificate must be installed in your personal certificate store.    
    .Inputs
    None.
    .Outputs
    None.
    .Example
    C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -UserName alice@contoso.onmicrosoft.com
    
    C:\PS> $AuthorisationToken
    
    Name                           Value
    ----                           -----
    Authorization                  Bearer eyJ0eXAiOiJK...
    Content-Type                   application/json
    
    C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
    
    .Example
    C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -ApplicationId e5e53f0d-c79e-430c-b2ac-3facc6fec1c8 -CertificateThumbprint 16F0C35E40E6C9F0E1806940E8185FBA37DF666E
    
    C:\PS> $AuthorisationToken

    Name                           Value
    ----                           -----
    Authorization                  Bearer eyJ0eXAiOiJK...
    Content-Type                   application/json
    
    C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
    
    .Example
    C:\PS> $ApplicationSecret = "K9h60/G0PaFeQjV/M*q_mKW3ak-.]RmM" | ConvertTo-SecureString -AsPlainText -Force
    # note - there are better ways to enter a secure string!
    
    C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -ApplicationId e5e53f0d-c79e-430c-b2ac-3facc6fec1c8 -ApplicationSecret $ApplicationSecret
    
    C:\PS> $AuthorisationToken

    Name                           Value
    ----                           -----
    Authorization                  Bearer eyJ0eXAiOiJK...
    Content-Type                   application/json
    
    C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
  
    #>
    [CmdletBinding(DefaultParameterSetName="ByUserName")] 
    Param(
        [parameter(ParameterSetName="ByUserName", Mandatory=$false)]
        [parameter(ParameterSetName="ByServicePrincipalWithSecret", Mandatory=$false)]
        [parameter(ParameterSetName="ByServicePrincipalWithCertificate", Mandatory=$false)]
        [String]$TenantName = "contoso.onmicrosoft.com",
        
        [parameter(ParameterSetName="ByUserName", Mandatory=$true)]
        [parameter(ParameterSetName="ByServicePrincipalWithSecret", Mandatory=$true)]
        [parameter(ParameterSetName="ByServicePrincipalWithCertificate", Mandatory=$true)]
        # I had this as a constant at the beginning of the doc, but Posh doesn't like it! Very annoying. You can modify this if you have additional APIs
        [ValidateSet("https://graph.microsoft.com", "https://graph.windows.net", "https://management.azure.com", "https://consumption.azure.com", "74658136-14ec-4630-ad9b-26e160ff0fc6")]
        [String]$API,
        
        
        [parameter(ParameterSetName="ByUserName", Mandatory=$false)]        
        [String]$UserName,
        
        [parameter(ParameterSetName="ByServicePrincipalWithSecret", Mandatory=$true)]
        [parameter(ParameterSetName="ByServicePrincipalWithCertificate", Mandatory=$true)]
        [String]$ApplicationId,
        
        [parameter(ParameterSetName="ByServicePrincipalWithSecret", Mandatory=$true)]
        [SecureString]$ApplicationSecret,
        
        [parameter(ParameterSetName="ByServicePrincipalWithCertificate", Mandatory=$true)]
        [String]$CertificateThumbprint
        
    )
    
    try{
        Import-Module AzureRM -ErrorAction Stop
    }
    catch{
        Write-Warning "Can't load AzureRM module."
        Return
    }

    # use a switch statement because there may be additional APIs later that need to be identified (to MS) as GUIDs
    switch ($API){
     "74658136-14ec-4630-ad9b-26e160ff0fc6" {
      $API = "74658136-14ec-4630-ad9b-26e160ff0fc6"
       
      Write-Host -ForegroundColor Yellow "Note: The https://main.iam.ad.ext.azure.com API is undocumented, and you're probably using it because you're reverse-engineering the Azure Portal. Good for you!"
      Write-Host -ForegroundColor Yellow "You need to add an additional header to your method invocations to be able to call it: 'x-ms-client-request-id', whose value is a GUID."
      Write-Host -ForegroundColor Yellow "e.g."
      Write-Host -ForegroundColor Yellow "  $RestApiToken.Add('x-ms-client-request-id', (New-Guid).ToString())"
      Write-Host -ForegroundColor Yellow ""
      Write-Host -ForegroundColor Yellow "As far as I can tell, the GUID _probably_ should be renewed with each call to the API, but it seems to work without it. I'm guessing that write actions may experience odd behaviour if you don't, though."
     }
    }

    $AuthenticationContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList "$AuthenticationEndpoint/$TenantName"
    
    switch ($psCmdlet.ParameterSetName){
        "ByUserName" {
            try{
                $AuthenticationResult = $AuthenticationContext.AcquireToken($API, $APIClientID, $RedirectUri, $AuthenticationPromptBehaviour)
            } catch {
                Write-Warning "Couldn't acquire token."
                Write-Warning $_.Exception.Message
                Write-Warning "Aborting."
                Return
            }
        }
        "ByServicePrincipalWithSecret" {
            try{
                $ClientCredential = New-Object -Type Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential -ArgumentList $ApplicationId,$ApplicationSecret
            
                $AuthenticationResult = $AuthenticationContext.AcquireToken($API, $ClientCredential)
            } catch {
                Write-Warning "Couldn't acquire token."
                Write-Warning $_.Exception.Message
                Write-Warning "Aborting."
                Return
            }
        }
        "ByServicePrincipalWithCertificate" {
            $CertificatePath = "Cert:\CurrentUser\My\$CertificateThumbprint"
        
            If (-Not (Test-Path $CertificatePath)) {
                Write-Warning "Couldn't find the certificate in your certificate store! Please check."
                Write-Warning "Aborting."
                Return
            }
            
            try{
                $ClientAssertionCertificate = New-Object -Type Microsoft.IdentityModel.Clients.ActiveDirectory.ClientAssertionCertificate -ArgumentList $ApplicationId,(Get-Item $CertificatePath)
                
                $AuthenticationResult = $AuthenticationContext.AcquireToken($API, $ClientAssertionCertificate)
            } catch {
                Write-Warning "Couldn't acquire token."
                Write-Warning $_.Exception.Message
                Write-Warning "Aborting."
                Return
            }
        }
    }

    @{
       'Content-Type'='application/json'
       'Authorization'=$AuthenticationResult.CreateAuthorizationHeader()
    }
}
