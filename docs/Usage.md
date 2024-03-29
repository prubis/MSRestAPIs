# MSRestAPIs Module
## Get-MicrosoftAPIAuthorisationToken
### Synopsis
Returns a Java Web Token \(JWT\), usable as authorisation headers when calling Microsoft APIs. Each token is good for only one API endpoint, which must be specified when calling Get-MicrosoftAPIAuthorisationToken.
### Syntax
```powershell

Get-MicrosoftAPIAuthorisationToken [-TenantName <String>] -API <String> [-UserName <String>] [<CommonParameters>]

Get-MicrosoftAPIAuthorisationToken [-TenantName <String>] -API <String> -ApplicationId <String> -CertificateThumbprint <String> [<CommonParameters>]

Get-MicrosoftAPIAuthorisationToken [-TenantName <String>] -API <String> -ApplicationId <String> -ApplicationSecret <SecureString> [<CommonParameters>]





```
### Parameters
| Name  | Alias  | Description | Required? | Pipeline Input | Default Value |
| - | - | - | - | - | - |
| <nobr>TenantName</nobr> |  | e.g. 'contoso.onmicrosoft.com' | false | false | contoso.onmicrosoft.com |
| <nobr>API</nobr> |  | This is the REST API endpoint you wish to access. The ones I know about are:  https://graph.windows.net         Azure AD Graph API \("legacy", now\) https://graph.microsoft.com       Microsoft Graph API https://management.azure.com      Azure REST API https://consumption.azure.com     Supposedly the EA portal, or similar functionality.  There may be other API endpoints, which I don't know about. If you need to use one not in this list, you must edit this function. | true | false |  |
| <nobr>UserName</nobr> |  | A valid Azure AD User Principal Name \(UPN\) such as alice@contoso.onmicrosoft.com . | false | false |  |
| <nobr>ApplicationId</nobr> |  | Service Principal's AppId, if connecting as a Service Principal. | true | false |  |
| <nobr>ApplicationSecret</nobr> |  | Service Principal's secret, if connecting as a Service Principal using a secret. The secret must be passed as a secure string. | true | false |  |
| <nobr>CertificateThumbprint</nobr> |  | Service Principal's certificate's private key's thumbprint, if connecting as a Service Principal using a certificate. The certificate must be installed in your personal certificate store. | true | false |  |
### Inputs
 - None.

### Outputs
 - None.

### Examples
**EXAMPLE 1**
```powershell
C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -UserName alice@contoso.onmicrosoft.com

C:\PS> $AuthorisationToken

Name                           Value
----                           -----
Authorization                  Bearer eyJ0eXAiOiJK...
Content-Type                   application/json

C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
```

**EXAMPLE 2**
```powershell
C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -ApplicationId e5e53f0d-c79e-430c-b2ac-3facc6fec1c8 -CertificateThumbprint 16F0C35E40E6C9F0E1806940E8185FBA37DF666E

C:\PS> $AuthorisationToken

Name                           Value
----                           -----
Authorization                  Bearer eyJ0eXAiOiJK...
Content-Type                   application/json

C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
```

**EXAMPLE 3**
```powershell
C:\PS> $ApplicationSecret = "K9h60/G0PaFeQjV/M*q_mKW3ak-.]RmM" | ConvertTo-SecureString -AsPlainText -Force

# note - there are better ways to enter a secure string!

C:\PS> $AuthorisationToken = Get-MicrosoftAPIAuthorisationToken -API https://graph.microsoft.com -TenantName contoso.onmicrosoft.com -ApplicationId
e5e53f0d-c79e-430c-b2ac-3facc6fec1c8 -ApplicationSecret $ApplicationSecret

C:\PS> $AuthorisationToken

Name                           Value
----                           -----
Authorization                  Bearer eyJ0eXAiOiJK...
Content-Type                   application/json

C:\PS> Invoke-RestMethod -Uri https://graph.microsoft.com/... -Headers $AuthorisationToken -...
```

