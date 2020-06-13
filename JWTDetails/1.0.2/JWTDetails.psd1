@{
    RootModule           = 'JWTDetails.psm1'
    ModuleVersion        = '1.0.2'
    GUID                 = 'fc04acca-f218-46c3-9c60-2ba5fbcc8d3c'
    Author               = 'Darren J Robinson'
    CompanyName          = 'Community'
    Copyright            = '(c) 2020 Darren J Robinson. All rights reserved.'
    Description          = 'Decode a JWT Access Token and convert to a PowerShell Object. JWT Access Token updated to include the JWT Signature (sig), JWT Token Expiry (expiryDateTime) and JWT Token time to expiry (timeToExpiry).'
    PowerShellVersion    = '5.0.0'
    CompatiblePSEditions = 'Core', 'Desktop'
    RequiredModules      = ''
    FunctionsToExport    = @('Get-JWTDetails')
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            ProjectUri = 'https://github.com/darrenjrobinson/JWTDetails'
        } 
    } 
}
