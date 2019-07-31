@{
    RootModule        = 'JWTDetails.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'fc04acca-f218-46c3-9c60-2ba5fbcc8d3c'
    Author            = 'Darren J Robinson'
    CompanyName       = 'Community'
    Copyright         = '(c) 2019 Darren J Robinson. All rights reserved.'
    Description       = 'Decode a JWT Access Token and convert to a PowerShell Object. JWT Access Token updated to include the JWT Signature (sig), JWT Token Expiry (expiryDateTime) and JWT Token time to expiry (timeToExpiry).'
    PowerShellVersion = '5.0.0'
    RequiredModules   = ''
    FunctionsToExport = @('get-JWTDetails')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}

