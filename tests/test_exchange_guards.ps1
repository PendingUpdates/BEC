#requires -Version 7.4
# Run in a fresh pwsh -NoProfile -NonInteractive process. Only connection metadata is used.
$ErrorActionPreference = 'Stop'
enum BecMetadataState { Connected; Disconnected }
enum BecMetadataTokenStatus { Active; Expired }
if (Get-Module ExchangeOnlineManagement) { throw 'Use a fresh PowerShell process without a loaded Exchange module.' }
$adapter = Join-Path $PSScriptRoot '../bec/data/Invoke-BEC.ps1'
$tokens = $null
$errors = $null
foreach ($scriptPath in $adapter, (Join-Path $PSScriptRoot '../Invoke-BEC.ps1')) {
    $null = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw $errors[0] }
}
$tenant = [guid]::NewGuid()
$module = New-Module -Name ExchangeOnlineManagement -ScriptBlock {
    $script:Rows = @()
    function Get-ConnectionInformation { [CmdletBinding()] param() $script:Rows }
    Export-ModuleMember -Function Get-ConnectionInformation
}
Import-Module $module
$base = @{ State = 'Connected'; TokenStatus = 'Active'; TenantID = $tenant; ConnectionId = [guid]::NewGuid()
           CertificateAuthentication = $false; IsEopSession = $false; Organization = ''; DelegatedOrganization = ''
           ModulePrefix = ''; ModuleName = 'NoWorkloadModule'; UserPrincipalName = 'operator@example.invalid'
           TokenExpiryTimeUTC = [DateTimeOffset]::UtcNow.AddHours(1) }
$checks = 0
function Assert-Rejection($rows, $reason, [guid]$ExpectedTenant = $tenant, [switch]$OmitTenant) {
    & $module { param($value) $script:Rows = $value } $rows
    $message = ''
    $parameters = @{ Python = 'PYTHON-MUST-NOT-START' }
    if (-not $OmitTenant) { $parameters['TenantId'] = $ExpectedTenant }
    try { & $adapter @parameters }
    catch { $message = $_.Exception.Message }
    if ($message -notlike "*$reason*") { throw "Expected guard '$reason'. Received '$message'." }
    $script:checks++
}
Assert-Rejection @() 'exactly one'
Assert-Rejection @([pscustomobject]$base, [pscustomobject]$base) 'exactly one'
foreach ($invalid in @(@{ TenantID = [guid]::NewGuid() }, @{ TokenStatus = 'Expired' },
                       @{ State = 'Disconnected' }, @{ State = 0 }, @{ TokenStatus = 0 },
                       @{ State = [BecMetadataState]::Disconnected },
                       @{ TenantID = [guid]::Empty }, @{ ConnectionId = [guid]::Empty },
                       @{ CertificateAuthentication = $true }, @{ DelegatedOrganization = 'customer.invalid' },
                       @{ IsEopSession = $true }, @{ UserPrincipalName = '' }, @{ ModuleName = '' },
                       @{ CertificateAuthentication = 'False' }, @{ IsEopSession = 'False' },
                       @{ CertificateAuthentication = $null }, @{ IsEopSession = 0 },
                       @{ Organization = 'customer.invalid' }, @{ ModulePrefix = 'Prefix' },
                       @{ ModulePrefix = $false }, @{ TenantID = $true },
                       @{ UserPrincipalName = "operator@example.invalid`nother" })) {
    $row = $base.Clone()
    foreach ($k in $invalid.Keys) { $row[$k] = $invalid[$k] }
    Assert-Rejection @([pscustomobject]$row) 'direct, active user session'
}
foreach ($field in 'TenantID', 'UserPrincipalName', 'TokenExpiryTimeUTC', 'CertificateAuthentication') {
    $row = $base.Clone()
    $row.Remove($field)
    Assert-Rejection @([pscustomobject]$row) 'Incomplete direct user session'
}
$row = $base.Clone()
$row.TokenExpiryTimeUTC = [DateTimeOffset]::UtcNow.AddMinutes(-1)
Assert-Rejection @([pscustomobject]$row) 'token has expired'
foreach ($invalidExpiry in $null, '', '2035-01-01 00:00:00') {
    $row = $base.Clone()
    $row.TokenExpiryTimeUTC = $invalidExpiry
    Assert-Rejection @([pscustomobject]$row) 'Cannot verify the session token expiry'
}
foreach ($validExpiry in [DateTimeOffset]::UtcNow.AddHours(1).ToOffset([TimeSpan]::FromHours(2)),
                          [DateTime]::UtcNow.AddHours(1),
                          [DateTime]::SpecifyKind([DateTime]::UtcNow.AddHours(1), [DateTimeKind]::Unspecified),
                          [DateTime]::UtcNow.AddHours(1).ToString('o')) {
    $row = $base.Clone()
    $row.TokenExpiryTimeUTC = $validExpiry
    Assert-Rejection @([pscustomobject]$row) 'unique command module'
}
Assert-Rejection @([pscustomobject]$base) 'unique command module'
$row = $base.Clone()
$row.State = [BecMetadataState]::Connected
$row.TokenStatus = [BecMetadataTokenStatus]::Active
Assert-Rejection @([pscustomobject]$row) 'unique command module'
Assert-Rejection @([pscustomobject]$base) 'unique command module' -OmitTenant
Assert-Rejection @([pscustomobject]$base) 'explicit tenant ID must be a nonempty GUID' -ExpectedTenant ([guid]::Empty)
"PowerShell scripts parsed and $checks pre-read metadata guards passed. No workload command or Python process ran."
