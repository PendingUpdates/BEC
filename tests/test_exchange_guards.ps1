#requires -Version 7.4
# Run in a fresh pwsh -NoProfile -NonInteractive process. Only connection metadata is used.
$ErrorActionPreference = 'Stop'
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
           ModulePrefix = ''; ModuleName = 'NoWorkloadModule'; UserPrincipalName = 'operator@example.invalid' }
function Assert-Rejection($rows, $reason) {
    & $module { param($value) $script:Rows = $value } $rows
    $message = ''
    try { & $adapter -TenantId $tenant -Python 'PYTHON-MUST-NOT-START' }
    catch { $message = $_.Exception.Message }
    if ($message -notlike "*$reason*") { throw "Expected guard '$reason'. Received '$message'." }
}
Assert-Rejection @() 'exactly one'
Assert-Rejection @([pscustomobject]$base, [pscustomobject]$base) 'exactly one'
foreach ($invalid in @(@{ TenantID = [guid]::NewGuid() }, @{ TokenStatus = 'Expired' },
                       @{ CertificateAuthentication = $true }, @{ DelegatedOrganization = 'customer.invalid' },
                       @{ IsEopSession = $true }, @{ UserPrincipalName = '' })) {
    $row = $base.Clone()
    foreach ($k in $invalid.Keys) { $row[$k] = $invalid[$k] }
    Assert-Rejection @([pscustomobject]$row) 'direct, active user session'
}
Assert-Rejection @([pscustomobject]$base) 'unique command module'
'PowerShell scripts parsed and nine pre-read session guards passed.'
