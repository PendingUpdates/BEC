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

# Run only local helper definitions against an unavailable or denied command.
# These checks exercise the host PowerShell without opening an Exchange session.
$ast = [Management.Automation.Language.Parser]::ParseFile($adapter, [ref]$tokens, [ref]$errors)
$helpers = $ast.FindAll({ param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst] -and
        ($n.Name -like '*BecSnapshot*' -or $n.Name -eq 'Get-BecReadFailure')
}, $false)
foreach ($helper in $helpers) { . ([scriptblock]::Create($helper.Extent.Text)) }
function Assert-BecConnection { $script:sessionChecks++ }
$script:sessionChecks = 0
$dateFormat = [Globalization.CultureInfo]::InvariantCulture
$stamp = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
$target = [guid]::NewGuid()
$address = "$([guid]::NewGuid())@example.invalid"
$mailbox = [pscustomobject]@{ PrimarySmtpAddress = $address; ExternalDirectoryObjectId = [guid]::NewGuid()
    Guid = $target; ExchangeGuid = [guid]::NewGuid(); ForwardingAddress = $null
    ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @() }
$anchor = Get-BecSnapshotAnchor $mailbox $address
$commands = @{}
$at = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
$unavailable = Get-BecSnapshotObservations $mailbox $anchor $at
if ($unavailable.inbox_rules.status -ne 'unavailable' -or $unavailable.inbox_rules.records.Count -ne 0) {
    throw 'A missing inbox-rule command must produce an empty coverage gap.'
}
function Read-DeniedRule {
    [CmdletBinding()]param([string]$Mailbox,[int]$ResultSize,[switch]$IncludeHidden)
    if ($Mailbox -cne $target.ToString() -or $ResultSize -ne 1000 -or -not $IncludeHidden) {
        throw 'Snapshot query lost its native target or bounded options.'
    }
    throw [UnauthorizedAccessException]::new('Unavailable to the current operator.')
}
$commands['Get-InboxRule'] = Get-Command Read-DeniedRule
$denied = Get-BecSnapshotObservations $mailbox $anchor $at
if ($denied.inbox_rules.status -ne 'denied' -or $denied.inbox_rules.records.Count -ne 0 -or
    $script:sessionChecks -lt 2) { throw 'A denied read must preserve its gap and session guards.' }
'Native unavailable and denied current-state checks passed with local mocks.'
