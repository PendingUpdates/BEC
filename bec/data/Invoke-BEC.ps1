#requires -Version 7.4
<# Run in the operator's current PowerShell instance. Only Python runs as a child. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [Parameter(Mandatory)][guid]$TenantId,
    [string[]]$Accounts,
    [string]$StartUtc,
    [string]$EndUtc,
    [string]$CaseRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Get-BecSession {
    if (@(Get-Module -Name ExchangeOnlineManagement).Count -ne 1) {
        throw 'Use the PowerShell window where you signed in to Exchange Online.'
    }
    $connections = @(ExchangeOnlineManagement\Get-ConnectionInformation -ErrorAction Stop)
    if ($connections.Count -ne 1) { throw 'Use a window with exactly one direct customer Exchange connection.' }
    $c = $connections[0]
    if ($c.State -ne 'Connected' -or $c.TokenStatus -ne 'Active' -or
        [string]$c.CertificateAuthentication -ne 'False' -or [string]$c.IsEopSession -ne 'False' -or
        $c.Organization -or $c.DelegatedOrganization -or $c.ModulePrefix -or
        -not $c.UserPrincipalName -or -not $c.ModuleName -or
        [guid]$c.ConnectionId -eq [guid]::Empty -or [guid]$c.TenantID -ne $TenantId -or $TenantId -eq [guid]::Empty) {
        throw 'A direct, active user session for the specified customer tenant is required. No mailbox read was authorized.'
    }
    return $c
}

function Assert-BecConnection {
    $current = Get-BecSession
    if ($current.ConnectionId -ne $session.ConnectionId -or $current.UserPrincipalName -ne $session.UserPrincipalName -or
        $current.ModuleName -ne $session.ModuleName) { throw 'The operator session changed. Stopping collection.' }
}

$session = Get-BecSession
$sourceModules = @(Get-Module -All | Where-Object {
    $_.Path -eq $session.ModuleName -or $_.ModuleBase -eq $session.ModuleName -or $_.Name -eq $session.ModuleName
})
if ($sourceModules.Count -ne 1) { throw 'Cannot identify the unique command module for this connection.' }
$commands = $sourceModules[0].ExportedCommands
$mailboxRead = $commands['Get-Mailbox']
if (-not $mailboxRead) { throw 'Cannot verify the mailbox with Get-Mailbox in this session. No incident records were read.' }

$scopeArgs = @('--tenant', $TenantId.ToString(), '--operator', $session.UserPrincipalName,
               '--connection', $session.ConnectionId.ToString())
if ($StartUtc) { $scopeArgs += @('--start', $StartUtc) }
if ($EndUtc) { $scopeArgs += @('--end', $EndUtc) }
if ($CaseRoot) { $scopeArgs += @('--root', $CaseRoot) }
if ($Accounts) { $scopeArgs += '--accounts'; $scopeArgs += $Accounts }
$planText = & $Python -I -m bec.exchange plan @scopeArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$plan = $planText | ConvertFrom-Json
# PowerShell versions can coerce ISO strings to local DateTime objects during JSON decoding.
$wire = [System.Text.Json.JsonDocument]::Parse([string]$planText)
try {
    $plan.start = $wire.RootElement.GetProperty('start').GetString()
    $plan.end = $wire.RootElement.GetProperty('end').GetString()
} finally { $wire.Dispose() }
$dateFormat = [Globalization.CultureInfo]::InvariantCulture
$from = [DateTimeOffset]::Parse($plan.start, $dateFormat).UtcDateTime
$until = [DateTimeOffset]::Parse($plan.end, $dateFormat).UtcDateTime
$result = 0
foreach ($account in $plan.accounts) {
    Assert-BecConnection
    try { $mailbox = @(& $mailboxRead -Identity $account -ErrorAction Stop -WarningAction Stop) }
    catch { throw "Get-Mailbox could not verify $account in this session. No incident reads were made for this account." }
    if ($mailbox.Count -ne 1 -or [string]$mailbox[0].PrimarySmtpAddress -ne $account -or
        -not $mailbox[0].ExternalDirectoryObjectId) {
        throw 'Could not verify one mailbox with that exact primary SMTP address. Stopping before incident reads.'
    }
    $parent = Join-Path $plan.root "exchange-exports/$TenantId"
    [void][IO.Directory]::CreateDirectory($parent)
    $directory = Join-Path $parent ([guid]::NewGuid().ToString())
    $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    $manifest = [ordered]@{
        schema = 'bec.exchange-powershell/v2'; tenant = $plan.tenant; directory_id = $plan.tenant
        scope = [ordered]@{account = $account; start = $plan.start; end = $plan.end
                           operator = $plan.operator; connection = $plan.connection}
        reads = [ordered]@{}; files = @()
    }
    foreach ($key in 'sent', 'received') {
        Assert-BecConnection
        $parameters = @{ StartDate = $from; EndDate = $until; ResultSize = $plan.limit; ErrorAction = 'Stop'
                         WarningAction = 'Stop' }
        $read = $commands['Get-MessageTraceV2']
        if ($key -eq 'sent') { $parameters['SenderAddress'] = $account }
        else { $parameters['RecipientAddress'] = $account }
        if (-not $read) { $manifest.reads[$key] = 'unavailable'; continue }
        try {
            $rows = @(& $read @parameters)
        } catch {
            $manifest.reads[$key] = 'denied-or-failed'
            continue
        }
        Assert-BecConnection
        if ($rows.Count -gt $plan.limit) { throw 'Exchange returned more records than requested. Stopping.' }
        $file = "$key.json"
        try { $json = ConvertTo-Json -InputObject $rows -Depth 32 -Compress -WarningAction Stop }
        catch { $manifest.reads[$key] = 'serialization-failed'; continue }
        # Carry the exact serialization through stdin. Python validates the whole page before opening a file.
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
        $captureArgs = @('--direction', $key, '--directory', $directory, '--tenant', $plan.tenant,
                         '--account', $account, '--start', $plan.start, '--end', $plan.end)
        $resultText = $encoded | & $Python -I -m bec.exchange save-trace @captureArgs
        if ($LASTEXITCODE -ne 0) { throw 'Stopped. The trace page could not be verified and saved.' }
        $page = $resultText | ConvertFrom-Json
        $manifest.files += @{dataset = 'trace'; path = $file; sha256 = $page.sha256}
        $manifest.reads[$key] = $page.status
    }
    Assert-BecConnection
    $manifest['captured_at'] = [DateTimeOffset]::UtcNow.ToString('o')
    $bundle = Join-Path $directory 'bundle.json'
    [IO.File]::WriteAllText($bundle, (ConvertTo-Json -InputObject $manifest -Depth 8), [Text.UTF8Encoding]::new($false))
    Write-Host "Local Exchange export for $account saved in $directory"
    & $Python -I -m bec --root $plan.root offline --bundle $bundle --tenant $plan.tenant --directory-id $plan.tenant --user $account --start $plan.start --end $plan.end
    if ($LASTEXITCODE -notin 0, 2) { exit $LASTEXITCODE }
    if ($LASTEXITCODE -eq 2) { $result = 2 }
}
exit $result
