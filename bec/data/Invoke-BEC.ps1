#requires -Version 7.4
<# Run in the operator's current PowerShell instance. Only Python runs as a child. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Python,
    [guid]$TenantId,
    [string[]]$Accounts,
    [string]$StartUtc,
    [string]$EndUtc,
    [string]$CaseRoot
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

function Get-BecCommandPin($Module, [string]$Name, [bool]$Required) {
    $command = $Module.ExportedCommands[$Name]
    if ($null -eq $command) {
        if ($Required) { throw "The verified module does not export $Name. No mailbox read was authorized." }
        return $null
    }
    if (($command -isnot [Management.Automation.FunctionInfo] -and
         $command -isnot [Management.Automation.CmdletInfo]) -or $command.Name -cne $Name -or
        $command.Module -isnot [Management.Automation.PSModuleInfo]) {
        throw "Cannot bind $Name to its loaded command module. No mailbox read was authorized."
    }
    $owners = @($Module) + @($Module.NestedModules)
    $matchingOwners = @($owners | Where-Object { [object]::ReferenceEquals($_, $command.Module) })
    if ($matchingOwners.Count -ne 1) {
        throw "Cannot bind $Name to its loaded command module. No mailbox read was authorized."
    }
    $body = if ($command -is [Management.Automation.FunctionInfo]) { $command.ScriptBlock } else { $command.ImplementingType }
    if ($null -eq $body) { throw "Cannot pin the implementation of $Name. No mailbox read was authorized." }
    return [pscustomobject]@{ Command = $command; Body = $body; SourceModule = $command.Module
        CommandType = $command.CommandType }
}

function Assert-BecCommandPin($Module, [string]$Name, $Pin) {
    $current = Get-BecCommandPin $Module $Name $false
    if ($null -eq $Pin) {
        if ($null -ne $current) { throw 'The session command exports changed. Stopping collection.' }
        return
    }
    if ($null -eq $current -or $current.CommandType -ne $Pin.CommandType -or
        -not [object]::ReferenceEquals($current.SourceModule, $Pin.SourceModule)) {
        throw 'The session command exports changed. Stopping collection.'
    }
    # Export lookup may create a new CommandInfo wrapper. Pin the loaded owner and implementation,
    # then invoke the original CommandInfo; neither command-name resolution nor text equality suffices.
    $pinnedBody = if ($Pin.Command -is [Management.Automation.FunctionInfo]) { $Pin.Command.ScriptBlock } else { $Pin.Command.ImplementingType }
    if (-not [object]::ReferenceEquals($current.Body, $Pin.Body) -or
        -not [object]::ReferenceEquals($pinnedBody, $Pin.Body) -or
        -not [object]::ReferenceEquals($Pin.Command.Module, $Pin.SourceModule)) {
        throw 'The session command implementation changed. Stopping collection.'
    }
}

function Get-BecStatusName($Value) {
    if ($Value -is [string]) { return $Value }
    if ($Value -is [Enum] -and [Enum]::IsDefined($Value.GetType(), $Value)) { return $Value.ToString() }
    return $null
}

function Get-BecExpiry($Value) {
    if ($Value -is [DateTimeOffset]) { return $Value.ToUniversalTime() }
    if ($Value -is [DateTime]) {
        # This metadata field is explicitly UTC even when its DateTime kind is unspecified.
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) {
            $Value = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc)
        }
        return [DateTimeOffset]::new($Value).ToUniversalTime()
    }
    $expiry = [DateTimeOffset]::MinValue
    if ($Value -is [string] -and
        $Value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})$' -and
        [DateTimeOffset]::TryParse($Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::None, [ref]$expiry)) {
        return $expiry.ToUniversalTime()
    }
    throw 'Cannot verify the session token expiry as a UTC instant. No mailbox read was authorized.'
}

$hasExpectedTenant = $PSBoundParameters.ContainsKey('TenantId')
$expectedTenantId = $TenantId
if ($hasExpectedTenant -and $expectedTenantId -eq [guid]::Empty) {
    throw 'The explicit tenant ID must be a nonempty GUID. No mailbox read was authorized.'
}
$metadataModules = @(Get-Module -Name ExchangeOnlineManagement)
if ($metadataModules.Count -ne 1) {
    throw 'Use the PowerShell window where you signed in to Exchange Online.'
}
$metadataModule = $metadataModules[0]
$metadataPin = Get-BecCommandPin $metadataModule 'Get-ConnectionInformation' $true
$metadataRead = $metadataPin.Command

function Get-BecSession {
    $loaded = @(Get-Module -Name ExchangeOnlineManagement)
    if ($loaded.Count -ne 1 -or -not [object]::ReferenceEquals($loaded[0], $metadataModule)) {
        throw 'The Exchange metadata module changed. Stopping collection.'
    }
    Assert-BecCommandPin $metadataModule 'Get-ConnectionInformation' $metadataPin
    $connections = @(& $metadataRead -ErrorAction Stop)
    if ($connections.Count -ne 1) { throw 'Use a window with exactly one direct customer Exchange connection.' }
    $c = $connections[0]
    foreach ($name in 'State', 'TokenStatus', 'CertificateAuthentication', 'IsEopSession', 'Organization',
             'DelegatedOrganization', 'ModulePrefix', 'UserPrincipalName', 'ModuleName', 'ConnectionId',
             'TenantID', 'TokenExpiryTimeUTC') {
        if ($null -eq $c.PSObject.Properties[$name]) {
            throw 'Incomplete direct user session metadata. No mailbox read was authorized.'
        }
    }
    if ((Get-BecStatusName $c.State) -cne 'Connected' -or
        (Get-BecStatusName $c.TokenStatus) -cne 'Active' -or
        $c.CertificateAuthentication -isnot [bool] -or $c.CertificateAuthentication -ne $false -or
        $c.IsEopSession -isnot [bool] -or $c.IsEopSession -ne $false -or
        $c.UserPrincipalName -isnot [string] -or [string]::IsNullOrWhiteSpace($c.UserPrincipalName) -or
        $c.UserPrincipalName.Length -gt 320 -or $c.UserPrincipalName -match '[\p{Cc}\p{Cf}]' -or
        $c.ModuleName -isnot [string] -or [string]::IsNullOrWhiteSpace($c.ModuleName)) {
        throw 'A direct, active user session for the specified customer tenant is required. No mailbox read was authorized.'
    }
    foreach ($name in 'Organization', 'DelegatedOrganization', 'ModulePrefix') {
        if ($null -ne $c.$name -and ($c.$name -isnot [string] -or $c.$name.Length -ne 0)) {
            throw 'A direct, active user session for the specified customer tenant is required. No mailbox read was authorized.'
        }
    }
    $nativeTenant = [guid]::Empty
    $connectionId = [guid]::Empty
    if (($c.TenantID -isnot [guid] -and $c.TenantID -isnot [string]) -or
        ($c.ConnectionId -isnot [guid] -and $c.ConnectionId -isnot [string]) -or
        -not [guid]::TryParse([string]$c.TenantID, [ref]$nativeTenant) -or $nativeTenant -eq [guid]::Empty -or
        -not [guid]::TryParse([string]$c.ConnectionId, [ref]$connectionId) -or $connectionId -eq [guid]::Empty -or
        ($hasExpectedTenant -and $nativeTenant -ne $expectedTenantId)) {
        throw 'A direct, active user session for the specified customer tenant is required. No mailbox read was authorized.'
    }
    if ((Get-BecExpiry $c.TokenExpiryTimeUTC) -le [DateTimeOffset]::UtcNow) {
        throw 'The session token has expired. No mailbox read was authorized.'
    }
    # Copy identity values; a later mutation of the metadata object cannot alter this pin.
    return [pscustomobject]@{ TenantID = $nativeTenant; ConnectionId = $connectionId
        UserPrincipalName = $c.UserPrincipalName; ModuleName = $c.ModuleName }
}

function Assert-BecConnection {
    $current = Get-BecSession
    if ($current.TenantID -ne $TenantId -or $current.ConnectionId -ne $session.ConnectionId -or
        $current.UserPrincipalName -cne $session.UserPrincipalName -or $current.ModuleName -cne $session.ModuleName) {
        throw 'The operator session changed. Stopping collection.'
    }
    $loaded = @(Get-Module -All | Where-Object {
        $_.Path -ceq $session.ModuleName -or $_.ModuleBase -ceq $session.ModuleName -or $_.Name -ceq $session.ModuleName
    })
    if ($loaded.Count -ne 1 -or -not [object]::ReferenceEquals($loaded[0], $sourceModule)) {
        throw 'The session command module changed. Stopping collection.'
    }
    foreach ($name in 'Get-Mailbox', 'Get-MessageTraceV2') {
        Assert-BecCommandPin $sourceModule $name $commandPins[$name]
    }
}

$session = Get-BecSession
$TenantId = $session.TenantID
$sourceModules = @(Get-Module -All | Where-Object {
    $_.Path -ceq $session.ModuleName -or $_.ModuleBase -ceq $session.ModuleName -or $_.Name -ceq $session.ModuleName
})
if ($sourceModules.Count -ne 1) { throw 'Cannot identify the unique command module for this connection.' }
$sourceModule = $sourceModules[0]
$commandPins = @{
    'Get-Mailbox' = (Get-BecCommandPin $sourceModule 'Get-Mailbox' $true)
    'Get-MessageTraceV2' = (Get-BecCommandPin $sourceModule 'Get-MessageTraceV2' $false)
}
$commands = @{}
foreach ($name in 'Get-Mailbox', 'Get-MessageTraceV2') {
    $commands[$name] = if ($null -eq $commandPins[$name]) { $null } else { $commandPins[$name].Command }
}
$mailboxRead = $commands['Get-Mailbox']

$scopeArgs = @('--tenant', $TenantId.ToString(), '--operator', $session.UserPrincipalName,
               '--connection', $session.ConnectionId.ToString())
if ($StartUtc) { $scopeArgs += @('--start', $StartUtc) }
if ($EndUtc) { $scopeArgs += @('--end', $EndUtc) }
if ($CaseRoot) { $scopeArgs += @('--root', $CaseRoot) }
if ($Accounts) { $scopeArgs += '--accounts'; $scopeArgs += $Accounts }
$planText = & $Python -I -m bec.exchange plan-session @scopeArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Assert-BecConnection
$plan = $planText | ConvertFrom-Json
# Read time fields as strings even on PowerShell versions that convert JSON dates to local DateTime.
$wire = [System.Text.Json.JsonDocument]::Parse([string]$planText)
try {
    foreach ($name in 'start', 'end', 'planned_at') { $plan.$name = $wire.RootElement.GetProperty($name).GetString() }
    $chunks = @(foreach ($chunk in $wire.RootElement.GetProperty('chunks').EnumerateArray()) {
        [pscustomobject]@{ Id = $chunk.GetProperty('id').GetString()
                          Start = $chunk.GetProperty('start').GetString(); End = $chunk.GetProperty('end').GetString() }
    })
} finally { $wire.Dispose() }

function Get-BecReadFailure($failure) {
    if ($failure.FullyQualifiedErrorId -match 'throttl|TooManyRequests|ServerBusy') { return 'throttled' }
    if ($failure.FullyQualifiedErrorId -match 'AccessDenied|Unauthorized|Forbidden|PermissionDenied') { return 'access-denied' }
    for ($err = $failure.Exception; $null -ne $err; $err = $err.InnerException) {
        if ($err -is [OperationCanceledException] -or $err -is [Management.Automation.PipelineStoppedException]) {
            throw $failure
        }
        if ($err -is [UnauthorizedAccessException]) { return 'access-denied' }
        if ($err.Message -match '\btoo many requests\b|\bthrottl(ed|ing)\b|\brate limit exceeded\b') { return 'throttled' }
        $objects = @($err)
        $response = $err.PSObject.Properties['Response']
        if ($null -ne $response) { $objects += $response.Value }
        foreach ($obj in $objects) {
            if ($null -eq $obj) { continue }
            $http = $obj.PSObject.Properties['StatusCode']
            if ($null -ne $http -and [string]$http.Value -in '429', 'TooManyRequests') { return 'throttled' }
            if ($null -ne $http -and [string]$http.Value -in '401', '403', 'Unauthorized', 'Forbidden') { return 'access-denied' }
        }
    }
    return 'denied-or-failed'
}

$dateFormat = [Globalization.CultureInfo]::InvariantCulture
$stamp = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
$calls = [Collections.Generic.Queue[datetime]]::new()
$serviceThrottled = $false
$result = 0
foreach ($account in $plan.accounts) {
    Assert-BecConnection
    try { $mailbox = @(& $mailboxRead -Identity $account -ErrorAction Stop -WarningAction Stop) }
    catch { throw "Get-Mailbox could not verify $account in this session. No incident reads were made for this account." }
    Assert-BecConnection
    if ($mailbox.Count -ne 1 -or [string]$mailbox[0].PrimarySmtpAddress -ne $account -or
        -not $mailbox[0].ExternalDirectoryObjectId) {
        throw 'Could not verify one mailbox with that exact primary SMTP address. Stopping before incident reads.'
    }
    $parent = Join-Path $plan.root "exchange-exports/$TenantId"
    $directory = Join-Path $parent ([guid]::NewGuid().ToString())
    $directoryCreated = $false
    $manifest = [ordered]@{
        schema = 'bec.exchange-powershell/v3'; tenant = $plan.tenant; directory_id = $plan.tenant; planned_at = $plan.planned_at
        scope = [ordered]@{account = $account; start = $plan.start; end = $plan.end
                           operator = $plan.operator; connection = $plan.connection}
        reads = [ordered]@{}; files = @()
    }
    foreach ($chunk in $chunks) {
        $plannedFrom = [DateTimeOffset]::Parse($chunk.Start, $dateFormat).UtcDateTime
        $until = [DateTimeOffset]::Parse($chunk.End, $dateFormat).UtcDateTime
        foreach ($direction in 'sent', 'received') {
            Assert-BecConnection
            $checked = [DateTime]::UtcNow
            $cutoff = [datetime]::new($checked.Year, $checked.Month, $checked.Day, $checked.Hour,
                $checked.Minute, 0, [DateTimeKind]::Utc).AddMinutes(1).AddDays(-90)
            $from = $plannedFrom
            if ($from -lt $cutoff) { $from = $cutoff }
            if ($from -gt $until) { $from = $until }
            $key = "$direction-$($chunk.Id)"
            $outcome = [ordered]@{start = $from.ToString($stamp, $dateFormat); end = $chunk.End
                                  checked_at = $checked.ToString($stamp, $dateFormat); status = 'unavailable'}
            $manifest.reads[$key] = $outcome
            if ($from -eq $until) { $outcome.status = 'retention'; continue }
            $read = $commands['Get-MessageTraceV2']
            if (-not $read) { continue }
            while ($calls.Count -gt 0 -and $calls.Peek() -le $checked.AddMinutes(-5)) { $null = $calls.Dequeue() }
            if ($serviceThrottled -or $calls.Count -ge 100) { $outcome.status = 'budget-limited'; continue }
            # The authorized interval is half open. Request the last representable .NET instant inside it.
            $parameters = @{ StartDate = $from; EndDate = $until.AddTicks(-1); ResultSize = $plan.limit
                             ErrorAction = 'Stop'; WarningAction = 'Stop' }
            if ($direction -eq 'sent') { $parameters['SenderAddress'] = $account }
            else { $parameters['RecipientAddress'] = $account }
            $calls.Enqueue($checked)
            try {
                $rows = @(& $read @parameters)
            } catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] {
                throw
            } catch {
                $failure = $_
                Assert-BecConnection
                $outcome.status = Get-BecReadFailure $failure
                if ($outcome.status -eq 'throttled') { $serviceThrottled = $true }
                continue
            }
            Assert-BecConnection
            if ($rows.Count -gt $plan.limit) { throw 'Exchange returned more records than requested. Stopping.' }
            try { $json = ConvertTo-Json -InputObject $rows -Depth 32 -Compress -WarningAction Stop }
            catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] { throw }
            catch { $outcome.status = 'serialization-failed'; continue }
            $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
            $captureArgs = @('--direction', $direction, '--chunk', $chunk.Id, '--directory', $directory,
                             '--tenant', $plan.tenant, '--account', $account, '--start', $outcome.start, '--end', $chunk.End)
            if (-not $directoryCreated) { $captureArgs += '--new-directory' }
            Assert-BecConnection
            $resultText = $encoded | & $Python -I -m bec.exchange save-trace @captureArgs
            if ($LASTEXITCODE -eq 3) { $outcome.status = 'boundary-overlap'; continue }
            if ($LASTEXITCODE -ne 0) { throw 'Stopped. The trace page could not be verified and saved.' }
            $directoryCreated = $true
            $page = $resultText | ConvertFrom-Json
            $manifest.files += @{dataset = 'trace'; path = "$key.json"; sha256 = $page.sha256}
            $outcome.status = $page.status
        }
    }
    Assert-BecConnection
    if (-not $directoryCreated) {
        [void][IO.Directory]::CreateDirectory($parent)
        $null = New-Item -ItemType Directory -Path $directory -ErrorAction Stop
    }
    $manifest['captured_at'] = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
    $bundle = Join-Path $directory 'bundle.json'
    [IO.File]::WriteAllText($bundle, (ConvertTo-Json -InputObject $manifest -Depth 8), [Text.UTF8Encoding]::new($false))
    Write-Host "Local Exchange export for $account saved in $directory"
    & $Python -I -m bec --root $plan.root offline --bundle $bundle --tenant $plan.tenant --directory-id $plan.tenant --user $account --start $plan.start --end $plan.end
    if ($LASTEXITCODE -notin 0, 2) { exit $LASTEXITCODE }
    if ($LASTEXITCODE -eq 2) { $result = 2 }
}
exit $result
