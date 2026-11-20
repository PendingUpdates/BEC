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
    foreach ($name in 'Get-Mailbox', 'Get-MessageTraceV2', 'Get-InboxRule', 'Get-MailboxPermission', 'Get-RecipientPermission') {
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
    'Get-InboxRule' = (Get-BecCommandPin $sourceModule 'Get-InboxRule' $false)
    'Get-MailboxPermission' = (Get-BecCommandPin $sourceModule 'Get-MailboxPermission' $false)
    'Get-RecipientPermission' = (Get-BecCommandPin $sourceModule 'Get-RecipientPermission' $false)
}
$commands = @{}
foreach ($name in 'Get-Mailbox', 'Get-MessageTraceV2', 'Get-InboxRule', 'Get-MailboxPermission', 'Get-RecipientPermission') {
    $commands[$name] = if ($null -eq $commandPins[$name]) { $null } else { $commandPins[$name].Command }
}
$mailboxRead = $commands['Get-Mailbox']

$scopeArgs = @('--tenant', $TenantId.ToString(), '--operator', $session.UserPrincipalName,
               '--connection', $session.ConnectionId.ToString())
if ($StartUtc) { $scopeArgs += @('--start', $StartUtc) }
if ($EndUtc) { $scopeArgs += @('--end', $EndUtc) }
if ($CaseRoot) { $scopeArgs += @('--root', $CaseRoot) }
if ($Accounts) { $scopeArgs += '--accounts'; $scopeArgs += $Accounts }
$planText = & $Python -I -m bec.exchange plan-session --mailbox-state --run-layout @scopeArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Assert-BecConnection
$plan = $planText | ConvertFrom-Json
if ($null -eq $plan.PSObject.Properties['snapshot_schema'] -or $plan.snapshot_schema -cne 'bec.exchange-snapshot/v1') {
    throw 'The installed planner did not authorize current mailbox observations. Use the matching BEC package and adapter.'
}
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

function Get-BecSnapshotProperty($Row, [string]$Name) {
    $property = $Row.PSObject.Properties[$Name]
    if ($null -eq $property) { throw 'field-unavailable' }
    return $property.Value
}

function ConvertTo-BecSnapshotGuid($Value, [bool]$Optional = $false) {
    if ($null -eq $Value -and $Optional) { return $null }
    $id = [guid]::Empty
    if (($Value -isnot [string] -and $Value -isnot [guid]) -or
        -not [guid]::TryParse([string]$Value, [ref]$id)) { throw 'unbound-result' }
    if ($id -eq [guid]::Empty) {
        if ($Optional) { return $null }
        throw 'unbound-result'
    }
    return $id.ToString()
}

function Assert-BecSnapshotTenant($Row) {
    foreach ($name in 'TenantId', 'ExternalDirectoryOrganizationId') {
        $property = $Row.PSObject.Properties[$name]
        if ($null -ne $property) {
            if ((ConvertTo-BecSnapshotGuid $property.Value) -cne $TenantId.ToString()) { throw 'unbound-result' }
        }
    }
}

function Get-BecSnapshotAnchor($Mailbox, [string]$Account) {
    Assert-BecSnapshotTenant $Mailbox
    if ([string](Get-BecSnapshotProperty $Mailbox 'PrimarySmtpAddress') -ine $Account) { throw 'unbound-result' }
    $anchor = [ordered]@{ PrimarySmtpAddress = $Account
        ExternalDirectoryObjectId = (ConvertTo-BecSnapshotGuid (Get-BecSnapshotProperty $Mailbox 'ExternalDirectoryObjectId'))
        Guid = $null; ExchangeGuid = $null }
    foreach ($name in 'Guid', 'ExchangeGuid') {
        $property = $Mailbox.PSObject.Properties[$name]
        if ($null -ne $property) { $anchor[$name] = ConvertTo-BecSnapshotGuid $property.Value $true }
    }
    return $anchor
}

function Get-BecSnapshotTarget($Row, [string]$Property, $Anchor) {
    # Native ADObjectId.ObjectGuid names the target. Trustee/User and flattened names do not.
    if ($null -eq $Anchor.Guid) { throw 'unbound-result' }
    $identity = Get-BecSnapshotProperty $Row $Property
    if ($null -eq $identity -or $identity -is [string] -or $identity -is [guid]) { throw 'unbound-result' }
    $target = ConvertTo-BecSnapshotGuid (Get-BecSnapshotProperty $identity 'ObjectGuid')
    if ($target -cne $Anchor.Guid) { throw 'unbound-result' }
    return @{ ObjectGuid = $target }
}

function ConvertTo-BecSnapshotText($Value) {
    if ($Value -is [string]) { return $Value }
    if ($Value -is [Enum] -and [Enum]::IsDefined($Value.GetType(), $Value)) { return $Value.ToString() }
    $known = @('Microsoft.Exchange.Data.SmtpAddress', 'Microsoft.Exchange.Data.SmtpProxyAddress',
        'Microsoft.Exchange.Data.ProxyAddress', 'Microsoft.Exchange.Configuration.Tasks.RecipientIdParameter',
        'Microsoft.Exchange.Configuration.Tasks.SecurityPrincipalIdParameter', 'System.Security.Principal.SecurityIdentifier')
    if ($null -ne $Value -and $Value.GetType().FullName -in $known) { return $Value.ToString() }
    throw 'field-unavailable'
}

function ConvertTo-BecSnapshotBoolean($Value) {
    if ($Value -isnot [bool]) { throw 'field-unavailable' }
    return $Value
}

function ConvertTo-BecSnapshotRecipient($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    $guidProperty = $Value.PSObject.Properties['ObjectGuid']
    if ($null -ne $guidProperty) {
        return @{ ObjectGuid = (ConvertTo-BecSnapshotGuid $guidProperty.Value) }
    }
    # ADRecipientOrAddress exposes these fields. Preserve the routing type rather than assuming SMTP.
    $address = $Value.PSObject.Properties['Address']
    $routing = $Value.PSObject.Properties['RoutingType']
    if ($null -ne $address -and $null -ne $routing -and $address.Value -is [string] -and $routing.Value -is [string]) {
        return @{ Address = $address.Value; RoutingType = $routing.Value }
    }
    return ConvertTo-BecSnapshotText $Value
}

function ConvertTo-BecSnapshotRow($Row, [string]$Source, $Anchor) {
    Assert-BecSnapshotTenant $Row
    $record = [ordered]@{}
    if ($Source -in 'forwarding', 'send_on_behalf') {
        $returned = Get-BecSnapshotAnchor $Row $Anchor.PrimarySmtpAddress
        foreach ($key in $Anchor.Keys) {
            if ($returned[$key] -cne $Anchor[$key]) { throw 'unbound-result' }
            $record[$key] = $returned[$key]
        }
    } else {
        $field = if ($Source -eq 'inbox_rules') { 'MailboxOwnerId' } else { 'Identity' }
        $record[$field] = Get-BecSnapshotTarget $Row $field $Anchor
    }
    switch ($Source) {
        'inbox_rules' {
            $ruleId = Get-BecSnapshotProperty $Row 'RuleIdentity'
            if ($ruleId -isnot [string] -and $ruleId -isnot [uint64] -and $ruleId -isnot [long] -and $ruleId -isnot [int]) {
                throw 'field-unavailable'
            }
            $record.RuleIdentity = [string]$ruleId
            $record.Enabled = ConvertTo-BecSnapshotBoolean (Get-BecSnapshotProperty $Row 'Enabled')
            $priority = Get-BecSnapshotProperty $Row 'Priority'
            if ($priority -isnot [int] -and $priority -isnot [long] -and $priority -isnot [uint32]) { throw 'field-unavailable' }
            $record.Priority = $priority
            foreach ($name in 'Name', 'InError', 'SupportedByTask', 'DeleteMessage', 'MarkAsRead', 'StopProcessingRules') {
                $property = $Row.PSObject.Properties[$name]
                if ($null -ne $property) {
                    $record[$name] = if ($name -eq 'Name') { ConvertTo-BecSnapshotText $property.Value }
                        else { ConvertTo-BecSnapshotBoolean $property.Value }
                }
            }
            foreach ($name in 'ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo', 'From') {
                $property = $Row.PSObject.Properties[$name]
                if ($null -ne $property) {
                    $values = @($property.Value)
                    if ($values.Count -gt 1000) { throw 'result-limit' }
                    $record[$name] = @(foreach ($value in $values) {
                        if ($null -ne $value) { ConvertTo-BecSnapshotRecipient $value }
                    })
                }
            }
        }
        'forwarding' {
            $record.ForwardingAddress = ConvertTo-BecSnapshotRecipient (Get-BecSnapshotProperty $Row 'ForwardingAddress')
            $smtp = Get-BecSnapshotProperty $Row 'ForwardingSmtpAddress'
            $record.ForwardingSmtpAddress = if ($null -eq $smtp) { $null } else { ConvertTo-BecSnapshotText $smtp }
            $record.DeliverToMailboxAndForward = ConvertTo-BecSnapshotBoolean (Get-BecSnapshotProperty $Row 'DeliverToMailboxAndForward')
        }
        'send_on_behalf' {
            $delegates = @(Get-BecSnapshotProperty $Row 'GrantSendOnBehalfTo')
            if ($delegates.Count -gt 1000) { throw 'result-limit' }
            $record.GrantSendOnBehalfTo = @(foreach ($delegate in $delegates) {
                if ($null -ne $delegate) { ConvertTo-BecSnapshotRecipient $delegate }
            })
        }
        'full_access' {
            $record.User = ConvertTo-BecSnapshotText (Get-BecSnapshotProperty $Row 'User')
            $record.AccessRights = @(foreach ($right in (Get-BecSnapshotProperty $Row 'AccessRights')) { ConvertTo-BecSnapshotText $right })
            $record.Deny = ConvertTo-BecSnapshotBoolean (Get-BecSnapshotProperty $Row 'Deny')
            $record.IsInherited = ConvertTo-BecSnapshotBoolean (Get-BecSnapshotProperty $Row 'IsInherited')
        }
        'send_as' {
            $record.Trustee = ConvertTo-BecSnapshotText (Get-BecSnapshotProperty $Row 'Trustee')
            $record.AccessRights = @(foreach ($right in (Get-BecSnapshotProperty $Row 'AccessRights')) { ConvertTo-BecSnapshotText $right })
            $record.AccessControlType = ConvertTo-BecSnapshotText (Get-BecSnapshotProperty $Row 'AccessControlType')
            $record.IsInherited = ConvertTo-BecSnapshotBoolean (Get-BecSnapshotProperty $Row 'IsInherited')
        }
    }
    return $record
}

function Get-BecSnapshotObservations($Mailbox, $Anchor, [string]$MailboxObservedAt) {
    $observations = [ordered]@{}
    $sources = [ordered]@{ inbox_rules = 'Get-InboxRule'; forwarding = 'Get-Mailbox'
        full_access = 'Get-MailboxPermission'; send_as = 'Get-RecipientPermission'; send_on_behalf = 'Get-Mailbox' }
    $throttled = $false
    foreach ($source in $sources.Keys) {
        Assert-BecConnection
        $name = $sources[$source]
        $observation = [ordered]@{ command = $name; observed_at = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
            status = 'unavailable'; reason_codes = @('unavailable'); records = @(); hidden_included = $null }
        if ($source -eq 'inbox_rules') { $observation.hidden_included = $false }
        $observations[$source] = $observation
        $rows = @()
        if ($source -in 'forwarding', 'send_on_behalf') {
            $rows = @($Mailbox)
            $observation.observed_at = $MailboxObservedAt
        } else {
            if ($throttled) { $observation.reason_codes = @('throttled'); continue }
            $read = $commands[$name]
            if ($null -eq $read -or -not $read.Parameters.ContainsKey('ResultSize')) { continue }
            $targetParameter = if ($source -eq 'inbox_rules') { 'Mailbox' } else { 'Identity' }
            if (-not $read.Parameters.ContainsKey($targetParameter) -or $null -eq $Anchor.Guid) {
                $observation.reason_codes = @('mailbox-identity-unavailable'); continue
            }
            $parameters = @{ ResultSize = 1000; ErrorAction = 'Stop'; WarningAction = 'Stop' }
            $parameters[$targetParameter] = $Anchor.Guid
            if ($source -eq 'inbox_rules' -and $read.Parameters.ContainsKey('IncludeHidden')) {
                $parameters.IncludeHidden = $true
                $observation.hidden_included = $true
            }
            try { $rows = @(& $read @parameters) }
            catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] { throw }
            catch {
                $failure = $_
                Assert-BecConnection
                $outcome = Get-BecReadFailure $failure
                $observation.status = if ($outcome -eq 'access-denied') { 'denied' } else { 'partial' }
                $observation.reason_codes = @(switch ($outcome) { 'access-denied' { 'denied' }; 'throttled' { 'throttled' }; default { 'failed' } })
                if ($outcome -eq 'throttled') { $throttled = $true; $script:serviceThrottled = $true }
                continue
            }
            Assert-BecConnection
            $observation.observed_at = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
        }
        $observation.status = 'collected'
        $observation.reason_codes = @()
        if ($source -eq 'inbox_rules') { $observation.reason_codes += 'projection-limited' }
        if ($rows.Count -ge 1000) { $observation.reason_codes += 'result-limit' }
        if ($source -eq 'inbox_rules' -and -not $observation.hidden_included) { $observation.reason_codes += 'hidden-unavailable' }
        if ($rows.Count -gt 1000) { $observation.status = 'partial'; continue }
        try {
            # Validate every returned target, including ACL rows later excluded from this observation.
            $projected = @(foreach ($row in $rows) { ConvertTo-BecSnapshotRow $row $source $Anchor })
            $observation.records = @(foreach ($record in $projected) {
                if ($source -eq 'full_access' -and 'FullAccess' -cnotin $record.AccessRights) { continue }
                if ($source -eq 'send_as' -and 'SendAs' -cnotin $record.AccessRights) { continue }
                $record
            })
            if ($source -eq 'inbox_rules') {
                foreach ($record in $observation.records) {
                    foreach ($field in 'Name', 'InError', 'SupportedByTask', 'DeleteMessage', 'MarkAsRead',
                        'StopProcessingRules', 'ForwardTo', 'RedirectTo', 'ForwardAsAttachmentTo', 'From') {
                        if (-not $record.Contains($field)) { $observation.reason_codes += 'field-unavailable' }
                    }
                }
            }
        } catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] { throw }
        catch {
            $reason = $_.Exception.Message
            if ($reason -notin 'unbound-result', 'field-unavailable', 'result-limit') { $reason = 'invalid-result' }
            $observation.reason_codes += $reason
            $observation.records = @()
        }
        if ($observation.records.Count -eq 0) { $observation.reason_codes += 'empty' }
        $observation.reason_codes = @($observation.reason_codes | Select-Object -Unique)
        if ($observation.reason_codes.Count) { $observation.status = 'partial' }
    }
    return $observations
}

$dateFormat = [Globalization.CultureInfo]::InvariantCulture
$stamp = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'"
$calls = [Collections.Generic.Queue[datetime]]::new()
$serviceThrottled = $false
$result = 0
$runJson = $planText | & $Python -I -m bec.run_index create
if ($LASTEXITCODE -ne 0) { throw 'Could not create the local run before mailbox reads.' }
$runDirectory = ConvertFrom-Json -InputObject $runJson -ErrorAction Stop
if ($runDirectory -isnot [string] -or [string]::IsNullOrWhiteSpace($runDirectory)) {
    throw 'The local run writer returned an invalid directory.'
}
Write-Host "Run results: $runDirectory"
Write-Host 'When the run ends, open Run summary.pdf for mailbox status and report folders.'

$runOutcome = 'failed'
try {
    foreach ($account in $plan.accounts) {
        $null = $planText | & $Python -I -m bec.run_index begin --run $runDirectory --account $account
        if ($LASTEXITCODE -ne 0) { throw 'Could not record the start of this mailbox in the run.' }
        Assert-BecConnection
        try { $mailbox = @(& $mailboxRead -Identity $account -ErrorAction Stop -WarningAction Stop) }
        catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] { throw }
        catch { throw "Get-Mailbox could not verify $account in this session. No incident reads were made for this account." }
        Assert-BecConnection
        $mailboxObservedAt = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
        if ($mailbox.Count -ne 1 -or [string]$mailbox[0].PrimarySmtpAddress -ne $account -or
            -not $mailbox[0].ExternalDirectoryObjectId) {
            throw 'Could not verify one mailbox with that exact primary SMTP address. Stopping before incident reads.'
        }
        # A contradictory or unusable native tenant marker invalidates the account read itself.
        # This check precedes any subsequent provider read or evidence write for this mailbox.
        Assert-BecSnapshotTenant $mailbox[0]
        $snapshotAnchor = $null
        $snapshotObservations = $null
        try { $snapshotAnchor = Get-BecSnapshotAnchor $mailbox[0] $account }
        catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] { throw }
        catch { Write-Warning 'Current mailbox observations are unavailable because native mailbox identity could not be verified.' }
        if ($null -ne $snapshotAnchor) {
            $snapshotObservations = Get-BecSnapshotObservations $mailbox[0] $snapshotAnchor $mailboxObservedAt
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
                if ($LASTEXITCODE -eq 130) { throw [OperationCanceledException]::new('Trace preservation was canceled.') }
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
        $snapshotPath = $null
        $snapshotHash = $null
        if ($null -ne $snapshotObservations) {
            Assert-BecConnection
            $traceHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($bundle))).ToLowerInvariant()
            $snapshot = [ordered]@{ schema = 'bec.exchange-snapshot/v1'; tenant = $plan.tenant; directory_id = $plan.tenant
                scope = $manifest.scope; mailbox = $snapshotAnchor; captured_at = [DateTime]::UtcNow.ToString($stamp, $dateFormat)
                trace_receipt_sha256 = $traceHash; evidence_class = 'allowlisted-source-properties'; observations = $snapshotObservations }
            $snapshotJson = ConvertTo-Json -InputObject $snapshot -Depth 12 -Compress -WarningAction Stop
            $snapshotEncoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($snapshotJson))
            Assert-BecConnection
            $savedSnapshot = $snapshotEncoded | & $Python -I -m bec.exchange_snapshot --directory $directory
            if ($LASTEXITCODE -eq 130) { throw [OperationCanceledException]::new('Snapshot preservation was canceled.') }
            if ($LASTEXITCODE -ne 0) { throw 'Current mailbox observations failed validation. No snapshot bytes were saved.' }
            Assert-BecConnection
            $snapshotReceipt = $savedSnapshot | ConvertFrom-Json
            if ($snapshotReceipt.sha256 -isnot [string] -or $snapshotReceipt.sha256 -cnotmatch '^[a-f0-9]{64}$' -or
                $snapshotReceipt.path -isnot [string] -or [string]::IsNullOrWhiteSpace($snapshotReceipt.path)) {
                throw 'The snapshot writer did not return a valid saved path and byte hash.'
            }
            $snapshotPath = $snapshotReceipt.path
            $snapshotHash = $snapshotReceipt.sha256
            Write-Verbose "Current mailbox snapshot saved in $snapshotPath with SHA-256 $snapshotHash"
        }
        Write-Verbose "Local Exchange export for $account saved in $directory"
        $offlineArgs = @('--root', $plan.root, 'offline', '--bundle', $bundle, '--tenant', $plan.tenant,
            '--directory-id', $plan.tenant, '--user', $account, '--start', $plan.start, '--end', $plan.end, '--review-package')
        if ($snapshotPath) { $offlineArgs += @('--exchange-snapshot', $snapshotPath, '--snapshot-sha256', $snapshotHash) }
        $offlineArgs += @('--run-directory', $runDirectory)
        $planText | & $Python -I -m bec @offlineArgs
        if ($LASTEXITCODE -eq 130) { throw [OperationCanceledException]::new('Mailbox packaging was canceled.') }
        if ($LASTEXITCODE -notin 0, 2) { throw 'The mailbox case or report could not be verified and saved.' }
        if ($LASTEXITCODE -eq 2) { $result = 2 }
    }
    $runOutcome = 'completed'
} catch [Management.Automation.PipelineStoppedException], [OperationCanceledException] {
    $runOutcome = 'canceled'
    $result = 130
} finally {
    $null = $planText | & $Python -I -m bec.run_index close --run $runDirectory --outcome $runOutcome
    $closeStatus = $LASTEXITCODE
    if ($runOutcome -eq 'completed') {
        if ($closeStatus -notin 0, 2) { throw 'Could not finish the run index. Check the saved mailbox status.' }
        if ($closeStatus -eq 2) { $result = 2 }
    } elseif ($runOutcome -eq 'canceled') {
        Write-Warning 'The run was canceled. Open Run summary.pdf for the last recorded mailbox status.'
    }
}
exit $result
