# Investigation guide

## Investigate Microsoft 365 in PowerShell

From the extracted BEC folder, use the PowerShell window with your single authorized, direct interactive Exchange Online session. Check the displayed operator and tenant GUID against the incident. BEC does not sign in automatically or infer a customer label from an account's domain. [Windows first use](../README.md#first-investigation-on-windows) · [Platform setup](prerequisites.md) · [Session requirements](security.md#investigator-sign-in)

```powershell
.\Invoke-BEC.ps1
```

Enter the affected primary email addresses, then choose a window ending when BEC plans the request.

| Choice | UTC interval |
| --- | --- |
| 24 hours (default) | Previous 24 hours |
| One week | Previous seven days |
| One calendar month | Same UTC time on the corresponding date in the previous month |
| 90 days | Previous 90 days |
| One calendar year | Same UTC time on the corresponding date in the previous year |

Month and year choices clamp missing dates to the target month's last valid day and preserve the UTC time. A month back from March 31 uses February's last day, and a year back from February 29 uses February 28. Review the accounts, tenant GUID, requested and queryable UTC intervals, and output directory. Only explicit **yes** authorizes incident reads. Confirmation defaults to no, and **q** cancels.

Exchange message trace has rolling 90-day retention. For a year request, BEC shows the unavailable range and requires explicit **yes** to collect only the retained slice. A range with no retained overlap is refused. A one-minute moving cutoff guard can also exclude the oldest part of a range. These omissions remain coverage gaps. An empty result does not establish that no activity occurred. Obtain older evidence through a separately authorized ordinary offline case.

To pin an independently known tenant GUID, append the optional `-TenantId $CustomerTenantId`. A mismatch stops collection. For explicit bounds, supply both completed UTC timestamps ending in `Z` or `+00:00` and the affected address. The interval must be positive, no longer than one calendar year measured back from its end, and overlap current retention. The same review and confirmation apply.

```powershell
.\Invoke-BEC.ps1 -Accounts $AffectedAccount -StartUtc $StartUtc -EndUtc $EndUtc
```

One case is written per mailbox. `-CaseRoot` selects a protected local directory. Cases default to `~/BEC-Cases/TENANT/CASE_ID` and exports to `~/BEC-Cases/exchange-exports/TENANT`, using the verified tenant GUID. The console prints the export and report paths. `bec microsoft --help` explains the launcher. Python cannot inherit the PowerShell connection. With a wheel installed in an activated virtual environment, use its adapter in the same window.

```powershell
& (bec microsoft --adapter) -Python (Get-Command python -CommandType Application).Source
```

The adapter divides the queryable interval into ranges of at most ten days and requests up to 1,000 rows per direction per range. It verifies every row before saving a page. The interval includes the start and excludes the end. A page containing the excluded endpoint is discarded and reported as a boundary gap. Other invalid account, tenant or time scope stops collection. Reports distinguish capped, denied, throttled, empty and unavailable coverage. A full page may omit records, so use a shorter explicit interval for high volume.

The run allows at most 100 trace calls in any rolling five minutes, with no automatic retry. An explicit service throttle stops further trace reads and leaves unattempted ranges visible. Retry later only when authorized. Mailbox audit is not collected. Missing Entra and Defender data and omitted inbox-rule state remain gaps. An unverifiable session or mailbox stops incident reads. Live tenant operation and Windows script-policy acceptance remain unverified. [Workload limits](security.md#microsoft-sources-and-limits)

## Investigate Google Workspace

Copy `config/example-workspace.json` to `workspace.json`. Set the case tenant alias, the Workspace customer ID, and the reporting administrator's primary email. Configure read-only delegation and point `BEC_GOOGLE_SERVICE_ACCOUNT` to the service account key file. A Workspace-only profile can create a case without Microsoft credentials. [Google Workspace setup and access](workspace.md)

```powershell
$env:BEC_GOOGLE_SERVICE_ACCOUNT = 'C:\IR\credentials\workspace-reports.json'
$start = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
$end = [DateTimeOffset]::UtcNow.ToString('o')
$env:BEC_CASES = 'C:\IR\cases'
$caseId = .\.venv\Scripts\bec.exe case create --config .\workspace.json --tenant CLIENT-A --user analyst@example.com --start $start --end $end
.\.venv\Scripts\bec.exe investigate $caseId
```

Use a Workspace-only profile for live Google reads. Already acquired Microsoft and Workspace exports can share an offline case with both native bindings.

## Work with an existing export

Use already authorized exports from one tenant on a local drive. Preserve their original bytes. Create a `bundle.json` alongside them. For example:

```json
{
  "tenant": "CLIENT-A",
  "directory_id": "11111111-1111-1111-1111-111111111111",
  "files": [
    {"dataset": "interactive", "path": "signins.json"},
    {"dataset": "ual", "path": "mailbox.json"}
  ]
}
```

Use the same tenant and directory ID as the case. For offline cases with no configured directory ID, omit it from the bundle. Records declaring a native organization ID require a matching profile. Each file may hold a JSON array or a Graph response object with a `value` array. UAL also accepts arrays containing Exchange `AuditData` JSON strings. Available dataset keys are `interactive`, `noninteractive`, `directory`, `ual`, `trace`, and `service_principal`. Keep the original byte encoding as UTF-8, optionally with BOM. Exports should contain evidence from one tenant.

```powershell
.\.venv\Scripts\bec.exe offline --bundle .\exports\bundle.json --tenant $TenantAlias --directory-id $DirectoryId --user $AffectedAccount --start $StartUtc --end $EndUtc
```

For Defender exports, use the exact table name as the dataset key. Supported tables are `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents` and `AlertEvidence`. Files can contain a native row array or an Advanced Hunting response with a `results` array. Preserve column names and timestamps. To add such a bundle to a v0.1 export case, use `investigate ID --defender --bundle FILE`.

Use the exact alias and native identifiers from the investigation. For Workspace files also pass `--google-customer-id`. For a case without a Microsoft directory binding, omit `--directory-id`. Use `bec offline --case CASE_ID --bundle FILE` to add evidence to an existing export case. The importer checks the listed files and their bindings before creating a new case.

Existing trace-only `bec.exchange-powershell/v2` receipts still import with their per-direction coverage and hashes. New captures use `bec.exchange-powershell/v3`, preserving the requested interval, queryable ranges and each directional range's outcome with its trace file hash when a file was saved. Imports refuse v1 receipts, audit claims and capture directories containing the old `audit.json` export. Keep previously saved cases and reports for local verification, search and replay. Use a separate ordinary offline case for independently authorized audit exports or older evidence. The importer refuses to mix ordinary exports and operator-session captures in one case. For replay, supply the original tenant GUID as both `--tenant` and `--directory-id`, the primary account and the exact authorized UTC bounds. The evidence manifest records the preserved record bytes and the SHA-256 of the capture receipt.

## Compare saved cases offline

Pass two complete case directories, in earlier/later order. They can reside in different case stores. Comparison verifies preserved raw evidence, reads no live provider, and leaves both case directories unchanged. It does not use derived timelines as evidence.

```powershell
.\.venv\Scripts\bec.exe compare C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa C:\IR\cases\CLIENT-A\INC-2026-bbbbbbbbbbbb --output C:\IR\reports\delta.json
.\.venv\Scripts\bec.exe compare C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa C:\IR\cases\CLIENT-A\INC-2026-bbbbbbbbbbbb --format html --output C:\IR\reports\delta.html
```

Use real case directory names in place of those examples. Without `--output`, the selected report format is printed to stdout; JSON is the default. Output files must be new and outside both inputs. The command uses explicit directories, so `--root` is not used for comparison.

The report separates newly observed records, records only observed in the earlier input, and conflicting content sharing a native identity. Each changed record includes its original file link, SHA-256 hash, and zero-based record index. Identical duplicate rows and different page/row ordering do not create evidence additions. The report also shows incident-window, investigation-setting, query, normalization, and coverage differences.

**Absence is not deletion.** A record missing from the later case does not establish that a mailbox rule, OAuth grant, or other configuration was deleted or remediated. A newly observed record may have existed before either collection. Comparison includes all preserved rows, including baseline and out-of-scope evidence; it is an evidence inventory comparison, not a comparison of current tenant state.

Tenant aliases, Microsoft directory IDs, and Workspace customer IDs must match, including missing bindings. For Microsoft exports without a native directory binding in either case, the report explicitly identifies reliance on the analyst-supplied tenant alias. Comparisons return `0` when the report is produced, even when evidence or coverage differs; invalid inputs return `1`. [Comparison semantics and limits](comparison.md).

## Search a saved case offline

`search` performs a read-only lookup in an existing case. Unlike `pivot ip|user`, it does not collect evidence, save analyst seeds, or rebuild case reports.

```powershell
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa email analyst@example.com
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa domain example.com --format html --output C:\IR\reports\domain-search.html
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa url 'https://login.example.com/invoice?id=7' --output C:\IR\reports\url-search.json
```

Use an actual case directory. Types are `email`, `domain`, `ip`, `url`, `sha256`, and `sha1`. Matching uses listed normalized fields, not arbitrary text. Domains match exact domains/hosts rather than subdomains or substrings; each result names whether it matched an email domain, URL host, or explicit domain field. URL equality preserves the complete literal URL, including case, path, query, encoding, and fragment. There is no DNS lookup, URL request, decoding, or Safe Links expansion.

Results preserve raw artifact hashes, record indexes, and Google child-event indexes. Duplicate records retain every source reference without inflating the unique record count. Coverage gaps and unsupported/invalid fields remain visible, including when there are no hits. **No match does not establish absence in the tenant.** JSON is the default; optional output files must be new and outside the case. [Search fields, semantics, and limits](search.md).

## Commands

| Command | Result |
| --- | --- |
| `Invoke-BEC.ps1 [-TenantId GUID]` / `bec microsoft --help` | Confirm the verified session, accounts and UTC window, then read scoped message traces and print one local report per account |
| `bec offline --bundle FILE --case ID` | Verify and import a local export. Use `--tenant`, the account and incident bounds to start a case. |
| `bec compare BEFORE_DIR AFTER_DIR [--format json\|html] [--output FILE]` | Verify and compare saved raw evidence without changing either source case |
| `bec search CASE_DIR TYPE VALUE [--format json\|html] [--output FILE]` | Read-only exact typed indicator lookup in verified saved evidence |
| `bec case create --tenant … --user … --start … --end … [--config FILE]` | Create a case and print its ID |
| `bec collect ID [--bundle FILE] [--dry-run] [--defender] [--workspace-config FILE]` | Import scoped exports or acquire Google Workspace evidence |
| `bec investigate ID [--bundle FILE] [--dry-run] [--defender] [--workspace-config FILE]` | Analyze a local case or run a Workspace-only investigation |
| `bec analyze ID` or `bec report ID` | Verify stored raw evidence and rebuild the analysis locally |
| `bec pivot ip 198.51.100.74 --case ID [--dry-run]` | Add a persistent analyst IP seed and rebuild the case |
| `bec pivot user user@example.com --case ID [--dry-run]` | Add a persistent analyst user seed |
| `bec timeline ID --format html` | Rebuild timelines and print the selected HTML, CSV or JSON path |
| `bec timeline export-timesketch ID` | Write JSONL containing datetime, timestamp_desc and message |
| `bec evidence ID` / `bec verify ID` | Display the evidence manifest / verify raw bytes and inventory |

A dry run shows the initial queries and the rules for later evidence-driven expansion. Rerunning live collection skips completed queries and retries failed queries. A new case performs a fresh acquisition, including any records ingested by Microsoft after the first search.

Exit code **0** indicates completion, **2** indicates completion with telemetry gaps, **1** indicates a runtime error, and **130** indicates analyst interruption. Argument errors also return **2**, accompanied by usage/error output. Missing history, limits, permission failures, and unparseable records are visible in the case. In PowerShell, inspect `$LASTEXITCODE` after a command.

## Read a case

| File | Contents |
| --- | --- |
| `raw/<dataset>/<sha256>.json`, `evidence_manifest.json` | Original response or export bytes, origin, query scope, acquisition time, hash and record counts |
| `collection_summary.json`, `bec.log`, `telemetry_gaps.json` | Per-query status, operational log and consolidated gaps |
| `normalized/events.jsonl`, `baseline.json` | Scoped incident events, score contributions, evidence references and historical observations |
| `entities.json`, `entities/graph.json`, `pivots/queue.json` | Typed entities, event-backed relationships and expansion decisions |
| `findings.json` | Sequence matches, join identifiers and ordered supporting records |
| `timeline/complete.csv` | One row per normalized in-scope incident event |
| `timeline/timeline.csv` | Investigation view with repetitive mailbox activity grouped |
| `timeline/timeline.json`, `timeline/timeline.html` | Both views, correlation findings and telemetry gaps |

A sequence match describes observed order and shared identifiers. Assessing malicious control, phishing interaction or fraudulent intent requires independent evidence. Baseline sizes are reported per user so an analyst can judge the significance of a new location or device.

## Scope and verification

The Exchange adapter needs separate operator qualification on supported PowerShell and Exchange module versions. Legacy Microsoft Graph collection is retired. Historical cases retain verification, replay, search and comparison.

BEC's Defender export support covers the six email-related tables listed above. It does not collect endpoint telemetry, install device agents, capture disks or memory, execute ransomware exercises, or perform containment. It does not reset credentials, revoke tokens, remediate mailbox rules, fetch message bodies, or expose an arbitrary hunting-query console. Identity and OAuth evidence supports the email/account investigation; it does not turn this project into a device capture tool.

This standalone source continues the email-only v0.3.0 implementation, independently packaged in v0.6.0 and extended with saved-case comparison in v0.7.0 and typed offline search in v0.8.0. It does not include the endpoint/image features from the intervening combined releases. Use a separate case directory for this tool; opening combined Windows/image cases is not a supported migration path. Export original cloud records into a tenant-bound bundle when transferring an investigation, and retain the original case separately.

[Architecture and analysis rules](architecture.md) · [Security and permissions](security.md) · [Validation record](validation.md)

## Offline mailbox-state companion

Offline `snapshot-import` / `snapshot-view` preserve a tenant-bound current mailbox snapshot separately from historical UAL rule evidence. They do not call providers or modify the original case. The commands are included in this source checkout; live producer data has not been validated. See [contract, usage and limits](mailbox-state.md) and [recorded validation](mailbox-state-validation.md).

[Installation by platform and package contents](prerequisites.md)
