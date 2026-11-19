# Investigation guide

For your first Microsoft account investigation, start with the [Windows walkthrough](../README.md#first-microsoft-investigation-on-windows) or [platform setup](prerequisites.md). The commands below run from the BEC directory. On macOS and Ubuntu use `.venv/bin/bec` in place of the Windows launcher.

Browser sign-in uses the investigator's delegated access. Unattended collection uses application permissions and a tenant-bound credential. Read the setup for your workflow. [Delegated sign-in](security.md#investigator-sign-in) · [Unattended application access](security.md#unattended-application-access)

## Configure an unattended Microsoft investigation

1. Configure the application permissions and Exchange message trace prerequisite in [Security and permissions](security.md).
2. Copy `config/example-tenant.json` to `client-a.json`. Set your tenant alias, Entra directory GUID and application client GUID. Set the display timezone and known shared egress CIDRs for your tenant.
3. Supply an app certificate with its private key through `BEC_CERTIFICATE_PATH`. The credential can also come from a secret store that sets `BEC_CLIENT_SECRET` in the process environment.
4. Choose an incident window within your tenant's available log retention. This example investigates the last completed 24 hours.

```powershell
$env:BEC_CERTIFICATE_PATH = 'C:\IR\credentials\bec-app.pem'
$start = [DateTimeOffset]::UtcNow.AddDays(-1).ToString('o')
$end = [DateTimeOffset]::UtcNow.ToString('o')
$env:BEC_CASES = 'C:\IR\cases'
$caseId = .\.venv\Scripts\bec.exe case create --config .\client-a.json --tenant CLIENT-A --user analyst@example.com --start $start --end $end
.\.venv\Scripts\bec.exe investigate $caseId --dry-run
.\.venv\Scripts\bec.exe --verbose investigate $caseId
.\.venv\Scripts\bec.exe verify $caseId
```

The case store defaults to `cases` under the working directory. Set `BEC_CASES` or supply `--root D:\IR\cases` **before** the command to choose another store. Keep real cases and credentials outside the source checkout. Tenant binding and investigation options are captured at creation. The command prints only the case ID on successful creation.

New cases include Defender collection by default. To enable it for an existing v0.1 live case, grant the application the Microsoft Graph application permission `ThreatHunting.Read.All` and run the following from the same case store. The dry run previews the plan. The investigation saves the choice and collects the newly enabled sources.

```powershell
.\.venv\Scripts\bec.exe investigate $caseId --defender --dry-run
.\.venv\Scripts\bec.exe investigate $caseId --defender
```

For a tenant without Defender telemetry, set `"defender": false` under the profile's `options`. Explicit API failures are reported as telemetry gaps while other workloads can continue, but an unavailable table can also return HTTP success with zero rows. A successful empty response does not prove that the workload was available or that the incident had no activity. Integrity verification can pass even when telemetry is missing or incomplete. Validate each in-scope workload against an independently known event and record every excluded workload, including Defender when disabled. [Permission and provisioning details](security.md)

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

For an existing Microsoft case, use the same case store and tenant alias. The first command previews collection. The second saves the Google customer binding and adds Workspace evidence to the case.

```powershell
.\.venv\Scripts\bec.exe investigate $caseId --workspace-config .\workspace.json --dry-run
.\.venv\Scripts\bec.exe investigate $caseId --workspace-config .\workspace.json
```

## Work with an existing export

Copy a tenant's JSON exports into one directory. Create a `bundle.json` alongside them. For example:

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
.\.venv\Scripts\bec.exe investigate $caseId --bundle .\exports\bundle.json
```

For Defender exports, use the exact table name as the dataset key. Supported tables are `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents` and `AlertEvidence`. Files can contain a native row array or an Advanced Hunting response with a `results` array. Preserve column names and timestamps. To add such a bundle to a v0.1 export case, use `investigate ID --defender --bundle FILE`.

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
| `bec microsoft [ACCOUNT ...]` | Sign in, collect account-scoped Microsoft 365 logs and print one report per account |
| `bec compare BEFORE_DIR AFTER_DIR [--format json\|html] [--output FILE]` | Verify and compare saved raw evidence without changing either source case |
| `bec search CASE_DIR TYPE VALUE [--format json\|html] [--output FILE]` | Read-only exact typed indicator lookup in verified saved evidence |
| `bec case create --tenant … --user … --start … --end … [--config FILE]` | Create a case and print its ID |
| `bec collect ID [--bundle FILE] [--dry-run] [--defender] [--workspace-config FILE]` | Acquire primary-user evidence and historical sign-ins |
| `bec investigate ID [--bundle FILE] [--dry-run] [--defender] [--workspace-config FILE]` | Collect, expand entity scope, correlate, render and summarize |
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

For authorized live lab acceptance, use the [E2 lab-validation procedure](lab-validation.md) and `scripts/validate_lab.py`. It previews exact bounded queries and checks known events against preserved live evidence. No lab target has been supplied for the current E2 validation, so that gate remains **not executed**.

This release covers Microsoft 365 investigation and Google Workspace login, OAuth and Gmail audit acquisition and correlation. Investigation runs perform forensic reads and create Purview search jobs. Each provider can also run on its own.

BEC's Defender collection is limited to the six email-related tables listed above. It does not collect endpoint telemetry, install device agents, capture disks or memory, execute ransomware exercises, or perform containment. It does not reset credentials, revoke tokens, remediate mailbox rules, fetch message bodies, or expose an arbitrary hunting-query console. Identity and OAuth evidence supports the email/account investigation; it does not turn this project into a device capture tool.

This standalone source continues the email-only v0.3.0 implementation, independently packaged in v0.6.0 and extended with saved-case comparison in v0.7.0 and typed offline search in v0.8.0. It does not include the endpoint/image features from the intervening combined releases. Use a separate case directory for this tool; opening combined Windows/image cases is not a supported migration path. Export original cloud records into a tenant-bound bundle when transferring an investigation, and retain the original case separately.

[Architecture and analysis rules](architecture.md) · [Security and permissions](security.md) · [Validation record](validation.md)

## Offline mailbox-state companion

Offline `snapshot-import` / `snapshot-view` preserve a tenant-bound current mailbox snapshot separately from historical UAL rule evidence. They do not call providers or modify the original case. The commands are included in this source checkout; live producer data has not been validated. See [contract, usage and limits](mailbox-state.md) and [recorded validation](mailbox-state-validation.md).

[Installation by platform and package contents](prerequisites.md)

## First live Microsoft 365 pilot

Use the [bounded lab-validation procedure](lab-validation.md) for an explicitly authorized pilot on either Windows or macOS. Start with one named mailbox, a completed UTC window of at most 24 hours, and an independently known native event. Run `preflight` before `run`; preflight makes no provider calls and does not validate access. The runner uses zero baseline days, zero expansion depth and `collect` rather than automatic `investigate` pivots. Its required-source list is an assertion, not a query selector. Missing pagination/restricted-access gates remain untested, not passed. The example plan leaves both gate lists empty. If the other gates pass, a live `run` with either list empty returns `2` with status `incomplete`. A failed assessment also returns `2`. Read `public-summary.json` for the status and individual gate results. A live `run` returns `0` only when every gate passes.

Use separate new private run directories per platform. Windows commands use `.\.venv\Scripts\python.exe -I scripts\validate_lab.py`; macOS uses `.venv/bin/python -I scripts/validate_lab.py`. Both accept `preflight --plan PRIVATE_PLAN` or, only for the authorized operator, `run --plan PRIVATE_PLAN --run-dir NEW_PRIVATE_DIRECTORY`. Replace all plan/profile placeholders and keep credentials outside the checkout. App-only authentication and provider-side Purview search jobs are documented in the security guide; this is incident collection, not a posture audit.

For this pilot, use only existing, explicitly approved application permissions and the operator-selected app-only certificate/client-secret mechanism. The pilot runner uses the application profile. The investigator command uses browser sign-in. Preflight checks the plan and lists queries; it neither reads credentials nor proves access. Stop and record a blocker if approved access is missing rather than changing permissions during the test. Record excluded workloads and compare in-scope results with independently known events; successful integrity verification alone is not telemetry-coverage acceptance.
