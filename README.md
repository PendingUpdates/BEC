# Bacon Egg and Cheese

![BEC: bacon, egg and cheese sandwich beside an email investigation magnifier](docs/assets/BEC-Banner.gif)

BEC v0.9.0 is a standalone business email compromise investigation tool for Microsoft 365 and Google Workspace. Give it a tenant, an account and a time window to build one chronology from Entra, Exchange, Defender email telemetry and Workspace audit records. Compare saved cases, search exact typed indicators, or inspect a current mailbox snapshot beside historical rule evidence offline, with original source pointers and visible coverage limits. The `bacon-egg-and-cheese` distribution owns the `bec` package, command, report templates, and synthetic fixtures; it does not require another incident-response project.

## Install and run

Use Python 3.12 or later on Windows, macOS, or Linux. Run these commands from this repository's root. The base installation supports offline export investigations and the synthetic demo; no provider credentials are needed.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install .
.\.venv\Scripts\bec.exe --version
.\.venv\Scripts\bec.exe --root "$env:TEMP\bec-demo" demo
```

The generated `.venv\Scripts\bec.exe` is the Python console launcher. No compiled application or bundled runtime is checked into this repository. The same entry point is available as `.\.venv\Scripts\python.exe -m bec`.

On macOS or Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/bec --version
.venv/bin/python -m bec --root /tmp/bec-demo demo
```

For live Microsoft or Google collection, install the optional authentication libraries into the same environment:

```powershell
.\.venv\Scripts\python.exe -m pip install ".[live]"
```

On macOS or Linux use `.venv/bin/python -m pip install '.[live]'`. The examples below use the Windows console launcher explicitly; use `.venv/bin/bec` on other systems. Global options such as `--root` and `--verbose` precede the command.

## Read the synthetic investigation

Open the HTML path printed by `demo`. Under **Correlation findings**, find **Workspace OAuth grant followed by Gmail message access** and select **Show linked events**. The three rows show a login, an app authorization and a Gmail audit event for that app. Expand a row for the raw record and child-event index. Keep the case directory together so its evidence links work.

Before switching from the linked-events view, click **Clear filters** in **Chronology**. This clears **Search**, **Source**, **Actor**, **IP**, **Phase**, **Assessment** and the previous message selection; leave **Timeline** set to **Complete** to inspect every observation. Then select **October invoice** under **Message evidence**, or click the subject on a mailbox row. The sample links eight observations: a message trace, Defender's email, URL and attachment records, a blocked Safe Links click, an Exchange mailbox read, XDR alert evidence and a later post-delivery action. Expand **linked observations** to inspect each source. URLs appear as plain text. File names and hashes are searchable.

## Access and permissions by workflow

Offline demo, export investigation, saved-case search/comparison and mailbox-snapshot import/view need **no tenant login, application consent or cloud role**. They require local read access to their input evidence and write access only where the selected command creates cases or outputs. Installing `.[live]` adds authentication SDKs; it grants no permissions. Keep real cases and credentials outside this checkout.

### Microsoft 365: application access, not an operator session

BEC's implemented Microsoft client uses a tenant-bound application and Azure Identity `CertificateCredential` or `ClientSecretCredential`. It requests `https://graph.microsoft.com/.default`, meaning the application's already-consented Graph application permissions. Configure the exact directory/client IDs, then supply `BEC_CERTIFICATE_PATH` (optional `BEC_CERTIFICATE_PASSWORD`) or `BEC_CLIENT_SECRET`; certificates take precedence. BEC does not implement delegated/device-code login, managed identity or federated-credential authentication, and does not reuse Exchange Online PowerShell sessions. Microsoft public cloud only.

| Implemented collector | Microsoft Graph **application** permission | Additional prerequisite or limit |
| --- | --- | --- |
| Entra sign-ins and directory audits | `AuditLog.Read.All` | Tenant licensing, retention and available fields constrain evidence; non-interactive/service-principal sign-ins use beta endpoints. |
| Purview Exchange audit search | `AuditLogsQuery-Exchange.Read.All` | Audit availability/retention must cover the incident. BEC creates and polls search jobs, then reads results. This is Exchange audit coverage, not every Purview workload. |
| Exchange message trace | `ExchangeMessageTrace.Read.All` | Provision Microsoft's message-trace service principal once; see onboarding below. |
| Defender XDR email Advanced Hunting | `ThreatHunting.Read.All` | Relevant Defender services/licensing and populated email tables are required. No write permission is needed for BEC's read-only KQL. |

An authorized administrator must grant the selected application permissions tenant consent before use. Human roles such as Reports Reader or Security Reader used with **delegated** APIs are not substitutes for BEC's application permissions, and BEC does not require the investigator to run as Global Administrator. Do not add broad write permissions merely to address a denied collector. [Sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [directory audits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0), [Purview queries](https://learn.microsoft.com/en-us/graph/api/security-auditcoreroot-post-auditlogqueries?view=graph-rest-1.0), [Graph hunting](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery?view=graph-rest-1.0).

Exchange onboarding additionally provisions the Microsoft service principal with application ID `8bd644d1-64a1-4d4b-ae52-2e0cbf64e373`. Microsoft's example uses an administrator's `Application.ReadWrite.All` provisioning session; that is **not** a BEC runtime permission. Provisioning is a separate administrative change and can take hours to become effective. [Official onboarding](https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/graph-api-message-trace).

Conditional Access policy details can be omitted from sign-in responses without additional policy-read permission such as `Policy.Read.ConditionalAccess` or `Policy.Read.All`. These are **not part of BEC's baseline permission set**. An empty or partial response is not proof of clean configuration or complete coverage.

### Google Workspace: native Reports API, not GAM

Implemented sources are login, OAuth/token and Gmail **audit activities**, using only `https://www.googleapis.com/auth/admin.reports.audit.readonly`. Enable the Admin SDK API, authorize the service account's numeric OAuth client ID for domain-wide delegation, configure the actual Workspace customer ID and reporting administrator, and supply the service-account JSON path through `BEC_GOOGLE_SERVICE_ACCOUNT`. A Workspace super administrator grants domain-wide delegation; the impersonated runtime administrator needs access to the requested reports, not necessarily the Super Admin role. SDKs come from `.[live]`. [Reports authorization](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list), [delegation setup](https://developers.google.com/identity/protocols/oauth2/service-account#delegatingauthority).

This does not grant message-body or Gmail settings access. Edition, reporting privileges, retention and delay still constrain audit records. Native Reports/compatible ALFA JSON or JSONL imports are implemented; arbitrary GAM-export compatibility, GAM execution and on-premises Active Directory adapters are **not implemented**. Do not install GAM or grant AD permissions as a prerequisite for current BEC.

### Read-only boundaries and validation

BEC reads investigation evidence and writes local case artifacts. Purview search-job creation is an intentional provider-side operation, not a tenant configuration or remediation change. BEC does not grant consent, provision the trace service principal, change mailbox rules or reset accounts. Missing permissions and unavailable telemetry remain visible gaps; offline tests do not establish live access. Use the existing [security guide](docs/security.md), [Workspace guide](docs/workspace.md) and [authorized lab procedure](docs/lab-validation.md) before live acceptance.

## Investigate a Microsoft tenant

1. Configure the application permissions and Exchange message trace prerequisite in [Security and permissions](docs/security.md).
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

For a tenant without Defender telemetry, set `"defender": false` under the profile's `options`. Explicit API failures are reported as telemetry gaps while other workloads can continue, but an unavailable table can also return HTTP success with zero rows. A successful empty response does not prove that the workload was available or that the incident had no activity. Integrity verification can pass even when telemetry is missing or incomplete. Validate each in-scope workload against an independently known event and record every excluded workload, including Defender when disabled. [Permission and provisioning details](docs/security.md)

## Investigate Google Workspace

Copy `config/example-workspace.json` to `workspace.json`. Set the case tenant alias, the Workspace customer ID, and the reporting administrator's primary email. Configure read-only delegation and point `BEC_GOOGLE_SERVICE_ACCOUNT` to the service account key file. A Workspace-only profile can create a case without Microsoft credentials. [Google Workspace setup and access](docs/workspace.md)

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

The bundled example lives in `bec/data/demo`. It includes a separate traveler account and shared corporate egress traffic for testing user scoping.

For Defender exports, use the exact table name as the dataset key. Supported tables are `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents` and `AlertEvidence`. Files can contain a native row array or an Advanced Hunting response with a `results` array. Preserve column names and timestamps. See `bec/data/demo/defender-bundle.json` for a complete manifest. To add such a bundle to a v0.1 export case, use `investigate ID --defender --bundle FILE`.

## Compare saved cases offline

Pass two complete case directories, in earlier/later order. They can reside in different case stores. Comparison verifies preserved raw evidence, reads no live provider, and leaves both case directories unchanged. It does not use derived timelines as evidence.

```powershell
.\.venv\Scripts\bec.exe compare C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa C:\IR\cases\CLIENT-A\INC-2026-bbbbbbbbbbbb --output C:\IR\reports\delta.json
.\.venv\Scripts\bec.exe compare C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa C:\IR\cases\CLIENT-A\INC-2026-bbbbbbbbbbbb --format html --output C:\IR\reports\delta.html
```

Use real case directory names in place of those examples. Without `--output`, the selected report format is printed to stdout; JSON is the default. Output files must be new and outside both inputs. The command uses explicit directories, so `--root` is not used for comparison.

The report separates newly observed records, records only observed in the earlier input, and conflicting content sharing a native identity. Each changed record includes its original file link, SHA-256 hash, and zero-based record index. Identical duplicate rows and different page/row ordering do not create evidence additions. The report also shows incident-window, investigation-setting, query, normalization, and coverage differences.

**Absence is not deletion.** A record missing from the later case does not establish that a mailbox rule, OAuth grant, or other configuration was deleted or remediated. A newly observed record may have existed before either collection. Comparison includes all preserved rows, including baseline and out-of-scope evidence; it is an evidence inventory comparison, not a comparison of current tenant state.

Tenant aliases, Microsoft directory IDs, and Workspace customer IDs must match, including missing bindings. For Microsoft exports without a native directory binding in either case, the report explicitly identifies reliance on the analyst-supplied tenant alias. Comparisons return `0` when the report is produced, even when evidence or coverage differs; invalid inputs return `1`. [Comparison semantics and limits](docs/comparison.md).

## Search a saved case offline

`search` performs a read-only lookup in an existing case. Unlike `pivot ip|user`, it does not collect evidence, save analyst seeds, or rebuild case reports.

```powershell
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa email analyst@example.com
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa domain example.com --format html --output C:\IR\reports\domain-search.html
.\.venv\Scripts\bec.exe search C:\IR\cases\CLIENT-A\INC-2026-aaaaaaaaaaaa url 'https://login.example.com/invoice?id=7' --output C:\IR\reports\url-search.json
```

Use an actual case directory. Types are `email`, `domain`, `ip`, `url`, `sha256`, and `sha1`. Matching uses listed normalized fields, not arbitrary text. Domains match exact domains/hosts rather than subdomains or substrings; each result names whether it matched an email domain, URL host, or explicit domain field. URL equality preserves the complete literal URL, including case, path, query, encoding, and fragment. There is no DNS lookup, URL request, decoding, or Safe Links expansion.

Results preserve raw artifact hashes, record indexes, and Google child-event indexes. Duplicate records retain every source reference without inflating the unique record count. Coverage gaps and unsupported/invalid fields remain visible, including when there are no hits. **No match does not establish absence in the tenant.** JSON is the default; optional output files must be new and outside the case. [Search fields, semantics, and limits](docs/search.md).

## Commands

| Command | Result |
| --- | --- |
| `bec demo` | Create and investigate the bundled synthetic email case |
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

All fixture addresses and events are synthetic. A sequence match describes observed order and shared identifiers. Assessing malicious control, phishing interaction or fraudulent intent requires independent evidence. Baseline sizes are reported per user so an analyst can judge the significance of a new location or device.

## Scope and verification

For authorized live lab acceptance, use the [E2 lab-validation procedure](docs/lab-validation.md) and `scripts/validate_lab.py`. It previews exact bounded queries and checks known events against preserved live evidence. No lab target has been supplied for the current E2 validation, so that gate remains **not executed**; offline tests and demo runs do not establish a live pass.

This release covers Microsoft 365 investigation and Google Workspace login, OAuth and Gmail audit acquisition and correlation. Investigation runs perform forensic reads and create Purview search jobs. Each provider can also run on its own.

BEC's Defender collection is limited to the six email-related tables listed above. It does not collect endpoint telemetry, install device agents, capture disks or memory, execute ransomware exercises, or perform containment. It does not reset credentials, revoke tokens, remediate mailbox rules, fetch message bodies, or expose an arbitrary hunting-query console. Identity and OAuth evidence supports the email/account investigation; it does not turn this project into a device capture tool.

This standalone source continues the email-only v0.3.0 implementation, independently packaged in v0.6.0 and extended with saved-case comparison in v0.7.0 and typed offline search in v0.8.0. It does not include the endpoint/image features from the intervening combined releases. Use a separate case directory for this tool; opening combined Windows/image cases is not a supported migration path. Export original cloud records into a tenant-bound bundle when transferring an investigation, and retain the original case separately.

The automated suite exercises fixture reconstruction and simulated Microsoft API exchanges, including permissions errors, throttling, pagination, search resumption and integrity failures. Tenant-specific authentication, provisioning, retention and service behavior require a live validation in your environment.

Install the optional authentication libraries before running the full suite. Tests remain offline and require no credentials, but provider transport tests import SDK exception types. The base installation alone remains sufficient for the demo and export-only investigations.

```powershell
.\.venv\Scripts\python.exe -m pip install ".[live]"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

On macOS or Linux, run `.venv/bin/python -m pip install '.[live]'`, then `.venv/bin/python -m unittest discover -s tests -v`. Tests run offline against synthetic fixtures and mocked provider exchanges. Live authentication, tenant provisioning, licensing, retention, and provider behavior need validation in the intended environment.

[Architecture and analysis rules](docs/architecture.md) · [Security and permissions](docs/security.md) · [Validation record](docs/validation.md) · [Component agent instructions](agents/bec-email.md)

## License

MIT, preserving the [Bacon Egg and Cheese contributors' attribution](LICENSE).

## Offline mailbox-state companion

Offline `snapshot-import` / `snapshot-view` preserve a tenant-bound current mailbox snapshot separately from historical UAL rule evidence. They do not call providers or modify the original case. The commands are included in this source checkout; live producer data has not been validated. See [contract, usage and limits](docs/mailbox-state.md) and [recorded validation](docs/mailbox-state-validation.md).

[Prerequisites by purpose: offline use, optional live SDKs and tests](docs/prerequisites.md)

## First live Microsoft 365 pilot

Use the [bounded lab-validation procedure](docs/lab-validation.md) for an explicitly authorized pilot on either Windows or macOS. Start with one named mailbox, a completed UTC window of at most 24 hours, and an independently known native event. Run `preflight` before `run`; preflight makes no provider calls and does not validate access. The runner uses zero baseline days, zero expansion depth and `collect` rather than automatic `investigate` pivots. Its required-source list is an assertion, not a query selector. Missing pagination/restricted-access gates remain untested, not passed. The example plan leaves both gate lists empty. If the other gates pass, a live `run` with either list empty returns `2` with status `incomplete`. A failed assessment also returns `2`. Read `public-summary.json` for the status and individual gate results. A live `run` returns `0` only when every gate passes.

Use separate new private run directories per platform. Windows commands use `.\.venv\Scripts\python.exe -I scripts\validate_lab.py`; macOS uses `.venv/bin/python -I scripts/validate_lab.py`. Both accept `preflight --plan PRIVATE_PLAN` or, only for the authorized operator, `run --plan PRIVATE_PLAN --run-dir NEW_PRIVATE_DIRECTORY`. Replace all plan/profile placeholders and keep credentials outside the checkout. App-only authentication and provider-side Purview search jobs are documented in the security guide; this is incident collection, not a posture audit.

For this pilot, use only existing, explicitly approved application permissions and the operator-selected app-only certificate/client-secret mechanism. Unlike Flapjacks, BEC does not use an interactive delegated operator session. Preflight checks the plan and lists queries; it neither reads credentials nor proves access. Stop and record a blocker if approved access is missing rather than changing permissions during the test. Record excluded workloads and compare in-scope results with independently known events; successful integrity verification alone is not telemetry-coverage acceptance.
