# Read an investigation package

After you confirm an Exchange investigation, BEC prints one **Run results** folder. Open **Run summary.pdf** to find the folder for each requested mailbox and see whether its report was saved. If a run stops, check the last recorded status for each account. An unfinished mailbox has no verified report in the index.

```text
BEC-Cases/Runs/<UTC-run-id>/
  Run summary.pdf
  <mailbox-folder>/
    investigation.pdf
    triage.xlsx
    raw/
    originals/
    manifest.json
```

Each mailbox PDF opens with a plain-English summary. Current inbox rules, mailbox-wide forwarding, delegation and dated activity are presented separately. The rule description names the recorded actions and destinations. The current Exchange projection includes selected conditions such as senders. It does not establish every condition, exception or an individual rule’s hidden status. The workbook and evidence index link observations to original files, hashes and record locations.

Use a protected, nonsynced folder for case files, inputs and outputs. Existing `review-packages` acquisitions remain where they were created. Standalone `bec package` and `bec offline --review-package` retain the per-case acquisition layout for local rebuilds.

| Package member | Use |
| --- | --- |
| `raw/*.display.csv` | Source-specific tables for analysis. Formula-like text is neutralized in these display copies. |
| `raw/*.original.csv`, `originals/` | Exact bytes of admitted source CSVs, JSON, scoped trace pages and acquisition receipts. Use a text reader for original CSVs. The native Exchange sidecar preserves the first local serialization of selected properties. |
| `findings.json`, `observations.json`, `evidence.json` | Stable links within this acquisition from observations and triage findings to every supporting original. JSON pointers select native records. In CSV, `csv:2` denotes the first logical data record after the header. |
| `coverage.json` | Requested and available trace ranges, per-read outcomes, acquired export windows, missing sources and inaccessible current settings. Empty, denied and capped results have different meanings. |
| `manifest.json`, `SHA256SUMS.txt` | Source provenance, byte counts and file hashes. Preserve a separate protected copy of the acquisition hashes for custody. |

The workbook uses literal text cells and internal navigation. The PDF uses static text and internal references. Display truncation or character substitution leaves the original evidence intact. The package builder checks source bytes and targets before writing and refuses to replace an earlier acquisition. If a scoped trace page has columns outside the approved metadata, the package lists its original hash and the reason for exclusion. A verified current-state snapshot can still be included. A legacy case-wide report by itself is insufficient evidence for a per-user package.

If a PDF reader held the index open and BEC reports that an update is pending, close it and refresh the saved index locally. From the extracted Windows project folder, run `.\.venv\Scripts\bec.exe run-summary "$RunDirectory"` using the printed run directory. In an activated environment, use `bec run-summary "$RunDirectory"`.

## Rebuild locally

Use the saved directory that contains `case.json`. The output root must be outside that directory. For a saved, scoped v2 or v3 Exchange trace case, this command needs no account credentials.

```powershell
.\.venv\Scripts\bec.exe package $CaseDirectory --output $ReviewRoot
```

To include the original current-state sidecar, add `--exchange-snapshot $SnapshotFile --snapshot-sha256 $RecordedHash`. Use the original acquisition hash. In a saved mailbox package, the `exchange_current_state` source in `manifest.json` records this SHA-256. The sidecar must also match the case's trace receipt, directory, mailbox, operator, connection and time window. Existing offline mailbox companions continue to use `snapshot-import` and `snapshot-view`.

## Add an authorized offline source

An offline source is a previously authorized, mailbox- or account-scoped export with the native metadata columns below. BEC performs no remote query for these sources. The acquisition receipt records who attests to the approved scope and exact input hash. The case, independently obtained identifiers and native row fields must agree. An acquisition receipt is an operator statement, not a provider signature. Keep the original export in custody. A source with extra fields, other users, contradictory identities or rows outside the stated window is refused as a whole.

Use an existing directory-bound case. To create a new offline case without an Exchange trace, supply the approved incident identifiers and dates. Then package the case with a receipt for at least one accepted source.

```powershell
$bec = '.\.venv\Scripts\bec.exe'
$caseId = & $bec --root $CaseRoot case create --tenant $TenantAlias --directory-id $DirectoryId --user $AffectedAccount --start $StartUtc --end $EndUtc
$CaseDirectory = Join-Path (Join-Path $CaseRoot $TenantAlias) $caseId
& $bec package $CaseDirectory --output $ReviewRoot --source $ReceiptFile --user-object-id $UserObjectId
```

Store the UTF-8 acquisition receipt beside its export. Every receipt needs the following string fields.

| Field | Value |
| --- | --- |
| `schema`, `source`, `format`, `file` | Use `bec.authorized-source/v1`, a source name from the table below, `json` or `csv`, and the original filename without directories. |
| `tenant_id`, `account` | Customer directory GUID and exact affected primary email address. |
| `start`, `end`, `acquired_at` | UTC timestamps ending in `Z` or `+00:00`. The export may cover a subset of the case window. The start is included and the end is excluded. |
| `scope_basis`, `attested_by`, `input_sha256` | Scope from the table, accountable operator UPN and the approved lowercase SHA-256 of the exact source bytes. To compare the original locally, use `(Get-FileHash -Algorithm SHA256 -LiteralPath $SourceFile).Hash.ToLowerInvariant()`. |

Pass one `--source` per receipt, up to 32 receipts and 128 MiB of combined input. Entra imports need an independently known `--user-object-id`. Purview needs `--mailbox-guid`, the Exchange mailbox GUID. A verified current-state sidecar can supply these identifiers. When both are supplied they must agree.

| Source and scope | Accepted native rows |
| --- | --- |
| `entra.audit-logs` · `user-targeted` | JSON array from Azure Monitor `AuditLogs`. Requires `Id`, `AADTenantId`, `Type`, `ActivityDateTime`, `ActivityDisplayName`, `Result` and `TargetResources`. The affected User must include the pinned object ID and UPN. A device registration needs the related Device ID in the same event. An optional `InitiatedBy` identifies the actor. Supported operations include password changes/resets, security-info and method events, and device registration changes. Started or failed resets stay distinct from successful terminal events. |
| `entra.user-signins.interactive`, `entra.user-signins.noninteractive` · `user-targeted` | UTF-8 native-column CSV or JSON array. Requires `Id`, `AADTenantId`, `Type`, `UserId`, `UserPrincipalName`, `CreatedDateTime`, `IsInteractive` and `ResultType`. Use the matching `SigninLogs` or `AADNonInteractiveUserSignInLogs` table. Method types describe a sign-in. They do not establish current enrollment. |
| `entra.workload-signins.service-principal`, `entra.workload-signins.managed-identity` · `case-linked-workload` | JSON array from `AADServicePrincipalSignInLogs` or `AADManagedIdentitySignInLogs`. Requires `Id`, `AADTenantId`, `Type`, `ServicePrincipalId`, `CorrelationId`, `CreatedDateTime` and `ResultType`. Include the approved `workload_principal_id` and `related_audit_sha256` as two additional receipt fields. Supply the referenced user-targeted audit acquisition in the same command. Every workload row must match its principal and correlation ID in the verified audit. These are application authentications. |
| `purview.mailbox-audit` · `mailbox-targeted` | JSON array of Exchange audit metadata. Requires `Id`, `OrganizationId`, `MailboxOwnerUPN`, `MailboxGuid`, `CreationTime`, `Operation`, `Workload` and `ResultStatus`. Selected access, send, move, deletion and `UpdateInboxRules` events are supported. An actor's `UserId` alone cannot establish the mailbox. |
| `defender.url-clicks` · `clicker-targeted` | Native Defender streaming JSON with a `records` array. Each record retains native `tenantId`, `time`, `category` and `properties`. Use `AdvancedHunting-UrlClickEvents` with `Timestamp`, `AccountUpn`, `ReportId`, `ActionType`, `IsClickedThrough` and `Workload`. The clicker must match the account. Blocked and click-through rows sharing a report ID remain distinct. |

Select documented metadata at acquisition. Do not invent missing identifiers or replace the originals to make an import pass. In the Azure Monitor tables above, `AADTenantId` identifies the customer and `TenantId` identifies the workspace. A plain Defender hunting CSV without the native customer envelope does not qualify for this mapping. Current MFA or Intune inventory, unlinked workload activity, Azure control-plane activity, risk/federation feeds and file-sharing evidence are outside these mappings. The separate saved-export workflow continues to support its documented sources. [Existing export workflow](investigations.md#work-with-an-existing-export) · [Exact allowed columns and operations](../bec/incident_imports.py)

Each mapped export supports up to 16 MiB and 10,000 records, with a 1,000-row limit for each workload sign-in export. Split larger authorized acquisitions by narrower UTC intervals and record their individual hashes. An unavailable source or zero submitted rows cannot establish that no activity occurred. [Entra audit schema](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) · [Purview schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema) · [Defender streaming format](https://learn.microsoft.com/en-us/defender-xdr/streaming-api-event-hub)
