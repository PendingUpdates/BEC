# Historical E2 lab validation

Microsoft Graph live execution in this runner is retired. Preflight remains available for historical plans. Only separately authorized Workspace-only plans retain live execution here. [Current Microsoft operator guide](investigations.md)

The repository includes an explicit-target acceptance runner at `scripts/validate_lab.py`. It uses the installed standalone BEC package and existing commands. It does not generate activity, change permissions, remediate accounts, run arbitrary queries, or create connectors. The installer and command checks establish local availability. Provider acceptance requires the authorized tenant procedure below.

**Current E2 status: not executed.** No designated tenant profile, lab account, expected native event IDs, or incident window has been supplied for this validation. The runner and its offline checker tests are preparation, not a live pass.

## Required operator inputs

Keep the following outside the public checkout:

1. The user's explicit lab-target designation, recorded as a short private authorization reference.
2. An existing BEC tenant profile: exact tenant alias and Microsoft directory/application IDs and/or Workspace customer ID and delegated reporting administrator. The profile contains identifiers and options only.
3. One to three exact authorized lab user addresses and a completed, timezone-aware window of at most 24 hours containing already-observed benign activity.
4. Required source datasets and independently known native event IDs, event types, and actors. Each account needs at least one known event. Record these from the operator's existing admin-console or audit view; do not derive expectations from BEC's own result.
5. The selected credential mechanism, supplied through the existing environment variables. Do not put keys, certificates, secrets, or service-account contents into the plan or source repository.
6. For pagination and permission-failure gates, a source known to paginate and an already-existing restricted-access credential/profile with a known expected 401/403. Missing conditions remain untested. The runner never alters access to manufacture a failure.

The lab runner uses the profile's certificate or client-secret application for Microsoft collection. Workspace uses its delegated reporting service account. Access prerequisites remain in [security.md](security.md) and [workspace.md](workspace.md). This procedure does not claim those external prerequisites have been validated.

## Private plan

Create a JSON plan outside the repository. This example is intentionally a template: reserved example addresses and IDs are rejected, and placeholders must be replaced with the explicitly designated target and independently observed events.

```json
{
  "schema_version": 1,
  "authorization_reference": "Replace with the user's lab-target designation",
  "profile": "C:\\IR\\private\\lab-profile.json",
  "tenant": "REPLACE_LAB_ALIAS",
  "users": ["lab-user@example.invalid"],
  "start": "2026-11-15T12:00:00Z",
  "end": "2026-11-15T13:00:00Z",
  "credential_source": {"microsoft": "certificate"},
  "required_sources": ["interactive"],
  "expected_events": [
    {
      "user": "lab-user@example.invalid",
      "dataset": "interactive",
      "source_event_id": "REPLACE_WITH_INDEPENDENTLY_OBSERVED_NATIVE_ID",
      "event_type": "authentication.success",
      "actor": "lab-user@example.invalid"
    }
  ],
  "pagination_sources": [],
  "permission_denied_sources": [],
  "timeout_seconds": 900
}
```

The profile path can be absolute or relative to the private plan. Supported credential choices are `microsoft: certificate`, `microsoft: client_secret`, and `google: service_account`; include exactly the enabled providers. These select `BEC_CERTIFICATE_PATH` (plus optional `BEC_CERTIFICATE_PASSWORD`), `BEC_CLIENT_SECRET`, or `BEC_GOOGLE_SERVICE_ACCOUNT`. Unselected mechanisms are removed from the collector subprocess environment. No credential files are searched or automatically selected.

`required_sources` and expected events are assertions, **not collection selectors**. The preview shows every existing primary-user query enabled by the profile, including supported Entra/Exchange/Defender or Workspace sources. `service_principal` is not a primary-user query and cannot be selected for this bounded runner. Defender can be disabled with the profile's documented `options.defender` setting.

The runner overrides the profile to zero baseline days, zero expansion depth, one user/IP budget, and at most 5,000 raw records per case. It invokes `collect`, never automatic `investigate` pivots. Each named user gets a fresh case. The subprocess timeout is 60–1,800 seconds per command. Timeouts/failures preserve private evidence and do not become passes.

## Preview and execute

From this repository root, install the package and optional SDKs into the selected Python environment:

```powershell
.\.venv\Scripts\python.exe -m pip install ".[live]"
.\.venv\Scripts\python.exe -I scripts\validate_lab.py preflight --plan C:\IR\private\lab-plan.json > C:\IR\private\preflight.private.json
```

Preflight performs no provider calls and does not inspect credential files. Its output contains private account/profile/query details. Review the exact accounts, native bindings, time bounds, sources, and query count before execution. A preflight success means only that the plan is well formed.

Once the target is explicitly authorized, configure only the selected credential variables and execute into a new private directory:

```powershell
.\.venv\Scripts\python.exe -I scripts\validate_lab.py run --plan C:\IR\private\lab-plan.json --run-dir C:\IR\private\bec-lab-run-01
```

No secret is a command-line argument. The runner records installed BEC/distribution versions, Python/module locations, exact command arguments, and actual return codes privately. It uses `python -I -m bec` for case creation, collection, verification, and local analysis. The historical Microsoft collector created tenant-side search jobs. The current Exchange adapter collects sent and received message traces. It does not collect mailbox audit.

## Acceptance gates

| Gate | Required observation |
| --- | --- |
| Live origin | Actual runner collection invocation, live collection mode, matching native bindings/account, provider collector labels, collection timestamps inside the execution interval, and no rows matching the retained legacy sample fingerprints. Exported or known sample evidence is rejected. |
| Integrity | Original manifest/raw hashes, inventory, and identity checks pass using the read-only saved-case verifier. |
| Source coverage | Every declared required source has completed query statuses. A permission or parsing gap cannot silently qualify a required available source. |
| Known activity | Each exact native ID, dataset, event type, and actor appears inside the declared window, with original file/hash/record references retained. |
| Query bounds | Saved query keys equal the previewed primary-user query set, and the case window equals the plan. |
| Unexpected gaps | No undeclared failures or unparseable preserved records. Expected permission failures must actually report 401/403; another error is not equivalent. |
| Pagination | For each declared pagination source: multiple distinct preserved pages under the same completed query, including a continuation-bearing page and a terminal page. An empty declaration or absent evidence remains untested. |
| Permission failures | Actual 401/403 query gaps from the operator-designated existing restricted-access condition. Missing/restricted profiles are not invented; absence remains untested. |
| Saved-case comparison | Comparing the collected case with itself produces no additions or earlier-only evidence. This exercises the installed comparison against real captured bytes without modifying them. |

Native expected IDs use the existing normalizer's `source_event_id`: Entra/directory `id`, Exchange UAL `Id`, Workspace `uniqueQualifier`, and available Defender report/alert IDs. Include exact actor and event type so an ambiguous source ID cannot match an unrelated observation. For provider records without a usable native ID, select a different independently identifiable known activity for this acceptance procedure.

Pagination proof uses preserved provider page shapes and collection completion, not an independent network capture. Live-origin checks protect the normal runner workflow from confusing exports/fixtures with live evidence; they are not cryptographic attestation against an operator fabricating every receipt and manifest.

The overall result is `failed` if a mandatory observed check fails, `incomplete` while pagination or permission-failure gates are untested, and `passed_for_declared_scope` only when every listed gate is observed passing. This does not qualify untested providers or accounts. Exit status is `0` for a passing declared scope, `2` for an executed incomplete/failed assessment, and `1` for invalid setup. Preflight returns `0` with `status: not_executed`.

For a meaningful between-run delta, retain two separately authorized fresh lab runs with the same native bindings and use `bec compare BEFORE_CASE_DIR AFTER_CASE_DIR --output PRIVATE_NEW_FILE`. Record independently expected late-arriving/new observations before examining the result. Absence never demonstrates deleted rules or revoked grants. The runner does not automatically perform a second collection or generate new activity.

## Private and public records

The new private run directory holds the actual case stores, normalized profile/plan, command outputs, execution receipts, source-linked acceptance details, and errors. Those files must not be committed or copied into public validation records.

Only `public-summary.json` is designed for publication review. It uses an explicit allowlist: tool/version, execution and overall status, anonymous case count, gate statuses, unrun gate names, and a fixed interpretation note. It excludes tenant/account/IP/event identifiers, paths, queries, profile content, and free-form error messages. Review even this sanitized file before publishing. Public prose must distinguish actual live observations, failed gates, unrun gates, and offline checker tests.
