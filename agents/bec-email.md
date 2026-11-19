# BEC email investigation agent

Use this task prompt for work inside the standalone BEC repository. Fill in the requested objective and any narrower path ownership before starting.

> Own the assigned BEC email investigation change. BEC is a complete standalone package, not a wrapper for another project. Preserve its Microsoft 365, Defender email, and Google Workspace workflows and their evidence guarantees. Deliver the change with relevant offline tests and a concise handoff.

## Ownership

Allowed implementation paths, subject to the current task's narrower assignments:

```text
bec/cli.py                  command parsing and case workflow
bec/storage.py              tenant-bound cases, raw bytes, manifests, locks
bec/collection.py           live collection, export import, replay
bec/graph.py                historical query descriptions and Workspace planning
bec/exchange.py             Exchange scope and verified capture receipts
bec/bundles.py              local evidence bundle validation
bec/data/Invoke-BEC.ps1     bounded reads in the existing Exchange operator session
bec/hunting.py              Defender email table collection
bec/workspace.py            Google Reports collection
bec/normalize.py            Microsoft/Defender normalization
bec/google_events.py        Google event normalization
bec/analysis.py             scoped entities, baselines, correlations
bec/messages.py             identifier-backed message correlation
bec/reporting.py            offline reports and timeline exports
bec/comparison.py           read-only saved-case evidence comparison
bec/search.py               exact typed read-only indicator lookup
bec/mailbox_state.py        offline current-state companion import/view
bec/data/                   report template and rule data
bec/__init__.py
bec/__main__.py
tests/
scripts/installed_smoke.py  isolated installed-package acceptance checks
scripts/validate_lab.py     explicit-target lab acceptance and private/sanitized records
config/                     example identifiers only
docs/
README.md
pyproject.toml
AGENTS.md
agents/bec-email.md
.gitignore
```

Do not edit another repository, a copied release, credentials, or a real case store. Preserve `LICENSE` attribution. Changes to publication, repository settings, CI, or git history belong to the assigned integration owner unless explicitly included in the task.

Start with the specific command, provider function, or failing test relevant to the objective. Read `docs/architecture.md` and the relevant provider guide when their contracts are involved. Use targeted searches; do not rescan the whole workspace or duplicate another agent's discovery. Delegate only if the user or task explicitly asks for agent work.

## Component boundary

BEC supports account compromise investigation through:

- Entra interactive, noninteractive, and service principal sign-ins; directory audit; historical baselines; Exchange unified audit and message trace.
- Defender `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `UrlClickEvents`, `EmailPostDeliveryEvents`, and `AlertEvidence`, scoped to case accounts and message identifiers.
- Workspace `login`, `token`, and `gmail` audit reports, including supporting identity/OAuth correlation.

Microsoft live collection uses the existing-session PowerShell launcher. Entra sign-ins and Defender tables are supported export sources. The command surface is `offline`, `case create`, `microsoft`, `collect`, `investigate`, `analyze`, `report`, `pivot ip|user`, `timeline`, `verify`, `evidence`, `compare`, `search`, `snapshot-import`, and `snapshot-view`. Global `--root` and `--verbose` precede the command. `collect` and `investigate` accept `--bundle`, `--dry-run`, `--defender`, and `--workspace-config`. `compare` accepts two explicit saved-case directories; `search` accepts one directory, a supported indicator type, and its value. Both accept optional `--format json|html` / `--output FILE` and do not use `--root`. Snapshot commands accept an explicit bound case directory and either an exported v1 snapshot or imported companion directory; import also requires a new `--output` directory outside the case. The installed `bec` console script and `python -m bec` invoke the same package entry point.

Prohibited scope includes device-agent provisioning, endpoint telemetry, ransomware exercises, disk/RAM capture, image custody, arbitrary hunting-query execution, and unrequested containment or account/mailbox remediation. Do not import or depend on a sibling IR package to implement BEC. Reject requests to disguise those capabilities as email commands; route them to their separate project owner.

## Upstream inputs and downstream contract

Inputs are an explicit tenant/customer binding, affected account, bounded incident interval, configured investigation limits, and either live provider access or a compatible tenant-bound export bundle. Credentials enter through the documented environment variables and remain outside source control and case metadata.

Outputs are preserved raw vendor bytes with SHA-256 manifests, collection checkpoints, normalized events, baselines, entity links, findings, visible telemetry gaps, and HTML/CSV/JSON/Timesketch timelines. Keep the original source references available after deduplication and grouping. Do not establish message or app attribution using a filename, app name, subject, or temporal proximity alone. Observed sequence matches do not prove malicious control or code execution.

Preserve stdout/stderr and statuses: `0` completed, `2` completed with telemetry gaps or parser usage error, `1` runtime error, `130` interruption. `case create` prints only its ID on success; `evidence` remains valid JSON. Dry runs do not acquire evidence or persist requested provider changes. Resume completed queries and retry incomplete ones without silently changing export/live mode.

The distribution is `bacon-egg-and-cheese`, Python package `bec`, console `bec`. Keep project and package versions aligned and include the owned templates and rule data in distributions. Keep developer fixture archives outside published artifacts. A clean installation must not resolve code or data from another checkout. Combined Windows/image cases are not a supported migration input; retain the original case and transfer cloud records through a compatible bundle instead.

Saved-case comparison must verify original raw evidence read-only, refuse tenant/native-customer mismatches, retain different content sharing a native identity, and make coverage/window differences explicit. Identical/reordered rows do not become additions. Absence never means deleted configuration. Do not use `Case.verify()` for this read-only path because it can recover pending transactions and change the source case. Comparison output must be a new file outside both cases. Successful comparison returns `0` even with evidence differences or documented source coverage gaps; invalid inputs return `1`.

Saved-case search uses the same read-only integrity/native-binding boundary and only explicitly listed structured fields. Preserve exact typed equality, named domain relations, meaningful URL case/path/query/encoding, raw record variants, and every duplicate source pointer. Do not search arbitrary strings, resolve URLs, introduce substring/suffix matches, or mutate pivot state. No-hit output must retain coverage and interpretation limits. Search output must be new and outside its input case; successful zero-hit searches return `0`, while invalid evidence returns `1`.

Mailbox-state companions preserve exact imported bytes, native tenant/mailbox binding, synthetic provenance, source coverage, and record pointers. Current objects remain separate from historical UAL events; an acquisition timestamp is not a configuration-change time. Keep denied/partial/unavailable coverage and missing-field unknowns explicit. Do not infer effective grants or historical state from current objects. This file-format interoperability must not introduce a producer runtime dependency or copy another project's source or fixtures.

## Validation

1. Identify the changed contract. Use the test coverage authorized for the current pass.
2. Keep the archived QA harness and its data outside the public Git tree and every distribution.
3. Check syntax, package contents and normal command discovery before handoff. Report the actual platform, commands and results.
4. For packaging or entry point changes, verify installed command help, version, template and rule availability outside the checkout using `scripts/installed_smoke.py`. Check release archive contents. Provider acceptance requires an explicitly authorized operator.
5. Confirm endpoint/image commands remain unavailable and no sibling package/runtime is required. Keep the test store outside the repository. Inspect the final diff and intended publication files for credentials, client data, binaries, or generated cases.

Provider authentication, permissions, licensing, retention, and delayed ingestion need a separately authorized live check. Record that limitation instead of claiming fixture tests verify tenant behavior. Do not broaden successful testing without a new change or concrete unresolved risk.

For E2 lab validation, follow `docs/lab-validation.md`. Require the user's explicit tenant/profile/account/window designation and independently known benign native event IDs before provider calls. Run preflight first; keep cases, commands, profiles, and detailed results private. Use only existing primary-user collectors with the bounded lab profile. Do not generate activity, change permissions, or choose arbitrary cached credentials. Exports/fixtures cannot qualify as live evidence. Missing pagination/restricted-access conditions stay untested, and public status must use the runner's allowlisted sanitized summary.

## Stop conditions

Stop the dependent change and inform the integration owner when work requires unowned paths, changes a shared contract under active development, weakens tenant isolation or evidence provenance, needs live credentials, or would mutate a real case irreversibly. Continue independent work inside the assigned scope. Report unrelated defects without silently taking over another project. A provider extraction or schema migration requires explicit source ownership and compatibility decisions before edits.

## Handoff

Return the outcome, exact files changed, commands to install/run the result, tests run with actual counts and outcomes, and any unresolved compatibility or live-validation limits. Identify follow-up work owned by another agent. Do not claim other projects or publication are complete from this component handoff.
