# Mailbox-state companion validation

## Evidence-fidelity release candidate compatibility, 2026-11-17

The candidate starts from public BEC `2d9f59dbe388d54e5243b1dc004e9ede9d0705f7` (0.9.0). This compatibility note adds no new producer or live validation result; the historical execution records below are unchanged.

The retained v1 [contract](mailbox-state.md) and previous independent BEC fixture checks cover **3/3 BEC source groups**: `inbox_rules`, `forwarding`, and `delegates`. The [recorded producer check below](#windows-offline-stabilization-2026-11-17) covers **one synthetic export with five objects**: one rule, one whole mailbox/forwarding object, and three delegate wrappers. The broader Flapjacks producer-mapping denominator remains unassessed. These BEC counts do not establish broader producer mapping, live acceptance or publication acceptance.

The next gate is to retain and run the v1 regression tests against the candidate, with results recorded separately. Independent producer acceptance is a separate, explicitly authorized check before operational reliance, not a required companion handoff. The literal `response-menu.mailbox-snapshot.v1` remains accepted; no schema rename, existing companion/report migration, overwrite, deletion or producer dependency is required.

## Windows offline stabilization, 2026-11-17

Starting source: `85e3f0bde4c7c4e190f8b1df5b04a4dec9148e74`, which already includes the companion commands. Review found no production-code change needed for the documented v1 export. The initial Windows focused run exposed a test-only symlink privilege assumption (`WinError 1314`). Link-metadata refusal is now tested independently; actual source-file symlink creation has a separate capability-gated test.

- Full source suite on Windows/Python 3.14 in the existing BEC development environment: **91 tests discovered, 90 passed, 1 skipped**. The skip is the real file-symlink test because this account lacks that privilege; the deterministic metadata/refusal test passed. No privileges or machine settings were changed.
- The 14 mailbox-state test cases include 13 passes and that one native-symlink skip. Added independent fixtures verify seven-digit PowerShell UTC timestamps, whole mailbox objects, the three delegate wrapper forms, exact BOM/bytes/hash preservation and resolvable pointers, plus denied/partial/empty/missing-property semantics.
- `scripts/installed_smoke.py` now exercises the actual `snapshot-import` and `snapshot-view` CLI commands in isolated installed subprocesses. It checks bound identity, current/history separation, source statuses, synthetic labeling, provenance, exact bytes and unchanged case/source modification times. The coordinator built the 0.9.0 wheel, installed it into a fresh Windows Python 3.14.7 environment, and passed this smoke before optional SDKs were installed. After adding that wheel's `live` extra for mocked transport tests, the isolated full suite passed: **91 discovered, 90 passed, one native-file-symlink skip**. Imports resolved from the environment's `site-packages`, with sibling tools absent.
- The coordinator ran the actual `Export-ToolkitMailboxSnapshot` function from [Flapjacks at aca99b8](https://github.com/FordTruckMonth/Flapjacks/tree/aca99b8aec3588bca5701f354f2c604dbbc972f0) against its explicit synthetic input, using PowerShell 7.6.9. The fresh BEC wheel imported/viewed the resulting v1 file successfully: one rule object, one whole mailbox/forwarding object, and three labeled delegate wrappers. All pointers resolved, the seven-digit UTC value and synthetic marker survived, and exact bytes/SHA-256 matched. Case files and source bytes/modification time stayed unchanged through import/view. Historical rule activity stayed empty in the separate empty synthetic case, with missing historical coverage explicit. No Flapjacks source or fixture was copied into BEC; regression fixtures here were independently authored from the documented contract.
- `git diff --check`: passed.

This pass is offline only. No authentication, provider calls, consent, permission changes, or live tenant validation occurred. Version 0.9.0 packages the upstream companion feature with these Windows and installed-package checks. Hosted CI status is recorded on the publishing revision; local success is not an assertion of hosted or live acceptance.

## Historical macOS implementation validation

Base: `07c4593215d11db0e8d2ebc57e2797e000c85e12` (BEC v0.8.0). No remote write or live collection.

Platform: TheBox, macOS, existing Python 3.14 runtime. An isolated temporary virtual environment contains this local package and its declared optional test SDKs. No runtime was replaced.

- Focused tests: 11 passed.
- Complete offline regression suite: 88 passed (77 upstream + 11 new).
- Rebuilt installed package, isolated upstream `scripts/installed_smoke.py`: passed demo, verification, comparisons and exact searches, with unchanged source cases.
- Isolated installed-package mailbox-state suite from outside checkout: 10 passed before the window-filter follow-up; final 11-test source suite and 88-test regression suite passed. The follow-up has not been reinstalled.
- `git diff --check`: passed.
- Original BEC artwork copied byte-for-byte; SHA256 `4c21412db376f33fdc273b2d354e38f4a11baf5f160071957c54c1657732243e` matches supplied asset.

Tests exercise exact bytes/BOM/hash preservation, source/index pointers, unchanged case bytes and modification times, native tenant/mailbox binding, unbound real/synthetic rejection, malformed coverage and duplicate keys, output protection, tampering, opaque delegate wrappers, separate historical/current rule semantics and CLI paths with collection forbidden.

That original run did not perform live provider, GAM, AD, Windows/Linux acceptance or production-case validation. Full regression tests mock provider exchanges. Hashes establish post-import preservation, not source authenticity. Current snapshots remain companion artifacts, not integrated into standard case replay/report/search. Provider or legacy-source code was not copied from another repository.

Follow-up review: snapshot SHA-256 computed once per view and reused for all record pointers. Historical observations now use exact [case start,case end) bounds; a new regression covers start inclusion, end exclusion, baseline exclusion and an explicit unparseable-UAL count.
