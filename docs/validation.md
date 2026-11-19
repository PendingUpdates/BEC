# Validation record

Status for standalone BEC v0.8.0, 2026-11-16:

| Check | Result |
| --- | --- |
| Focused saved-case search tests | Passed: 13 offline tests. |
| Full suite in the BEC development environment (`work/milestone2-envs/BEC`) | Passed: 77 tests, comprising the 64-test baseline and 13 indicator-search tests. Optional provider SDKs were installed; all provider exchanges remained mocked. |
| v0.8.0 installed-package smoke in that development environment | Passed in Python isolated mode outside the checkout: 30-event demo, raw verification, equivalent/added-evidence comparisons, exact email/URL/hash searches, no-hit coverage, HTML local evidence links, and unchanged source-case hashes. |
| Fresh v0.8.0 base wheel and isolated full-suite acceptance | Passed independently on Windows/Python 3.14.7: the extended installed smoke passed in a new BEC-only environment before optional SDK installation. After installing that wheel's `live` extra, all 77 tests passed with Python isolated mode. Imports resolved from this environment's `site-packages`; neither sibling tool was installed. |
| Live Microsoft 365, Defender, and Google tenant access | Not executed; no authorized lab target has been supplied. |

Search regressions cover all six indicator types; exact domain relations without substring or subdomain matches; literal URL case/path/query/encoding/fragment distinctions; IPv6 and hexadecimal normalization; invalid query and candidate values; duplicate transport wrappers retaining every source pointer without inflated hit counts; same-native-ID raw variants; Google child-event pointers; no-hit/source-gap coverage; tampered evidence and native-binding refusals; pending and concurrently changing inputs; protected output placement; and escaped HTML. Tests compare source bytes and modification times before and after read-only search. No provider collection or new activity was performed.

## Historical v0.7.0 acceptance

The preceding standalone BEC v0.7.0 release had these results:

| Check | Result |
| --- | --- |
| Full suite in the BEC development environment (`work/standalone-envs/BEC`) | Passed: 53 tests, including the 40-test v0.6.0 baseline and 13 saved-case comparison tests. |
| v0.7.0 installed-package smoke test in that development environment | Passed in Python isolated mode outside the checkout: synthetic demo/verification, equivalent-case comparison, one source-linked added sign-in, HTML output, and unchanged source-case hashes. This environment already contains the optional SDK libraries. |
| Fresh v0.7.0 base wheel/environment acceptance | Passed on Windows/Python 3.14.7: the installed smoke exercised the demo, zero-delta and added-evidence comparisons, HTML output and unchanged inputs before optional provider SDKs were installed. |
| Full suite against the fresh installed wheel | Passed: 53 tests using Python isolated mode after installing the wheel's `live` extra. Neither sibling tool was installed; the package resolved from the new environment's `site-packages`. |
| Live Microsoft 365, Defender, and Google tenant access | Not tested in this validation. |

## E2 lab preparation

**Live E2 validation is not executed.** No explicit lab tenant/profile, account list, independently known native event IDs, or completed activity window has been supplied. No provider calls, permission changes, or activity generation were performed for this preparation.

The repository now includes `scripts/validate_lab.py` and the [bounded lab procedure](lab-validation.md). Its preflight previews existing primary-user queries without provider access. A subsequent authorized run uses the installed BEC collector, verifies captured raw evidence and known events, checks query limits, and records pagination and permission-failure evidence only when actually observed. Actual cases, plans, command records, and detailed results stay private; public status uses a fixed field allowlist.

The complete source suite passed **64 offline tests** in the BEC development environment (`work/milestone2-envs/BEC`): the 53-test product baseline plus 11 lab-checker tests. These tests reject exported/demo fixture evidence and missing execution receipts as live qualification, keep absent pagination/restricted-access gates untested, check expected-event mismatches and integrity failures, and verify that public status excludes private identifiers and paths. Synthetic checker tests are not an E2 live run.

The E2 addition was repository lab-support tooling and did not change the packaged v0.7.0 command behavior. Live provider gates remain unrun until the user supplies the exact target and expected observations.

The publishing coordinator independently built a wheel and installed it in a new BEC-only Windows virtual environment using Python 3.14.7. The base installed smoke passed before optional authentication libraries were installed. After installing that wheel's `live` extra, all **64 tests passed with Python isolated mode**. The lab support script remains in the repository; tested product imports came from the installed wheel. These checks used no provider credentials or live tenant access.

Comparison regressions cover reordered rows and duplicate copies; equivalent whole-row/UAL JSON transport wrappers; sign-in, rule, and OAuth additions with resolvable evidence pointers; same-native-ID variants; window and coverage differences; tenant/native-binding refusals; malformed metadata; missing/tampered/unmanifested evidence; pending and concurrently changing inputs; output placement/overwrite guards; escaped HTML; and processing budgets. Tests verify that comparison leaves source file bytes and modification times unchanged.

The previous v0.6.0 release passed 40 tests in a fresh Windows environment with the `live` extra, and its base wheel demo produced 30 incident events with zero gaps and successful raw verification without optional authentication libraries. Historical baseline results do not replace acceptance for the current release.

The full suite uses synthetic fixtures and mocked provider exchanges. Install `.[live]` before running it because provider transport tests import optional SDK types; no live credentials are needed. The base package supports export-only investigations.

The installed-wheel smoke test uses Python isolated mode from a temporary working directory, so source-checkout imports cannot supply missing package files. Each GitHub CI job installs and tests only this repository. Offline results do not establish live authentication, permissions, licensing, retention, or provider availability.
