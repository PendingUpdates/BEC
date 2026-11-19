# BEC repository instructions

This repository is the standalone `bacon-egg-and-cheese` Python distribution. Its package and console command are both `bec`. It investigates business email compromise using Microsoft 365, Defender email evidence, and Google Workspace. It must install and run without a sibling repository, shared dispatcher, or umbrella runtime.

- Read [the email component role](agents/bec-email.md) before changing the investigation workflow.
- Keep implementation and templates in this repository. Keep private fixture data and the tests that embed or load it outside the tracked source tree. Do not introduce dependencies on CrumbTrail, HashBrown, CaseCrumb, or a legacy combined engine.
- Preserve tenant and Workspace customer bindings, original evidence bytes, hashes, provenance, per-case locks, retry/checkpoint behavior, and visible telemetry gaps.
- Keep endpoint agents, device telemetry, ransomware exercises, disk/RAM capture, and image custody outside BEC. Supporting sign-in, identity, OAuth, and message correlation stays in scope.
- Use targeted `rg` searches and bounded reads. Review full source and diffs for exact edits. Coordinate ownership before changing an interface owned by another agent; do not repeat broad discovery.
- Verify installed version, command help and report-resource availability outside the checkout. The public command checks use no case evidence. Keep generated cases outside the repository.
- On Windows, prefer RTK for supported verbose commands, including `rtk test <python> -m unittest discover -s tests -v`. Run PowerShell and unsupported commands normally. Preserve working directory, arguments, environment, and exit status. A generic RTK hook warning is not a reason to install a hook.
- Keep tests offline by default. Live tenant collection, credentials, and external administrative changes require explicit task authorization. A simulated API response does not establish live tenant availability.
- Never track credentials, real tenant profiles, case exports, runtime binaries, or generated reports. Preserve the MIT license and original attribution.
- Do not publish, push, create repositories, or expand into another repository unless the task explicitly assigns that work.

Use the checks authorized for the current change. Report actual results and unresolved limitations.
