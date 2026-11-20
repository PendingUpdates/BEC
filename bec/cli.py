"""BEC command-line entry points."""
import argparse
import ipaddress
import json
import os
import sys
import uuid
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from . import __version__
from .analysis import scope
from .bundles import ExportBundle, local_path
from .collection import Collection, replay, verify_export_files
from .exchange import ExchangeReceipt, affected_accounts, ADAPTER
from .reporting import report, timesketch
from .storage import Case, CaseError, GOOGLE_APPS, create, iso, read, save, user_address, workspace_profile


def parser():
    p = argparse.ArgumentParser(prog="bec", description="Investigate business email compromise in an existing Exchange Online PowerShell session. "
                                "Start with 'bec microsoft --help'.")
    p.add_argument("--root", type=Path, default=os.environ.get("BEC_CASES"), help="case store")
    p.add_argument("--verbose", action="store_true", help="print collection and pivot progress")
    p.add_argument("--version", action="version", version="BEC " + __version__)
    cmd = p.add_subparsers(dest="command", required=True)
    microsoft = cmd.add_parser("microsoft", help="start a read-only investigation in your connected PowerShell window",
        description="In your connected PowerShell window, run ./Invoke-BEC.ps1 from the BEC folder. "
                    "Review the tenant and operator, then confirm the accounts, trace window and current mailbox state reads. "
                    "For a wheel install, use --adapter to locate the packaged launcher.")
    microsoft.add_argument("--adapter", action="store_true", help="print the installed PowerShell adapter path")
    offline = cmd.add_parser("offline", help="import an authorized local bundle and write the case report",
                             description="Analyze a local export bundle. Supply an existing case or a tenant, "
                             "affected account and incident window for a new offline case.")
    offline.add_argument("--bundle", required=True, metavar="FILE", help="local bundle.json listing the export files")
    target = offline.add_mutually_exclusive_group(required=True)
    target.add_argument("--case", dest="case_id", metavar="ID", help="reuse a saved case and its scope")
    target.add_argument("--tenant", help="expected tenant alias for a new case")
    offline.add_argument("--user", help="affected account for a new case")
    offline.add_argument("--start", help="incident start with UTC offset for a new case")
    offline.add_argument("--end", help="incident end with UTC offset for a new case")
    offline.add_argument("--directory-id", help="expected Microsoft directory GUID, when the manifest declares one")
    offline.add_argument("--google-customer-id", help="expected customer ID for Workspace exports")
    offline.add_argument("--review-package", action="store_true",
                         help="also write a local analyst package for this verified Exchange trace receipt")
    offline.add_argument("--run-directory", type=Path, metavar="RUN", help=argparse.SUPPRESS)
    offline.add_argument("--exchange-snapshot", type=Path, metavar="FILE",
                         help="include the current mailbox observations paired with this trace receipt")
    offline.add_argument("--snapshot-sha256", help="original hash recorded by the Exchange snapshot capture")
    package = cmd.add_parser("package", help="write the local per-user analyst package from verified, scoped evidence")
    package.add_argument("directory", type=Path, help="saved case directory containing case.json")
    package.add_argument("--output", type=Path, metavar="ROOT", required=True,
                         help="local package root outside the source case")
    package.add_argument("--source", dest="sources", type=Path, action="append", default=[], metavar="RECEIPT",
                         help="include a separately authorized source acquisition receipt (repeatable)")
    package.add_argument("--exchange-snapshot", type=Path, metavar="FILE",
                         help="include current mailbox observations paired to a trace receipt in this case")
    package.add_argument("--snapshot-sha256", help="original hash recorded by the Exchange snapshot capture")
    package.add_argument("--user-object-id", help="independently verified Entra object GUID of the affected account")
    package.add_argument("--mailbox-guid", help="independently verified Exchange mailbox GUID")
    index = cmd.add_parser("run-summary", help="refresh a saved run index after closing its PDF")
    index.add_argument("directory", type=Path, metavar="RUN", help="the local run folder printed by BEC")
    case = cmd.add_parser("case", help="create a tenant-scoped case").add_subparsers(dest="action", required=True)
    new = case.add_parser("create")
    for flag in ("tenant", "user", "start", "end"):
        new.add_argument("--" + flag, required=True)
    binding = new.add_mutually_exclusive_group()
    binding.add_argument("--config", type=Path, help="tenant profile JSON")
    binding.add_argument("--directory-id", help="bind a new offline Microsoft case to an independently verified directory GUID")
    comparison = cmd.add_parser("compare", help="compare two saved case directories without changing them")
    comparison.add_argument("before", type=Path, help="earlier case directory containing case.json")
    comparison.add_argument("after", type=Path, help="later case directory containing case.json")
    comparison.add_argument("--format", choices=("json", "html"), default="json")
    comparison.add_argument("--output", type=Path, help="new report file outside both input cases; otherwise stdout")
    search = cmd.add_parser("search", help="find exact typed indicators in a saved case without changing it")
    search.add_argument("directory", type=Path, help="saved case directory containing case.json")
    search.add_argument("type", choices=("email", "domain", "ip", "url", "sha256", "sha1"))
    search.add_argument("value")
    search.add_argument("--format", choices=("json", "html"), default="json")
    search.add_argument("--output", type=Path, help="new report file outside the input case; otherwise stdout")
    for action in ("snapshot-import", "snapshot-view"):
        sub = cmd.add_parser(action, help="offline mailbox state companion, separate from historical events")
        sub.add_argument("directory", type=Path, help="existing tenant-bound case directory")
        sub.add_argument("snapshot", type=Path, help="snapshot JSON for import; imported companion directory for view")
        if action == "snapshot-import":
            sub.add_argument("--output", type=Path, required=True, help="new companion directory outside the case")
    commands = {"collect": "import a case bundle or collect Google Workspace evidence",
                "investigate": "investigate a saved export or Google Workspace case",
                "analyze": "analyze verified saved evidence", "report": "rebuild a local case report",
                "timeline": "export a case timeline", "verify": "verify preserved evidence hashes",
                "evidence": "show the case evidence manifest"}
    for name, help_text in commands.items():
        sub = cmd.add_parser(name, help=help_text)
        if name == "timeline":
            sub.add_argument("case_id", help="case ID or export-timesketch")
            sub.add_argument("export_case", nargs="?")
            sub.add_argument("--format", choices=("html", "csv", "json"), default="html")
        else:
            sub.add_argument("case_id")
        if name in ("collect", "investigate"):
            sub.add_argument("--bundle", type=Path, help="tenant-bound export bundle.json")
            sub.add_argument("--dry-run", action="store_true")
            sub.add_argument("--defender", action="store_true", help="include Defender evidence in an export case")
            sub.add_argument("--workspace-config", type=Path, help="bind Google Workspace from a matching tenant profile")
    pivot = cmd.add_parser("pivot", help="pivot within a saved export or Google Workspace investigation")
    pivot.add_argument("kind", choices=("ip", "user"))
    pivot.add_argument("value")
    pivot.add_argument("--case", dest="case_id", required=True)
    pivot.add_argument("--dry-run", action="store_true")
    return p


def manual_pivots(case):
    path = case.path / "pivots" / "analyst.json"
    return [tuple(p) for p in read(path)] if path.exists() else []


def summarize(case, overview):
    print(f"{case.id}  {case.tenant}  {case.meta['user']}")
    workspace = f"{overview['workspace_matches']} Workspace correlations | " if case.meta.get("google_workspace") else ""
    print(f"{overview['event_count']} incident events | {overview['findings']} findings | "
          f"{overview['mailbox_message_matches']} mailbox/message matches | {workspace}{overview['gaps']} telemetry gaps")
    for capture in overview.get("exchange_coverage", []):
        requested, queryable = capture["requested"], capture["queryable"]
        print(f"  Requested UTC: {requested['start']} to {requested['end']} (end excluded)")
        print(f"  Queryable UTC: {queryable['start']} to {queryable['end']} ({capture['queryable_basis']})")
        if capture["aged_off_prefix"]:
            gap = capture["aged_off_prefix"]
            print(f"  [!] Older than 90-day retention: {gap['start']} to {gap['end']}")
        for entry in capture["reads"]:
            count = str(entry["records"]) if entry["records"] is not None else "unknown"
            print(f"    {entry['id']}: {entry['start']} to {entry['end']} | {entry['outcome']} | "
                  f"{count} preserved rows | limit {entry['result_limit']} | checked {entry['checked_at'] or 'unavailable (v2)'}")
            if entry["aged_off_prefix"]:
                gap = entry["aged_off_prefix"]
                print(f"      [!] Rolling retention cutoff excluded {gap['start']} to {gap['end']}")
        print("  [!] " + capture["audit_gap"])
        print("  " + capture["caveat"])
    for gap in read(case.path / "telemetry_gaps.json")[:5]:
        print(f"  [!] {gap['dataset']}: {gap['reason']}")
    print(overview["output"])


def run_case(args, case):
    from .graph import plan

    cmd = args.command
    bundle = getattr(args, "bundle", None)
    manual = manual_pivots(case)
    extra = None
    if cmd == "pivot":
        extra = (args.kind, str(ipaddress.ip_address(args.value)) if args.kind == "ip" else user_address(args.value))
    primary = ("user", case.meta["user"])
    workspace_config = getattr(args, "workspace_config", None)
    if workspace_config:
        profile = read(workspace_config)
        if profile.get("tenant") != case.tenant:
            raise CaseError("Workspace profile tenant alias does not match the case.")
        cfg = workspace_profile(profile.get("google_workspace"))
        existing = case.meta.get("google_workspace")
        if existing and existing["customer_id"] != cfg["customer_id"]:
            raise CaseError("This case is already bound to a different Workspace customer.")
        case.meta["google_workspace"] = cfg
    enable_defender = getattr(args, "defender", False) and not case.options.get("defender", False)
    if enable_defender:
        case.options["defender"] = True
    primary_plan = plan(case, *primary, baseline=True) + plan(case, *primary)
    state = Collection(case)
    if getattr(args, "dry_run", False):
        dry_queries = plan(case, *extra) if extra else primary_plan
        active_mode = "export" if bundle else state.state.get("mode") or "live"
        if active_mode == "live" and case.meta.get("microsoft", True):
            raise CaseError("Use Invoke-BEC.ps1 for Microsoft reads. Legacy Graph query plans cannot run.")
        print(json.dumps(dict(case=case.meta, mode=active_mode,
            bundle=str(bundle) if bundle else None,
            queries=[q.metadata() for q in dry_queries] if active_mode == "live" else [],
            pivots=[dict(kind=k, value=v) for k, v in [extra or primary]],
            expansion=("Named account only." if case.meta.get("microsoft_auth") == "delegated" else
                       "Evidence-derived IPs, users, user IDs and consented principals within configured limits.")),
            indent=2))
        return 0
    with case.lock():
        # Reload mutable state after acquiring the lock.
        case.verify()
        case = Case(case.path)
        if workspace_config:
            existing = case.meta.get("google_workspace")
            if existing and existing["customer_id"] != cfg["customer_id"]:
                raise CaseError("This case is already bound to a different Workspace customer.")
            case.meta["google_workspace"] = cfg
        if enable_defender:
            case.options["defender"] = True
        if workspace_config or enable_defender:
            save(case.path / "case.json", case.meta)
            case.log("update_providers")
        primary_plan = plan(case, *primary, baseline=True) + plan(case, *primary)
        state = Collection(case)
        if cmd == "verify":
            print(f"Verified {len(case.manifest()['artifacts'])} raw artifacts for {case.id}.")
            return 0
        if cmd == "evidence":
            print(json.dumps(case.manifest(), indent=2))
            return 0
        manual = manual_pivots(case)
        if extra and extra not in manual:
            manual.append(extra)
            save(case.path / "pivots" / "analyst.json", manual)
        if cmd in ("collect", "investigate", "pivot"):
            if bundle:
                state.import_bundle(bundle.resolve())
            elif state.state["mode"] != "export":
                if args.verbose:
                    print("Collecting tenant-scoped evidence.", file=sys.stderr)
                state.collect(primary_plan)
                if cmd != "collect" and case.meta.get("microsoft_auth") != "delegated":
                    searched = {primary}
                    # Recompute sharing and scope after each acquisition wave.
                    while True:
                        events, _ = replay(case)
                        _, wanted, history, _, _ = scope(case, events, manual)
                        pending = [e for e in wanted if e not in searched]
                        if not pending:
                            break
                        for entity in pending:
                            searched.add(entity)
                            if args.verbose:
                                print("Pivot:", *entity, file=sys.stderr)
                            case.log("pivot", kind=entity[0], value=entity[1])
                            state.collect(plan(case, *entity))
                            if entity[0] == "user":
                                state.collect(plan(case, *entity, baseline=True))
            if cmd == "collect":
                print(json.dumps(dict(case=case.id, artifacts=len(case.manifest()["artifacts"]),
                                      gaps=state.state["gaps"]), indent=2))
                return 2 if state.state["gaps"] else 0
        overview = report(case, manual)
        if cmd == "timeline":
            if args.export_case:
                print(timesketch(case))
            else:
                print(case.path / "timeline" / ("timeline." + args.format))
        else:
            summarize(case, overview)
        return 2 if overview["gaps"] else 0


def write_package(directory, output, inputs=None, *, run_plan=None):
    from .case_package import package_case

    destination = package_case(directory, output, components=inputs, run_plan=run_plan)
    if run_plan is None:
        manifest = read(destination / "manifest.json")
        print(f"Investigation package: {destination}")
        print(f"Analyst workbook: {destination / 'triage.xlsx'}")
        print(f"Investigation PDF: {destination / 'investigation.pdf'}")
    else:
        from .package_safety import read_bytes
        from .run_index import finish_account
        from .storage import digest

        raw_manifest = read_bytes(destination / "manifest.json")
        manifest = json.loads(raw_manifest)
        account = manifest["scope"]["account"]
        finish_account(output, run_plan, account, destination, digest(raw_manifest))
        status = "saved with coverage gaps" if manifest["has_coverage_gaps"] else "saved"
        print(f"{account} - {status}. Folder: {destination.name}", flush=True)
    return 2 if manifest["has_coverage_gaps"] else 0


def run_offline(args):
    run_plan = None
    if args.run_directory is not None:
        if not args.review_package or args.case_id or args.google_customer_id or not args.root:
            raise CaseError("A run requires a new, scoped Exchange capture under its confirmed case root.")
        from .run_index import read_plan

        if sys.stdin.isatty():
            raise CaseError("Run packaging requires the confirmed plan from the launcher.")
        run_plan = read_plan(sys.stdin.buffer)
        if local_path(run_plan["root"]) != local_path(args.root):
            raise CaseError("The run and the requested case store differ.")
    if bool(args.exchange_snapshot) != bool(args.snapshot_sha256):
        raise CaseError("Supply the Exchange snapshot and its original acquisition SHA-256 together.")
    if args.exchange_snapshot and not args.review_package:
        raise CaseError("--exchange-snapshot requires --review-package for this trace import.")
    bundle = ExportBundle.load(args.bundle, offline=True)
    root = local_path(args.root or Path.home() / "BEC-Cases")
    if args.case_id:
        if any((args.user, args.start, args.end, args.directory_id, args.google_customer_id)):
            raise CaseError("Use --case by itself with --bundle. Scope comes from the saved case.")
        case = Case.find(root, args.case_id, other_root=local_path("cases") if args.root is None else None)
        if case.meta.get("microsoft_auth") == "delegated" or Collection(case).state["mode"] == "live":
            raise CaseError("Use a separate offline case for exports from a live case.")
        receipt = ExchangeReceipt.check(bundle, case.tenant, case.meta["directory_id"], case.meta["user"],
                                        case.meta["start"], case.meta["end"])
        hashes = verify_export_files(bundle, case.tenant, case.meta["directory_id"],
                                     (case.meta.get("google_workspace") or {}).get("customer_id"),
                                     case.meta.get("microsoft", True), receipt)
    else:
        if not all((args.user, args.start, args.end)):
            raise CaseError("A new offline case requires --tenant, --user, --start and --end.")
        accounts = affected_accounts([args.user])
        if len(accounts) != 1:
            raise CaseError("Give one affected account per offline case.")
        try:
            directory = str(uuid.UUID(args.directory_id)) if args.directory_id else None
        except ValueError as exc:
            raise CaseError("--directory-id must be a Microsoft directory GUID.") from exc
        customer = args.google_customer_id
        datasets = {dataset for dataset, _, _ in bundle.files}
        if datasets.intersection(GOOGLE_APPS) and not customer:
            raise CaseError("Workspace exports require the expected --google-customer-id.")
        profile = dict(tenant=args.tenant, directory_id=directory,
                       microsoft=bool(directory or datasets.difference(GOOGLE_APPS)))
        if customer:
            profile["google_workspace"] = {"customer_id": customer}
        receipt = ExchangeReceipt.check(bundle, args.tenant, directory, accounts[0], args.start, args.end)
        if receipt:
            profile["options"] = dict(baseline_days=0, max_depth=0, max_users=1)
        hashes = verify_export_files(bundle, args.tenant, directory, customer, profile["microsoft"], receipt)
    package_inputs = None
    if args.review_package:
        if not receipt:
            raise CaseError("--review-package on an import requires a verified scoped Exchange trace receipt.")
        if run_plan is not None:
            from .run_index import check_capture

            confirmed = check_capture(args.run_directory, run_plan, bundle)
            if confirmed.sha != receipt.sha:
                raise CaseError("The run and the offline importer verified different capture receipts.")
        if args.exchange_snapshot:
            from .package_inputs import PackageInputs, paired_snapshot

            current = paired_snapshot(args.exchange_snapshot, (receipt,), bundle.manifest["directory_id"],
                                      receipt.scope["account"], receipt.scope["start"], receipt.scope["end"],
                                      expected_hash=args.snapshot_sha256)
            package_inputs = PackageInputs(exchange_snapshot=args.exchange_snapshot, snapshot_sha256=current.sha256)
    if not args.case_id:
        case = create(root, args.tenant, accounts[0], args.start, args.end, profile, export_only=True, named_account=bool(receipt))
        if run_plan is None:
            print(f"Case {case.id}", flush=True)
    with case.lock():
        case = Case(case.path)
        if case.meta.get("microsoft_auth") == "delegated":
            raise CaseError("Use a separate offline case for exports from an investigator sign-in case.")
        case.verify()
        Collection(case).import_files(bundle, verified_hashes=hashes, receipt=receipt)
        overview = report(case, manual_pivots(case))
        if run_plan is None:
            summarize(case, overview)
    status = 0
    if args.review_package:
        destination = args.run_directory if run_plan is not None else case.path.parent.parent / "review-packages"
        status = write_package(case.path, destination, package_inputs, run_plan=run_plan)
    return 2 if overview["gaps"] else status


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "offline":
            return run_offline(args)
        if args.command == "run-summary":
            from .run_index import refresh_run

            print(refresh_run(args.directory))
            return 0
        if args.command == "package":
            from .package_inputs import PackageInputs

            inputs = None
            if args.sources or args.exchange_snapshot or args.snapshot_sha256 or args.user_object_id or args.mailbox_guid:
                inputs = PackageInputs(imports=tuple(args.sources), exchange_snapshot=args.exchange_snapshot,
                                       snapshot_sha256=args.snapshot_sha256, user_object_id=args.user_object_id,
                                       mailbox_guid=args.mailbox_guid)
            return write_package(args.directory, args.output, inputs)
        if args.command == "microsoft":
            if args.adapter:
                print(ADAPTER)
                return 0
            print("In your connected PowerShell window, run ./Invoke-BEC.ps1 from the extracted BEC folder. "
                  "Review the tenant and operator, enter the affected accounts, choose a time window and confirm.",
                  file=sys.stderr)
            return 1
        investigator_root = Path.home() / "BEC-Cases"
        root = (args.root or Path("cases")).resolve()
        if args.command in ("snapshot-import", "snapshot-view"):
            from .mailbox_state import import_snapshot, view_snapshot
            result = (import_snapshot(args.directory, args.snapshot, args.output)
                      if args.command == "snapshot-import" else view_snapshot(args.directory, args.snapshot))
            print(json.dumps(result, ensure_ascii=True, indent=2))
            return 0
        if args.command == "search":
            from .search import search, render_html, write_report
            result = search(args.directory, args.type, args.value)
            if args.output:
                print(write_report(result, args.output, args.format))
            else:
                print(render_html(result) if args.format == "html" else json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "compare":
            from .comparison import compare, render_html, write_report
            result = compare(args.before, args.after)
            if args.output:
                print(write_report(result, args.output, args.format))
            else:
                print(render_html(result) if args.format == "html" else json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if args.command == "case":
            if args.directory_id:
                directory = uuid.UUID(args.directory_id)
                if not directory.int:
                    raise CaseError("Use a nonempty Microsoft directory GUID.")
                cfg = dict(tenant=args.tenant, directory_id=str(directory), microsoft=True)
                case = create(root, args.tenant, args.user, args.start, args.end, cfg, export_only=True, named_account=True)
            else:
                cfg = read(args.config) if args.config else None
                case = create(root, args.tenant, args.user, args.start, args.end, cfg)
            print(case.id)
            return 0
        if args.command == "timeline" and args.case_id == "export-timesketch" and args.export_case:
            args.case_id = args.export_case
        elif args.command == "timeline" and args.export_case:
            raise CaseError("Use bec timeline export-timesketch CASE_ID.")
        case = Case.find(root, args.case_id, other_root=investigator_root if args.root is None else None)
        if (args.command in ("collect", "investigate", "pivot") and case.meta.get("microsoft", True)
                and not getattr(args, "bundle", None) and not getattr(args, "dry_run", False)
                and Collection(case).state["mode"] != "export"):
            raise CaseError("Use Invoke-BEC.ps1 in your authorized Exchange Online session for Microsoft collection. "
                            "Saved cases remain available through analyze, report, verify and search.")
        return run_case(args, case)
    except (CaseError, OSError, ValueError, KeyError, TypeError, ZoneInfoNotFoundError) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Preserved pages are available for replay.", file=sys.stderr)
        return 130
