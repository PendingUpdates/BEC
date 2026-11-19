"""BEC command-line entry points."""
import argparse
import ipaddress
import json
import os
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfoNotFoundError

from . import __version__
from .analysis import scope
from .collection import Collection, replay
from .graph import Graph, plan
from .microsoft_login import sign_in
from .reporting import report, timesketch
from .storage import Case, CaseError, create, iso, read, save, user_address, workspace_profile


def parser():
    p = argparse.ArgumentParser(prog="bec", description="Bacon Egg and Cheese · Microsoft 365, Defender and Google Workspace email compromise investigations")
    p.add_argument("--root", type=Path, default=os.environ.get("BEC_CASES"), help="case store")
    p.add_argument("--verbose", action="store_true", help="print collection and pivot progress")
    p.add_argument("--version", action="version", version="BEC " + __version__)
    cmd = p.add_subparsers(dest="command", required=True)
    case = cmd.add_parser("case", help="create a tenant-scoped case").add_subparsers(dest="action", required=True)
    new = case.add_parser("create")
    for flag in ("tenant", "user", "start", "end"):
        new.add_argument("--" + flag, required=True)
    new.add_argument("--config", type=Path, help="tenant profile JSON")
    microsoft = cmd.add_parser("microsoft", help="sign in and investigate one or more Microsoft 365 accounts")
    microsoft.add_argument("accounts", nargs="*", metavar="ACCOUNT", help="affected email addresses (or enter after sign-in)")
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
    for name in ("collect", "investigate", "analyze", "report", "timeline", "verify", "evidence"):
        sub = cmd.add_parser(name)
        if name == "timeline":
            sub.add_argument("case_id", help="case ID or export-timesketch")
            sub.add_argument("export_case", nargs="?")
            sub.add_argument("--format", choices=("html", "csv", "json"), default="html")
        else:
            sub.add_argument("case_id")
        if name in ("collect", "investigate"):
            sub.add_argument("--bundle", type=Path, help="tenant-bound export bundle.json")
            sub.add_argument("--dry-run", action="store_true")
            sub.add_argument("--defender", action="store_true", help="enable Defender collection for this case")
            sub.add_argument("--workspace-config", type=Path, help="bind Google Workspace from a matching tenant profile")
    pivot = cmd.add_parser("pivot", help="investigate an additional user or IP within the case")
    pivot.add_argument("kind", choices=("ip", "user"))
    pivot.add_argument("value")
    pivot.add_argument("--case", dest="case_id", required=True)
    pivot.add_argument("--dry-run", action="store_true")
    return p


def manual_pivots(case):
    path = case.path / "pivots" / "analyst.json"
    return [tuple(p) for p in read(path)] if path.exists() else []


def affected_accounts(values):
    addresses = []
    for value in values:
        for text in re.split(r"[,;\s]+", value.strip()):
            if not text:
                continue
            address = user_address(text)
            local, domain = address.split("@")
            labels = domain.split(".")
            if (any(c in local for c in "*?") or
                    not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels)):
                raise CaseError("Enter exact account addresses such as name@company.com. Wildcards are unsupported.")
            if address not in addresses:
                addresses.append(address)
    if not addresses:
        raise CaseError("Enter at least one affected account address.")
    return addresses


def investigate_accounts(args, root):
    accounts = affected_accounts(args.accounts) if args.accounts else None
    with sign_in() as session:
        print(f"Signed into Microsoft tenant {session.directory_id}.")
        while accounts is None:
            try:
                accounts = affected_accounts([input("Accounts to investigate (separate addresses with commas): ")])
            except EOFError as exc:
                raise CaseError("Account entry ended before an address was supplied.") from exc
            except CaseError as exc:
                print(str(exc), file=sys.stderr)
        end = datetime.now(UTC)
        start, end = iso(end - timedelta(hours=24)), iso(end)
        print(f"Collecting the last 24 hours, {start} to {end}. Saving cases in {root}.", flush=True)
        profile = dict(tenant=session.directory_id, directory_id=session.directory_id, client_id=session.client_id,
                       options=dict(baseline_days=0, max_depth=0, max_users=1))
        status = 0
        for account in accounts:
            case = create(root, session.directory_id, account, start, end, profile, delegated=True)
            print(f"Collecting {account}. Case {case.id} (resume with bec investigate {case.id}).", flush=True)
            result = run_case(args, case, session)
            if result:
                status = result
        return status


def summarize(case, overview):
    print(f"{case.id}  {case.tenant}  {case.meta['user']}")
    workspace = f"{overview['workspace_matches']} Workspace correlations | " if case.meta.get("google_workspace") else ""
    print(f"{overview['event_count']} incident events | {overview['findings']} findings | "
          f"{overview['mailbox_message_matches']} mailbox/message matches | {workspace}{overview['gaps']} telemetry gaps")
    for gap in read(case.path / "telemetry_gaps.json")[:5]:
        print(f"  [!] {gap['dataset']}: {gap['reason']}")
    print(overview["output"])


def run_case(args, case, session=None):
    cmd = "investigate" if args.command == "microsoft" else args.command
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
        if session is not None:
            state.graph = Graph(case, session)
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


def main(argv=None):
    args = parser().parse_args(argv)
    investigator_root = Path.home() / "BEC-Cases"
    root = (args.root or (investigator_root if args.command == "microsoft" else Path("cases"))).resolve()
    try:
        if args.command == "microsoft":
            return investigate_accounts(args, root)
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
            cfg = read(args.config) if args.config else None
            case = create(root, args.tenant, args.user, args.start, args.end, cfg)
            print(case.id)
            return 0
        if args.command == "timeline" and args.case_id == "export-timesketch" and args.export_case:
            args.case_id = args.export_case
        elif args.command == "timeline" and args.export_case:
            raise CaseError("Use bec timeline export-timesketch CASE_ID.")
        case = Case.find(root, args.case_id, other_root=investigator_root if args.root is None else None)
        if case.meta.get("microsoft_auth") == "delegated" and args.command in ("collect", "investigate", "pivot"):
            if args.command == "pivot" or args.bundle or args.workspace_config:
                raise CaseError("This Microsoft sign-in case collects only its named account. Create a separate case for a new target or source.")
            if not args.dry_run:
                with sign_in(case.meta["client_id"], case.meta["directory_id"]) as session:
                    return run_case(args, case, session)
        return run_case(args, case)
    except (CaseError, OSError, ValueError, KeyError, TypeError, ZoneInfoNotFoundError) as exc:
        print(f"BEC: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted. Preserved pages are available for replay.", file=sys.stderr)
        return 130
