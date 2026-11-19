"""Explicit-target lab acceptance using installed BEC collectors; never generates activity."""
import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import uuid

from bec import __version__
from bec.comparison import Snapshot, compare
from bec.graph import plan as query_plan
from bec.storage import (CASE_ID, GOOGLE_APPS, LABEL, RESERVED, CaseError, digest, encode,
                         iso, read, save, settings, timestamp, user_address, workspace_profile)


REPOSITORY = Path(__file__).resolve().parents[1]
PROVIDERS = {"microsoft": {"certificate", "client_secret"}, "google": {"service_account"}}
GATES = ("live_origin", "input_integrity", "source_coverage", "expected_events", "bounded_queries",
         "unexpected_gaps", "pagination", "permission_failures", "saved_case_comparison")
PLACEHOLDER_IDS = {"11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"}


def outside_repository(path, label):
    path = Path(path).resolve()
    if path.is_relative_to(REPOSITORY):
        raise CaseError(label + " must be outside the public source repository.")
    return path


def _actual_address(value):
    value = user_address(value)
    domain = value.rsplit("@", 1)[1]
    if domain in {"example.com", "example.org", "example.net"} or domain.endswith((".example", ".invalid", ".test")):
        raise CaseError("Replace example/reserved-domain addresses with explicitly designated lab accounts.")
    return value


def prepare(plan_file):
    """Validate a private target declaration and preview fixed existing queries without I/O to providers."""
    plan_file = outside_repository(plan_file, "Lab plan")
    target = read(plan_file)
    allowed = {"schema_version", "authorization_reference", "profile", "tenant", "users", "start", "end",
               "credential_source", "required_sources", "expected_events", "pagination_sources",
               "permission_denied_sources", "timeout_seconds"}
    if not isinstance(target, dict) or set(target) - allowed or target.get("schema_version") != 1:
        raise CaseError("Lab plan must use schema_version 1 and only documented fields.")
    if not isinstance(target.get("authorization_reference"), str) or len(target["authorization_reference"].strip()) < 8:
        raise CaseError("Record the user's explicit lab-target designation in authorization_reference.")
    users = target.get("users")
    if not isinstance(users, list) or not 1 <= len(users) <= 3:
        raise CaseError("Designate between one and three exact lab users.")
    users = [_actual_address(value) for value in users]
    if len(set(users)) != len(users):
        raise CaseError("Lab users must be distinct.")
    start, end = timestamp(target["start"]), timestamp(target["end"])
    if not timedelta(0) < end - start <= timedelta(hours=24) or end > datetime.now(UTC):
        raise CaseError("Use a completed, positive UTC-aware activity window of at most 24 hours.")
    profile_path = outside_repository(plan_file.parent / target["profile"], "Tenant profile")
    profile = read(profile_path)
    if not isinstance(profile, dict) or set(profile) - {"tenant", "directory_id", "client_id", "options", "google_workspace", "microsoft"}:
        raise CaseError("Use an existing BEC tenant profile containing only documented identifier/options fields.")
    if not target.get("tenant") or profile.get("tenant") != target["tenant"]:
        raise CaseError("Lab plan and tenant profile aliases must match.")
    if not isinstance(target["tenant"], str) or not LABEL.fullmatch(target["tenant"]) or target["tenant"].upper() in RESERVED:
        raise CaseError("Use a valid BEC tenant alias.")
    google = workspace_profile(profile["google_workspace"]) if profile.get("google_workspace") else None
    microsoft = profile.get("microsoft", bool(profile.get("directory_id")) or not google)
    if type(microsoft) is not bool or not (microsoft or google):
        raise CaseError("Select a supported live provider.")
    if bool(profile.get("directory_id")) != bool(profile.get("client_id")):
        raise CaseError("Supply both Microsoft directory and client IDs, or neither for a Workspace-only profile.")
    if microsoft or profile.get("directory_id"):
        for key in ("directory_id", "client_id"):
            profile[key] = str(uuid.UUID(profile.get(key, "")))
            if profile[key] in PLACEHOLDER_IDS:
                raise CaseError("Example Microsoft IDs cannot designate a lab target.")
    if google:
        if google["customer_id"] in {"C012example", "C02becdemo"}:
            raise CaseError("Example Workspace IDs cannot designate a lab target.")
        google["admin_email"] = _actual_address(google.get("admin_email", ""))
    sources = target.get("credential_source")
    enabled = ({"microsoft"} if microsoft else set()) | ({"google"} if google else set())
    if not isinstance(sources, dict) or set(sources) != enabled or any(sources[key] not in PROVIDERS[key] for key in sources):
        raise CaseError("Explicitly select the documented credential source for every enabled provider.")
    options = settings(profile.get("options", {}))
    options.update(baseline_days=0, max_depth=0, max_users=1, max_ips=1, max_events=min(options["max_events"], 5000))
    profile = {**profile, "microsoft": microsoft, "options": options}
    if google:
        profile["google_workspace"] = google
    meta = {**profile, "start": iso(start), "end": iso(end), "google_workspace": google}
    preview = {user: [query.metadata() for query in query_plan(SimpleNamespace(meta=meta, options=options), "user", user)]
               for user in users}
    planned = {query["dataset"] for queries in preview.values() for query in queries}
    for key in ("required_sources", "pagination_sources", "permission_denied_sources"):
        values = target.get(key, [])
        if not isinstance(values, list) or any(value not in planned for value in values) or len(values) != len(set(values)):
            raise CaseError(key + " must list distinct datasets in the previewed primary-user queries.")
        target[key] = values
    if not target["required_sources"] or set(target["required_sources"]) & set(target["permission_denied_sources"]):
        raise CaseError("Require at least one available source; denied sources cannot also be required available sources.")
    if any(value not in GOOGLE_APPS and value not in {"interactive", "noninteractive", "directory", "ual", "trace"}
           for value in target["pagination_sources"]):
        raise CaseError("Pagination gates support existing Graph list and Google Reports sources only.")
    expected = target.get("expected_events")
    if not isinstance(expected, list) or not 1 <= len(expected) <= 150:
        raise CaseError("Provide one to 150 independently known benign event expectations.")
    for event in expected:
        if not isinstance(event, dict) or set(event) != {"user", "dataset", "source_event_id", "event_type", "actor"}:
            raise CaseError("Each expected event needs exact user, dataset, source_event_id, event_type and actor fields.")
        if event["user"] not in users or event["dataset"] not in target["required_sources"]:
            raise CaseError("Expected events must belong to designated users and required sources.")
        if any(not isinstance(event[key], str) or not event[key] for key in event):
            raise CaseError("Expected event selectors must be nonempty strings.")
        _actual_address(event["actor"])
    if {event["user"] for event in expected} != set(users):
        raise CaseError("Every designated user needs an independently known expected event.")
    timeout = target.get("timeout_seconds", 900)
    if type(timeout) is not int or not 60 <= timeout <= 1800:
        raise CaseError("timeout_seconds must be between 60 and 1800.")
    return {**target, "users": users, "start": iso(start), "end": iso(end), "profile": profile,
            "profile_path": str(profile_path), "timeout_seconds": timeout, "query_preview": preview}


def credential_environment(target):
    """Honor only the operator-selected environment credential mechanism, without reading key contents."""
    environment = os.environ.copy()
    required = []
    selected = target["credential_source"]
    if selected.get("microsoft") == "certificate":
        required.append("BEC_CERTIFICATE_PATH")
        environment.pop("BEC_CLIENT_SECRET", None)
    else:
        environment.pop("BEC_CERTIFICATE_PATH", None)
        environment.pop("BEC_CERTIFICATE_PASSWORD", None)
        if selected.get("microsoft") == "client_secret":
            required.append("BEC_CLIENT_SECRET")
        else:
            environment.pop("BEC_CLIENT_SECRET", None)
    if selected.get("google") == "service_account":
        required.append("BEC_GOOGLE_SERVICE_ACCOUNT")
    else:
        environment.pop("BEC_GOOGLE_SERVICE_ACCOUNT", None)
    if any(not environment.get(key) for key in required):
        raise CaseError("Missing selected credential environment variable(s): " + ", ".join(key for key in required if not environment.get(key)))
    return environment


def fixture_fingerprints():
    # Preserve the original qualification exclusions without distributing the sample records.
    text = Path(__file__).with_name("lab-excluded-rows.sha256").read_text(encoding="ascii")
    if digest(text.encode("ascii")) != "f0a7ec07e8aba1475224d577b3d9829f499a5d8c170145f715f5590bb4fc8a24":
        raise CaseError("The lab evidence exclusion list is missing entries or has changed.")
    return set(text.splitlines())


def assess(case_directory, target, user, receipt):
    """Assess observed artifacts, never infer a live pass from a report, fixture, or collector label alone."""
    snapshot = Snapshot(case_directory)
    case = snapshot.case
    manifest = case.manifest()
    state = read(case.path / "collection_summary.json") if (case.path / "collection_summary.json").exists() else {}
    queries = list(state.get("queries", {}).values())
    artifacts = manifest["artifacts"]
    expected_binding = dict(tenant=target["tenant"], directory_id=target["profile"].get("directory_id"),
        google_customer_id=(target["profile"].get("google_workspace") or {}).get("customer_id"))
    origin = dict(collector_receipt=bool(receipt.get("collector_invoked") and receipt.get("case_id") == case.id and
        receipt.get("collect_exit") in (0, 2)), live_mode=state.get("mode") == "live", raw_evidence_present=bool(artifacts),
        identity_matches=snapshot.binding == expected_binding and case.meta["user"] == user,
        fixture_free=not bool(set(snapshot.inventory) & fixture_fingerprints()), collectors_valid=True, collection_times_valid=True)
    for artifact in artifacts:
        expected_collector = "google_reports" if artifact["dataset"] in GOOGLE_APPS else "graph"
        origin["collectors_valid"] = origin["collectors_valid"] and artifact["collector"] == expected_collector
        origin["collection_times_valid"] = origin["collection_times_valid"] and (
            timestamp(receipt["started"]) <= timestamp(artifact["collected_at"]) <= timestamp(receipt["finished"]))
    live_origin = all(origin.values())
    planned = {digest(encode(query)) for query in target["query_preview"][user]}
    actual = set(state.get("queries", {}))
    scoped = actual == planned and snapshot.context["incident_window"] == [target["start"], target["end"]]
    by_source = {dataset: [query for query in queries if query.get("dataset") == dataset]
                 for dataset in {query.get("dataset") for query in queries}}
    coverage = {dataset: bool(by_source.get(dataset)) and all(query.get("status") == "collected" for query in by_source[dataset])
                for dataset in target["required_sources"]}
    denied = {dataset: bool(by_source.get(dataset)) and any(query.get("status") == "gap" and
              any(code in query.get("reason", "") for code in ("HTTP 401", "HTTP 403")) for query in by_source[dataset])
              for dataset in target["permission_denied_sources"]}
    unexpected = [query for query in queries if query.get("status") == "gap" and not (
        query.get("dataset") in target["permission_denied_sources"] and
        any(code in query.get("reason", "") for code in ("HTTP 401", "HTTP 403")))]
    unexpected.extend(dict(dataset=dataset, reason="Unparseable preserved records", count=coverage["normalization_issues"])
                      for dataset, coverage in snapshot.coverage.items() if coverage["normalization_issues"])
    expected_results = []
    for expected in [event for event in target["expected_events"] if event["user"] == user]:
        matches = [dict(observation=observation, evidence=item["evidence"]) for item in snapshot.inventory.values()
                   if item["dataset"] == expected["dataset"] for observation in item["observations"]
                   if str(observation["source_event_id"]) == expected["source_event_id"] and
                   observation["event_type"] == expected["event_type"] and observation["actor"].get("user") == expected["actor"].casefold() and
                   timestamp(target["start"]) <= timestamp(observation["timestamp_utc"]) < timestamp(target["end"])]
        expected_results.append(dict(expected=expected, matched=bool(matches), matches=matches))
    page_groups = {}
    for artifact in artifacts:
        obj = json.loads(case.raw_path(artifact).read_bytes().decode("utf-8-sig"))
        continuation = isinstance(obj, dict) and bool(obj.get("@odata.nextLink") or obj.get("nextPageToken"))
        for query in artifact.get("queries", []):
            key = digest(encode(query))
            page_groups.setdefault((artifact["dataset"], key), []).append(dict(file=artifact["artifact"],
                sha256=artifact["sha256"], continuation=continuation))
    pagination = {dataset: [pages for (source, key), pages in page_groups.items() if source == dataset and
                  len(pages) > 1 and any(page["continuation"] for page in pages) and any(not page["continuation"] for page in pages)
                  and state.get("queries", {}).get(key, {}).get("status") == "collected"]
                  for dataset in target["pagination_sources"]}
    same = compare(case.path, case.path)
    gates = dict(live_origin="passed" if live_origin else "failed", input_integrity="passed",
        source_coverage="passed" if all(coverage.values()) else "failed",
        expected_events="passed" if expected_results and all(item["matched"] for item in expected_results) else "failed",
        bounded_queries="passed" if scoped else "failed", unexpected_gaps="passed" if not unexpected else "failed",
        pagination=("passed" if all(pagination.values()) else "not_observed") if pagination else "not_exercised",
        permission_failures=("passed" if all(denied.values()) else "not_observed") if denied else "not_exercised",
        saved_case_comparison="passed" if same["summary"]["newly_observed"] == same["summary"]["only_in_earlier"] == 0 else "failed")
    status = "failed" if "failed" in gates.values() else "passed_for_declared_scope" if all(value == "passed" for value in gates.values()) else "incomplete"
    return dict(status=status, gates=gates, case_id=case.id, case_directory=str(case.path),
        coverage=coverage, expected_events=expected_results, pagination=pagination, permission_failures=denied,
        unexpected_gaps=unexpected, origin_evidence=origin, raw_artifacts=len(artifacts), raw_records=snapshot.metadata["raw_records"],
        comparison_summary=same["summary"], receipt=receipt)


def public_summary(result):
    """Allowlist-only publication status: no account, tenant, IP, event ID, query, or path fields."""
    runs = result.get("cases", [])
    return dict(tool="bacon-egg-and-cheese", version=result["tool"]["version"],
        live_execution=result["live_execution"], status=result["status"], case_count=len(runs),
        checks=[{gate: case["gates"][gate] for gate in GATES} for case in runs],
        execution_error="private_error" in result,
        unrun_gates=sorted({gate for case in runs for gate in GATES if case["gates"][gate] in {"not_exercised", "not_observed"}} if runs else set(GATES)),
        note="Live qualification applies only to declared checks. Offline fixtures never qualify a tenant; absent pagination or permission-failure observations remain untested.")


def run(target, directory):
    directory = outside_repository(directory, "Run directory")
    environment = credential_environment(target)
    directory.mkdir(parents=True, exist_ok=False)
    info = subprocess.run([sys.executable, "-I", "-c",
        "import bec, json, importlib.metadata; print(json.dumps({'version': bec.__version__, 'distribution_version': importlib.metadata.version('bacon-egg-and-cheese'), 'module': bec.__file__}))"],
        capture_output=True, text=True, check=True, timeout=30, env=environment)
    tool = json.loads(info.stdout)
    if tool["version"] != __version__ or tool["distribution_version"] != __version__:
        raise CaseError("Runner and installed BEC versions differ; install this repository before lab validation.")
    profile = directory / "tenant-profile.private.json"
    save(profile, target["profile"])
    save(directory / "plan.private.json", target)
    commands, results = [], []
    result = dict(tool={**tool, "python": sys.executable}, live_execution=False, status="not_executed", cases=results)

    def invoke(*arguments):
        command = [sys.executable, "-I", "-m", "bec", *map(str, arguments)]
        completed = subprocess.run(command, cwd=directory, env=environment, capture_output=True,
                                   text=True, timeout=target["timeout_seconds"])
        commands.append(dict(command=command, exit_code=completed.returncode, stdout=completed.stdout, stderr=completed.stderr))
        save(directory / "commands.private.json", commands)
        return completed

    try:
        for user in target["users"]:
            created = invoke("--root", directory / "cases", "case", "create", "--tenant", target["tenant"],
                "--user", user, "--start", target["start"], "--end", target["end"], "--config", profile)
            case_id = created.stdout.strip()
            if created.returncode or not CASE_ID.fullmatch(case_id):
                raise CaseError("Lab case creation failed; inspect private command output.")
            started = iso(datetime.now(UTC))
            result["live_execution"] = True
            collected = invoke("--root", directory / "cases", "collect", case_id)
            finished = iso(datetime.now(UTC))
            receipt = dict(collector_invoked=True, case_id=case_id, started=started, finished=finished, collect_exit=collected.returncode)
            if collected.returncode not in (0, 2):
                raise CaseError("Live collection failed; preserved evidence and private command output remain available.")
            verified = invoke("--root", directory / "cases", "verify", case_id)
            analyzed = invoke("--root", directory / "cases", "analyze", case_id)
            if verified.returncode or analyzed.returncode not in (0, 2):
                raise CaseError("Verification or local analysis failed; inspect private command output.")
            assessment = assess(directory / "cases" / target["tenant"] / case_id, target, user, receipt)
            results.append(assessment)
            save(directory / "acceptance.private.json", result)
        result["status"] = "failed" if any(case["status"] == "failed" for case in results) else (
            "passed_for_declared_scope" if all(case["status"] == "passed_for_declared_scope" for case in results) else "incomplete")
    except (CaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result["status"] = "failed"
        result["private_error"] = str(error)
    finally:
        save(directory / "acceptance.private.json", result)
        save(directory / "public-summary.json", public_summary(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicit-target BEC live lab acceptance; preflight performs no provider calls.")
    parser.add_argument("action", choices=("preflight", "run"))
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path)
    arguments = parser.parse_args(argv)
    try:
        target = prepare(arguments.plan)
        if arguments.action == "preflight":
            print(json.dumps(dict(status="not_executed", provider_calls=False, plan=target), indent=2))
            return 0
        if arguments.run_dir is None:
            raise CaseError("run requires a new private --run-dir outside the repository.")
        result = run(target, arguments.run_dir)
        print(json.dumps(public_summary(result), indent=2))
        return 0 if result["status"] == "passed_for_declared_scope" else 2
    except (CaseError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("BEC lab validation: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
