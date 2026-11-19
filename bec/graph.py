"""Microsoft Graph public cloud transport and scoped queries."""
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import timedelta
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from . import hunting
from .storage import CaseError, iso, read, save, timestamp, microsoft_enabled

ROOT = "https://graph.microsoft.com"
SIGN = "/auditLogs/signIns"
AUDIT = "/v1.0/security/auditLog/queries"
TRACE = "/v1.0/admin/exchange/tracing/messageTraces"
DIRECTORY = "/v1.0/auditLogs/directoryAudits"
PERMISSIONS = {"ual": "AuditLogsQuery-Exchange.Read.All", "trace": "ExchangeMessageTrace.Read.All"}
PERMISSIONS.update(dict.fromkeys(hunting.TABLES, "ThreatHunting.Read.All"))


class SourceError(Exception):
    """A reportable telemetry gap with a safe-to-log explanation."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Graph:
    session = None

    def __init__(self, case, session=None):
        if not case.meta["directory_id"]:
            raise CaseError("Live collection requires a case created with a Microsoft tenant profile.")
        self.case = case
        self.opener = build_opener(NoRedirect)
        if case.meta.get("microsoft_auth") == "delegated":
            if (session is None or session.directory_id != case.meta["directory_id"]
                    or session.client_id != case.meta["client_id"]):
                raise CaseError("This case requires a Microsoft sign-in for its original tenant and application.")
            self.session = session
            return
        if session is not None:
            raise CaseError("This case was not created for investigator sign-in.")
        try:
            from azure.identity import CertificateCredential, ClientSecretCredential
        except ImportError as exc:
            raise CaseError("Install the live extra: pip install '.[live]'") from exc
        args = case.meta["directory_id"], case.meta["client_id"]
        if path := os.environ.get("BEC_CERTIFICATE_PATH"):
            self.credential = CertificateCredential(*args, certificate_path=path,
                password=os.environ.get("BEC_CERTIFICATE_PASSWORD"))
        elif secret := os.environ.get("BEC_CLIENT_SECRET"):
            self.credential = ClientSecretCredential(*args, secret)
        else:
            raise CaseError("Set BEC_CERTIFICATE_PATH or BEC_CLIENT_SECRET before live collection.")

    def request(self, url, body=None):
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or not parsed.path.startswith(("/v1.0/", "/beta/")):
            raise SourceError("Rejected a Graph URL outside the configured public cloud.")
        hunt = parsed.path == hunting.ENDPOINT
        repeatable = body is None or hunt
        for attempt in range(5):
            if self.session is not None:
                token = self.session.access_token()
            else:
                try:
                    token = self.credential.get_token(ROOT + "/.default").token
                except Exception as exc:
                    raise SourceError("Graph authentication failed. Check the tenant, application and credential.") from exc
            req = Request(url, data=json.dumps(body).encode() if body is not None else None,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json; charset=utf-8",
                                   "Accept": "application/json"})
            try:
                with self.opener.open(req, timeout=200 if hunt else 45) as response:
                    return response.read()
            except HTTPError as exc:
                code = exc.code
                exc.close()
                if code not in (429, 500, 502, 503, 504) or (not repeatable and code != 429):
                    guidance = {403: "check consent, investigator or application access, workload provisioning and licensing",
                                401: "check tenant authentication", 400: "query rejected by this API",
                                404: "resource or endpoint unavailable"}
                    raise SourceError(f"Graph HTTP {code}: {guidance.get(code, 'request failed')}.") from exc
                retry = exc.headers.get("Retry-After", "")
                delay = int(retry) if retry.isdecimal() else 2 ** attempt
            except (URLError, TimeoutError, socket.timeout, OSError) as exc:
                if not repeatable:
                    raise SourceError("Audit search submission outcome unknown after network failure.") from exc
                delay, code = 2 ** attempt, "network"
            if attempt == 4 or delay > 120:
                raise SourceError(f"Graph retry budget exceeded ({code}). Retry collection later.")
            self.case.log("retry", api=parsed.path, status=code, delay_seconds=delay)
            time.sleep(delay)
        raise AssertionError("retry loop")

    def pages(self, url):
        seen = set()
        while url:
            if url in seen:
                raise SourceError("Graph returned a repeated pagination URL.")
            seen.add(url)
            raw = self.request(url)
            obj = json.loads(raw)
            if not isinstance(obj, dict) or not isinstance(obj.get("value"), list):
                raise SourceError("Graph response lacks a record collection.")
            yield raw
            url = obj.get("@odata.nextLink")


@dataclass(frozen=True)
class Query:
    dataset: str
    kind: str
    value: str
    start: str
    end: str
    field: str
    path: str

    def metadata(self):
        meta = dict(dataset=self.dataset, kind=self.kind, value=self.value, start=self.start,
                    end=self.end, field=self.field, endpoint=self.path,
                    permission=PERMISSIONS.get(self.dataset, "AuditLog.Read.All"))
        if self.dataset == "ual":
            meta["record_types"] = ["exchangeAdmin", "exchangeItem", "exchangeItemGroup",
                                    "exchangeAggregatedOperation", "exchangeItemAggregated", "exchangeSearch"]
        return meta


def plan(case, kind, value, baseline=False):
    from .workspace import queries as workspace_queries
    start, end = timestamp(case.meta["start"]), timestamp(case.meta["end"])
    if baseline:
        end, start = start, start - timedelta(days=case.options["baseline_days"])
    if start == end:
        return []
    entries = []
    if kind in ("user", "ip"):
        fld = "userPrincipalName" if kind == "user" else "ipAddress"
        entries.extend([("interactive", fld, "/v1.0" + SIGN), ("noninteractive", fld, "/beta" + SIGN)])
        if not baseline:
            entries.append(("ual", "userPrincipalNameFilters" if kind == "user" else "ipAddressFilters", AUDIT))
            if kind == "user":
                entries.extend([("directory", "initiatedBy/user/userPrincipalName", DIRECTORY),
                                ("trace", "recipientAddress", TRACE), ("trace", "senderAddress", TRACE)])
                if case.options.get("defender", False):
                    entries.extend((table, "account/message scope", hunting.ENDPOINT) for table in hunting.TABLES)
                    entries.append(("AlertEvidence", "NetworkMessageId", hunting.ENDPOINT))
    elif kind == "principal":
        entries.append(("service_principal", "servicePrincipalId", "/beta" + SIGN))
    elif kind == "user_id":
        entries.append(("directory", "targetResources", DIRECTORY))
    queries = []
    for dataset, field, path in (entries if microsoft_enabled(case) else ()):
        low = start
        while low < end:
            high = min(low + timedelta(days=9 if dataset == "trace" else 30), end)
            queries.append(Query(dataset, kind, value, iso(low), iso(high), field, path))
            low = high
    if case.meta.get("google_workspace"):
        queries.extend(workspace_queries(case, kind, value, start, end, baseline))
    return queries


def list_url(q):
    timefield = {"trace": "receivedDateTime", "directory": "activityDateTime"}.get(q.dataset, "createdDateTime")
    val = q.value.replace("'", "''")
    filt = f"{timefield} ge {q.start} and {timefield} le {q.end}"
    if q.field == "targetResources":
        filt += f" and targetResources/any(t:t/id eq '{val}')"
    else:
        filt += f" and {q.field} eq '{val}'"
    types = {"noninteractive": "nonInteractiveUser", "service_principal": "servicePrincipal"}
    if q.dataset in types:
        filt += f" and signInEventTypes/any(t:t eq '{types[q.dataset]}')"
    return ROOT + q.path + "?" + urlencode({"$filter": filt, "$top": 50 if q.kind == "ip" else 500})


def fetch(graph, q, key):
    if q.dataset in hunting.TABLES:
        yield from hunting.pages(graph, q)
        return
    if q.dataset != "ual":
        yield from graph.pages(list_url(q))
        return
    # Reuse an outstanding Purview search after interruption or poll timeout.
    jobs = graph.case.path / "collection" / "audit_jobs.json"
    known = read(jobs) if jobs.exists() else {}
    query_id = known.get(key)
    if not query_id:
        body = dict(displayName="BEC " + graph.case.id, filterStartDateTime=q.start,
                    filterEndDateTime=q.end, recordTypeFilters=q.metadata()["record_types"], **{q.field: [q.value]})
        response = json.loads(graph.request(ROOT + AUDIT, body))
        query_id = str(uuid.UUID(response["id"]))
        known[key] = query_id
        save(jobs, known)
    url = ROOT + AUDIT + "/" + str(uuid.UUID(query_id))
    deadline = time.monotonic() + 900
    while True:
        state = json.loads(graph.request(url))
        status = state.get("status")
        if status == "succeeded":
            break
        if status not in ("notStarted", "running"):
            known.pop(key, None)
            save(jobs, known)
            raise SourceError("Purview search ended without success.")
        if time.monotonic() >= deadline:
            raise SourceError("Purview search still running. Rerun collection to resume.")
        time.sleep(5)
    yield from graph.pages(url + "/records")
    known.pop(key, None)
    save(jobs, known)
    if state.get("isRecordCountLimitExceeded"):
        raise SourceError("Purview record limit exceeded. Use a shorter case window for full coverage.")
