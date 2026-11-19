"""Offline query descriptions for saved Microsoft profiles and Workspace planning."""
from dataclasses import dataclass
from datetime import timedelta

from . import hunting
from .storage import SourceError, iso, timestamp, microsoft_enabled

ROOT = "https://graph.microsoft.com"
SIGN = "/auditLogs/signIns"
AUDIT = "/v1.0/security/auditLog/queries"
TRACE = "/v1.0/admin/exchange/tracing/messageTraces"
DIRECTORY = "/v1.0/auditLogs/directoryAudits"
PERMISSIONS = {"ual": "AuditLogsQuery-Exchange.Read.All", "trace": "ExchangeMessageTrace.Read.All"}
PERMISSIONS.update(dict.fromkeys(hunting.TABLES, "ThreatHunting.Read.All"))


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
