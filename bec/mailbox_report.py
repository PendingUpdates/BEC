"""Plain-language review of already admitted mailbox evidence.

This is a display layer, not a collector, validator, risk score or intent detector.
Missing source properties stay unknown; current observations stay separate from
dated events. Complete fields and source references remain in the package indexes.
"""
import json
import re
from collections import Counter
from dataclasses import replace

from .package_documents import PdfParagraph, PdfSection, display_text
from .storage import CaseError


CURRENT_LIMIT = 50  # Per dataset, so many rules cannot hide forwarding/delegation.
HISTORY_LIMIT = 200
MISSING = object()
CURRENT_LABELS = {"inbox_rules": "Inbox rules", "forwarding": "Mailbox forwarding",
                  "full_access": "Full Access", "send_as": "Send As",
                  "send_on_behalf": "Send on Behalf"}
SOURCE_LABELS = {
    "exchange_trace": "Message trace", "exchange_current_state": "Current mailbox settings",
    "purview.mailbox-audit": "Mailbox audit", "entra.audit-logs": "Account identity history",
    "entra.user-signins.interactive": "Interactive user sign-ins",
    "entra.user-signins.noninteractive": "Noninteractive user sign-ins",
    "entra.workload-signins.service-principal": "Related application sign-ins",
    "entra.workload-signins.managed-identity": "Related managed-identity sign-ins",
    "defender.url-clicks": "Safe Links click observations",
}
STATUS_TEXT = {
    "collected": "returned selected properties", "returned": "returned records",
    "observed": "records supplied for the acquired window", "empty": "no results returned",
    "partial": "partial results; some properties or records are unavailable",
    "not_supplied": "not checked here; no source supplied", "not-supplied": "not checked here; no source supplied",
    "not_collected": "not collected for this interval", "unavailable": "unavailable; not checked",
    "denied": "access denied; not checked", "access-denied": "access denied; not checked",
    "failed": "the read failed", "denied-or-failed": "the read was denied or failed",
    "throttled": "the service limited the read", "serialization-failed": "results could not be saved",
    "at-limit": "the result limit was reached; further results may be missing",
    "retention": "outside the available retention window", "budget-limited": "the read budget was reached",
    "boundary-overlap": "the boundary could not be represented without overlap",
    "excluded": "source material was excluded from this package",
    "gap": "a coverage gap was recorded",
}


def _plain(value, limit=1200):
    return " ".join(display_text(value, limit).split())


def _when(value):
    value = _plain(value).replace("T", " ", 1)
    for suffix in ("Z", "+00:00"):
        if value.endswith(suffix):
            value = value[:-len(suffix)]
            break
    return re.sub(r"\.0+$", "", value)


def _decoded(fields, name):
    if name not in fields:
        return MISSING
    value = fields[name]
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            pass
    return value


def _flag(fields, name):
    value = _decoded(fields, name)
    return value if type(value) is bool else None


def _yesno(value):
    return "yes" if value is True else "no" if value is False else "unknown (not supplied)"


def _recipient(value):
    if value is MISSING:
        return "unknown (not supplied)"
    if value is None:
        return "unresolved recipient (null value)"
    if isinstance(value, dict):
        if "Address" in value:
            return _plain(value["Address"], 220) + " (routing: " + _plain(value.get("RoutingType", "unknown"), 80) + ")"
        if "ObjectGuid" in value:
            return "directory recipient whose address is unresolved (identifier in evidence)"
        return "unresolved recipient (see evidence)"
    return _plain(value, 240) or "empty recipient value"


def _recipients(value, *, empty):
    if value is MISSING:
        return "unknown (not supplied)"
    if isinstance(value, list):
        if not value:
            return empty
        text = "; ".join(_recipient(item) for item in value[:8])
        if len(value) > 8:
            text += f"; {len(value) - 8} more values in the workbook and original evidence"
        return text
    return _recipient(value)


def _coverage_line(dataset, rows, coverage):
    entries = [entry for entry in coverage if entry.get("dataset") == dataset]
    states = list(dict.fromkeys(entry.get("status", "unknown") for entry in entries))
    # The unchanged snapshot validator retains its reason codes in this fixed
    # coverage sentence. Read only those known codes, never infer from row count.
    reasons = set()
    for entry in entries:
        if entry.get("source") == "exchange_current_state":
            match = re.search(r"(?:^|\s)Gaps: ([a-z, -]+)\.", entry.get("detail", ""))
            if match:
                reasons.update(value.strip() for value in match.group(1).split(","))
    label = CURRENT_LABELS[dataset]
    reason_text = {"throttled": "the service limited this read", "unbound-result": "some returned entries could not be tied to this mailbox and were omitted",
        "invalid-result": "some returned entries could not be admitted", "field-unavailable": "one or more selected properties were unavailable",
        "hidden-unavailable": "hidden-rule query coverage was unavailable", "result-limit": "the source result limit was reached",
        "serialization-failed": "some results could not be saved"}
    details = [text for reason, text in reason_text.items() if reason in reasons]
    successful = {"collected", "returned", "observed"}
    failure = next((value for value in states if value in {"denied", "access-denied", "unavailable", "not_supplied", "not-supplied", "failed", "denied-or-failed"}), None)
    if rows:
        noun = "rule" if dataset == "inbox_rules" else "entry"
        plural = "rules" if dataset == "inbox_rules" else "entries"
        suffix = ""
        if "partial" in states:
            suffix = " — partial; " + ("; ".join(details) if details else "selected properties only")
        elif failure:
            suffix = " — other reads " + STATUS_TEXT[failure]
        elif not states or not set(states) <= successful:
            suffix = " — coverage is limited or unknown"
        return f"{label}: {len(rows)} {noun if len(rows) == 1 else plural} returned{suffix}."
    if failure:
        reasons = {"denied": "access denied", "access-denied": "access denied", "unavailable": "source unavailable",
                   "not_supplied": "no source supplied", "not-supplied": "no source supplied", "failed": "the read failed",
                   "denied-or-failed": "the read was denied or failed"}
        return f"{label}: not checked — {reasons[failure]}."
    if not entries:
        return f"{label}: not checked — no coverage information supplied."
    clean_zero = ("empty" in states or "empty" in reasons) and reasons <= {"empty"} and set(states) <= {"partial", "empty", "collected", "returned", "observed"}
    if clean_zero:
        return f"{label}: no entries returned in this observation; coverage remains partial. This does not establish that no entries exist."
    why = "; ".join(details) or "; ".join(STATUS_TEXT.get(value, "source status: " + _plain(value)) for value in states)
    return f"{label}: no entries could be included — {why}."


def _evidence_paragraphs(row, selected):
    identifiers = [row["evidence_id"], *row.get("supporting_evidence_ids", [])]
    result = []
    for index, identifier in enumerate(identifiers[:4]):
        selected.add(identifier)
        label = "Evidence" if index == 0 else "Supporting audit evidence"
        result.append(PdfParagraph(f"{label}: {identifier}", "note", (identifier,)))
    if len(identifiers) > 4:
        result.append(PdfParagraph(f"{len(identifiers) - 4} additional supporting evidence IDs are linked in the workbook and evidence.json.", "note"))
    return result


def _observed(row):
    return "Observed at " + _when(row.get("utc", "unknown time")) + " UTC."


def _record_block(paragraphs):
    """Keep a readable entry and its evidence together when they fit on a page."""
    return [replace(paragraph, keep_with_next=index < len(paragraphs) - 1)
            for index, paragraph in enumerate(paragraphs)]


def _short_name(value):
    value = _plain(value)
    return value if len(value) <= 120 else value[:120] + "… [full name below or in appendix]"


def _review_leads(current, selected):
    """Concrete source properties to review, without a risk or intent ranking."""
    leads = []
    rules = current["inbox_rules"]
    if rules:
        row = rules[0]
        fields = row["fields"]
        name = fields.get("Name", "Rule name not supplied") or "Rule has an explicitly empty name"
        state = "enabled" if _flag(fields, "Enabled") is True else "disabled" if _flag(fields, "Enabled") is False else "enabled state unknown"
        actions = []
        for key, label in (("ForwardTo", "its forwarding action lists"), ("RedirectTo", "its redirect action lists"), ("ForwardAsAttachmentTo", "its forward-as-attachment action lists")):
            values = _decoded(fields, key)
            if isinstance(values, list) and values:
                actions.append(label + " " + _recipient(values[0]) + (f" and {len(values) - 1} other recorded value(s)" if len(values) > 1 else ""))
        if _flag(fields, "DeleteMessage") is True:
            actions.append("its delete-message setting is on")
        if _flag(fields, "MarkAsRead") is True:
            actions.append("its mark-as-read setting is on")
        sender = _decoded(fields, "From")
        if isinstance(sender, list) and sender and all(isinstance(value, str) or isinstance(value, dict) and "Address" in value for value in sender):
            context = "For messages from " + _recipients(sender[:2], empty="") + (f" and {len(sender) - 2} more recorded senders" if len(sender) > 2 else "") + ", "
        else:
            context = "The sender condition is unknown. " if sender is MISSING else "The recorded sender list does not establish the full matching conditions. "
        detail = "; ".join(actions[:3]) if actions else "action details are listed below; omitted actions remain unknown"
        if not context.endswith(", "):
            detail = detail[:1].upper() + detail[1:]
        state_sentence = f"{_short_name(name)} is {state}." if state != "enabled state unknown" else f"{_short_name(name)} has an unknown enabled state."
        leads.extend(_record_block([PdfParagraph(f"{state_sentence} {context}{detail}. Other conditions and exceptions were not supplied."),
                                    *_evidence_paragraphs(row, selected)[:1]]))
    if current["forwarding"]:
        row = current["forwarding"][0]
        values = row.get("native_fields")
        if values is None:
            detail = "destination types are unknown; inspect the original properties"
        elif values.get("ForwardingAddress", MISSING) is None and values.get("ForwardingSmtpAddress", MISSING) is None:
            detail = "no destination was recorded in the observed mailbox properties"
        else:
            destination = values.get("ForwardingAddress")
            if destination is None:
                destination = values.get("ForwardingSmtpAddress", MISSING)
            detail = "recorded destination: " + _recipient(destination)
        leads.extend(_record_block([PdfParagraph("Mailbox-level forwarding: " + detail + "."),
                                    *_evidence_paragraphs(row, selected)[:1]]))
    for dataset in ("full_access", "send_as", "send_on_behalf"):
        if current[dataset]:
            row = current[dataset][0]
            details = _delegation(row)
            leads.extend(_record_block([PdfParagraph(CURRENT_LABELS[dataset] + ": " + details[0].text + ". " + details[1].text),
                                        *_evidence_paragraphs(row, selected)[:1]]))
            break
    return leads


def _rule(row):
    fields = row["fields"]
    name = fields.get("Name", "Rule name not supplied")
    if name == "":
        name = "Rule has an explicitly empty name"
    enabled = _flag(fields, "Enabled")
    state = "enabled" if enabled is True else "disabled" if enabled is False else "enabled state unknown"
    visible_name = _plain(name)
    if len(visible_name) > 180:
        visible_name = visible_name[:180] + "… [full name in appendix]"
    heading = PdfParagraph(f"{visible_name} — {state}", "subheading")
    # The current projection has no per-rule hidden flag. Do not infer one from
    # observation.hidden_included, a query option, source coverage or the name.
    hidden = _flag(fields, "IsHidden")
    hidden_text = "Hidden: " + _yesno(hidden) if hidden is not None else "Hidden status unknown (not supplied)"
    state_text = f"Priority: {_plain(fields.get('Priority', 'unknown (not supplied)'))}. {hidden_text}."
    sender = _recipients(_decoded(fields, "From"), empty="no sender values recorded; this does not establish an unconditional rule")
    actions = []
    for key, label in (("ForwardTo", "Forward to"), ("RedirectTo", "Redirect to"), ("ForwardAsAttachmentTo", "Forward as attachment to")):
        actions.append(label + ": " + _recipients(_decoded(fields, key), empty="no destination values recorded") + ".")
    flags = " ".join(label + ": " + _yesno(_flag(fields, key)) + "." for key, label in (
        ("DeleteMessage", "Delete message"), ("MarkAsRead", "Mark as read"), ("StopProcessingRules", "Stop later rules")))
    health = []
    for key, label in (("InError", "Source reports an error"), ("SupportedByTask", "Source reports this rule as supported")):
        if key in fields:
            health.append(label + ": " + _yesno(_flag(fields, key)) + ".")
    return [heading, PdfParagraph(state_text), PdfParagraph("From: " + sender + "."),
            PdfParagraph(" ".join(actions)), PdfParagraph(flags),
            *([PdfParagraph(" ".join(health), "note")] if health else []),
            PdfParagraph(_observed(row), "note")]


def _forwarding(row):
    fields = row["fields"]
    native = row.get("native_fields")
    values = native if native is not None else fields
    address = values.get("ForwardingAddress", MISSING)
    smtp = values.get("ForwardingSmtpAddress", MISSING)
    no_destination = address is None and smtp is None
    if native is None:
        summary = "Mailbox forwarding destination types are unknown in the display projection; consult the original evidence."
    elif no_destination:
        summary = "No mailbox forwarding destination was recorded in this observation."
    elif address is MISSING or smtp is MISSING:
        summary = "Mailbox forwarding cannot be fully assessed because a destination property was not supplied."
    else:
        summary = "The source recorded mailbox-level forwarding destination properties."
    result = [PdfParagraph(summary, "subheading")]
    if native is None:
        result.append(PdfParagraph("Projected text such as 'null' is not proof of an absent destination. Native strings and structured values may share the same display text.", "note"))
    for label, value in (("Directory forwarding destination", address), ("SMTP forwarding destination", smtp)):
        result.append(PdfParagraph(label + ": " + ("not set (explicit null)" if value is None else _recipient(value)) + "."))
    if address not in (None, MISSING) and smtp not in (None, MISSING):
        result.append(PdfParagraph("Review ForwardingAddress first when both destination properties are set. This snapshot does not establish their effective routing.", "note"))
    delivery = _flag(fields, "DeliverToMailboxAndForward")
    result.append(PdfParagraph("Keep a copy in the mailbox when forwarding is configured: " + _yesno(delivery) + "."))
    if no_destination:
        result.append(PdfParagraph("The delivery flag alone does not mean messages were forwarded or discarded. Rule-based forwarding and earlier settings require separate evidence.", "note"))
    result.append(PdfParagraph(_observed(row), "note"))
    return result


def _delegation(row):
    fields, dataset = row["fields"], row["dataset"]
    if dataset == "send_on_behalf":
        delegates = _decoded(fields, "GrantSendOnBehalfTo")
        return [PdfParagraph("Send on Behalf", "subheading"),
                PdfParagraph("Recorded delegates: " + _recipients(delegates, empty="no delegate values recorded") + "."),
                PdfParagraph("Deny and inheritance flags are not supplied for this property. " + _observed(row), "note")]
    trustee = fields.get("User" if dataset == "full_access" else "Trustee", "unknown (not supplied)")
    if dataset == "full_access":
        deny = _flag(fields, "Deny")
        decision = "deny entry" if deny is True else "allow entry (Deny=false)" if deny is False else "allow/deny unknown"
    else:
        control = fields.get("AccessControlType")
        decision = "deny entry" if control == "Deny" else "allow entry" if control == "Allow" else "allow/deny unknown"
    inherited = _flag(fields, "IsInherited")
    inheritance = "inherited" if inherited is True else "not inherited" if inherited is False else "inheritance unknown (not supplied)"
    rights = _decoded(fields, "AccessRights")
    rights_text = ", ".join(_plain(value, 100) for value in rights) if isinstance(rights, list) else "unknown (not supplied)"
    return [PdfParagraph(f"{_plain(trustee)} — {decision}", "subheading"),
            PdfParagraph(f"Recorded rights: {rights_text}. Entry is {inheritance}."),
            PdfParagraph(_observed(row), "note")]


def _event_text(row):
    fields, operation = row["fields"], _plain(row["operation"], 240)
    kind = fields.get("event_type", "")
    if row["dataset"] == "trace":
        return ("Message trace: " + _plain(fields.get("SenderAddress", "sender not supplied"), 200) + " to "
                + _plain(fields.get("RecipientAddress", "recipient not supplied"), 200) + ". Recorded status: "
                + _plain(fields.get("Status", "not supplied"), 100) + ". This does not establish who read the message.")
    if kind.startswith("password."):
        outcome = "The source confirms a completed password change" if fields.get("change_confirmed_by_source") == "true" else "Password attempt or progress record; a completed change is not established"
        return f"{outcome}. Operation: {operation}. Source result: {_plain(fields.get('native_result', 'not supplied'), 120)}."
    if kind == "safe_links.click":
        action = {"ClickAllowed": "click allowed", "ClickBlocked": "click blocked"}.get(fields.get("action_type"), "action unknown")
        return (f"Safe Links: {action}; source click-through flag: {_yesno(_flag(fields, 'is_clicked_through'))}. "
                "Neither field establishes page load, credential submission or intent.")
    if kind == "workload.signin.related_audit":
        return ("Application activity linked to the account's audit evidence. Source result: "
                + _plain(fields.get("source_outcome", "not supplied"), 120) + ". This is application authentication, not a user sign-in.")
    if kind == "user.signin":
        label = "Interactive user sign-in" if fields.get("sign_in_class") == "user-interactive" else "Noninteractive user sign-in"
        outcome = fields.get("source_outcome", "not supplied")
        if outcome == "uninterpreted-native-code":
            outcome = "native result code " + _plain(fields.get("native_result_type", "unknown"), 40) + " (not interpreted as success or failure)"
        return label + ". Source outcome: " + _plain(outcome, 180) + "."
    if kind == "mailbox.rule.event":
        return f"Historical inbox-rule operation: {operation}. Source result: {_plain(fields.get('native_result', 'not supplied'), 120)}. Current rule details and creation time are not established by this row."
    if kind in {"authentication_method.event", "device.registration.event"}:
        return f"Historical account identity operation: {operation}. Source result: {_plain(fields.get('native_result', 'not supplied'), 120)}. This is not a current inventory or proof of an effective change."
    return operation + ". Source result: " + _plain(fields.get("native_result", fields.get("source_outcome", "not supplied")), 120) + "."


def _history_coverage(coverage):
    groups = {}
    for entry in coverage:
        if entry.get("source") == "exchange_current_state":
            continue
        groups.setdefault(entry.get("source", "unknown source"), []).append(entry)
    result = []
    for source, entries in groups.items():
        states = list(dict.fromkeys(entry.get("status", "unknown") for entry in entries))
        result.append(PdfParagraph(SOURCE_LABELS.get(source, _plain(source)) + ": " + "; ".join(
            STATUS_TEXT.get(state, "source status: " + _plain(state)) for state in states) + "."))
        windows = {(entry.get("requested_start"), entry.get("requested_end"), entry.get("queryable_start"), entry.get("queryable_end"))
                   for entry in entries if entry.get("requested_start")}
        for requested_start, requested_end, available_start, available_end in sorted(windows):
            result.append(PdfParagraph(f"Requested trace interval (UTC): {_when(requested_start)} to {_when(requested_end)}. "
                f"Queryable interval at planning (UTC): {_when(available_start)} to {_when(available_end)}. Actual reads and any aged-off intervals are listed in the appendix.", "note"))
    return result or [PdfParagraph("Historical source coverage was not supplied; zero admitted events does not establish no activity.")]


def trace_row_summary(coverage, observations, evidence):
    """Count saved directional rows only when receipt counts and references agree.

    A read's identity is (receipt SHA, read ID), not a sender/recipient guess.
    A row may legitimately be present in both directions or multiple reads; these
    are preserved read rows, never a unique-message or whole-window traffic count.
    """
    trace_ids = {row["evidence_id"] for row in observations if row["kind"] == "event" and row["dataset"] == "trace"}
    rows_by_read = {}
    for entry in evidence:
        if entry["id"] not in trace_ids:
            continue
        for ref in entry.get("references", []):
            if ref.get("receipt_sha256") and ref.get("read_id"):
                rows_by_read.setdefault((ref["receipt_sha256"], ref["read_id"]), set()).add((ref["file"], ref["locator"]))
    trace_coverage = [entry for entry in coverage if entry.get("source") == "exchange_trace" and entry.get("dataset") == "trace"]
    directions, notes = [], []
    good_statuses = {"returned", "empty", "at-limit"}
    for direction in ("sent", "received"):
        reads = [entry for entry in trace_coverage if entry.get("direction") == direction and entry.get("id") and entry.get("receipt_sha256")]
        total, checked, problems, seen = 0, False, [], set()
        for entry in reads:
            key = (entry["receipt_sha256"], entry["id"])
            if key in seen:
                continue
            seen.add(key)
            status, count = entry.get("status"), entry.get("records")
            if status in good_statuses and type(count) is int and count >= 0:
                actual = len(rows_by_read.get(key, set()))
                if actual == count:
                    total += count
                    checked = True
                else:
                    problems.append("the saved-row count could not be reconciled with its evidence references")
                if status == "at-limit":
                    problems.append("a result limit was reached; more rows may be missing")
            else:
                problems.append(STATUS_TEXT.get(status, "read status is unknown"))
        if checked:
            directions.append(f"{total} {direction} {'row' if total == 1 else 'rows'}")
        elif reads:
            directions.append(f"{direction} count unavailable")
        else:
            directions.append(f"{direction} direction not checked" if not trace_ids else f"{direction} count unavailable (no verified directional read)")
        if problems:
            notes.append(direction.capitalize() + ": " + "; ".join(dict.fromkeys(problems)) + ".")
    if all(value.endswith("direction not checked") for value in directions):
        result = "Message traces: not checked — no verified directional reads were supplied."
    elif all("no verified directional read" in value for value in directions):
        result = "Message traces: direction counts unavailable — the rows have no verified directional read metadata."
    else:
        result = "Message traces: " + " and ".join(directions) + ". Counts are saved trace rows, not unique messages or complete traffic totals."
    if any(not entry.get("id") and entry.get("status") not in {"returned", "empty", "not_supplied"} for entry in trace_coverage):
        notes.append("Some requested trace ranges are not covered; see the detailed coverage appendix.")
    return result + (" " + " ".join(notes) if notes else "")


def native_snapshot_rows(sources, evidence, originals):
    """Read native types from the already admitted snapshot bytes, for display only.

    The caller has verified exact bytes, scope and each evidence locator. This
    helper neither admits data nor changes saved indexes. In particular, it
    prevents string 'null' from becoming JSON null in a human interpretation.
    """
    snapshot_sources = {entry["id"] for entry in sources if entry["source"] == "exchange_current_state"}
    parsed, rows = {}, {}
    for entry in evidence:
        if entry["source_id"] not in snapshot_sources:
            continue
        filename = entry["file"]
        if filename not in parsed:
            parsed[filename] = json.loads(originals[filename].decode("utf-8-sig"))
        pointer = entry["locator"]
        if not re.fullmatch(r"/observations/(inbox_rules|forwarding|full_access|send_as|send_on_behalf)/records/(0|[1-9][0-9]*)", pointer):
            raise CaseError("Snapshot report locator does not select a validated observation.")
        _, _, dataset, _, index = pointer.split("/")
        native = parsed[filename]["observations"][dataset]["records"][int(index)]
        if not isinstance(native, dict):
            raise CaseError("Snapshot report locator does not select an object.")
        rows[entry["id"]] = native
    return rows


def build_mailbox_report(scope, observations, coverage, findings, evidence, limits, *, coverage_details=(), native_rows=None):
    """Return sections and an evidence index without changing any package data.

    All arguments come from package_case after source-specific validation. Each
    current dataset gets its own display budget; historical details are ordered
    by time. No missing property is converted to false, empty or an inferred name.
    """
    native_rows = native_rows or {}
    current = {dataset: [dict(row, native_fields=native_rows.get(row["evidence_id"])) for row in observations
                        if row["kind"] == "snapshot" and row["dataset"] == dataset]
               for dataset in CURRENT_LABELS}
    events = sorted((row for row in observations if row["kind"] == "event"), key=lambda row: (row["utc"], row["id"]))
    selected = set()
    snapshots = [row for rows in current.values() for row in rows]
    observed_times = sorted({row["utc"] for row in snapshots})
    overview = [PdfParagraph("Mailbox: " + _plain(scope["account"]), "subheading"),
        PdfParagraph(f"Requested history (UTC): {_when(scope['start'])} to {_when(scope['end'])} (end excluded)."),
        PdfParagraph("Current settings describe the observation time, not necessarily the incident window. "
                     + ("Observed (UTC): " + ", ".join(_when(value) for value in observed_times[:3]) + ("; further times in the workbook." if len(observed_times) > 3 else ".")
                        if observed_times else "No current mailbox observations were admitted."), "note")]
    leads = _review_leads(current, selected)
    if leads:
        overview.append(PdfParagraph("Recorded settings to review", "subheading"))
        overview.extend(leads)
    overview.append(PdfParagraph("What was available", "subheading"))
    for dataset in CURRENT_LABELS:
        overview.append(PdfParagraph(_coverage_line(dataset, current[dataset], coverage)))
        if dataset == "inbox_rules" and current[dataset]:
            flags = Counter(_flag(row["fields"], "Enabled") for row in current[dataset])
            deletion = sum(_flag(row["fields"], "DeleteMessage") is True for row in current[dataset])
            deletion_unknown = sum(_flag(row["fields"], "DeleteMessage") is None for row in current[dataset])
            states = ", ".join(f"{flags[value]} {label}" for value, label in ((True, "enabled"), (False, "disabled"), (None, "state unknown")) if flags[value])
            detail = f"Rule state: {states}."
            if deletion:
                detail += f" The delete-message setting is on for {deletion} {'rule' if deletion == 1 else 'rules'}."
            if deletion_unknown:
                detail += f" The delete-message setting is unknown for {deletion_unknown} {'rule' if deletion_unknown == 1 else 'rules'}."
            overview.append(PdfParagraph(detail, "note"))
    other_events = sum(row["dataset"] != "trace" for row in events)
    overview.append(PdfParagraph(trace_row_summary(coverage, observations, evidence)))
    if other_events:
        overview.append(PdfParagraph(f"Other dated sources: {other_events} {'event' if other_events == 1 else 'events'} included; see historical activity below."))
    overview.extend([
        PdfParagraph("These observations identify settings and activity to review. They do not establish malicious intent, compromise or who controlled the account.", "note")])
    sections = [PdfSection("Mailbox at a glance", tuple(overview))]

    rules = [PdfParagraph("Full conditions and exceptions, MoveToFolder and CopyToFolder are not included. An empty From list does not mean the rule applies unconditionally. Hidden-rule query coverage does not identify an individual rule as hidden.", "note")]
    if not current["inbox_rules"]:
        rules.append(PdfParagraph("No rule details are available to review. The availability summary above distinguishes an empty read from an incomplete or unchecked source."))
    for row in current["inbox_rules"][:CURRENT_LIMIT]:
        rules.extend(_record_block(_rule(row) + _evidence_paragraphs(row, selected)))
    sections.append(PdfSection("Current inbox rules", tuple(rules)))

    forwarding = [PdfParagraph("Mailbox-level forwarding is separate from forwarding performed by inbox rules. Address-like values are recorded source values; directory identifiers have not been resolved into addresses.", "note")]
    if not current["forwarding"]:
        forwarding.append(PdfParagraph("No forwarding properties are available to review. This does not establish that mailbox forwarding is absent."))
    for row in current["forwarding"][:CURRENT_LIMIT]:
        forwarding.extend(_record_block(_forwarding(row) + _evidence_paragraphs(row, selected)))
    sections.append(PdfSection("Mailbox-level forwarding", tuple(forwarding)))

    delegation = [PdfParagraph("Permission entries describe selected current settings. An allow entry is not proof of effective access or past use. A deny entry is not a grant.", "note")]
    for dataset in ("full_access", "send_as", "send_on_behalf"):
        if current[dataset] and dataset != "send_on_behalf":
            delegation.append(PdfParagraph(CURRENT_LABELS[dataset], "subheading"))
        for row in current[dataset][:CURRENT_LIMIT]:
            delegation.extend(_record_block(_delegation(row) + _evidence_paragraphs(row, selected)))
    if not any(current[dataset] for dataset in ("full_access", "send_as", "send_on_behalf")):
        delegation.append(PdfParagraph("No delegation entries are available to review. The availability summary above records which sources were empty, incomplete or not checked."))
    sections.append(PdfSection("Delegation", tuple(delegation)))

    history = [PdfParagraph("These records describe dated activity. Current rule, forwarding and permission observations above do not establish when those settings changed.")]
    history.extend(_history_coverage(coverage))
    counts = Counter(row["dataset"] for row in events)
    if counts:
        history.append(PdfParagraph("Counts are source observations, not unique messages or proven incidents. Every displayed event retains its evidence ID.", "note"))
    sections.append(PdfSection("Historical activity and coverage", tuple(history)))
    if events:
        details = [PdfParagraph(f"Showing {min(HISTORY_LIMIT, len(events))} of {len(events)} events in chronological order. The Timeline worksheet and observations.json contain every admitted event.", "note")]
        for row in events[:HISTORY_LIMIT]:
            details.extend(_record_block([PdfParagraph(_when(row["utc"]) + " UTC", "subheading"),
                PdfParagraph(_event_text(row)), *_evidence_paragraphs(row, selected)]))
        sections.append(PdfSection("Historical activity — selected records", tuple(details)))

    displayed_current = sum(min(len(rows), CURRENT_LIMIT) for rows in current.values())
    appendix = [PdfParagraph("The workbook and JSON indexes retain all admitted observations, complete projected properties, native identifiers and source references. This PDF is a bounded reading copy."),
        PdfParagraph("Characters unavailable in the PDF font appear as [U+XXXX] Unicode code points. For example, [U+4E2D] represents that source character, not a question mark. The workbook and originals retain the original Unicode text.", "note"),
        PdfParagraph(f"Current settings shown: {displayed_current} of {len(snapshots)} observations, up to {CURRENT_LIMIT} per category. Historical events shown: {min(HISTORY_LIMIT, len(events))} of {len(events)}. "
                     "Up to eight recipients per property and four evidence IDs per observation are printed; additional values and supporting references remain in the workbook and JSON.", "note"),
        PdfParagraph(f"Case: {scope['case_id']}. Tenant label: {scope['tenant']}. Directory ID: {scope.get('directory_id') or 'not supplied'}.", "note"),
        PdfParagraph(f"{len(findings)} linked finding group(s); {len(evidence)} evidence record(s). A finding is a review lead, not a determination of intent.", "note")]
    appendix.extend(PdfParagraph(text, "note") for text in limits)
    sections.append(PdfSection("Appendix — scope and reading limits", tuple(appendix), page_break=True))
    long_names = []
    for row in current["inbox_rules"][:CURRENT_LIMIT]:
        name = _plain(row["fields"].get("Name", ""))
        if len(name) > 180:
            long_names.extend(_record_block([PdfParagraph("Full recorded rule name", "subheading"),
                PdfParagraph(name, "note"), *_evidence_paragraphs(row, selected)]))
    if long_names:
        sections.append(PdfSection("Appendix — full rule names", tuple(long_names)))
    sections.append(PdfSection("Appendix — detailed source coverage", tuple(PdfParagraph(text, "note") for text in coverage_details)
                               or (PdfParagraph("No additional technical coverage detail was supplied.", "note"),)))
    references = [(entry["id"], f"{entry['file']} | SHA-256 {entry['sha256']} | {entry['locator']} | native ID {_plain(entry.get('native_id', ''), 256)} | "
                   f"{len(entry.get('references', []))} source reference(s); complete aliases and supporting links are in the workbook and evidence.json")
                  for entry in evidence if entry["id"] in selected]
    return sections, references
