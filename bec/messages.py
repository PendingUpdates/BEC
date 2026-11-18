"""Exact message links between Defender hunting, Exchange trace and mailbox evidence."""
from collections import defaultdict

from .evidence import evidence_references
from .storage import digest, encode


def internet_id(raw):
    """Transport brackets and domain case may differ across providers."""
    value = str(raw or "").strip()
    if value.startswith("<") and value.endswith(">"):
        value = value[1:-1]
    local, sep, domain = value.rpartition("@")
    if not sep or not local or not domain or any(c.isspace() or c in "<>" for c in value):
        return None
    return local + "@" + domain.lower()


def related_to_email(record, recipient):
    """Addressless URL metadata belongs to the network message as a whole."""
    dataset = record["dataset"]
    fields = record.get("defender", {})
    if dataset == "EmailUrlInfo":
        return True
    if dataset == "UrlClickEvents":
        return (str(fields.get("Workload", "")).casefold() == "email"
                and (record["actor"]["user"] or "") == recipient)
    if dataset == "AlertEvidence":
        account = str(fields.get("AccountUpn") or "").casefold()
        return not account or account == recipient
    if dataset in ("EmailAttachmentInfo", "EmailPostDeliveryEvents"):
        return recipient in record["entities"]["mailbox"]
    return False


def include_message_artifacts(selected, index):
    # A message's URL metadata can have neither a user nor an IP address.
    # Add only compatible children. This is local replay of already acquired records.
    for email in list(selected.values()):
        if email["dataset"] != "EmailEvents":
            continue
        for nid in email["entities"]["network_message"]:
            recipient = str(email["target"]["resource"] or "").casefold()
            for row in index.get(("network_message", nid), []):
                if related_to_email(row, recipient):
                    selected[row["event_id"]] = row


def correlate_messages(events):
    by_native, by_mailbox = defaultdict(list), defaultdict(set)
    dossiers, findings = {}, []
    for event in events:
        if event["dataset"] != "EmailEvents":
            continue
        ent = event["entities"]
        for nid in ent["network_message"]:
            for recipient in ent["mailbox"]:
                key = (event["tenant_id"], nid, recipient)
                if key not in dossiers:
                    dossiers[key] = {}
                    by_native[key[:2]].append(key)
                dossiers[key][event["event_id"]] = event
                for raw in ent["message"]:
                    iid = internet_id(raw)
                    if iid:
                        by_mailbox[key[0], recipient, iid, "recipient"].add(key)
                        by_mailbox[key[0], event["actor"]["user"], iid, "sender"].add(key)
    for event in events:
        tenant, source, entities = event["tenant_id"], event["dataset"], event["entities"]
        if source == "EmailEvents":
            continue
        if source in ("ual", "trace"):
            if source == "ual" and not event["event_type"].startswith("mail."):
                continue
            mailboxes = entities["mailbox"] if source == "ual" else [str(event["target"]["resource"] or "").casefold()]
            role = "sender" if event["event_type"] == "mail.send" else "recipient"
            for addr in mailboxes:
                for raw in entities["message"]:
                    keys = by_mailbox.get((tenant, addr, internet_id(raw), role), set())
                    if len({k[1] for k in keys}) > 1:
                        event.setdefault("link_notes", []).append(f"Ambiguous InternetMessageId for {addr}: {raw}")
                        continue
                    for key in keys:
                        dossiers[key][event["event_id"]] = event
        else:
            for nid in entities.get("network_message", []):
                for key in by_native.get((tenant, nid), []):
                    if related_to_email(event, key[2]):
                        dossiers[key][event["event_id"]] = event

    messages = []
    for (tenant, nid, recipient), group in sorted(dossiers.items()):
        ordered = sorted(group.values(), key=lambda e: (e["timestamp_utc"], e["event_id"]))
        mid = "MSG-" + digest(encode([tenant, nid, recipient]))[:16]
        internet_ids, subjects, urls, attachments, observations = set(), set(), [], [], []
        mailbox_ids = []
        for event in ordered:
            event.setdefault("message_links", []).append(mid)
            source, fields = event["dataset"], event.get("defender", {})
            if source == "EmailEvents":
                internet_ids.update(event["entities"]["message"])
                if fields.get("Subject"):
                    subjects.add(fields["Subject"])
            elif source == "ual":
                mailbox_ids.append(event["event_id"])
            obs = dict(event_id=event["event_id"], source=source, utc=event["timestamp_utc"],
                       operation=event["operation"], result=event["result"], evidence=event["evidence"],
                       evidence_references=evidence_references(event))
            if source == "ual":
                obs["mailbox"] = event["entities"]["mailbox"]
                obs["actor"] = event["actor"]["user"]
            observations.append(obs)
            if source == "EmailUrlInfo":
                urls.append({k: fields[k] for k in ("Url", "UrlLocation", "UrlDomain") if k in fields}
                            | {"event_id": obs["event_id"]})
            if source == "EmailAttachmentInfo":
                attachments.append({k: fields[k] for k in ("FileName", "SHA256", "SHA1", "FileSize", "ThreatTypes") if k in fields}
                                   | {"event_id": obs["event_id"]})
        msg = dict(id=mid, tenant=tenant, network_message_id=nid, internet_message_ids=sorted(internet_ids),
                   recipient=recipient, subjects=sorted(subjects), urls=urls, attachments=attachments,
                   mailbox_event_ids=mailbox_ids, observations=observations)
        messages.append(msg)
        if mailbox_ids:
            fid = "F-" + digest(encode(["mailbox-message", mid]))[:16]
            findings.append(dict(id=fid, tenant=tenant, rule="mailbox-message", message_link=mid,
                observation="Defender email matched Exchange mailbox activity",
                join={"network_message_id": nid, "recipient": recipient, "internet_message_id": sorted(internet_ids),
                      "mailboxes": sorted({addr for o in observations for addr in o.get("mailbox", [])})},
                assessment="Contextual", confidence="High", event_ids=[o["event_id"] for o in observations],
                evidence=[o["evidence"] for o in observations],
                event_evidence=[dict(event_id=e["event_id"], references=evidence_references(e)) for e in ordered]))
            for event in ordered:
                event["finding_ids"].append(fid)
                if event["assessment"] == "Unknown":
                    event["assessment"] = "Contextual"
    return messages, findings
