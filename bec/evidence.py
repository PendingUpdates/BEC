"""Stable source-reference views, independent of event identity or interpretation."""
import json
from copy import deepcopy


def evidence_references(event, *, include_primary=True):
    """Return independent, exact-distinct pointers in canonical JSON order.

    Every pointer field participates in deduplication and ordering: dictionary
    keys are sorted, while values and nested array order remain significant.
    The primary pointer is preserved on the event, but need not sort first here.
    Replay excludes that exact pointer with ``include_primary=False`` when
    rebuilding only ``additional_evidence``. No source dictionary is modified.
    References grouped under an event ID do not establish that their contents
    agree; native-identity conflicts remain outside this accessor's scope.
    """
    key = lambda ref: json.dumps(ref, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    primary = key(event["evidence"])
    references = {primary: event["evidence"]}
    for reference in event.get("additional_evidence", []):
        references.setdefault(key(reference), reference)
    if not include_primary:
        references.pop(primary)
    return [deepcopy(references[value]) for value in sorted(references)]
