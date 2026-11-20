"""UTC intervals for retained Exchange message traces."""
import calendar
from datetime import timedelta

from .storage import CaseError, iso, timestamp

RETENTION = timedelta(days=90)
MAX_CHUNK = timedelta(days=10)
PRESETS = ("24 hours", "1 week", "1 month", "90 days", "1 year")


def _utc(value):
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        raise CaseError("Supply UTC date and time bounds ending in Z or +00:00.")
    return timestamp(value)


def preset_start(end, choice):
    if choice in ("1 month", "1 year"):
        year, month = end.year, end.month
        if choice == "1 year":
            year -= 1
        elif month == 1:
            year, month = year - 1, 12
        else:
            month -= 1
        day = min(end.day, calendar.monthrange(year, month)[1])
        return end.replace(year=year, month=month, day=day)
    days = {"24 hours": 1, "1 week": 7, "90 days": 90}
    return end - timedelta(days=days[choice])


def requested_window(start, end):
    low, high = _utc(start), _utc(end)
    if not preset_start(high, "1 year") <= low < high:
        raise CaseError("Use a positive UTC window of at most one calendar year.")
    return iso(low), iso(high)


def chunk_plan(start, end, planned_at):
    start, end = requested_window(start, end)
    ref = _utc(planned_at)
    low, high = max(_utc(start), ref - RETENTION), _utc(end)
    if high > ref:
        raise CaseError("The requested window must have ended by the planning time.")
    chunks = []
    while low < high:
        stop = min(low + MAX_CHUNK, high)
        chunks.append(dict(id=f"{len(chunks) + 1:02d}", start=iso(low), end=iso(stop)))
        low = stop
    return chunks


def read_start(chunk_start, chunk_end, checked_at):
    """Recheck the moving 90-day limit immediately before a request; allow time for transport."""
    safe_start = _utc(checked_at).replace(second=0, microsecond=0) + timedelta(minutes=1) - RETENTION
    return iso(min(_utc(chunk_end), max(_utc(chunk_start), safe_start)))
