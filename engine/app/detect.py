from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .db import db, now

_windows: dict[str, deque] = defaultdict(deque)
_seen_dests: set[str] = set()
_baselined = False


def reset_runtime() -> None:
    _windows.clear()
    _seen_dests.clear()


def note_dest(dest: str) -> None:
    _seen_dests.add(dest)


def load_known_dests(dests: set[str]) -> None:
    _seen_dests.update(dests)


def _trim(q: deque, ts: float, window: float) -> None:
    while q and ts - q[0] > window:
        q.popleft()


def hit_count(key: str, ts: float, window: float, add: bool = True) -> int:
    q = _windows[key]
    if add:
        q.append(ts)
    _trim(q, ts, window)
    return len(q)


def group_value(event: dict[str, Any], group_by: str) -> str:
    fields = event.get("fields") or {}
    if group_by in fields:
        return str(fields.get(group_by) or "unknown")
    return str(event.get(group_by) or "unknown")


def match_rule(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    if rule.get("source") and event.get("source") != rule.get("source"):
        return False
    if rule.get("event_type") and event.get("type") != rule.get("event_type"):
        return False

    match = rule.get("match") or {}
    fields = event.get("fields") or {}
    path = str(fields.get("path") or "")
    file_or_proc = str(
        fields.get("file_path") or fields.get("process_path") or path
    )
    ts = float(event.get("ts") or now())

    prefixes = match.get("path_prefixes") or []
    if prefixes and not any(path.startswith(p) for p in prefixes):
        return False

    if match.get("missing_auth") and fields.get("has_auth"):
        return False

    contains = match.get("path_contains") or []
    if contains and not any(c.lower() in file_or_proc.lower() for c in contains):
        return False

    if match.get("first_seen_dest"):
        dest_ip = fields.get("dest_ip")
        dest_port = fields.get("dest_port")
        dest = f"{dest_ip}:{dest_port}"
        if match.get("ignore_private"):
            from .surface import _private_ip

            if _private_ip(str(dest_ip) if dest_ip is not None else None):
                return False
        if dest in _seen_dests:
            return False
        _seen_dests.add(dest)

    group_by = match.get("group_by")
    threshold = match.get("threshold")
    if group_by and threshold:
        key = f"{rule.get('id')}:{group_value(event, group_by)}"
        count = hit_count(key, ts, float(match.get("window_seconds") or 10))
        if count < int(threshold):
            return False

    return True


def evaluate(rules: list[dict[str, Any]], event: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for rule in rules:
        try:
            if match_rule(rule, event):
                hits.append(rule)
        except Exception:
            continue
    return hits


def recent_event_count(source: str | None, etype: str | None, seconds: float) -> int:
    ts = now() - seconds
    sql = "SELECT COUNT(*) AS c FROM events WHERE ts >= ?"
    args: list[Any] = [ts]
    if source:
        sql += " AND source = ?"
        args.append(source)
    if etype:
        sql += " AND type = ?"
        args.append(etype)
    with db() as conn:
        row = conn.execute(sql, args).fetchone()
    return int(row["c"] if row else 0)
