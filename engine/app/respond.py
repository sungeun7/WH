from __future__ import annotations

import json
import subprocess
from typing import Any

from .db import add_audit, db, row_to_dict
from .surface import add_block, add_pending_action, is_blocked


SECRET_KEYS = {"password", "token", "authorization", "secret", "api_key", "cookie", "set-cookie"}


def mask_fields(fields: dict[str, Any] | None) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in (fields or {}).items():
        lk = str(key).lower()
        if lk in SECRET_KEYS or any(s in lk for s in ("password", "secret", "token")):
            clean[key] = "***"
        else:
            clean[key] = value
    return clean


def inspect_blocks(client_ip: str | None, path: str | None) -> dict[str, Any] | None:
    if client_ip:
        hit = is_blocked("ip", client_ip)
        if hit:
            return hit
    if path:
        hit = is_blocked("path", path)
        if hit:
            return hit
        # prefix blocks
        from .surface import list_active_blocks

        for block in list_active_blocks():
            if block["kind"] == "path" and path.startswith(str(block["value"])):
                return block
    return None


def apply_actions(
    actions: list[str],
    event: dict[str, Any],
    rule: dict[str, Any],
    auto: bool,
) -> dict[str, Any]:
    fields = event.get("fields") or {}
    result: dict[str, Any] = {
        "allow": True,
        "status": 200,
        "reason": None,
        "blocks": [],
        "pending": [],
    }
    http = event.get("source") == "http"
    for action in actions:
        if action == "deny_request" and http and auto:
            result["allow"] = False
            result["status"] = 403
            result["reason"] = rule.get("id")
        elif action == "deny_ip" and http and auto:
            ip = fields.get("client_ip")
            if ip:
                result["blocks"].append(add_block("ip", str(ip), rule.get("id") or "deny_ip"))
            result["allow"] = False
            result["status"] = 429 if rule.get("id") == "http_rate_limit" or "rate" in str(rule.get("id")) else 403
            result["reason"] = rule.get("id")
        elif action == "deny_ip" and not auto:
            ip = fields.get("client_ip") or fields.get("dest_ip")
            if ip:
                result["pending"].append(
                    add_pending_action("deny_ip", None, {"value": ip, "reason": rule.get("id")})
                )
        elif action in {"kill_process", "firewall_block"}:
            result["pending"].append(
                add_pending_action(action, None, {"fields": fields, "reason": rule.get("id")})
            )
    if not auto and event.get("source") == "windows":
        if "kill_process" in actions or event.get("type") == "process_start":
            pid = fields.get("pid")
            if pid and any(a in {"kill_process"} for a in actions):
                result["pending"].append(
                    add_pending_action("kill_process", None, {"pid": pid, "name": fields.get("process_name")})
                )
    return result


def execute_pending(action_id: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM pending_actions WHERE id = ?", (action_id,)
        ).fetchone()
    item = row_to_dict(row)
    if not item:
        return {"ok": False, "error": "not_found"}
    if item["status"] != "pending":
        return {"ok": False, "error": "not_pending", "item": item}
    payload = json.loads(item["payload"])
    kind = item["kind"]
    output = ""
    try:
        if kind == "kill_process":
            pid = int(payload.get("pid"))
            completed = subprocess.run(
                ["taskkill", "/PID", str(pid), "/F"],
                capture_output=True,
                text=True,
                check=False,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            ok = completed.returncode == 0
        elif kind == "firewall_block":
            dest = payload.get("dest_ip")
            port = payload.get("dest_port") or payload.get("listen_port")
            name = f"WH-block-{action_id[:8]}"
            if dest:
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={name}",
                    "dir=out",
                    "action=block",
                    f"remoteip={dest}",
                ]
            elif port:
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name={name}",
                    "dir=in",
                    "action=block",
                    "protocol=TCP",
                    f"localport={port}",
                ]
            else:
                return {"ok": False, "error": "missing_target"}
            completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
            output = (completed.stdout or "") + (completed.stderr or "")
            ok = completed.returncode == 0
        elif kind == "deny_ip":
            add_block("ip", str(payload.get("value")), str(payload.get("reason") or "manual"))
            ok = True
            output = "ip blocked in engine"
        else:
            return {"ok": False, "error": "unsupported"}
    except Exception as exc:
        ok = False
        output = str(exc)

    status = "executed" if ok else "failed"
    with db() as conn:
        conn.execute(
            "UPDATE pending_actions SET status = ? WHERE id = ?",
            (status, action_id),
        )
    add_audit("action", f"조치 {status}: {kind}", {"id": action_id, "output": output[:500]})
    return {"ok": ok, "status": status, "output": output[:500], "id": action_id}


def cancel_pending(action_id: str) -> bool:
    with db() as conn:
        cur = conn.execute(
            "UPDATE pending_actions SET status = 'cancelled' WHERE id = ? AND status = 'pending'",
            (action_id,),
        )
        return cur.rowcount > 0


def cancel_pending_for_alert(alert_id: str) -> int:
    with db() as conn:
        cur = conn.execute(
            """
            UPDATE pending_actions
            SET status = 'cancelled'
            WHERE alert_id = ? AND status = 'pending'
              AND kind IN ('kill_process', 'firewall_block')
            """,
            (alert_id,),
        )
        return cur.rowcount


def cancel_disruptive_pending() -> int:
    with db() as conn:
        cur = conn.execute(
            """
            UPDATE pending_actions
            SET status = 'cancelled'
            WHERE status = 'pending'
              AND kind IN ('kill_process', 'firewall_block')
            """
        )
        return cur.rowcount
