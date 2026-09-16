from __future__ import annotations

import ipaddress
import json
from typing import Any

from .config import BLOCK_SECONDS
from .db import add_audit, db, new_id, now, row_to_dict


def _private_ip(value: str | None) -> bool:
    if not value:
        return True
    try:
        ip = ipaddress.ip_address(value.split("%")[0])
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)
    except ValueError:
        return True


class SurfaceTracker:
    def upsert(
        self,
        kind: str,
        key: str,
        title: str,
        detail: str,
        risk: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ts = now()
        with db() as conn:
            row = conn.execute("SELECT * FROM surface WHERE key = ?", (key,)).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE surface
                    SET title=?, detail=?, risk=?, last_seen=?, extra=?
                    WHERE key=?
                    """,
                    (
                        title,
                        detail,
                        risk,
                        ts,
                        json.dumps(extra or {}, ensure_ascii=False),
                        key,
                    ),
                )
                item = row_to_dict(
                    conn.execute("SELECT * FROM surface WHERE key = ?", (key,)).fetchone()
                )
            else:
                sid = new_id()
                conn.execute(
                    """
                    INSERT INTO surface(id, kind, key, title, detail, risk, status, first_seen, last_seen, extra)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        sid,
                        kind,
                        key,
                        title,
                        detail,
                        risk,
                        "open",
                        ts,
                        ts,
                        json.dumps(extra or {}, ensure_ascii=False),
                    ),
                )
                item = row_to_dict(
                    conn.execute("SELECT * FROM surface WHERE id = ?", (sid,)).fetchone()
                )
                add_audit("surface", f"공격면 추가: {title}", {"id": sid, "kind": kind})
        return decode_surface(item)

    def observe_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        fields = event.get("fields") or {}
        updates: list[dict[str, Any]] = []
        etype = event.get("type")
        if etype == "request":
            path = fields.get("path") or "/"
            has_auth = bool(fields.get("has_auth"))
            if not has_auth:
                risk = "high" if _sensitive_path(path) else "medium"
                updates.append(
                    self.upsert(
                        "http_path",
                        f"path:{path}",
                        f"미인증 경로 {path}",
                        "인증 헤더 없이 관측된 공개 경로",
                        risk,
                        {"path": path, "client_ip": fields.get("client_ip")},
                    )
                )
        elif etype == "port_open":
            port = fields.get("listen_port")
            addr = fields.get("listen_addr") or "0.0.0.0"
            proc = fields.get("process_name") or "unknown"
            risky_ports = {21, 22, 23, 135, 139, 445, 3389, 5900, 5985, 5986}
            local = addr in {"127.0.0.1", "::1"}
            if port in risky_ports:
                risk = "high"
            elif local or port in {8000, 8080, 5173, 3000}:
                risk = "low"
            elif addr in {"0.0.0.0", "::"} and isinstance(port, int) and port < 1024:
                risk = "medium"
            else:
                risk = "low"
            updates.append(
                self.upsert(
                    "listen_port",
                    f"listen:{addr}:{port}",
                    f"리스닝 {addr}:{port}",
                    f"프로세스 {proc}",
                    risk,
                    {"addr": addr, "port": port, "process": proc},
                )
            )
        elif etype == "net_connect":
            dest_ip = fields.get("dest_ip")
            dest_port = fields.get("dest_port")
            if dest_ip and not _private_ip(str(dest_ip)):
                proc = fields.get("process_name") or "unknown"
                updates.append(
                    self.upsert(
                        "outbound",
                        f"out:{dest_ip}:{dest_port}",
                        f"외부 연결 {dest_ip}:{dest_port}",
                        f"프로세스 {proc}",
                        "medium",
                        {
                            "dest_ip": dest_ip,
                            "dest_port": dest_port,
                            "process": proc,
                            "pid": fields.get("pid"),
                        },
                    )
                )
        elif etype == "file_change":
            path = fields.get("file_path") or ""
            if _sensitive_file(path):
                updates.append(
                    self.upsert(
                        "file",
                        f"file:{path}",
                        "민감 파일 변경",
                        path,
                        "high",
                        {"path": path},
                    )
                )
        elif etype == "process_start":
            ppath = fields.get("process_path") or ""
            if _temp_path(ppath):
                updates.append(
                    self.upsert(
                        "process",
                        f"proc:{fields.get('pid')}:{fields.get('process_name')}",
                        f"임시 경로 프로세스 {fields.get('process_name')}",
                        ppath,
                        "medium",
                        {
                            "pid": fields.get("pid"),
                            "name": fields.get("process_name"),
                            "path": ppath,
                        },
                    )
                )
        return updates

    def list_items(self, status: str | None = None) -> list[dict[str, Any]]:
        with db() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM surface WHERE status = ? ORDER BY last_seen DESC",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM surface ORDER BY CASE risk WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, last_seen DESC"
                ).fetchall()
        return [decode_surface(row_to_dict(r)) for r in rows]

    def get(self, sid: str) -> dict[str, Any] | None:
        with db() as conn:
            row = conn.execute("SELECT * FROM surface WHERE id = ?", (sid,)).fetchone()
        return decode_surface(row_to_dict(row))

    def mitigate(self, sid: str) -> dict[str, Any] | None:
        item = self.get(sid)
        if not item:
            return None
        extra = item.get("extra") or {}
        result: dict[str, Any] = {"surface": item, "blocks": [], "actions": []}
        if item["kind"] == "http_path":
            path = extra.get("path") or item["key"].split("path:", 1)[-1]
            result["blocks"].append(add_block("path", path, f"surface:{sid}", None))
        elif item["kind"] == "outbound":
            dest = extra.get("dest_ip")
            if dest:
                result["actions"].append(
                    add_pending_action(
                        "firewall_block",
                        None,
                        {
                            "dest_ip": dest,
                            "dest_port": extra.get("dest_port"),
                            "reason": f"surface:{sid}",
                        },
                    )
                )
        elif item["kind"] == "process":
            pid = extra.get("pid")
            if pid:
                result["actions"].append(
                    add_pending_action(
                        "kill_process",
                        None,
                        {"pid": pid, "name": extra.get("name"), "reason": f"surface:{sid}"},
                    )
                )
        elif item["kind"] == "listen_port":
            result["actions"].append(
                add_pending_action(
                    "firewall_block",
                    None,
                    {
                        "listen_port": extra.get("port"),
                        "addr": extra.get("addr"),
                        "reason": f"surface:{sid}",
                    },
                )
            )
        with db() as conn:
            conn.execute(
                "UPDATE surface SET status = 'mitigated' WHERE id = ?",
                (sid,),
            )
        item["status"] = "mitigated"
        result["surface"] = item
        add_audit("action", f"공격면 완화: {item['title']}", {"id": sid})
        return result

    def known_dests(self) -> set[str]:
        with db() as conn:
            rows = conn.execute(
                "SELECT extra FROM surface WHERE kind = 'outbound'"
            ).fetchall()
        dests: set[str] = set()
        for row in rows:
            extra = json.loads(row["extra"] or "{}")
            ip = extra.get("dest_ip")
            port = extra.get("dest_port")
            if ip:
                dests.add(f"{ip}:{port}")
        return dests


def decode_surface(item: dict[str, Any] | None) -> dict[str, Any] | None:
    if not item:
        return None
    extra = item.get("extra")
    if isinstance(extra, str):
        item["extra"] = json.loads(extra or "{}")
    return item


def _sensitive_path(path: str) -> bool:
    p = path.lower()
    return any(x in p for x in ("/admin", "/.env", "/debug", "/console", "/actuator"))


def _sensitive_file(path: str) -> bool:
    p = path.lower()
    return any(
        x in p
        for x in (".env", "web.config", ".pem", "id_rsa", "secrets", "credentials")
    )


def _temp_path(path: str) -> bool:
    p = path.lower()
    return any(x in p for x in ("\\temp\\", "/temp/", "\\downloads\\", "/downloads/"))


def add_block(
    kind: str, value: str, reason: str, ttl: int | None = BLOCK_SECONDS
) -> dict[str, Any]:
    bid = new_id()
    created = now()
    expires = created + ttl if ttl else None
    with db() as conn:
        conn.execute(
            """
            INSERT INTO blocks(id, kind, value, reason, expires_at, created_at, active)
            VALUES (?,?,?,?,?,?,1)
            """,
            (bid, kind, value, reason, expires, created),
        )
    add_audit("block", f"차단 추가 {kind}:{value}", {"id": bid, "reason": reason})
    return {
        "id": bid,
        "kind": kind,
        "value": value,
        "reason": reason,
        "expires_at": expires,
        "active": True,
    }


def list_active_blocks() -> list[dict[str, Any]]:
    ts = now()
    with db() as conn:
        conn.execute(
            "UPDATE blocks SET active = 0 WHERE active = 1 AND expires_at IS NOT NULL AND expires_at < ?",
            (ts,),
        )
        rows = conn.execute(
            "SELECT * FROM blocks WHERE active = 1 ORDER BY created_at DESC"
        ).fetchall()
    return [row_to_dict(r) for r in rows]


def is_blocked(kind: str, value: str) -> dict[str, Any] | None:
    ts = now()
    with db() as conn:
        row = conn.execute(
            """
            SELECT * FROM blocks
            WHERE active = 1 AND kind = ? AND value = ?
              AND (expires_at IS NULL OR expires_at > ?)
            ORDER BY created_at DESC LIMIT 1
            """,
            (kind, value, ts),
        ).fetchone()
    return row_to_dict(row)


def deactivate_block(bid: str) -> bool:
    with db() as conn:
        cur = conn.execute("UPDATE blocks SET active = 0 WHERE id = ?", (bid,))
        return cur.rowcount > 0


def add_pending_action(kind: str, alert_id: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    aid = new_id()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO pending_actions(id, kind, alert_id, payload, status, created_at)
            VALUES (?,?,?,?,?,?)
            """,
            (aid, kind, alert_id, json.dumps(payload, ensure_ascii=False), "pending", now()),
        )
    add_audit("action", f"수동 조치 대기: {kind}", {"id": aid, "payload": payload})
    return {"id": aid, "kind": kind, "alert_id": alert_id, "payload": payload, "status": "pending"}


def list_pending_actions() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM pending_actions ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    items = []
    for row in rows:
        item = row_to_dict(row)
        item["payload"] = json.loads(item["payload"])
        items.append(item)
    return items


surface = SurfaceTracker()
