from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import detect, llm
from .bus import hub
from .config import CORS_ORIGINS, ENGINE_HOST, ENGINE_PORT
from .db import add_audit, db, init_db, new_id, now, row_to_dict
from .settings import get_settings, public_settings, save_settings
from .patterns import store, write_approved_pattern, set_pattern_enabled, write_custom_pattern
from .respond import (
    apply_actions,
    cancel_disruptive_pending,
    cancel_pending_for_alert,
    execute_pending,
    inspect_blocks,
    mask_fields,
)

_recent_alert_keys: dict[str, float] = {}


def _alert_once(rule_id: str | None, event: dict[str, Any]) -> bool:
    fields = event.get("fields") or {}
    key = f"{rule_id or event.get('type')}:{fields.get('client_ip') or fields.get('pid') or fields.get('dest_ip') or fields.get('path') or event.get('id')}"
    ts = now()
    last = _recent_alert_keys.get(key, 0)
    if ts - last < 20:
        return False
    _recent_alert_keys[key] = ts
    return True
from .surface import (
    add_block,
    add_pending_action,
    deactivate_block,
    list_active_blocks,
    list_pending_actions,
    surface,
)


class EventIn(BaseModel):
    source: str
    type: str
    timestamp: str | None = None
    severity_hint: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)
    id: str | None = None


class InspectIn(BaseModel):
    client_ip: str = "unknown"
    method: str = "GET"
    path: str = "/"
    has_auth: bool = False
    user_agent: str = ""
    status: int | None = None
    event_type: str = "request"


class SettingsIn(BaseModel):
    resolve_action: str | None = None
    http_block_on_resolve: bool | None = None
    windows_process: str | None = None
    windows_firewall: str | None = None
    http_auto_respond: bool | None = None
    llm_provider: str | None = None
    openai_api_key: str | None = None
    gemini_api_key: str | None = None


class SyntheticIn(BaseModel):
    kind: str
    count: int = 1
    client_ip: str = "203.0.113.10"
    path: str | None = None


def _parse_ts(value: str | None) -> float:
    if not value:
        return now()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return now()


def encode_event(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    if isinstance(item.get("fields"), str):
        item["fields"] = json.loads(item["fields"])
    item["timestamp"] = datetime.fromtimestamp(item["ts"], tz=timezone.utc).isoformat()
    return item


def encode_alert(row: dict[str, Any]) -> dict[str, Any]:
    item = dict(row)
    if isinstance(item.get("payload"), str):
        item["payload"] = json.loads(item["payload"] or "{}")
    event = (item.get("payload") or {}).get("event") or {}
    fields = event.get("fields") or {}
    source = event.get("source") or ""
    origin: list[str] = []
    cause: list[str] = []
    if source == "http":
        origin.append("웹/API 게이트웨이")
        if fields.get("client_ip"):
            origin.append(f"IP {fields.get('client_ip')}")
    elif source == "windows":
        origin.append("이 PC")
        name = fields.get("process_name")
        if name:
            pid = fields.get("pid")
            origin.append(f"{name} (PID {pid})" if pid else str(name))
    elif source:
        origin.append(str(source))
    if item.get("title"):
        cause.append(str(item["title"]))
    method = fields.get("method")
    path = fields.get("path")
    if method or path:
        cause.append(" ".join(str(x) for x in (method, path) if x))
    if fields.get("has_auth") is False and path:
        cause.append("인증 없음")
    if fields.get("process_path"):
        cause.append(str(fields.get("process_path")))
    if fields.get("dest_ip"):
        dest = str(fields.get("dest_ip"))
        port = fields.get("dest_port")
        cause.append(f"외부 {dest}:{port}" if port else f"외부 {dest}")
    if fields.get("file_path"):
        cause.append(str(fields.get("file_path")))
    if fields.get("listen_port"):
        cause.append(f"{fields.get('listen_addr') or '0.0.0.0'}:{fields.get('listen_port')}")
    if item.get("rule_id"):
        cause.append(f"규칙 {item['rule_id']}")
    item["origin"] = " · ".join(origin) or "출처를 특정하지 못함"
    seen: list[str] = []
    for part in cause:
        if part and part not in seen:
            seen.append(part)
    item["cause"] = " · ".join(seen) or (item.get("rationale") or "원인을 특정하지 못함")
    return item


def store_event(body: EventIn) -> dict[str, Any]:
    eid = body.id or new_id()
    ts = _parse_ts(body.timestamp)
    fields = mask_fields(body.fields)
    with db() as conn:
        conn.execute(
            """
            INSERT INTO events(id, source, type, ts, severity_hint, fields, created_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                eid,
                body.source,
                body.type,
                ts,
                body.severity_hint,
                json.dumps(fields, ensure_ascii=False),
                now(),
            ),
        )
    event = {
        "id": eid,
        "source": body.source,
        "type": body.type,
        "ts": ts,
        "severity_hint": body.severity_hint,
        "fields": fields,
    }
    if body.source != "windows":
        add_audit("event", f"{body.source}:{body.type}", {"id": eid})
    return event


def create_alert(
    event: dict[str, Any],
    rule: dict[str, Any] | None,
    classification: dict[str, Any],
) -> dict[str, Any]:
    aid = new_id()
    title = (rule or {}).get("name") or classification.get("category") or event["type"]
    ts = now()
    payload = {"event": event, "rule_id": (rule or {}).get("id")}
    with db() as conn:
        conn.execute(
            """
            INSERT INTO alerts(
              id, event_id, rule_id, title, category, severity, status,
              recommended_action, rationale, payload, created_at, updated_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                aid,
                event["id"],
                (rule or {}).get("id"),
                title,
                classification.get("category"),
                classification.get("severity") or "medium",
                "open",
                classification.get("recommended_action"),
                classification.get("rationale"),
                json.dumps(payload, ensure_ascii=False),
                ts,
                ts,
            ),
        )
    alert = {
        "id": aid,
        "event_id": event["id"],
        "rule_id": (rule or {}).get("id"),
        "title": title,
        "category": classification.get("category"),
        "severity": classification.get("severity") or "medium",
        "status": "open",
        "recommended_action": classification.get("recommended_action"),
        "rationale": classification.get("rationale"),
        "payload": payload,
        "created_at": ts,
        "updated_at": ts,
    }
    add_audit("alert", f"경보: {title}", {"id": aid, "severity": alert["severity"]})
    return alert


def get_alert(alert_id: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return encode_alert(row_to_dict(row)) if row else None


def get_event(event_id: str | None) -> dict[str, Any] | None:
    if not event_id:
        return None
    with db() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    return encode_event(row_to_dict(row)) if row else None


async def process_event(event: dict[str, Any], *, for_gateway: bool = False) -> dict[str, Any]:
    surface_items = surface.observe_event(event)
    detect.load_known_dests(surface.known_dests())
    rules = store.enabled()
    hits = detect.evaluate(rules, event)
    alerts: list[dict[str, Any]] = []
    decision = {"allow": True, "status": 200, "reason": None, "blocks": [], "pending": []}

    if for_gateway:
        fields = event.get("fields") or {}
        existing = inspect_blocks(fields.get("client_ip"), fields.get("path"))
        if existing:
            decision = {
                "allow": False,
                "status": 403,
                "reason": existing.get("reason") or "blocked",
                "blocks": [existing],
                "pending": [],
            }

    for rule in hits:
        if not _alert_once(rule.get("id"), event):
            auto = (
                bool(rule.get("auto_respond"))
                and event.get("source") == "http"
                and bool(get_settings().get("http_auto_respond", True))
            )
            applied = apply_actions(rule.get("actions") or ["alert"], event, rule, auto)
            if not applied["allow"]:
                decision["allow"] = False
                decision["status"] = applied["status"]
                decision["reason"] = applied["reason"]
            decision["blocks"].extend(applied.get("blocks") or [])
            continue
        classification = await llm.classify(event, rule)
        alert = create_alert(event, rule, classification)
        auto = (
            bool(rule.get("auto_respond"))
            and event.get("source") == "http"
            and bool(get_settings().get("http_auto_respond", True))
        )
        applied = apply_actions(rule.get("actions") or ["alert"], event, rule, auto)
        if not applied["allow"]:
            decision["allow"] = False
            decision["status"] = applied["status"]
            decision["reason"] = applied["reason"]
        decision["blocks"].extend(applied.get("blocks") or [])
        decision["pending"].extend(applied.get("pending") or [])
        alerts.append(alert)

    if not hits and event.get("type") not in {
        "request",
        "port_open",
        "process_start",
        "net_connect",
        "file_change",
    }:
        classification = await llm.classify(event, None)
        if classification.get("severity") in {"medium", "high", "critical"}:
            alerts.append(create_alert(event, None, classification))

    for alert in alerts:
        await hub.broadcast("alert", alert)
    for item in surface_items:
        await hub.broadcast("surface", item)
    await hub.broadcast("event", {"id": event["id"], "type": event["type"], "source": event["source"]})

    return {
        "event": event,
        "alerts": alerts,
        "surface": surface_items,
        "decision": decision,
    }


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    store.reload(force=True)
    detect.load_known_dests(surface.known_dests())
    yield


app = FastAPI(title="WH Defense Engine", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS + ["http://127.0.0.1:8080", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/v1/settings")
def read_settings() -> dict[str, Any]:
    data = public_settings()
    data["ai_providers"] = llm.available_providers()
    data["llm"] = llm.provider()
    return data


@app.put("/api/v1/settings")
async def update_settings(body: SettingsIn) -> dict[str, Any]:
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    saved = save_settings(payload)
    add_audit("settings", "설정 변경", {k: v for k, v in saved.items() if "key" not in k})
    await hub.broadcast("settings", public_settings())
    return read_settings()


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {
        "ok": True,
        "patterns": len(store.all()),
        "llm": llm.provider(),
    }


@app.get("/api/v1/stats")
def stats() -> dict[str, Any]:
    with db() as conn:
        open_alerts = conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE status = 'open'"
        ).fetchone()["c"]
        high = conn.execute(
            "SELECT COUNT(*) AS c FROM surface WHERE status = 'open' AND risk = 'high'"
        ).fetchone()["c"]
        drafts = conn.execute(
            "SELECT COUNT(*) AS c FROM drafts WHERE status = 'pending'"
        ).fetchone()["c"]
    return {
        "open_alerts": open_alerts,
        "high_surface": high,
        "pending_drafts": drafts,
        "active_blocks": len(list_active_blocks()),
        "llm": llm.provider(),
        "ai_providers": llm.available_providers(),
    }


@app.post("/api/v1/events")
async def ingest(body: EventIn) -> dict[str, Any]:
    event = store_event(body)
    return await process_event(event)


@app.post("/api/v1/gateway/inspect")
async def gateway_inspect(body: InspectIn) -> dict[str, Any]:
    event = store_event(
        EventIn(
            source="http",
            type=body.event_type,
            fields={
                "client_ip": body.client_ip,
                "method": body.method,
                "path": body.path,
                "has_auth": body.has_auth,
                "user_agent": (body.user_agent or "")[:180],
                "status": body.status,
            },
        )
    )
    result = await process_event(event, for_gateway=True)
    decision = result["decision"]
    return {
        "allow": decision["allow"],
        "status": decision["status"] if not decision["allow"] else 200,
        "reason": decision["reason"],
        "alert_ids": [a["id"] for a in result["alerts"]],
        "event_id": event["id"],
    }


@app.post("/api/v1/events/synthetic")
async def synthetic(body: SyntheticIn) -> dict[str, Any]:
    created: list[dict[str, Any]] = []
    kind = body.kind
    n = max(1, min(body.count, 40))
    if kind == "http_burst":
        for _ in range(n):
            created.append(
                await ingest(
                    EventIn(
                        source="http",
                        type="request",
                        fields={
                            "client_ip": body.client_ip,
                            "method": "GET",
                            "path": "/api/items",
                            "has_auth": False,
                        },
                    )
                )
            )
    elif kind == "unauth_admin":
        created.append(
            await ingest(
                EventIn(
                    source="http",
                    type="request",
                    fields={
                        "client_ip": body.client_ip,
                        "method": "GET",
                        "path": body.path or "/admin",
                        "has_auth": False,
                    },
                )
            )
        )
    elif kind == "auth_fail_burst":
        for _ in range(n):
            created.append(
                await ingest(
                    EventIn(
                        source="http",
                        type="auth_fail",
                        fields={"client_ip": body.client_ip, "path": "/login", "has_auth": False},
                    )
                )
            )
    elif kind == "process_from_temp":
        created.append(
            await ingest(
                EventIn(
                    source="windows",
                    type="process_start",
                    fields={
                        "pid": 4242,
                        "process_name": "synth-helper.exe",
                        "process_path": r"C:\Users\Public\Downloads\synth-helper.exe",
                        "parent_name": "explorer.exe",
                    },
                )
            )
        )
    elif kind == "new_outbound":
        created.append(
            await ingest(
                EventIn(
                    source="windows",
                    type="net_connect",
                    fields={
                        "pid": 77,
                        "process_name": "demo-agent.exe",
                        "dest_ip": "203.0.113.99",
                        "dest_port": 8443,
                    },
                )
            )
        )
    elif kind == "file_change":
        created.append(
            await ingest(
                EventIn(
                    source="windows",
                    type="file_change",
                    fields={"file_path": str(__file__).replace("main.py", ".env")},
                )
            )
        )
    else:
        return {"ok": False, "error": "unknown_kind"}
    return {"ok": True, "kind": kind, "results": len(created)}


@app.get("/api/v1/alerts")
def list_alerts(status: str | None = "open") -> list[dict[str, Any]]:
    with db() as conn:
        if status == "all":
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT 200",
                (status or "open",),
            ).fetchall()
    return [encode_alert(row_to_dict(r)) for r in rows]


def apply_mitigation(alert_id: str, *, bulk: bool = False) -> dict[str, Any]:
    cfg = get_settings()
    alert = get_alert(alert_id)
    result: dict[str, Any] = {"blocks": [], "pending": [], "executed": []}
    if not alert:
        return result
    event = get_event(alert.get("event_id")) or (alert.get("payload") or {}).get("event") or {}
    fields = event.get("fields") or {}
    if cfg.get("http_block_on_resolve") and event.get("source") == "http":
        ip = fields.get("client_ip")
        path = fields.get("path")
        if ip:
            result["blocks"].append(add_block("ip", str(ip), f"alert:{alert_id}"))
        if path:
            result["blocks"].append(add_block("path", str(path), f"alert:{alert_id}", ttl=None))
    proc_mode = cfg.get("windows_process") or "confirm"
    fw_mode = cfg.get("windows_firewall") or "confirm"
    if bulk:
        if proc_mode == "execute":
            proc_mode = "confirm"
        if fw_mode == "execute":
            fw_mode = "confirm"
    pid = fields.get("pid")
    dest = fields.get("dest_ip")
    if (
        pid
        and proc_mode != "off"
        and event.get("source") == "windows"
        and event.get("type") == "process_start"
    ):
        pending = add_pending_action(
            "kill_process",
            alert_id,
            {"pid": pid, "name": fields.get("process_name")},
        )
        if proc_mode == "execute":
            result["executed"].append(execute_pending(pending["id"]))
        else:
            result["pending"].append(pending)
    if (
        dest
        and fw_mode != "off"
        and event.get("source") == "windows"
        and event.get("type") == "net_connect"
    ):
        pending = add_pending_action(
            "firewall_block",
            alert_id,
            {"dest_ip": dest, "dest_port": fields.get("dest_port")},
        )
        if fw_mode == "execute":
            result["executed"].append(execute_pending(pending["id"]))
        else:
            result["pending"].append(pending)
    return result


def _resolve_alert(alert_id: str, *, bulk: bool = False) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT id FROM alerts WHERE id = ? AND status = 'open'", (alert_id,)
        ).fetchone()
        if not row:
            return None
    cfg = get_settings()
    applied: dict[str, Any] = {"blocks": [], "pending": [], "executed": []}
    if cfg.get("resolve_action") == "mitigate":
        applied = apply_mitigation(alert_id, bulk=bulk)
        status = "blocked"
        summary = "경보 처리: 원인 차단/종료 적용 후 목록 제거"
    else:
        cancel_pending_for_alert(alert_id)
        status = "resolved"
        summary = "경보 처리: 목록에서만 제거"
    with db() as conn:
        conn.execute(
            "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
            (status, now(), alert_id),
        )
    add_audit("alert", summary, {"id": alert_id, **{k: applied.get(k) for k in ("blocks", "pending", "executed")}})
    return {"id": alert_id, "status": status, **applied}


@app.post("/api/v1/alerts/{alert_id}/confirm")
async def confirm_alert(alert_id: str) -> dict[str, Any]:
    alert = get_alert(alert_id)
    if not alert:
        return {"ok": False, "error": "not_found"}
    with db() as conn:
        conn.execute(
            "UPDATE alerts SET status = 'confirmed', updated_at = ? WHERE id = ?",
            (now(), alert_id),
        )
    alert["status"] = "confirmed"
    event = get_event(alert.get("event_id"))
    draft_src = await llm.draft_pattern(alert, event)
    did = new_id()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO drafts(id, alert_id, name, yaml_text, status, origin, created_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                did,
                alert_id,
                draft_src["name"],
                draft_src["yaml_text"],
                "pending",
                draft_src["origin"],
                now(),
            ),
        )
    draft = {
        "id": did,
        "alert_id": alert_id,
        "name": draft_src["name"],
        "yaml_text": draft_src["yaml_text"],
        "status": "pending",
        "origin": draft_src["origin"],
    }
    add_audit("pattern", f"수비 패턴 초안: {draft['name']}", {"id": did})
    await hub.broadcast("draft", draft)
    await hub.broadcast("alert", alert)
    return {"ok": True, "alert": alert, "draft": draft}


@app.post("/api/v1/alerts/resolve-all")
async def resolve_all_alerts() -> dict[str, Any]:
    with db() as conn:
        rows = conn.execute("SELECT id FROM alerts WHERE status = 'open'").fetchall()
        ids = [r["id"] for r in rows]
    results = []
    cfg = get_settings()
    for alert_id in ids:
        item = _resolve_alert(alert_id, bulk=True)
        if item:
            results.append(item)
    if cfg.get("resolve_action") != "mitigate":
        cancel_disruptive_pending()
    add_audit("alert", f"열린 경보 {len(results)}건 처리", {"mode": cfg.get("resolve_action")})
    await hub.broadcast("alert", {"resolved_all": len(results)})
    return {"ok": True, "resolved": len(results)}


@app.post("/api/v1/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str) -> dict[str, Any]:
    item = _resolve_alert(alert_id, bulk=False)
    if not item:
        return {"ok": False, "error": "not_found"}
    await hub.broadcast("alert", item)
    return {"ok": True, **item}


@app.post("/api/v1/alerts/{alert_id}/dismiss")
async def dismiss_alert(alert_id: str) -> dict[str, Any]:
    return await resolve_alert(alert_id)


@app.post("/api/v1/alerts/{alert_id}/block")
async def block_from_alert(alert_id: str) -> dict[str, Any]:
    alert = get_alert(alert_id)
    if not alert:
        return {"ok": False, "error": "not_found"}
    event = get_event(alert.get("event_id")) or (alert.get("payload") or {}).get("event") or {}
    fields = event.get("fields") or {}
    blocks = []
    pending = []
    if event.get("source") == "http" and fields.get("client_ip"):
        blocks.append(add_block("ip", str(fields["client_ip"]), f"alert:{alert_id}"))
        if fields.get("path"):
            blocks.append(add_block("path", str(fields["path"]), f"alert:{alert_id}", ttl=None))
    elif fields.get("dest_ip"):
        pending.append(
            add_pending_action(
                "firewall_block",
                alert_id,
                {"dest_ip": fields.get("dest_ip"), "dest_port": fields.get("dest_port")},
            )
        )
    elif fields.get("pid"):
        pending.append(
            add_pending_action(
                "kill_process",
                alert_id,
                {"pid": fields.get("pid"), "name": fields.get("process_name")},
            )
        )
    with db() as conn:
        conn.execute(
            "UPDATE alerts SET status = 'blocked', updated_at = ? WHERE id = ?",
            (now(), alert_id),
        )
    await hub.broadcast("block", {"blocks": blocks, "pending": pending})
    return {"ok": True, "blocks": blocks, "pending": pending}


@app.get("/api/v1/surface")
def list_surface(status: str | None = None) -> list[dict[str, Any]]:
    return surface.list_items(status)


@app.post("/api/v1/surface/{sid}/mitigate")
async def mitigate_surface(sid: str) -> dict[str, Any]:
    result = surface.mitigate(sid)
    if not result:
        return {"ok": False, "error": "not_found"}
    await hub.broadcast("surface", result["surface"])
    return {"ok": True, **result}


@app.get("/api/v1/patterns")
def list_patterns() -> list[dict[str, Any]]:
    rules = store.all()
    rules.sort(key=lambda r: (not r.get("enabled"), r.get("name") or ""))
    return rules


class PatternEnableIn(BaseModel):
    enabled: bool


class PatternCreateIn(BaseModel):
    name: str
    source: str = "http"
    event_type: str = "request"
    severity: str = "medium"
    auto_respond: bool = False
    description: str = ""
    path_prefixes: list[str] = Field(default_factory=list)
    path_contains: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=lambda: ["alert"])


@app.post("/api/v1/patterns/{rule_id}/enabled")
async def enable_pattern(rule_id: str, body: PatternEnableIn) -> dict[str, Any]:
    rule = set_pattern_enabled(rule_id, body.enabled)
    if not rule:
        return {"ok": False, "error": "not_found"}
    add_audit("pattern", f"규칙 {'켜짐' if body.enabled else '꺼짐'}: {rule.get('name')}", {"id": rule_id})
    await hub.broadcast("pattern", {"id": rule_id, "enabled": body.enabled})
    return {"ok": True, "pattern": rule, "patterns": store.all()}


@app.post("/api/v1/patterns")
async def create_pattern(body: PatternCreateIn) -> dict[str, Any]:
    match: dict[str, Any] = {}
    prefixes = [p.strip() for p in body.path_prefixes if str(p).strip()]
    contains = [p.strip() for p in body.path_contains if str(p).strip()]
    if prefixes:
        match["path_prefixes"] = prefixes
        if body.source == "http":
            match["missing_auth"] = True
    if contains:
        match["path_contains"] = contains
    actions = body.actions or ["alert"]
    if body.auto_respond and body.source == "http" and "deny_request" not in actions:
        actions = [*actions, "deny_request"]
    rule = write_custom_pattern(
        {
            "id": body.name,
            "name": body.name,
            "source": body.source,
            "event_type": body.event_type,
            "severity": body.severity,
            "auto_respond": body.auto_respond,
            "match": match,
            "actions": actions,
            "description": body.description or "운영자가 추가한 수비 규칙입니다.",
        }
    )
    if not rule:
        return {"ok": False, "error": "invalid"}
    add_audit("pattern", f"규칙 추가: {rule.get('name')}", {"id": rule.get("id")})
    await hub.broadcast("pattern", {"id": rule.get("id"), "created": True})
    return {"ok": True, "pattern": rule, "patterns": store.all()}


@app.get("/api/v1/patterns/drafts")
def list_drafts(status: str = "pending") -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM drafts WHERE status = ? ORDER BY created_at DESC",
            (status,),
        ).fetchall()
    return [row_to_dict(r) for r in rows]


@app.post("/api/v1/patterns/drafts/{draft_id}/approve")
async def approve_draft(draft_id: str) -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM drafts WHERE id = ?", (draft_id,)).fetchone()
        if not row:
            return {"ok": False, "error": "not_found"}
        draft = row_to_dict(row)
        conn.execute("UPDATE drafts SET status = 'approved' WHERE id = ?", (draft_id,))
    filename = write_approved_pattern(draft["id"], draft["yaml_text"])
    add_audit("pattern", f"패턴 승인 {filename}", {"id": draft_id})
    await hub.broadcast("pattern", {"id": draft_id, "file": filename})
    return {"ok": True, "file": filename, "patterns": store.all()}


@app.post("/api/v1/patterns/drafts/{draft_id}/reject")
async def reject_draft(draft_id: str) -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute(
            "UPDATE drafts SET status = 'rejected' WHERE id = ?",
            (draft_id,),
        )
        if cur.rowcount == 0:
            return {"ok": False, "error": "not_found"}
    return {"ok": True}


@app.get("/api/v1/blocks")
def blocks() -> list[dict[str, Any]]:
    return list_active_blocks()


@app.delete("/api/v1/blocks/{block_id}")
async def remove_block(block_id: str) -> dict[str, Any]:
    ok = deactivate_block(block_id)
    if ok:
        add_audit("block", "차단을 해제했습니다", {"id": block_id})
        await hub.broadcast("block", {"removed": block_id})
    return {"ok": ok}


@app.get("/api/v1/actions")
def actions() -> list[dict[str, Any]]:
    return list_pending_actions()


@app.post("/api/v1/actions/{action_id}/execute")
async def run_action(action_id: str) -> dict[str, Any]:
    result = execute_pending(action_id)
    await hub.broadcast("action", result)
    return result


@app.delete("/api/v1/actions/{action_id}")
async def cancel_action(action_id: str) -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute(
            "UPDATE pending_actions SET status = 'cancelled' WHERE id = ? AND status = 'pending'",
            (action_id,),
        )
        ok = cur.rowcount > 0
    if ok:
        add_audit("action", "대기 조치를 취소했습니다", {"id": action_id})
        await hub.broadcast("action", {"cancelled": action_id})
    return {"ok": ok}


@app.delete("/api/v1/timeline/{item_id}")
async def delete_timeline_item(item_id: str) -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute("DELETE FROM audit WHERE id = ?", (item_id,))
        ok = cur.rowcount > 0
    if ok:
        await hub.broadcast("timeline", {"deleted": item_id})
    return {"ok": ok}


@app.delete("/api/v1/timeline")
async def clear_timeline() -> dict[str, Any]:
    with db() as conn:
        cur = conn.execute("DELETE FROM audit")
        deleted = cur.rowcount
    await hub.broadcast("timeline", {"cleared": deleted})
    return {"ok": True, "deleted": deleted}


@app.get("/api/v1/timeline")
def timeline(limit: int = 150) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM audit
            WHERE summary NOT LIKE 'windows:%'
            ORDER BY ts DESC LIMIT ?
            """,
            (min(limit, 500),),
        ).fetchall()
    items = []
    for row in rows:
        item = row_to_dict(row)
        item["detail"] = json.loads(item["detail"] or "{}")
        item["timestamp"] = datetime.fromtimestamp(item["ts"], tz=timezone.utc).isoformat()
        items.append(item)
    return items


@app.websocket("/api/v1/ws")
async def websocket(ws: WebSocket) -> None:
    await hub.connect(ws)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(ws)
    except Exception:
        await hub.disconnect(ws)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "engine.app.main:app",
        host=ENGINE_HOST,
        port=ENGINE_PORT,
        reload=False,
    )


if __name__ == "__main__":
    run()
