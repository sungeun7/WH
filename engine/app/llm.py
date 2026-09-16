from __future__ import annotations

import json
from typing import Any

import httpx

from .config import GEMINI_API_KEY, LLM_PROVIDER, OPENAI_API_KEY


def _runtime() -> tuple[str, str, str]:
    from .settings import get_settings

    s = get_settings()
    openai_key = (s.get("openai_api_key") or OPENAI_API_KEY or "").strip()
    gemini_key = (s.get("gemini_api_key") or GEMINI_API_KEY or "").strip()
    pref = (s.get("llm_provider") or LLM_PROVIDER or "auto").strip().lower()
    return openai_key, gemini_key, pref


def provider() -> str:
    openai_key, gemini_key, pref = _runtime()
    if pref == "none":
        return "none"
    if pref == "openai":
        return "openai" if openai_key else "none"
    if pref == "gemini":
        return "gemini" if gemini_key else "none"
    if openai_key:
        return "openai"
    if gemini_key:
        return "gemini"
    return "none"


def available_providers() -> list[dict[str, Any]]:
    openai_key, gemini_key, pref = _runtime()
    current = provider()
    return [
        {
            "id": "auto",
            "name": "자동 (키 있는 모델)",
            "ready": bool(openai_key or gemini_key),
            "selected": pref == "auto",
            "active": current in {"openai", "gemini"} and pref == "auto",
        },
        {
            "id": "openai",
            "name": "OpenAI",
            "ready": bool(openai_key),
            "selected": pref == "openai" or current == "openai" and pref == "auto",
            "active": current == "openai",
        },
        {
            "id": "gemini",
            "name": "Gemini",
            "ready": bool(gemini_key),
            "selected": pref == "gemini" or current == "gemini" and pref == "auto",
            "active": current == "gemini",
        },
        {
            "id": "none",
            "name": "규칙만 (AI 끄기)",
            "ready": True,
            "selected": pref == "none" or current == "none",
            "active": current == "none",
        },
    ]


SYSTEM = (
    "You are a defensive white-hat security advisor for an asset the operator owns. "
    "Classify security events and propose defensive detection rules only. "
    "Never provide exploits, payloads, attack reproduction steps, or offensive techniques. "
    "Rules may match behavioral features: path prefix, missing auth, rate thresholds, "
    "process path contains, first-seen destination. Actions limited to alert, deny_request, deny_ip. "
    "Respond with JSON only."
)


def _safe_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(text[start : end + 1])
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
        return None


async def _openai(prompt: str) -> dict[str, Any] | None:
    openai_key, _, _ = _runtime()
    async with httpx.AsyncClient(timeout=25) as client:
        res = await client.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {openai_key}"},
            json={
                "model": "gpt-4o-mini",
                "temperature": 0.1,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": SYSTEM},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        res.raise_for_status()
        content = res.json()["choices"][0]["message"]["content"]
        return _safe_json(content)


async def _gemini(prompt: str) -> dict[str, Any] | None:
    _, gemini_key, _ = _runtime()
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.0-flash:generateContent?key={gemini_key}"
    )
    async with httpx.AsyncClient(timeout=25) as client:
        res = await client.post(
            url,
            json={
                "systemInstruction": {"parts": [{"text": SYSTEM}]},
                "generationConfig": {"temperature": 0.1, "responseMimeType": "application/json"},
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            },
        )
        res.raise_for_status()
        content = res.json()["candidates"][0]["content"]["parts"][0]["text"]
        return _safe_json(content)


async def _complete(prompt: str) -> dict[str, Any] | None:
    kind = provider()
    try:
        if kind == "openai":
            return await _openai(prompt)
        if kind == "gemini":
            return await _gemini(prompt)
    except Exception:
        return None
    return None


def heuristic_classify(event: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    if rule:
        action = (rule.get("actions") or ["alert"])[0]
        return {
            "category": rule.get("id") or "signature",
            "severity": rule.get("severity") or "medium",
            "recommended_action": action,
            "rationale": rule.get("description") or f"규칙 {rule.get('name')}에 일치했습니다.",
        }
    etype = event.get("type")
    mapping = {
        "auth_fail": ("credential_abuse", "medium", "deny_ip", "반복 인증 실패 가능성이 있습니다."),
        "request": ("http_anomaly", "low", "alert", "HTTP 요청 이벤트를 기록했습니다."),
        "process_start": ("endpoint_process", "medium", "alert", "프로세스 생성 이벤트를 검토하세요."),
        "net_connect": ("outbound", "medium", "alert", "새로운 외부 연결입니다. 방화벽 차단은 승인 후 적용합니다."),
        "file_change": ("integrity", "medium", "alert", "파일 변경이 관측되었습니다."),
        "port_open": ("exposure", "low", "alert", "리스닝 포트가 공격면에 추가되었습니다."),
    }
    category, severity, action, rationale = mapping.get(
        etype, ("unknown", "low", "alert", "분류되지 않은 이벤트입니다.")
    )
    return {
        "category": category,
        "severity": event.get("severity_hint") or severity,
        "recommended_action": action,
        "rationale": rationale,
    }


async def classify(event: dict[str, Any], rule: dict[str, Any] | None) -> dict[str, Any]:
    base = heuristic_classify(event, rule)
    if provider() == "none" or rule:
        return base
    prompt = (
        "Classify this defensive telemetry event. JSON keys: "
        "category, severity (low|medium|high|critical), recommended_action "
        "(alert|deny_request|deny_ip), rationale (short, Korean preferred).\n"
        f"event={json.dumps(event, ensure_ascii=False)[:2000]}"
    )
    data = await _complete(prompt)
    if not data:
        return base
    return {
        "category": data.get("category") or base["category"],
        "severity": data.get("severity") or base["severity"],
        "recommended_action": data.get("recommended_action") or base["recommended_action"],
        "rationale": data.get("rationale") or base["rationale"],
    }


def heuristic_draft(alert: dict[str, Any], event: dict[str, Any] | None) -> dict[str, Any]:
    fields = (event or {}).get("fields") or {}
    rule_id = f"learned_{alert.get('id', 'x')[:10]}"
    name = f"학습 규칙: {alert.get('title')}"
    source = (event or {}).get("source") or "http"
    etype = (event or {}).get("type") or "request"
    match: dict[str, Any] = {}
    actions = ["alert"]
    auto = False
    if etype == "request":
        path = fields.get("path") or "/"
        match = {"path_prefixes": [path]}
        if not fields.get("has_auth"):
            match["missing_auth"] = True
        actions = ["alert", "deny_request"]
        auto = True
    elif etype == "auth_fail":
        match = {"group_by": "client_ip", "window_seconds": 60, "threshold": 5}
        actions = ["alert", "deny_ip"]
        auto = True
    elif etype == "net_connect":
        match = {"first_seen_dest": True, "ignore_private": True}
    elif etype == "process_start":
        p = fields.get("process_path") or ""
        match = {"path_contains": [p[-40:]]} if p else {}
    elif etype == "file_change":
        p = fields.get("file_path") or ""
        match = {"path_contains": [p.split("\\")[-1] or p.split("/")[-1]]}
    yaml_text = _to_yaml(
        {
            "id": rule_id,
            "name": name,
            "enabled": True,
            "source": source,
            "event_type": etype,
            "severity": alert.get("severity") or "medium",
            "auto_respond": auto,
            "match": match,
            "actions": actions,
            "description": alert.get("rationale") or "운영자가 확인한 경보에서 추출한 수비 패턴입니다.",
        }
    )
    return {"name": name, "yaml_text": yaml_text, "origin": "heuristic"}


async def draft_pattern(alert: dict[str, Any], event: dict[str, Any] | None) -> dict[str, Any]:
    base = heuristic_draft(alert, event)
    if provider() == "none":
        return base
    prompt = (
        "Propose ONE defensive YAML rule from this confirmed alert. "
        "JSON keys: name, yaml_text. yaml_text must include id, name, enabled, source, "
        "event_type, severity, auto_respond, match, actions, description. "
        "Do not include payloads or exploit content.\n"
        f"alert={json.dumps(alert, ensure_ascii=False)[:1500]}\n"
        f"event={json.dumps(event or {}, ensure_ascii=False)[:1500]}"
    )
    data = await _complete(prompt)
    if not data or not data.get("yaml_text"):
        return base
    return {
        "name": data.get("name") or base["name"],
        "yaml_text": data["yaml_text"],
        "origin": "llm",
    }


def _to_yaml(rule: dict[str, Any]) -> str:
    import yaml

    return yaml.safe_dump(rule, allow_unicode=True, sort_keys=False)
