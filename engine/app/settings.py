from __future__ import annotations

import json
import threading
from typing import Any

from .config import DATA_DIR

SETTINGS_PATH = DATA_DIR / "settings.json"
_lock = threading.Lock()

DEFAULTS: dict[str, Any] = {
    "resolve_action": "mitigate",
    "http_block_on_resolve": True,
    "windows_process": "confirm",
    "windows_firewall": "confirm",
    "http_auto_respond": True,
    "llm_provider": "auto",
    "openai_api_key": "",
    "gemini_api_key": "",
}

ALLOWED = {
    "resolve_action": {"ack", "mitigate"},
    "windows_process": {"off", "confirm", "execute"},
    "windows_firewall": {"off", "confirm", "execute"},
    "llm_provider": {"auto", "openai", "gemini", "none"},
}


def _normalize(data: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(DEFAULTS)
    if not data:
        return out
    for key, default in DEFAULTS.items():
        value = data.get(key, default)
        if key in ALLOWED:
            value = value if value in ALLOWED[key] else default
        elif isinstance(default, bool):
            value = bool(value)
        elif isinstance(default, str):
            value = "" if value is None else str(value)
        out[key] = value
    return out


def get_settings() -> dict[str, Any]:
    with _lock:
        if SETTINGS_PATH.exists():
            try:
                return _normalize(json.loads(SETTINGS_PATH.read_text(encoding="utf-8")))
            except Exception:
                return dict(DEFAULTS)
        return dict(DEFAULTS)


def save_settings(data: dict[str, Any]) -> dict[str, Any]:
    current = get_settings()
    incoming = dict(data)
    for key in ("openai_api_key", "gemini_api_key"):
        value = incoming.get(key)
        if value in (None, "", "********", "***"):
            incoming.pop(key, None)
    merged = _normalize({**current, **incoming})
    with _lock:
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH.write_text(
            json.dumps(merged, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return merged


def public_settings() -> dict[str, Any]:
    from .config import GEMINI_API_KEY, OPENAI_API_KEY

    raw = get_settings()
    return {
        "resolve_action": raw["resolve_action"],
        "http_block_on_resolve": raw["http_block_on_resolve"],
        "windows_process": raw["windows_process"],
        "windows_firewall": raw["windows_firewall"],
        "http_auto_respond": raw["http_auto_respond"],
        "llm_provider": raw["llm_provider"],
        "openai_key_set": bool(raw.get("openai_api_key") or OPENAI_API_KEY),
        "gemini_key_set": bool(raw.get("gemini_api_key") or GEMINI_API_KEY),
    }
