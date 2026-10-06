from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import yaml

from .config import PATTERNS_DIR


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def load_pattern_file(path) -> dict[str, Any] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("id"):
        return None
    data["enabled"] = bool(data.get("enabled", True))
    data["auto_respond"] = bool(data.get("auto_respond", False))
    data["match"] = data.get("match") or {}
    data["actions"] = _as_list(data.get("actions"))
    data["file"] = path.name
    return data


class PatternStore:
    def __init__(self) -> None:
        self.rules: list[dict[str, Any]] = []
        self._mtime: float = 0.0

    def reload(self, force: bool = False) -> bool:
        PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
        mtimes = [p.stat().st_mtime for p in self._files()]
        latest = max(mtimes) if mtimes else 0.0
        if not force and latest == self._mtime:
            return False
        rules: list[dict[str, Any]] = []
        for path in self._files():
            rule = load_pattern_file(path)
            if rule:
                rules.append(rule)
        self.rules = rules
        self._mtime = latest
        return True

    def enabled(self) -> list[dict[str, Any]]:
        self.reload()
        return [r for r in self.rules if r.get("enabled")]

    def all(self) -> list[dict[str, Any]]:
        self.reload()
        return list(self.rules)

    def _files(self) -> Iterable:
        return sorted(PATTERNS_DIR.glob("*.yaml")) + sorted(PATTERNS_DIR.glob("*.yml"))


store = PatternStore()


def write_approved_pattern(rule_id: str, yaml_text: str) -> str:
    PATTERNS_DIR.mkdir(parents=True, exist_ok=True)
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in rule_id)[:64]
    path = PATTERNS_DIR / f"approved_{safe}.yaml"
    path.write_text(yaml_text.strip() + "\n", encoding="utf-8")
    store.reload(force=True)
    return path.name
