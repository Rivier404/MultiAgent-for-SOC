from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
EVENT_ID_PATH = ROOT / "data" / "event_ids.json"
SUPPORTED_DOMAINS = {"ad", "endpoint"}
OFFICIAL_HOST = "learn.microsoft.com"

_cache: dict[str, dict[str, Any]] = {}
_cache_mtime_ns: int | None = None


def load_event_ids(path: Path | None = None) -> dict[str, dict[str, Any]]:
    target = path or EVENT_ID_PATH
    if not target.exists():
        return {}
    with target.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("Authoritative Event-ID catalog must be a JSON object")
    out: dict[str, dict[str, Any]] = {}
    for key, meta in value.items():
        if not isinstance(meta, dict):
            continue
        event_id = str(key).strip()
        source_url = str(meta.get("source_url") or "")
        if not event_id.isdigit() or urlparse(source_url).hostname != OFFICIAL_HOST:
            continue
        if f"event-{event_id}" not in source_url.lower():
            continue
        out[event_id] = dict(meta)
    return out


def _catalog() -> dict[str, dict[str, Any]]:
    global _cache, _cache_mtime_ns
    try:
        mtime = EVENT_ID_PATH.stat().st_mtime_ns
    except FileNotFoundError:
        mtime = None
    if mtime != _cache_mtime_ns:
        _cache = load_event_ids()
        _cache_mtime_ns = mtime
    return _cache


def validate_event_id(domain: str, value: Any) -> tuple[str | None, dict[str, Any] | None]:
    canonical = str(domain).strip().lower()
    if canonical not in SUPPORTED_DOMAINS or value in (None, ""):
        return None, None
    key = str(value).strip()
    metadata = _catalog().get(key)
    if not metadata:
        return None, None
    allowed = {str(x).lower() for x in metadata.get("domains", [])}
    if canonical not in allowed:
        return None, None
    return key, metadata


def _get_path(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for part in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def extract_event_id_candidate(event: dict[str, Any]) -> str | None:
    candidates: list[Any] = [
        event.get("event_code"), event.get("eventCode"), event.get("event.code"), event.get("EventID"),
        event.get("windows_event_id"), event.get("event_id_windows"),
        _get_path(event, "event", "code"), _get_path(event, "event", "id"),
        _get_path(event, "winlog", "event_id"), _get_path(event, "winlog", "id"), _get_path(event, "winlog", "code"),
        _get_path(event, "win", "system", "eventID"), _get_path(event, "win", "system", "eventId"),
        _get_path(event, "data", "win", "system", "eventID"), _get_path(event, "data", "win", "system", "eventId"),
        _get_path(event, "windows", "event", "event_id"),
    ]
    for value in candidates:
        if value not in (None, "") and str(value).strip().isdigit():
            return str(value).strip()
    return None
