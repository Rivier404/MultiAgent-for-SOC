from __future__ import annotations

import json
import re
from typing import Any

from .event_ids import extract_event_id_candidate, validate_event_id

ALIASES = {
    "ad": "ad", "active_directory": "ad", "active directory": "ad", "windows security": "ad", "windows_security": "ad",
    "endpoint": "endpoint", "windows endpoint": "endpoint", "windows_endpoint": "endpoint", "edr": "endpoint", "sysmon": "endpoint",
    "network": "network", "firewall": "network", "proxy": "network", "dns": "network", "zeek": "network", "ids": "network", "ips": "network",
    "web": "web", "http": "web", "webserver": "web", "waf": "web",
}


def _canonical_domain(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return ALIASES.get(str(value).strip().lower())


def _get_path(obj: dict[str, Any], *path: str) -> Any:
    cur: Any = obj
    for part in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _text(event: dict[str, Any]) -> str:
    try:
        return json.dumps(event, ensure_ascii=False).lower()
    except Exception:
        return str(event).lower()


def detect_domain(event: dict[str, Any], forced_domain: str | None = None) -> str:
    if forced_domain:
        canonical = _canonical_domain(forced_domain)
        if canonical:
            return canonical

    for value in (
        event.get("domain"), event.get("log_source"), event.get("source_type"), event.get("dataset"),
        event.get("event.module"), _get_path(event, "event", "module"), _get_path(event, "rule", "groups"),
    ):
        canonical = _canonical_domain(value)
        if canonical:
            return canonical

    text = _text(event)
    if any(term in text for term in ('"http"', '"uri"', '"url"', 'method=', 'status_code=', 'http_method', 'request_uri', 'webserver', 'waf')):
        return "web"
    if any(term in text for term in ('"winlog"', '"eventid"', 'microsoft-windows-security-auditing', '"win":', '"windows"')):
        if any(term in text for term in ("kerberos", "logon", "account", "credential", "domain controller", "active directory")):
            return "ad"
        return "endpoint"
    if any(term in text for term in ('"srcip"', '"dstip"', '"source_ip"', '"dest_ip"', '"dest_port"', 'conn_state', '"protocol"', '"proto"', 'zeek', 'firewall', 'dns')):
        return "network"
    return "unknown"


def detect_event_type(event: dict[str, Any], domain: str, event_metadata: dict[str, Any] | None) -> str:
    if event_metadata:
        return str(event_metadata.get("category") or "unknown").lower().replace(" ", "_")
    text = _text(event)
    explicit = event.get("event_type") or event.get("event.action") or _get_path(event, "event", "action")
    if domain in {"ad", "endpoint"} and any(x in text for x in ("authentication", "logon", "login", "kerberos", "credential")):
        return "authentication"
    if domain == "endpoint" and any(x in text for x in ("process", "powershell", "cmd.exe", "process_creation", "image")):
        return "process_creation"
    if domain == "network" and any(x in text for x in ("tcp", "udp", "conn_state", "dns", "firewall")):
        return "network_connection"
    if domain == "web" and any(x in text for x in ("http", "get ", "post ", "uri", "status_code", "request")):
        return "http_request"
    return str(explicit or "unknown")


def normalize_event(event: dict[str, Any], forced_domain: str | None = None) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise TypeError("Raw SOC event must be a JSON object")
    domain = detect_domain(event, forced_domain=forced_domain)
    candidate = extract_event_id_candidate(event)
    event_code, metadata = validate_event_id(domain, candidate)
    event_type = detect_event_type(event, domain, metadata)
    event_id = event.get("event_id") or event.get("id") or _get_path(event, "event", "id") or "UNKNOWN"
    return {
        "event_id": str(event_id),
        "domain": domain,
        "event_type": event_type,
        "event_code": event_code,
        "event_code_metadata": metadata,
        "raw_event": event,
    }
