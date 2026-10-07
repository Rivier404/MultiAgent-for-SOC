from __future__ import annotations

from typing import Any

from .event_ids import validate_event_id
from .grounding import dedupe_grounded, keep_grounded_actions

VALID_VERDICTS = {"benign", "suspicious", "malicious", "insufficient_evidence"}
VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
WEAK_ONLY_MARKERS = {
    "4625": "single failed authentication",
    "4688": "single process creation",
}


def normalize_references(raw_refs: Any, valid_context: dict[str, dict[str, Any]]) -> list[str]:
    if not isinstance(raw_refs, list):
        raw_refs = [] if raw_refs in (None, "") else [raw_refs]
    kept: list[str] = []
    for raw in raw_refs:
        ref = str(raw).strip()
        if not ref:
            continue
        base = ref.split("#", 1)[0]
        if ref in valid_context:
            kept.append(ref)
        elif base in valid_context:
            kept.append(base)
        else:
            if ref in {str(x.get("playbook_id")) for x in valid_context.values() if x.get("playbook_id")}:
                matching = next(x.get("source") for x in valid_context.values() if x.get("playbook_id") == ref)
                if matching and matching not in kept:
                    kept.append(str(matching))
    return list(dict.fromkeys(kept))[:8]


def validate_verdict(verdict: Any, evidence: list[str], event_code: str | None, raw_event: dict[str, Any]) -> str:
    value = str(verdict or "insufficient_evidence").strip().lower()
    if value not in VALID_VERDICTS:
        value = "insufficient_evidence"
    if not evidence:
        return "insufficient_evidence"
    if value == "malicious":
        description = str(raw_event.get("description") or raw_event.get("message") or raw_event.get("raw_log") or "").lower()
        if event_code == "4625" and not any(marker in description for marker in ("multiple", "repeated", "correlation", "same source", "same account")):
            return "suspicious"
        if event_code == "4688" and not any(marker in description for marker in ("malicious", "suspicious", "encoded", "unsigned", "parent-child", "correlation")):
            return "suspicious"
        if any(term in description for term in ("powershell", "port 443", "https", "http request")) and len(evidence) < 2:
            return "suspicious"
    return value


def validate_severity(value: Any, verdict: str) -> str:
    severity = str(value or "LOW").upper()
    if severity not in VALID_SEVERITIES:
        severity = "LOW"
    if verdict == "insufficient_evidence":
        return "LOW" if severity not in {"HIGH", "CRITICAL"} else "MEDIUM"
    return severity


def validate_event_code(domain: str, authoritative_code: str | None) -> str | None:
    if authoritative_code is None:
        return None
    code, _ = validate_event_id(domain, authoritative_code)
    return code


def validate_evidence(raw_evidence: Any, event: dict[str, Any]) -> list[str]:
    if not isinstance(raw_evidence, list):
        raw_evidence = [] if raw_evidence in (None, "") else [raw_evidence]
    return dedupe_grounded(raw_evidence, event, limit=8)


def validate_actions(raw_actions: Any, valid_sources: dict[str, str], raw_action_sources: Any) -> list[str]:
    if not isinstance(raw_actions, list):
        raw_actions = [] if raw_actions in (None, "") else [raw_actions]
    source_map: dict[int, str] = {}
    if isinstance(raw_action_sources, list):
        for idx, source in enumerate(raw_action_sources):
            if source not in (None, ""):
                source_map[idx] = str(source)
    return keep_grounded_actions(raw_actions, valid_sources, source_map, limit=8)
