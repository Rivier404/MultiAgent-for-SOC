from __future__ import annotations

import json
from typing import Any

RUBRIC_TEXT = """
0-2 LOW: no or near-zero system impact. Examples: reconnaissance, benign command,
failed attack, suspicious activity without demonstrated impact.
3-5 MEDIUM: attacker performed an action on the system but has not achieved
significant control. Examples: malicious process execution, user-level code
execution, creation/execution of a malicious file, limited configuration change.
6-8 HIGH: attacker has significant control. Examples: privilege escalation,
persistence, credential access, SYSTEM/root execution, established C2, successful
lateral movement.
9-10 CRITICAL: severe organizational/system impact. Examples: domain compromise,
ransomware, mass data exfiltration, destructive data loss, broad security-control
disablement, compromise of multiple critical assets.
""".strip()


def clamp_score(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0
    if number != number:
        return 0
    return int(max(0, min(10, round(number))))


def severity_from_score(score: int | float) -> str:
    s = clamp_score(score)
    if s <= 2:
        return "LOW"
    if s <= 5:
        return "MEDIUM"
    if s <= 8:
        return "HIGH"
    return "CRITICAL"


def _weak_without_demonstrated_impact(raw_event: Any) -> bool:
    try:
        text = json.dumps(raw_event, ensure_ascii=False).lower()
    except Exception:
        text = str(raw_event).lower()
    weak = (
        "failed", "failure", "recon", "reconnaissance", "scan", "benign",
        "blocked", "denied", "unsuccessful", "no impact", "single failed logon",
    )
    demonstrated = (
        "malicious process", "code execution", "executed malicious", "malicious file",
        "configuration changed", "privilege escalation", "persistence", "credential access",
        "system/root", "system privileges", "root execution", "c2 established",
        "lateral movement successful", "domain compromise", "ransomware", "encrypted files",
        "mass data exfil", "data exfiltration", "destroyed data", "destructive data",
        "security controls disabled", "multiple critical assets",
    )
    return any(x in text for x in weak) and not any(x in text for x in demonstrated)


def validate_ai_impact_score(value: Any, verdict: str, evidence: list[str], raw_event: Any | None = None) -> int:
    score = clamp_score(value)
    if not evidence or verdict in {"benign", "insufficient_evidence"}:
        return min(score, 2)
    if raw_event is not None and _weak_without_demonstrated_impact(raw_event):
        return min(score, 2)
    return score
