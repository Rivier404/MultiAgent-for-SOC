from __future__ import annotations

import re
from typing import Any, Iterable

TOKEN_RE = re.compile(r"[A-Za-z0-9_.:/@+-]{2,}")
STOP = {"the", "and", "for", "from", "with", "that", "this", "was", "were", "are", "is", "to", "of", "a", "an", "on", "in", "by", "it", "not"}


def tokens(text: str) -> set[str]:
    return {x.lower().strip(".,;!?()[]{}\"'") for x in TOKEN_RE.findall(text) if x.lower().strip(".,;!?()[]{}\"'") not in STOP}


def source_text(event: dict[str, Any]) -> str:
    return str(event)


def grounded_statement(statement: str, event: dict[str, Any], threshold: float = 0.22) -> bool:
    st = tokens(statement)
    if not st:
        return False
    ev = tokens(source_text(event))
    overlap = len(st & ev) / max(1, len(st))
    return overlap >= threshold


def dedupe_grounded(statements: Iterable[Any], event: dict[str, Any], limit: int = 8) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in statements:
        text = str(raw).strip()
        key = text.casefold()
        if not text or key in seen:
            continue
        if grounded_statement(text, event):
            out.append(text)
            seen.add(key)
        if len(out) >= limit:
            break
    return out


def action_grounded(action: str, source_text_block: str, threshold: float = 0.18) -> bool:
    a = tokens(action)
    s = tokens(source_text_block)
    if not a or not s:
        return False
    overlap = len(a & s) / max(1, len(a))
    return overlap >= threshold


def _resolve_source_text(source_id: str | None, sources_by_id: dict[str, str]) -> str | None:
    if not source_id:
        return None
    if source_id in sources_by_id:
        return sources_by_id[source_id]
    sid_lower = source_id.lower().strip()
    for k, text in sources_by_id.items():
        k_lower = k.lower().strip()
        if sid_lower in k_lower or k_lower in sid_lower:
            return text
    return None


def keep_grounded_actions(actions: Iterable[Any], sources_by_id: dict[str, str], result_sources: dict[int, str], limit: int = 8) -> list[str]:
    kept: list[str] = []
    all_source_texts = list(sources_by_id.values())
    for idx, raw in enumerate(actions):
        action = str(raw).strip()
        if not action:
            continue
        source_id = result_sources.get(idx)
        source = _resolve_source_text(source_id, sources_by_id)
        if source and action_grounded(action, source):
            kept.append(action)
        elif any(action_grounded(action, s) for s in all_source_texts):
            kept.append(action)
        if len(kept) >= limit:
            break
    return kept



