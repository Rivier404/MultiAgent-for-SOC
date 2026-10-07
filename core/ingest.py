from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path
from typing import Any, Iterable

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".ndjson", ".csv", ".log", ".txt"}
WRAPPER_KEYS = ("events", "alerts", "data", "items", "records", "results")


def _objects_from_json(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        for key in WRAPPER_KEYS:
            wrapped = value.get(key)
            if isinstance(wrapped, list) and all(isinstance(x, dict) for x in wrapped):
                return [dict(x) for x in wrapped]
        return [value]
    if isinstance(value, list):
        return [dict(x) for x in value if isinstance(x, dict)]
    return []


def parse_text(text: str, suffix: str = "") -> list[dict[str, Any]]:
    text = text.lstrip("\ufeff")
    if not text.strip():
        return []

    try:
        return _objects_from_json(json.loads(text))
    except json.JSONDecodeError:
        pass

    jsonl: list[dict[str, Any]] = []
    non_json_lines: list[str] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            non_json_lines.append(raw)
            continue
        jsonl.extend(_objects_from_json(obj))
    if jsonl and len(jsonl) >= max(1, len(non_json_lines)):
        return jsonl

    if suffix.lower() == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        return [{str(k): v for k, v in row.items()} for row in reader]

    return [{"raw_log": line.strip()} for line in text.splitlines() if line.strip()]


def load_path(path: Path) -> list[dict[str, Any]]:
    if path.is_dir():
        events: list[dict[str, Any]] = []
        for child in sorted(p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in SUPPORTED_SUFFIXES):
            events.extend(load_path(child))
        return events
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    return parse_text(text, path.suffix)


def load_inputs(inputs: Iterable[str], limit: int = 0) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for raw in inputs:
        if raw == "-":
            events = parse_text(sys.stdin.read())
            label = "stdin"
        else:
            p = Path(raw).expanduser().resolve()
            events = load_path(p)
            label = str(p)
        for event in events:
            out.append((label, event))
            if limit > 0 and len(out) >= limit:
                return out
    return out
