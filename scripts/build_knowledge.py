from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

PLAYBOOKS = {
    "IRP-AccountCompromised": {"domains": ["ad", "endpoint"], "topics": ["account compromise", "credential theft", "authentication", "identity"]},
    "IRP-Malware": {"domains": ["endpoint", "network"], "topics": ["malware", "process execution", "endpoint", "ioc"]},
    "IRP-Phishing": {"domains": ["endpoint", "web", "ad"], "topics": ["phishing", "email", "credential theft", "malicious attachment", "url"]},
    "IRP-Ransom": {"domains": ["endpoint", "ad", "network"], "topics": ["ransomware", "encryption", "lateral movement", "active directory", "backup"]},
    "IRP-DataLoss": {"domains": ["network", "web", "endpoint"], "topics": ["data loss", "exfiltration", "sensitive data", "scope"]},
    "IRP-Critical": {"domains": ["correlation"], "topics": ["critical incident", "incident commander", "escalation", "coordination"]},
}

KEEP_PHASES = {"scope", "2. detect", "3. analyze", "4. contain / eradicate", "5. recover"}
CRITICAL_KEEP = {"ci1 - build a crisis management cell", "ci3 - define communication schedule", "ci4 - return to the playbook"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def clean_markdown(text: str) -> str:
    text = re.sub(r"<\/?details[^>]*>", "", text, flags=re.I)
    text = re.sub(r"<summary>.*?</summary>", "", text, flags=re.I | re.S)
    text = re.sub(r"!\[[^\]]*\]\([^\)]*\)", "", text)
    text = text.replace("[[_TOC_]]", "")
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_sections(md: str) -> list[dict]:
    lines = md.splitlines()
    sections: list[dict] = []
    current = {"level": 0, "heading": "document", "lines": []}
    for line in lines:
        m = re.match(r"^(#{1,4})\s+(.*)$", line.strip())
        if m:
            if current["lines"]:
                sections.append(current)
            current = {"level": len(m.group(1)), "heading": m.group(2).strip(), "lines": []}
        else:
            current["lines"].append(line)
    if current["lines"]:
        sections.append(current)
    return sections


def relevant_sections(playbook_id: str, sections: list[dict]) -> list[dict]:
    out = []
    active_phase = None
    for sec in sections:
        heading = sec["heading"].strip()
        hlow = heading.lower()
        if sec["level"] == 2:
            active_phase = hlow
        keep = False
        if playbook_id == "IRP-Critical":
            keep = hlow in CRITICAL_KEEP or (sec["level"] >= 3 and active_phase in CRITICAL_KEEP)
        else:
            keep = active_phase in KEEP_PHASES
        if not keep:
            continue
        if hlow == "workflow":
            continue
        content = clean_markdown("\n".join(sec["lines"]))
        if len(content) < 20:
            continue
        out.append({"heading": heading, "level": sec["level"], "content": content})
    return out


def build_playbooks(source_root: Path, out_path: Path, archive_sha256: str | None) -> None:
    documents = []
    for playbook_id, routing in PLAYBOOKS.items():
        p = source_root / playbook_id / "README.md"
        if not p.exists():
            raise FileNotFoundError(p)
        md = p.read_text(encoding="utf-8", errors="ignore")
        sections = relevant_sections(playbook_id, parse_sections(md))
        title = next((s["heading"] for s in parse_sections(md) if s["level"] == 1), playbook_id)
        documents.append({
            "playbook_id": playbook_id,
            "title": title,
            "source_path": f"{playbook_id}/README.md",
            "source_sha256": sha256(p),
            "source_repository": "https://github.com/socfortress/Playbooks",
            "source_archive_sha256": archive_sha256,
            "domains": routing["domains"],
            "topics": routing["topics"],
            "normalization": "verbatim_selected_sections_with_markup_removed",
            "sections": sections,
        })
    payload = {
        "schema_version": 1,
        "selection_policy": "Only six incident-response playbooks relevant to the AD, endpoint, network, web and correlation agents are retained. Preparation-only, binary workflow images, empty product files, templates and repository-only documents are excluded from runtime RAG.",
        "documents": documents,
    }
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def extract_sigma_event_candidates(sigma_root: Path, out_path: Path, archive_sha256: str | None, top_n: int = 80) -> None:
    from collections import Counter, defaultdict
    counts = Counter()
    examples = defaultdict(list)
    for p in sigma_root.rglob("*.yml"):
        if "rules/windows" not in p.as_posix():
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        lines = text.splitlines()
        for idx, line in enumerate(lines):
            if not re.match(r"^\s*EventID\s*:", line):
                continue
            indent = len(line) - len(line.lstrip())
            values = re.findall(r"\b\d{3,5}\b", line.split(":", 1)[1])
            j = idx + 1
            while j < len(lines) and len(lines[j]) - len(lines[j].lstrip()) > indent:
                values.extend(re.findall(r"\b\d{3,5}\b", lines[j]))
                j += 1
            for eid in values:
                counts[eid] += 1
                if len(examples[eid]) < 3:
                    examples[eid].append(str(p.relative_to(sigma_root)))
    candidates = [
        {"event_id": eid, "sigma_rule_count": count, "example_rules": examples[eid]}
        for eid, count in counts.most_common(top_n)
    ]
    out_path.write_text(json.dumps({
        "schema_version": 1,
        "purpose": "Candidate discovery only. Never treat these IDs as authoritative. scripts/update_event_ids_from_microsoft.py keeps an ID only after a Microsoft Learn event page is fetched and parsed successfully.",
        "source_archive_sha256": archive_sha256,
        "candidates": candidates,
    }, ensure_ascii=False, indent=2), encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--playbooks-root", type=Path, required=True)
    ap.add_argument("--sigma-root", type=Path, required=False)
    ap.add_argument("--playbooks-archive-sha256")
    ap.add_argument("--sigma-archive-sha256")
    ap.add_argument("--out-dir", type=Path, default=Path("rag/knowledge"))
    args = ap.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    build_playbooks(args.playbooks_root, args.out_dir / "playbooks.json", args.playbooks_archive_sha256)
    if args.sigma_root:
        extract_sigma_event_candidates(args.sigma_root, args.out_dir / "sigma_event_candidates.json", args.sigma_archive_sha256)


if __name__ == "__main__":
    main()
