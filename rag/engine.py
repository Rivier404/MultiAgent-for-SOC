from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from .models import RAGResult

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KNOWLEDGE = ROOT / "rag" / "knowledge"
TOKEN_RE = re.compile(r"[a-zA-Z0-9_.:/+-]{2,}")

PLAYBOOK_TRIGGERS = {
    "IRP-AccountCompromised": ("account compromise", "compromised account", "credential", "failed logon", "successful logon", "authentication", "kerberos", "password spray", "brute force"),
    "IRP-Malware": ("malware", "malicious process", "malicious file", "payload", "code execution", "persistence", "privilege escalation", "credential access", "c2 established", "command and control"),
    "IRP-Phishing": ("phishing", "phish", "malicious attachment", "suspicious email", "email link", "credential harvesting"),
    "IRP-Ransom": ("ransomware", "ransom", "encrypted files", "file encryption", "shadow copies", "backup deletion"),
    "IRP-DataLoss": ("data loss", "data exfil", "exfiltration", "sensitive data", "data leak", "stolen data"),
    "IRP-Critical": ("critical incident", "crisis", "incident commander", "multiple critical assets", "domain compromise", "mass data exfil", "widespread security controls"),
}

STOP = {
    "the", "and", "for", "with", "from", "that", "this", "into", "are", "was", "were", "has", "have", "not", "but",
    "event", "events", "system", "security", "incident", "response", "playbook", "source", "observed",
}


class RAGEngine:

    def __init__(self, source_root: str | Path | None = None, relevance_threshold: float = 0.075, playbook_relevance_threshold: float = 0.09) -> None:
        self.source_root = Path(source_root).resolve() if source_root else DEFAULT_KNOWLEDGE
        self.relevance_threshold = float(relevance_threshold)
        self.playbook_relevance_threshold = float(playbook_relevance_threshold)
        self._docs: list[dict[str, Any]] = []
        self._index()

    @staticmethod
    def _tokens(text: str) -> set[str]:
        return {t.lower().strip(".,;!?()[]{}\"'") for t in TOKEN_RE.findall(text) if t.lower() not in STOP}

    def _index(self) -> None:
        self._docs.clear()
        self._index_playbooks(self.source_root / "playbooks.json")
        self._index_nist(self.source_root / "nist_ir.json")
        self._index_attack(self.source_root / "mitre_attack.json")
        self._index_sigma(self.source_root / "sigma_rules.json")

    def _index_playbooks(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for doc in data.get("documents", []):
            pid = str(doc.get("playbook_id") or "")
            source = str(doc.get("source_path") or pid)
            topics = [str(x) for x in doc.get("topics", [])]
            domains = [str(x).lower() for x in doc.get("domains", [])]
            for idx, sec in enumerate(doc.get("sections", []), 1):
                heading = str(sec.get("heading") or "section")
                content = str(sec.get("content") or "").strip()
                if not content:
                    continue
                text = f"{doc.get('title', pid)}\n{heading}\n{content}"
                self._docs.append({
                    "id": f"playbooks.json#{pid}:{idx}",
                    "name": pid,
                    "text": text,
                    "source": f"{source}#{heading}",
                    "source_file": source,
                    "source_kind": "playbook",
                    "playbook_id": pid,
                    "section": heading,
                    "topics": topics,
                    "domains": domains,
                })

    def _index_nist(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        title = str(data.get("source", {}).get("title") or "NIST SP 800-61r3")
        for item in data.get("documents", []):
            iid = str(item.get("id") or "nist")
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            page = item.get("page")
            topics = [str(x) for x in item.get("topics", [])]
            domains = [str(x).lower() for x in item.get("domains", [])]
            self._docs.append({
                "id": f"nist_ir.json#{iid}",
                "name": iid,
                "text": f"{title}\n{' '.join(topics)}\n{content}",
                "source": f"NIST.SP.800-61r3.pdf#page={page}",
                "source_file": "NIST.SP.800-61r3.pdf",
                "source_kind": "nist",
                "playbook_id": None,
                "section": iid,
                "topics": topics,
                "domains": domains,
            })

    def _index_attack(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("documents", []):
            iid = str(item.get("id") or "attack")
            tid = str(item.get("technique_id") or iid)
            name = str(item.get("name") or tid)
            tactic = str(item.get("tactic") or "")
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            topics = [str(x) for x in item.get("topics", [])]
            domains = [str(x).lower() for x in item.get("domains", [])]
            text = f"{name} ({tactic})\n{' '.join(topics)}\n{content}"
            self._docs.append({
                "id": iid,
                "name": name,
                "text": text,
                "source": f"attack.mitre.org#{tid}",
                "source_file": "mitre_attack.json",
                "source_kind": "attack",
                "playbook_id": None,
                "section": tid,
                "topics": topics,
                "domains": domains,
            })

    def _index_sigma(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("documents", []):
            iid = str(item.get("id") or "sigma")
            eid = str(item.get("event_id") or iid)
            name = str(item.get("name") or f"Event {eid}")
            content = str(item.get("content") or "").strip()
            if not content:
                continue
            topics = [str(x) for x in item.get("topics", [])]
            domains = [str(x).lower() for x in item.get("domains", [])]
            text = f"{name}\n{' '.join(topics)}\n{content}"
            self._docs.append({
                "id": iid,
                "name": name,
                "text": text,
                "source": f"sigma-rules#{eid}",
                "source_file": "sigma_rules.json",
                "source_kind": "sigma",
                "playbook_id": None,
                "section": f"Event {eid}",
                "topics": topics,
                "domains": domains,
            })

    @staticmethod
    def _playbook_triggered(query: str, playbook_id: str | None) -> bool:
        if not playbook_id:
            return False
        q = query.lower()
        triggers = PLAYBOOK_TRIGGERS.get(playbook_id, ())
        return any(term in q for term in triggers)

    def _score(self, collection: str, query: str, doc: dict[str, Any]) -> float:
        q = self._tokens(f"{collection} {query}")
        d = self._tokens(doc["text"])
        if not q or not d:
            return 0.0
        overlap = q & d
        if not overlap:
            return 0.0
        coverage = len(overlap) / max(1, len(q))
        rarity_boost = sum(1.0 / math.log(2.5 + len(t)) for t in overlap) / max(1, len(q))
        topic_tokens = self._tokens(" ".join(doc.get("topics", [])))
        topic_match = len(q & topic_tokens) / max(1, len(topic_tokens)) if topic_tokens else 0.0
        domains = set(doc.get("domains", []))
        domain_bonus = 0.16 if collection.lower() in domains else (0.08 if "correlation" in domains else 0.0)
        kind_bonus = 0.05 if doc.get("source_kind") == "playbook" else 0.02
        heading_tokens = self._tokens(str(doc.get("section") or ""))
        heading_bonus = 0.12 * (len(q & heading_tokens) / max(1, len(heading_tokens))) if heading_tokens else 0.0
        return min(1.0, 0.68 * coverage + 0.25 * rarity_boost + 0.25 * topic_match + domain_bonus + kind_bonus + heading_bonus)

    def search(self, collection: str, query: str, k: int = 8, *, playbooks_only: bool = False) -> list[RAGResult]:
        scored: list[RAGResult] = []
        for doc in self._docs:
            if playbooks_only and doc.get("source_kind") != "playbook":
                continue
            if doc.get("source_kind") == "playbook" and not self._playbook_triggered(query, doc.get("playbook_id")):
                continue
            score = self._score(collection, query, doc)
            threshold = self.playbook_relevance_threshold if doc.get("source_kind") == "playbook" else self.relevance_threshold
            if score < threshold:
                continue
            scored.append(RAGResult(
                id=doc["id"], name=doc["name"], description=doc["text"], score=round(score, 4),
                metadata={
                    "source": doc["source"], "source_file": doc["source_file"], "source_kind": doc["source_kind"],
                    "playbook_id": doc.get("playbook_id"), "section": doc.get("section"), "domains": doc.get("domains", []),
                },
            ))
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored[: max(1, int(k))]

    def search_playbooks(self, collection: str, query: str, k: int = 6) -> list[RAGResult]:
        return self.search(collection, query, k=k, playbooks_only=True)

    def search_products(self, collection: str, query: str, k: int = 4) -> list[RAGResult]:
        return []

    def count_by_kind(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self._docs:
            key = str(d.get("source_kind") or "unknown")
            counts[key] = counts.get(key, 0) + 1
        return counts

    def playbook_ids(self) -> list[str]:
        return sorted({str(d["playbook_id"]) for d in self._docs if d.get("playbook_id")})

    def source_context(self, hits: list[RAGResult]) -> dict[str, dict[str, Any]]:
        return {h.id: {**h.metadata, "score": h.score, "text": h.description} for h in hits}
