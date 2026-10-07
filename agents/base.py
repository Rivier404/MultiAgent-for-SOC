from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

from core.impact import severity_from_score, validate_ai_impact_score
from core.normalization import normalize_event
from core.validation import normalize_references, validate_actions, validate_evidence, validate_verdict
from llm_client import ChatJSONClient, LLMError, build_client_for_role
from rag.engine import RAGEngine


class BaseSOCAgent:

    name = "BaseSOCAgent"
    log_type = "unknown"
    system_prompt = ""

    def __init__(self, llm: ChatJSONClient | None = None, rag: RAGEngine | None = None, mode: str = "ollama", skip_react: bool = False) -> None:
        self.llm = llm or build_client_for_role(self.log_type, mode=mode)
        self.rag = rag or RAGEngine()
        self.mode = mode
        self.skip_react = skip_react
        self.last_react_trace: list[dict[str, Any]] = []
        self.last_score_debug: dict[str, Any] = {}

    @staticmethod
    def _flatten_values(value: Any, prefix: str = "", depth: int = 0) -> list[str]:
        if depth > 3:
            return []
        out: list[str] = []
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, (dict, list)):
                    out.extend(BaseSOCAgent._flatten_values(v, f"{prefix}.{k}" if prefix else str(k), depth + 1))
                elif v not in (None, ""):
                    out.append(f"{k}={v}")
        elif isinstance(value, list):
            for item in value[:30]:
                out.extend(BaseSOCAgent._flatten_values(item, prefix, depth + 1))
        elif value not in (None, ""):
            out.append(str(value))
        return out

    @staticmethod
    def _event_query(event: dict[str, Any], normalized: dict[str, Any]) -> str:
        values = [str(normalized.get("domain", "")), str(normalized.get("event_type", ""))]
        if normalized.get("event_code"):
            values.append(str(normalized["event_code"]))
        values.extend(BaseSOCAgent._flatten_values(event))
        return " ".join(values)[:20000].strip()

    @staticmethod
    def _format_hits(hits: list[Any]) -> str:
        if not hits:
            return "(no relevant source material retrieved)"
        blocks = []
        for hit in hits:
            md = hit.metadata or {}
            blocks.append(
                f"SOURCE_ID: {hit.id}\n"
                f"SOURCE_PATH: {md.get('source', hit.id)}\n"
                f"SOURCE_KIND: {md.get('source_kind', 'unknown')}\n"
                f"PLAYBOOK_ID: {md.get('playbook_id') or 'none'}\n"
                f"SECTION: {md.get('section') or 'n/a'}\n"
                f"SCORE: {hit.score}\n"
                f"CONTENT:\n{hit.description[:1500]}"
            )
        return "\n\n---\n\n".join(blocks)

    def _react_plan(self, normalized: dict[str, Any], initial_hits: list[Any]) -> dict[str, Any]:
        user = (
            "OBSERVE THIS NORMALIZED EVENT:\n" + json.dumps({k: v for k, v in normalized.items() if k != "raw_event"}, ensure_ascii=False, indent=2)
            + "\n\nINITIAL RETRIEVAL:\n" + self._format_hits(initial_hits)
            + "\n\nReturn JSON only: {\"observations\": [...], \"retrieval_queries\": [...], \"verification_questions\": [...]}"
        )
        result = self.llm.chat_json(
            self.system_prompt + "\nREACT-LITE PLANNING: use short retrieval phrases only; never invent facts, Event IDs, IOCs or playbook names.",
            user,
        )
        return {
            "observations": [str(x) for x in result.get("observations", [])][:5],
            "retrieval_queries": [str(x) for x in result.get("retrieval_queries", []) if str(x).strip()][:3],
            "verification_questions": [str(x) for x in result.get("verification_questions", [])][:5],
        }

    def _react_retrieve(self, event: dict[str, Any], normalized: dict[str, Any], initial_hits: list[Any]) -> tuple[list[Any], list[dict[str, Any]]]:
        raw_query = self._event_query(event, normalized)
        all_hits = {h.id: h for h in initial_hits}
        queries = [raw_query]
        trace: list[dict[str, Any]] = [{"step": "OBSERVE", "observation": "Normalized telemetry and validated any Event ID before retrieval."}]

        if self.mode != "mock" and not self.skip_react:
            try:
                plan = self._react_plan(normalized, initial_hits)
                queries.extend(plan["retrieval_queries"])
                trace.append({"step": "RETRIEVE", "query_count": len(queries)})
                trace.append({"step": "VALIDATE", "verification_questions": plan["verification_questions"]})
            except Exception:
                trace.append({"step": "RETRIEVE", "query_count": 1})
        else:
            trace.append({"step": "RETRIEVE", "query_count": 1})

        for q in queries[:4]:
            for hit in self.rag.search(self.log_type, q, k=5):
                all_hits[hit.id] = hit
        for hit in self.rag.search_playbooks(self.log_type, raw_query + " " + " ".join(queries[1:4]), k=5):
            all_hits[hit.id] = hit

        ranked = sorted(all_hits.values(), key=lambda x: x.score, reverse=True)
        ranked = [h for h in ranked if h.score >= self.rag.relevance_threshold]
        trace.append({"step": "VALIDATE", "relevant_hits": len(ranked), "threshold": self.rag.relevance_threshold})
        return ranked[:6], trace

    def build_rag_context(self, event: dict[str, Any], normalized: dict[str, Any]) -> tuple[list[Any], list[dict[str, Any]]]:
        query = self._event_query(event, normalized)
        initial_hits = self.rag.search(self.log_type, query, k=5)
        return self._react_retrieve(event, normalized, initial_hits)

    @staticmethod
    def _valid_context(hits: list[Any]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        context: dict[str, dict[str, Any]] = {}
        sources_by_id: dict[str, str] = {}
        for hit in hits:
            source = str(hit.metadata.get("source", hit.id))
            for key in (source, hit.id):
                context[key] = dict(hit.metadata)
                context[key]["source"] = source
                sources_by_id[key] = hit.description
        return context, sources_by_id

    def _llm_final(self, event: dict[str, Any], normalized: dict[str, Any], hits: list[Any]) -> dict[str, Any]:
        user = (
            "INPUT EVENT (untrusted raw telemetry; do not modify facts):\n" + json.dumps(event, ensure_ascii=False, indent=2)
            + "\n\nNORMALIZED/VALIDATED METADATA:\n" + json.dumps({k: v for k, v in normalized.items() if k != "raw_event"}, ensure_ascii=False, indent=2)
            + "\n\nRETRIEVED RAG CONTEXT:\n" + self._format_hits(hits)
            + "\n\nReturn JSON only. impact_score MUST be an integer 0-10 based on demonstrated impact, not intent or tool reputation."
            + "\nFor each recommended action, return a parallel internal recommendation_sources array containing the exact SOURCE_ID or SOURCE_PATH that supports it."
        )
        return self.llm.chat_json(self.system_prompt, user)

    @staticmethod
    def _mock_score(text: str) -> int:
        t = text.lower()
        if any(x in t for x in ("domain compromise", "ransomware", "mass data exfil", "destroyed data", "multiple critical assets", "widespread security controls disabled")):
            return 9
        if any(x in t for x in ("privilege escalation", "persistence", "credential access", "system privileges", "root execution", "c2 established", "lateral movement successful")):
            return 7
        if any(x in t for x in ("malicious process", "code execution", "executed malicious", "created malicious", "configuration changed")):
            return 4
        return 1

    @classmethod
    def _mock_llm(cls, event: dict[str, Any], normalized: dict[str, Any], hits: list[Any]) -> dict[str, Any]:
        raw = json.dumps(event, ensure_ascii=False)
        t = raw.lower()
        if normalized.get("event_code") == "4625":
            verdict = "insufficient_evidence"
            reasoning = "A failed logon is observed, but the supplied telemetry does not demonstrate successful access or system impact."
        elif normalized.get("event_code") == "4688" and not any(x in t for x in ("malicious", "encoded", "suspicious", "payload")):
            verdict = "insufficient_evidence"
            reasoning = "A process creation event is observed, but the supplied telemetry does not demonstrate malicious execution or impact."
        elif any(x in t for x in ("malicious", "ransomware", "privilege escalation", "c2 established", "lateral movement successful")):
            verdict = "malicious"
            reasoning = "The supplied telemetry contains an explicit adverse-action indicator; impact is scored only from the described outcome."
        elif any(x in t for x in ("failed", "scan", "recon", "suspicious")):
            verdict = "suspicious"
            reasoning = "Suspicious activity is present, but the supplied telemetry does not demonstrate substantial control or impact."
        else:
            verdict = "insufficient_evidence"
            reasoning = "The supplied telemetry does not contain enough grounded evidence for a stronger conclusion."

        evidence: list[str] = []
        for key in ("event_code", "source_ip", "srcip", "dest_ip", "dstip", "dest_port", "dstport", "uri", "url", "process", "command", "username", "user", "message", "description"):
            value = event.get(key)
            if value not in (None, ""):
                evidence.append(f"{key}={value}")
            if len(evidence) >= 5:
                break
        if normalized.get("event_code") and not any(str(normalized["event_code"]) in x for x in evidence):
            evidence.insert(0, f"event_code={normalized['event_code']}")

        refs = [str(h.metadata.get("source")) for h in hits if h.metadata.get("source_kind") == "playbook"][:1]
        actions: list[str] = []
        sources: list[str] = []
        if refs:
            actions = ["Use the retrieved playbook section to validate scope and guide the next response step."]
            sources = [refs[0]]
        return {
            "impact_score": cls._mock_score(raw),
            "verdict": verdict,
            "reasoning": reasoning,
            "evidence": evidence,
            "recommended_actions": actions,
            "playbook_references": refs,
            "recommendation_sources": sources,
        }

    def run_one(self, event: dict[str, Any]) -> dict[str, Any]:
        normalized = normalize_event(event, forced_domain=self.log_type)
        hits, trace = self.build_rag_context(event, normalized)
        self.last_react_trace = trace + [
            {"step": "REASON", "observation": "LLM verdict and impact score constrained to grounded telemetry and retrieved guidance."},
            {"step": "DECIDE", "observation": "Code validates evidence, references, actions and score range before output."},
        ]
        if self.mode == "mock":
            result = self._mock_llm(event, normalized, hits)
        else:
            try:
                result = self._llm_final(event, normalized, hits)
            except LLMError as exc:
                logger.warning("[%s] LLM call failed: %s", self.name, exc)
                result = {
                    "impact_score": 0,
                    "verdict": "insufficient_evidence",
                    "reasoning": "LLM analysis was unavailable; no impact conclusion is made.",
                    "evidence": [],
                    "recommended_actions": [],
                    "playbook_references": [],
                    "recommendation_sources": [],
                    "llm_error": str(exc),
                }
        return self.normalize_result(event, normalized, result, hits)

    def normalize_result(self, event: dict[str, Any], normalized: dict[str, Any], result: dict[str, Any], hits: list[Any]) -> dict[str, Any]:
        event_code = normalized.get("event_code")
        evidence = validate_evidence(result.get("evidence", []), event)
        verdict = validate_verdict(result.get("verdict"), evidence, event_code, event)
        context, sources_by_id = self._valid_context(hits)
        refs = normalize_references(result.get("playbook_references", []), context)
        actions = validate_actions(result.get("recommended_actions", []), sources_by_id, result.get("recommendation_sources", []))

        requested_score = result.get("impact_score", result.get("score", 0))
        score = validate_ai_impact_score(requested_score, verdict, evidence, event)
        severity = severity_from_score(score)
        self.last_score_debug = {"llm_impact_score": requested_score, "validated_impact_score": score, "severity": severity}

        reasoning = str(result.get("reasoning") or "").strip() or "Insufficient grounded reasoning was returned by the model."
        reasoning = reasoning[:600].rstrip()
        out = {
            "agent": self.name,
            "event_code": event_code,
            "impact_score": score,
            "severity": severity,
            "verdict": verdict,
            "reasoning": reasoning,
            "evidence": evidence,
            "recommended_actions": actions,
            "playbook_references": refs,
        }
        if result.get("llm_error"):
            out["llm_error"] = str(result["llm_error"])[:300]
        return out

    def mock_result(self, event: dict[str, Any]) -> dict[str, Any]:
        return self.run_one(event)
