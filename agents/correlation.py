from __future__ import annotations

import json
from typing import Any

from core.grounding import grounded_statement
from core.impact import RUBRIC_TEXT, severity_from_score, validate_ai_impact_score
from core.validation import normalize_references, validate_actions, validate_verdict
from llm_client import ChatJSONClient, LLMError, build_client_for_role
from rag.engine import RAGEngine

CORRELATION_PROMPT = f"""
You are CorrelationAgent, the senior multi-domain incident correlation specialist in a guarded SOC pipeline.
Your mission is to synthesize already-normalized SOC records from AD, Endpoint, Network, and Web into a comprehensive, coherent ATTACK SCENARIO & KILL-CHAIN NARRATIVE.

Core Operating Principles:
1. Strict Anti-Hallucination: Use ONLY supplied records and retrieved RAG context. Never invent Event IDs, IOCs, usernames, IP addresses, hosts, processes, timestamps, attack outcomes, or playbook references. A playbook is response guidance, never factual evidence that an attack occurred.
2. Cross-Domain Correlation: Identify common pivots (same host, IP address, user account, or session) across domain records. Correlate multiple independent events before asserting progression or incident compromise.
3. Attack Scenario & Kill-Chain Reconstruction:
   Reconstruct the chronological attack progression across MITRE ATT&CK stages:
   - Initial Access & Reconnaissance: How did activity originate (web request, network connection, login attempt)?
   - Execution: What commands or binaries ran on the target host(s)?
   - Persistence & Privilege Escalation: Were scheduled tasks, services, registry keys created, or accounts elevated?
   - Lateral Movement & Command and Control (C2): Were internal pivots or external beacons observed?
   - Impact & Objectives: What was the ultimate impact (ransomware encryption, data exfiltration, system damage)?

4. Reasoning Structure (Attack Narrative):
   The "reasoning" field MUST provide an evidence-grounded Attack Storyline:
   - State clearly if an attack chain is confirmed, or if events are isolated/unrelated.
   - Trace the chronological sequence: [Initial Access] -> [Execution] -> [Persistence/PrivEsc] -> [Impact].
   - Name the affected assets (host, user, IP) and summarize the cumulative threat to the organization.
   - If evidence is weak or disconnected, explain why cross-event progression cannot be confirmed.

5. Evidence Requirements:
   The "evidence" array must list explicit cross-domain links observed in telemetry (e.g. "Event 1 [Web] and Event 2 [Endpoint] share IP 10.10.10.25").
6. Demonstrated impact includes successful execution from web servers, credential theft from memory (LSASS), successful lateral movement, and Active Directory replication manipulation (DCSync), which represent CRITICAL (8-10) system compromise even if destructive ransomware is not yet deployed

AI IMPACT SCORE RUBRIC (score demonstrated cumulative impact across the incident):
{RUBRIC_TEXT}

impact_score is an integer 0-10 measuring cumulative demonstrated impact. If records show no demonstrated impact or are isolated benign/failed events, keep score in 0-2.
Do not expose chain-of-thought or internal ReAct tags.

Return JSON only with:
{{
  "impact_score": 0,
  "verdict": "benign | suspicious | malicious | insufficient_evidence",
  "reasoning": "Comprehensive attack scenario narrative detailing timeline, stages, and affected assets",
  "evidence": ["explicit cross-event correlation facts"],
  "recommended_actions": ["concrete playbook/D3FEND defensive countermeasures"],
  "playbook_references": ["exact retrieved playbook or source paths"],
  "recommendation_sources": ["SOURCE_ID or SOURCE_PATH"]
}}
"""



class CorrelationAgent:
    name = "CorrelationAgent"

    def __init__(self, llm: ChatJSONClient | None = None, rag: RAGEngine | None = None, mode: str = "ollama") -> None:
        self.llm = llm or build_client_for_role("correlation", mode=mode)
        self.rag = rag or RAGEngine()
        self.mode = mode
        self.last_react_trace: list[dict[str, Any]] = []
        self.last_score_debug: dict[str, Any] = {}

    @staticmethod
    def _normalize_records(records_or_findings: Any) -> list[dict[str, Any]]:
        if isinstance(records_or_findings, list):
            return [x for x in records_or_findings if isinstance(x, dict)]
        if isinstance(records_or_findings, dict):
            records = []
            for domain, values in records_or_findings.items():
                if not isinstance(values, list):
                    continue
                for result in values:
                    if isinstance(result, dict):
                        records.append({"domain": domain, "result": result, "event": {}})
            return records
        return []

    def _retrieve(self, records: list[dict[str, Any]]) -> list[Any]:
        compact = json.dumps(records, ensure_ascii=False, separators=(",", ":"))[:30000]
        domains = sorted({str(r.get("domain", "")) for r in records if r.get("domain")})
        query = "correlation incident impact scope " + " ".join(domains) + " " + compact
        hits = self.rag.search("correlation", query, k=4)
        by_id = {h.id: h for h in hits}
        for h in self.rag.search_playbooks("correlation", query, k=3):
            by_id[h.id] = h
        return sorted(by_id.values(), key=lambda x: x.score, reverse=True)[:6]

    @staticmethod
    def _format(hits: list[Any]) -> str:
        return "\n\n---\n\n".join(
            f"SOURCE_ID: {h.id}\nSOURCE_PATH: {h.metadata.get('source', h.id)}\n"
            f"SOURCE_KIND: {h.metadata.get('source_kind')}\nPLAYBOOK_ID: {h.metadata.get('playbook_id') or 'none'}\n"
            f"SECTION: {h.metadata.get('section') or 'n/a'}\nCONTENT:\n{h.description[:2000]}"
            for h in hits
        ) or "(no RAG context)"

    @staticmethod
    def _extract_shared_values(records: list[dict[str, Any]]) -> list[str]:
        interesting = {"source_ip", "srcip", "dest_ip", "dstip", "username", "user", "host", "hostname"}
        values: dict[str, int] = {}
        for r in records:
            event = r.get("event") if isinstance(r.get("event"), dict) else {}
            for k in interesting:
                v = event.get(k)
                if v not in (None, ""):
                    token = f"{k}={v}"
                    values[token] = values.get(token, 0) + 1
        return [k for k, n in values.items() if n >= 2]

    def _mock_llm(self, records: list[dict[str, Any]], hits: list[Any]) -> dict[str, Any]:
        results = [r.get("result", {}) for r in records if isinstance(r.get("result"), dict)]
        active = [x for x in results if x.get("verdict") in {"suspicious", "malicious"}]
        max_score = max([int(x.get("impact_score", 0) or 0) for x in results] or [0])
        shared = self._extract_shared_values(records)
        correlated = len(active) >= 2 and bool(shared)
        verdict = "malicious" if correlated and any(x.get("verdict") == "malicious" for x in active) else ("suspicious" if active else "insufficient_evidence")
        score = min(10, max_score + (1 if correlated else 0)) if active else 0
        evidence = []
        for i, x in enumerate(active[:5], 1):
            evidence.append(f"Finding {i} has verdict={x.get('verdict')} and impact_score={x.get('impact_score', 0)}.")
        if shared:
            evidence.append(f"Multiple supplied events share {shared[0]}.")
        refs = [str(h.metadata.get("source")) for h in hits if h.metadata.get("source_kind") == "playbook"][:1]
        if correlated:
            pivot_info = f"linked by {shared[0]}" if shared else "sharing incident context"
            has_malicious = any(x.get("verdict") == "malicious" for x in active)
            if has_malicious:
                reasoning = (
                    f"Attack Scenario Identified: Multi-stage attack progression observed across {len(active)} active events "
                    f"({pivot_info}). Telemetry demonstrates a coordinated chain progressing from initial access/reconnaissance "
                    f"to host-level execution and operational impact."
                )
            else:
                reasoning = (
                    f"Reconnaissance / Probing Activity Observed: Suspicious probing or scanning activity detected across {len(active)} events "
                    f"({pivot_info}). Telemetry indicates early-stage reconnaissance or failed access attempts; no evidence of successful "
                    f"code execution, persistence, or system compromise was demonstrated."
                )
        else:
            reasoning = "The supplied records do not establish a strong cross-event progression or unified attack scenario."
        return {
            "impact_score": score,
            "verdict": verdict,
            "reasoning": reasoning,
            "evidence": evidence,
            "recommended_actions": ["Use the retrieved playbook section to validate scope and the next response step."] if refs else [],
            "playbook_references": refs,
            "recommendation_sources": refs,
        }

    def run(self, records_or_findings: Any) -> dict[str, Any]:
        records = self._normalize_records(records_or_findings)
        hits = self._retrieve(records)
        self.last_react_trace = [
            {"step": "OBSERVE", "observation": f"Received {len(records)} normalized event records."},
            {"step": "RETRIEVE", "observation": f"Retrieved {len(hits)} relevance-filtered response chunks."},
            {"step": "VALIDATE", "observation": "Correlation uses only supplied events and agent findings."},
        ]
        if self.mode == "mock":
            result = self._mock_llm(records, hits)
        else:
            compact_records = []
            for r in records:
                cr = {**r}
                if isinstance(cr.get("result"), dict):
                    cr["result"] = {k: (v[:200] if isinstance(v, str) else v) for k, v in cr["result"].items()}
                compact_records.append(cr)
            user = "CORRELATION RECORDS:\n" + json.dumps(compact_records, ensure_ascii=False, separators=(",", ":")) + "\n\nRAG CONTEXT:\n" + self._format(hits)
            try:
                result = self.llm.chat_json(CORRELATION_PROMPT, user)
            except LLMError:
                result = {
                    "impact_score": 0,
                    "verdict": "insufficient_evidence",
                    "reasoning": "Correlation LLM was unavailable; no stronger conclusion is made.",
                    "evidence": [],
                    "recommended_actions": [],
                    "playbook_references": [],
                    "recommendation_sources": [],
                }
        return self.normalize_result(result, records, hits)

    def normalize_result(self, result: dict[str, Any], records: list[dict[str, Any]], hits: list[Any]) -> dict[str, Any]:
        for wrapper in ("analysis", "result", "correlation", "incident_response"):
            sub = result.get(wrapper)
            if isinstance(sub, dict):
                for k, v in sub.items():
                    if k not in result or result[k] in (None, "", []):
                        result[k] = v

        raw_evidence = result.get("evidence", [])
        if not isinstance(raw_evidence, list):
            raw_evidence = [] if raw_evidence in (None, "") else [raw_evidence]
        evidence: list[str] = []
        source_obj = {"records": records}
        for item in raw_evidence[:12]:
            text = str(item).strip()
            if text and grounded_statement(text, source_obj, threshold=0.16):
                evidence.append(text)

        verdict = validate_verdict(result.get("verdict"), evidence, None, {"message": json.dumps(records, ensure_ascii=False)})
        context: dict[str, dict[str, Any]] = {}
        sources: dict[str, str] = {}
        for h in hits:
            source = str(h.metadata.get("source", h.id))
            for key in (h.id, source):
                context[key] = dict(h.metadata)
                context[key]["source"] = source
                sources[key] = h.description
        refs = normalize_references(result.get("playbook_references", []), context)
        actions = validate_actions(result.get("recommended_actions", []), sources, result.get("recommendation_sources", []))

        requested = result.get("impact_score", 0)
        score = validate_ai_impact_score(requested, verdict, evidence, records)
        severity = severity_from_score(score)
        self.last_score_debug = {"llm_impact_score": requested, "validated_impact_score": score, "severity": severity}
        reasoning = str(result.get("reasoning") or "").strip()[:2000] or "Insufficient grounded correlation reasoning was returned."
        self.last_react_trace.extend([
            {"step": "REASON", "observation": "LLM correlation is bounded by supplied records and retrieved guidance."},
            {"step": "DECIDE", "observation": "Impact score range and evidence grounding are validated before output."},
        ])
        return {
            "agent": self.name,
            "event_code": None,
            "impact_score": score,
            "severity": severity,
            "verdict": verdict,
            "reasoning": reasoning,
            "evidence": evidence,
            "recommended_actions": actions,
            "playbook_references": refs,
        }

    @classmethod
    def mock_result(cls, findings: Any) -> dict[str, Any]:
        return cls(mode="mock").run(findings)
