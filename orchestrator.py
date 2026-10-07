from __future__ import annotations

from typing import Any

from agents import ADAgent, CorrelationAgent, EndpointAgent, NetworkAgent, WebAgent
from core.normalization import normalize_event
from llm_client import ChatJSONClient, describe_client
from rag.engine import RAGEngine


class SOCOrchestrator:

    AGENTS = {
        "ad": ADAgent,
        "endpoint": EndpointAgent,
        "network": NetworkAgent,
        "web": WebAgent,
    }

    def __init__(
        self,
        mode: str = "mock",
        rag: RAGEngine | None = None,
        clients: dict[str, ChatJSONClient] | None = None,
        batch_mode: bool = False,
    ) -> None:
        self.mode = mode.strip().lower()
        if self.mode not in {"mock", "ollama", "multi_api"}:
            raise ValueError("mode must be mock, ollama, or multi_api")

        self.rag = rag or RAGEngine()
        supplied = dict(clients or {})
        self.agents = {
            domain: cls(mode=self.mode, rag=self.rag, llm=supplied.get(domain), skip_react=batch_mode)
            for domain, cls in self.AGENTS.items()
        }
        self.correlation_agent = CorrelationAgent(
            mode=self.mode,
            rag=self.rag,
            llm=supplied.get("correlation"),
        )
        self._records: list[dict[str, Any]] = []

    def model_topology(self) -> dict[str, dict[str, Any]]:
        if self.mode == "mock":
            return {role: {"provider": "mock", "model": "deterministic_mock", "local": True} for role in [*self.AGENTS, "correlation"]}
        topology = {
            domain: describe_client(agent.llm)
            for domain, agent in self.agents.items()
        }
        topology["correlation"] = describe_client(self.correlation_agent.llm)
        return topology

    def process(self, event: dict[str, Any], source_hint: str | None = None) -> tuple[str, dict[str, Any]]:
        normalized = normalize_event(event, forced_domain=source_hint)
        domain = normalized["domain"]
        if domain not in self.agents:
            result = {
                "agent": "Router",
                "event_code": None,
                "impact_score": 0,
                "severity": "LOW",
                "verdict": "insufficient_evidence",
                "reasoning": "The event domain could not be determined from the supplied telemetry.",
                "evidence": [],
                "recommended_actions": [],
                "playbook_references": [],
            }
        else:
            result = self.agents[domain].run_one(event)

        correlation_keys = {
    "source_ip", "srcip", "dest_ip", "dstip", "dest_port", "dstport",
    "username", "user", "host", "hostname", "process", "image",
    "commandline", "uri", "event_code", "grantedaccess", "properties"
}

        compact_event = {k: v for k, v in event.items() if k in correlation_keys}

        self._records.append({
            "domain": domain,
            "normalized": {k: v for k, v in normalized.items() if k != "raw_event"},
            "event": compact_event,
            "result": result,
        })
        return domain, result

    def correlate(self, findings: dict[str, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
        if self._records:
            return self.correlation_agent.run(self._records)
        return self.correlation_agent.run(findings or {})

    def reset(self) -> None:
        self._records.clear()