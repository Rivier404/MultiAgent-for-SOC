from __future__ import annotations

"""Offline smoke/deployment checks. No network or Ollama connection is required."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.impact import severity_from_score
from core.ingest import load_path
from orchestrator import SOCOrchestrator
from rag.engine import RAGEngine

EXPECTED = {"agent", "event_code", "impact_score", "severity", "verdict", "reasoning", "evidence", "recommended_actions", "playbook_references"}


def run_checks() -> dict:
    rag = RAGEngine()
    assert rag.playbook_ids() == [
        "IRP-AccountCompromised", "IRP-Critical", "IRP-DataLoss",
        "IRP-Malware", "IRP-Phishing", "IRP-Ransom",
    ]
    events = load_path(ROOT / "data" / "demo" / "multi_events.json")
    assert len(events) >= 7
    orch = SOCOrchestrator(mode="mock", rag=rag)
    findings = []
    for event in events:
        domain, result = orch.process(event)
        assert set(result) == EXPECTED
        assert result["severity"] == severity_from_score(result["impact_score"])
        if domain in {"network", "web"}:
            assert result["event_code"] is None
        findings.append({"domain": domain, **result})
    corr = orch.correlate()
    assert set(corr) == EXPECTED
    return {"events": len(events), "findings": findings, "correlation": corr, "rag": rag.count_by_kind()}


def test_deployment_smoke():
    run_checks()


if __name__ == "__main__":
    print(json.dumps(run_checks(), ensure_ascii=False, indent=2))
