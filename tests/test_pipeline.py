from __future__ import annotations

import json
from pathlib import Path

from agents import ADAgent, EndpointAgent, NetworkAgent, WebAgent
from core.event_ids import load_event_ids
from core.impact import severity_from_score
from core.ingest import load_path
from llm_client import LLMError, OllamaClient, OpenAICompatibleClient, _parse_json_object, build_client_for_role
from orchestrator import SOCOrchestrator
from rag.engine import RAGEngine

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_KEYS = {
    "agent", "event_code", "impact_score", "severity", "verdict", "reasoning",
    "evidence", "recommended_actions", "playbook_references",
}


def assert_schema(result: dict) -> None:
    assert set(result) == EXPECTED_KEYS
    assert isinstance(result["impact_score"], int)
    assert 0 <= result["impact_score"] <= 10
    assert result["severity"] == severity_from_score(result["impact_score"])
    assert result["verdict"] in {"benign", "suspicious", "malicious", "insufficient_evidence"}
    assert "react_trace" not in result
    assert "is_false_positive" not in result


def test_qwen_upgraded_to_7b():
    assert OllamaClient().model == "qwen2.5:7b"


def test_rag_contains_only_selected_json_playbooks():
    rag = RAGEngine()
    assert rag.playbook_ids() == [
        "IRP-AccountCompromised", "IRP-Critical", "IRP-DataLoss",
        "IRP-Malware", "IRP-Phishing", "IRP-Ransom",
    ]
    assert set(rag.count_by_kind()) == {"playbook", "nist", "attack", "sigma"}
    assert not any(d.get("source_kind") == "product" for d in rag._docs)


def test_event_catalog_has_microsoft_provenance():
    catalog = load_event_ids()
    assert "4625" in catalog and "4688" in catalog
    for eid, meta in catalog.items():
        assert meta["source"] == "Microsoft Learn"
        assert "learn.microsoft.com" in meta["source_url"]
        assert f"event-{eid}" in meta["source_url"]


def test_ingestion_is_not_limited_to_two_events(tmp_path: Path):
    p = tmp_path / "many.json"
    p.write_text(json.dumps([{"raw_log": f"event {i}"} for i in range(7)]), encoding="utf-8")
    events = load_path(p)
    assert len(events) == 7


def test_ad_valid_id_authoritative_and_ai_low_score_for_failed_logon():
    event = {"event_code": 4625, "description": "single failed logon", "username": "alice"}
    result = ADAgent(mode="mock").run_one(event)
    assert_schema(result)
    assert result["event_code"] == "4625"
    assert result["impact_score"] <= 2
    assert result["severity"] == "LOW"


def test_endpoint_valid_id():
    event = {"event_code": 4688, "description": "new process created", "process": "cmd.exe"}
    result = EndpointAgent(mode="mock").run_one(event)
    assert_schema(result)
    assert result["event_code"] == "4688"
    assert result["impact_score"] <= 2


def test_invalid_event_id_becomes_null():
    result = ADAgent(mode="mock").run_one({"event_code": 99999, "description": "failed logon"})
    assert_schema(result)
    assert result["event_code"] is None



def test_sigma_candidate_is_not_automatically_authoritative():
    result = EndpointAgent(mode="mock").run_one({"event_code": 7045, "description": "service installation candidate"})
    assert_schema(result)
    assert result["event_code"] is None


def test_network_and_web_never_get_windows_event_ids():
    n = NetworkAgent(mode="mock").run_one({"event_code": 4625, "source_ip": "10.0.0.1", "dest_port": 443, "raw_log": "conn_state=SF"})
    w = WebAgent(mode="mock").run_one({"event_code": 4688, "uri": "/", "raw_log": "method=GET status_code=200"})
    assert_schema(n); assert_schema(w)
    assert n["event_code"] is None
    assert w["event_code"] is None


class HallucinatingLLM:
    def chat_json(self, system: str, user: str) -> dict:
        return {
            "event_code": "9999",
            "impact_score": 10,
            "verdict": "malicious",
            "reasoning": "Invented compromise.",
            "evidence": ["failed logon observed"],
            "recommended_actions": ["Erase the whole host"],
            "playbook_references": ["IRP-Fake/README.md"],
            "recommendation_sources": ["IRP-Fake/README.md"],
        }


def test_hallucinated_event_id_playbook_and_unrelated_action_are_removed():
    event = {"event_code": 4625, "description": "failed logon observed"}
    result = ADAgent(mode="ollama", llm=HallucinatingLLM()).run_one(event)
    assert_schema(result)
    assert result["event_code"] == "4625"
    assert result["playbook_references"] == []
    assert result["recommended_actions"] == []
    assert result["impact_score"] <= 2


class RansomwareLLM:
    def chat_json(self, system: str, user: str) -> dict:
        if "REACT-LITE PLANNING" in system:
            return {"observations": [], "retrieval_queries": ["ransomware encrypted files"], "verification_questions": []}
        return {
            "impact_score": 9,
            "verdict": "malicious",
            "reasoning": "Telemetry states ransomware encrypted files on multiple critical assets.",
            "evidence": ["ransomware encrypted files on multiple critical assets"],
            "recommended_actions": [],
            "playbook_references": [],
            "recommendation_sources": [],
        }


def test_ai_can_assign_critical_impact_when_grounded():
    event = {"description": "ransomware encrypted files on multiple critical assets", "host": "srv-critical"}
    result = EndpointAgent(mode="ollama", llm=RansomwareLLM()).run_one(event)
    assert_schema(result)
    assert result["impact_score"] == 9
    assert result["severity"] == "CRITICAL"
    assert result["verdict"] == "malicious"


def test_score_bands():
    expected = {0:"LOW", 2:"LOW", 3:"MEDIUM", 5:"MEDIUM", 6:"HIGH", 8:"HIGH", 9:"CRITICAL", 10:"CRITICAL"}
    for score, severity in expected.items():
        assert severity_from_score(score) == severity



def test_multi_api_factory_builds_distinct_domain_models_and_local_correlation(monkeypatch):
    monkeypatch.setenv("SOC_AD_API_URL", "https://ad.example/v1/chat/completions")
    monkeypatch.setenv("SOC_AD_API_KEY", "ad-secret")
    monkeypatch.setenv("SOC_AD_MODEL", "ad-model")
    monkeypatch.setenv("SOC_ENDPOINT_API_URL", "https://endpoint.example/v1/chat/completions")
    monkeypatch.setenv("SOC_ENDPOINT_API_KEY", "endpoint-secret")
    monkeypatch.setenv("SOC_ENDPOINT_MODEL", "endpoint-model")
    monkeypatch.setenv("SOC_NETWORK_API_URL", "https://network.example/v1/chat/completions")
    monkeypatch.setenv("SOC_NETWORK_API_KEY", "network-secret")
    monkeypatch.setenv("SOC_NETWORK_MODEL", "network-model")
    monkeypatch.setenv("CORRELATION_OLLAMA_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("CORRELATION_OLLAMA_MODEL", "qwen2.5:7b")
    for name in ("SOC_WEB_PROVIDER", "SOC_WEB_API_URL", "SOC_WEB_MODEL", "SOC_WEB_OLLAMA_URL"):
        monkeypatch.delenv(name, raising=False)

    orch = SOCOrchestrator(mode="multi_api", rag=RAGEngine())
    topology = orch.model_topology()

    assert topology["ad"]["model"] == "ad-model"
    assert topology["endpoint"]["model"] == "endpoint-model"
    assert topology["network"]["model"] == "network-model"
    assert topology["web"]["model"] == "network-model"
    assert topology["web"]["endpoint"] == "https://network.example/v1/chat/completions"
    assert topology["correlation"]["provider"] == "ollama"
    assert topology["correlation"]["model"] == "qwen2.5:7b"
    assert topology["correlation"]["local"] is True
    assert all("api_key" not in info for info in topology.values())


class TaggedLLM:
    def __init__(self, tag: str):
        self.tag = tag
        self.model = f"{tag}-model"
        self.calls = 0

    def describe(self):
        return {"provider": "test", "model": self.model, "endpoint": self.tag, "local": self.tag == "correlation"}

    def chat_json(self, system: str, user: str) -> dict:
        self.calls += 1
        if "REACT-LITE PLANNING" in system:
            return {"observations": [], "retrieval_queries": [], "verification_questions": []}
        if self.tag == "correlation":
            return {
                "impact_score": 1,
                "verdict": "insufficient_evidence",
                "reasoning": "No grounded cross-event progression is established.",
                "evidence": [],
                "recommended_actions": [],
                "playbook_references": [],
                "recommendation_sources": [],
            }
        return {
            "impact_score": 1,
            "verdict": "insufficient_evidence",
            "reasoning": f"{self.tag} specialist found insufficient grounded evidence.",
            "evidence": [],
            "recommended_actions": [],
            "playbook_references": [],
            "recommendation_sources": [],
        }


def test_orchestrator_routes_each_domain_to_its_own_client_then_correlation():
    clients = {name: TaggedLLM(name) for name in ("ad", "endpoint", "network", "web", "correlation")}
    orch = SOCOrchestrator(mode="multi_api", rag=RAGEngine(), clients=clients)

    orch.process({"event_code": 4625, "description": "single failed logon"}, source_hint="ad")
    orch.process({"event_code": 4688, "description": "new process"}, source_hint="endpoint")
    orch.process({"source_ip": "10.0.0.1", "dest_port": 443}, source_hint="network")
    orch.process({"method": "GET", "uri": "/", "status_code": 200}, source_hint="web")

    assert clients["ad"].calls == 2
    assert clients["endpoint"].calls == 2
    assert clients["network"].calls == 2
    assert clients["web"].calls == 2
    assert clients["correlation"].calls == 0

    correlation = orch.correlate()
    assert clients["correlation"].calls == 1
    assert correlation["agent"] == "CorrelationAgent"


def test_json_parsing_with_think_tags_and_fences():
    raw = "<think>Analyzing user event...</think>\n```json\n{\"impact_score\": 7, \"verdict\": \"suspicious\"}\n```"
    parsed = _parse_json_object(raw)
    assert parsed["impact_score"] == 7
    assert parsed["verdict"] == "suspicious"

    surrounded = "Here is your output:\n{\"impact_score\": 2}\nHope this helps!"
    assert _parse_json_object(surrounded) == {"impact_score": 2}

    raised_none = False
    try:
        _parse_json_object(None)
    except LLMError:
        raised_none = True
    assert raised_none

    raised_empty = False
    try:
        _parse_json_object("")
    except LLMError:
        raised_empty = True
    assert raised_empty


def test_openai_client_url_normalization():
    client = OpenAICompatibleClient(url="https://api.cerebras.ai/v1", model="llama-3.3-70b")
    assert client.url == "https://api.cerebras.ai/v1/chat/completions"


def test_web_agent_keeps_dedicated_config_when_provided(monkeypatch):
    monkeypatch.setenv("SOC_NETWORK_API_URL", "https://net.example/v1/chat/completions")
    monkeypatch.setenv("SOC_NETWORK_MODEL", "net-model")
    monkeypatch.setenv("SOC_WEB_PROVIDER", "openrouter")
    monkeypatch.setenv("SOC_WEB_MODEL", "web-model")
    client = build_client_for_role("web", mode="multi_api")
    assert client.model == "web-model"
    assert client.provider == "openrouter"


def test_overall_source_catalog_and_routing():
    import api_server

    sources = api_server.data_sources()
    assert "overall" in sources
    assert sources["overall"]["exists"] is True
    file_names = [f["name"] for f in sources["overall"]["files"]]
    assert "multi_events.json" in file_names

    assert api_server.source_hint("overall") is None
    assert api_server.source_hint("demo") is None
    overall_dirs = api_server._resolve_source_dirs("overall")
    assert len(overall_dirs) == 1 and str(ROOT / "data" / "demo") == overall_dirs[0]

    all_dirs = api_server._resolve_source_dirs("all")
    assert str(ROOT / "data" / "demo") not in all_dirs


def test_overall_analyze_and_batch_execution(monkeypatch):
    monkeypatch.setenv("SOC_MODE", "mock")
    import api_server

    single_ad = api_server.analyze({"source": "overall", "file": "multi_events.json", "index": 0})
    assert single_ad["domain"] == "ad"
    assert single_ad["result"]["agent"] == "ADAgent"

    single_ep = api_server.analyze({"source": "overall", "file": "multi_events.json", "index": 1})
    assert single_ep["domain"] == "endpoint"
    assert single_ep["result"]["agent"] == "EndpointAgent"

    batch = api_server.analyze_batch({"source": "overall", "file": "multi_events.json", "limit": 4})
    assert batch["count"] == 4
    domains = [f["domain"] for f in batch["findings"]]
    assert domains == ["ad", "endpoint", "network", "web"]
    assert batch["correlation"]["agent"] == "CorrelationAgent"


def test_correlation_agent_prompt_and_scenario_synthesis():
    from agents.correlation import CORRELATION_PROMPT, CorrelationAgent

    assert "ATTACK SCENARIO & KILL-CHAIN NARRATIVE" in CORRELATION_PROMPT
    assert "Initial Access & Reconnaissance" in CORRELATION_PROMPT
    assert "Execution" in CORRELATION_PROMPT
    assert "Persistence & Privilege Escalation" in CORRELATION_PROMPT
    assert "Impact & Objectives" in CORRELATION_PROMPT
    assert "Attack Narrative" in CORRELATION_PROMPT

    agent = CorrelationAgent(mode="mock")

    correlated_findings = [
        {
            "domain": "web",
            "event": {"source_ip": "192.168.1.50", "uri": "/login"},
            "result": {"verdict": "suspicious", "impact_score": 4},
        },
        {
            "domain": "endpoint",
            "event": {"source_ip": "192.168.1.50", "process": "malware.exe"},
            "result": {"verdict": "malicious", "impact_score": 7},
        },
    ]
    res = agent.run(correlated_findings)
    assert res["agent"] == "CorrelationAgent"
    assert res["verdict"] == "malicious"
    assert "Attack Scenario Identified" in res["reasoning"]
    assert "192.168.1.50" in res["reasoning"]

    long_narrative = (
        "Phase 1: Initial access was observed from external IP 192.168.1.50 via HTTP probing. "
        "Phase 2: Execution succeeded with process malware.exe spawning under elevated privileges. "
        "Phase 3: Persistence was established via scheduled task creation targeting lab assets. "
        "Phase 4: Impact resulted in widespread encryption and destructive telemetry alteration across critical infrastructure. "
    ) * 3
    assert len(long_narrative) > 700
    mock_raw = {
        "impact_score": 8,
        "verdict": "malicious",
        "reasoning": long_narrative,
        "evidence": ["Phase 1: Initial access was observed"],
        "recommended_actions": [],
        "playbook_references": [],
        "recommendation_sources": [],
    }
    normalized = agent.normalize_result(mock_raw, correlated_findings, [])
    assert len(normalized["reasoning"]) > 700
    assert normalized["reasoning"].startswith("Phase 1: Initial access")





