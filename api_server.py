from __future__ import annotations

"""Optional local HTTP API for the standalone UI.

Install with: pip install -r requirements-api.txt
Run with:     uvicorn api_server:app --host 127.0.0.1 --port 8000
"""

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from core.event_ids import load_event_ids
from core.ingest import load_inputs
from llm_client import LLMError
from orchestrator import SOCOrchestrator
from rag.engine import RAGEngine

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
load_dotenv(ROOT / ".env", override=False)

SOURCE_DIRS = {
    "ad": DATA_DIR / "ad",
    "endpoint": DATA_DIR / "endpoint",
    "network": DATA_DIR / "network",
    "web": DATA_DIR / "web",
    "overall": DATA_DIR / "demo",
}

app = FastAPI(title="AI Multi-Agent SOC API", version="multi-model-api")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in os.getenv("SOC_CORS_ORIGINS", "http://127.0.0.1:8080,http://localhost:8080").split(",") if x.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def mode() -> str:
    value = os.getenv("SOC_MODE", "mock").strip().lower()
    return value if value in {"mock", "ollama", "multi_api"} else "mock"


def source_hint(value: Any) -> str | None:
    value = str(value or "auto").lower()
    if value in {"auto", "overall", "demo", "all"}:
        return None
    if value not in {"ad", "endpoint", "network", "web"}:
        raise HTTPException(400, "source must be auto/ad/endpoint/network/web/overall")
    return value


def _resolve_source_dirs(source: str) -> list[str]:
    source = (source or "all").strip().lower()
    if source == "all":
        return [str(p) for k, p in SOURCE_DIRS.items() if k != "overall" and p.exists()]
    if source not in SOURCE_DIRS:
        raise HTTPException(400, "source must be one of: ad, endpoint, network, web, overall, all")
    p = SOURCE_DIRS[source]
    if not p.exists():
        raise HTTPException(404, f"No data folder found for source '{source}' (expected {p})")
    return [str(p)]


def _resolve_source_file(source: str, filename: str) -> str:
    source = (source or "").strip().lower()
    if source not in SOURCE_DIRS:
        raise HTTPException(400, "source must be one of: ad, endpoint, network, web, overall")
    base = SOURCE_DIRS[source]
    candidate = (base / filename).resolve()
    if base.resolve() not in candidate.parents and candidate != base.resolve():
        raise HTTPException(400, "invalid filename")
    folder_display = "demo" if source == "overall" else source
    if not candidate.exists() or not candidate.is_file():
        raise HTTPException(404, f"File '{filename}' not found under data/{folder_display}/")
    return str(candidate)



def load_events_from_data(source: str, filename: str | None = None, limit: int = 0) -> list[tuple[str, dict[str, Any]]]:
    if filename:
        inputs = [_resolve_source_file(source, filename)]
    else:
        inputs = _resolve_source_dirs(source)
    return load_inputs(inputs, limit=limit)


def build_orchestrator(rag: RAGEngine | None = None, batch_mode: bool = False) -> SOCOrchestrator:
    try:
        return SOCOrchestrator(mode=mode(), rag=rag, batch_mode=batch_mode)
    except (LLMError, ValueError) as exc:
        raise HTTPException(503, f"LLM topology configuration error: {exc}") from exc


@app.get("/health")
def health() -> dict[str, Any]:
    rag = RAGEngine()
    try:
        orch = SOCOrchestrator(mode=mode(), rag=rag)
        topology = orch.model_topology()
        ok = True
        config_error = None
    except (LLMError, ValueError) as exc:
        topology = {}
        ok = False
        config_error = str(exc)
    return {
        "ok": ok,
        "mode": mode(),
        "topology": topology,
        "config_error": config_error,
        "rag": rag.count_by_kind(),
    }


@app.get("/rag/stats")
def rag_stats() -> dict[str, Any]:
    rag = RAGEngine()
    return {"count_by_kind": rag.count_by_kind(), "playbooks": rag.playbook_ids(), "indexed_chunks": len(rag._docs)}


@app.get("/event-ids")
def event_ids() -> dict[str, Any]:
    return load_event_ids()


@app.get("/data/sources")
def data_sources() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for source, folder in SOURCE_DIRS.items():
        if not folder.exists():
            out[source] = {"exists": False, "files": []}
            continue
        files = sorted(
            (
                {"name": p.name, "modified": p.stat().st_mtime}
                for p in folder.rglob("*")
                if p.is_file()
            ),
            key=lambda f: f["modified"],
            reverse=True,
        )
        out[source] = {"exists": True, "file_count": len(files), "files": files}
    return out


@app.post("/analyze")
def analyze(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    source = payload.get("source")
    filename = payload.get("file")
    index = int(payload.get("index", 0) or 0)
    if not source or not filename:
        raise HTTPException(400, "source and file are required, e.g. {'source': 'endpoint', 'file': 'name.jsonl'}")
    hint = source_hint(source)
    loaded = load_events_from_data(source, filename=filename)
    if not loaded:
        folder_display = "demo" if source == "overall" else source
        raise HTTPException(404, f"No events found in data/{folder_display}/{filename}")
    if index < 0 or index >= len(loaded):
        raise HTTPException(400, f"index out of range: file has {len(loaded)} event(s)")
    origin, event = loaded[index]
    orch = build_orchestrator()
    domain, result = orch.process(event, source_hint=hint)
    return {"origin": origin, "domain": domain, "result": result, "model_topology": orch.model_topology()}


@app.post("/analyze/batch")
def analyze_batch(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    source = payload.get("source", "all")
    filename = payload.get("file")
    limit = int(payload.get("limit", 0) or 0)
    if filename and source == "all":
        raise HTTPException(400, "file can only be combined with a specific source, not 'all'")

    loaded = load_events_from_data(source, filename=filename, limit=limit)
    if not loaded:
        raise HTTPException(404, f"No events found for source '{source}'" + (f", file '{filename}'" if filename else ""))
    if len(loaded) > 500:
        raise HTTPException(413, "maximum 500 events per batch; narrow the source, file, or limit")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    forced_hint = source_hint(source) if source != "all" else None
    orch = build_orchestrator(batch_mode=True)

    max_workers = min(3, len(loaded))
    findings_map: dict[int, dict] = {}

    def _process_one(idx: int, origin: str, event: dict) -> dict:
        domain, result = orch.process(event, source_hint=forced_hint)
        return {"index": idx, "origin": origin, "domain": domain, "result": result}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_process_one, idx, origin, event): idx
            for idx, (origin, event) in enumerate(loaded)
        }
        for future in as_completed(futures):
            item = future.result()
            findings_map[item["index"]] = item

    findings = [findings_map[i] for i in sorted(findings_map)]
    return {
        "source": source,
        "count": len(findings),
        "findings": findings,
        "correlation": orch.correlate(),
        "model_topology": orch.model_topology(),
    }
