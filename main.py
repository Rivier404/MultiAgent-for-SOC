from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from core.ingest import load_inputs
from orchestrator import SOCOrchestrator
from rag.engine import RAGEngine

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"


def legacy_demo_inputs(source: str) -> list[str]:
    mapping = {
        "ad": DATA_DIR / "ad",
        "endpoint": DATA_DIR / "endpoint",
        "network": DATA_DIR / "network",
        "web": DATA_DIR / "web",
    }
    if source == "all":
        return [str(p) for p in mapping.values() if p.exists()]
    p = mapping[source]
    return [str(p)] if p.exists() else []


def main() -> None:
    load_dotenv(ROOT / ".env", override=False)
    parser = argparse.ArgumentParser(description="AI Multi-Agent SOC - JSON RAG + Microsoft Event-ID catalog + AI impact scoring")
    parser.add_argument("--mode", choices=["mock", "ollama", "multi_api"], default="mock", help="mock=no LLM calls; ollama=legacy single local model; multi_api=remote domain specialists + local correlation")
    parser.add_argument("--input", "-i", action="append", default=[], help="File, directory, or '-' for stdin. Repeatable.")
    parser.add_argument("--source", choices=["auto", "ad", "endpoint", "network", "web", "all"], default="auto", help="Optional routing hint. 'all' uses bundled demo folders only when --input is omitted.")
    parser.add_argument("--limit", type=int, default=0, help="Maximum total events; 0 = all events.")
    parser.add_argument("--rag-root", default=None, help="Alternative normalized RAG knowledge directory.")
    parser.add_argument("--rag-stats", action="store_true")
    args = parser.parse_args()

    rag = RAGEngine(source_root=args.rag_root)
    print(f"[config] mode={args.mode} source={args.source} limit={'all' if args.limit == 0 else args.limit}")
    print(f"[rag] knowledge={rag.source_root} indexed_chunks={len(rag._docs)} kinds={rag.count_by_kind()} playbooks={rag.playbook_ids()}")
    if args.rag_stats:
        return

    inputs = list(args.input)
    if not inputs:
        legacy_source = "all" if args.source == "auto" else args.source
        inputs = legacy_demo_inputs(legacy_source)
        if not inputs:
            parser.error("No --input supplied and no bundled demo data exists for the selected source")

    loaded = load_inputs(inputs, limit=args.limit)
    print(f"[ingest] loaded {len(loaded)} event(s) from {len(inputs)} input target(s)")
    orchestrator = SOCOrchestrator(mode=args.mode, rag=rag)
    print(f"[models] {json.dumps(orchestrator.model_topology(), ensure_ascii=False)}")
    all_findings: dict[str, list[dict[str, Any]]] = {"ad": [], "endpoint": [], "network": [], "web": [], "unknown": []}

    forced = None if args.source in {"auto", "all"} else args.source
    for index, (origin, event) in enumerate(loaded, 1):
        domain, result = orchestrator.process(event, source_hint=forced)
        all_findings.setdefault(domain, []).append(result)
        print(f"\n[{index}/{len(loaded)}] origin={origin} domain={domain}\n{json.dumps(result, ensure_ascii=False, indent=2)}")

    correlation = orchestrator.correlate()
    print("\n=== CORRELATION ===\n" + json.dumps(correlation, ensure_ascii=False, indent=2))

    out_dir = ROOT / "outputs"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "agent_results.json").write_text(json.dumps(all_findings, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "correlation.json").write_text(json.dumps(correlation, ensure_ascii=False, indent=2), encoding="utf-8")
    (out_dir / "rag_stats.json").write_text(json.dumps({
        "knowledge_root": str(rag.source_root), "count_by_kind": rag.count_by_kind(), "playbook_ids": rag.playbook_ids(),
        "indexed_docs": len(rag._docs), "relevance_threshold": rag.relevance_threshold,
        "playbook_relevance_threshold": rag.playbook_relevance_threshold,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSaved outputs to: {out_dir}")


if __name__ == "__main__":
    main()
