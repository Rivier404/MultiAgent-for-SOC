from __future__ import annotations

import re
from datetime import datetime

import requests
import streamlit as st

st.set_page_config(page_title="SOC Multi-Agent Console", page_icon="🛰️", layout="wide")

st.markdown(
    """
    <style>
    button[kind="primary"], button[data-testid="baseButton-primary"] {
        background-color: #16a34a !important;
        border-color: #16a34a !important;
        color: #ffffff !important;
    }
    button[kind="primary"]:hover, button[data-testid="baseButton-primary"]:hover {
        background-color: #15803d !important;
        border-color: #15803d !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

SOURCES = ["ad", "endpoint", "network", "web", "overall"]
SOURCE_LABELS = {"ad": "AD", "endpoint": "Endpoint", "network": "Network", "web": "Web", "overall": "Overall"}

SEVERITY_COLOR = {
    "LOW": "#3b82f6",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444",
}
SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}
VERDICT_COLOR = {
    "malicious": "#ef4444",
    "suspicious": "#f59e0b",
    "benign": "#22c55e",
    "insufficient_evidence": "#6b7280",
}

DEFAULT_MAX_EVENTS = 50

for key, default in {
    "findings": [],
    "health": None,
    "health_error": None,
    "sources": None,
    "sources_error": None,
    "selected_source": "ad",
    "auto_connected": False,
    "last_run_file": None,
}.items():
    if key not in st.session_state:
        st.session_state[key] = default


def _hide_urls(text: str) -> str:
    return re.sub(r"https?://\S+", "the API server", text)


def api_error_detail(resp: requests.Response) -> str:
    try:
        body = resp.json()
        if isinstance(body, dict) and "detail" in body:
            return _hide_urls(str(body["detail"]))
    except ValueError:
        pass
    return f"HTTP {resp.status_code}"


def refresh_connection(api_base: str) -> None:
    try:
        resp = requests.get(f"{api_base}/health", timeout=10)
        resp.raise_for_status()
        st.session_state.health = resp.json()
        st.session_state.health_error = None
    except Exception as exc:
        st.session_state.health = None
        st.session_state.health_error = _hide_urls(str(exc))

    try:
        resp = requests.get(f"{api_base}/data/sources", timeout=10)
        resp.raise_for_status()
        st.session_state.sources = resp.json()
        st.session_state.sources_error = None
    except Exception as exc:
        st.session_state.sources = None
        st.session_state.sources_error = _hide_urls(str(exc))


def files_for(source: str) -> list[dict]:
    info = (st.session_state.sources or {}).get(source, {})
    if not info.get("exists"):
        return []
    return info.get("files", [])


def badge(text: str, color: str) -> str:
    return (
        f"<span style='background:{color}22; color:{color}; border:1px solid {color}55; "
        f"padding:3px 10px; border-radius:999px; font-size:0.82rem; font-weight:600; "
        f"white-space:nowrap;'>{text}</span>"
    )


def severity_metric_card(sev: str, count: int) -> str:
    color = SEVERITY_COLOR.get(sev, "#6b7280")
    return (
        f"<div style='display:flex; align-items:center; justify-content:space-between; "
        f"background:rgba(128,128,128,0.06); border:1px solid rgba(128,128,128,0.18); "
        f"border-radius:8px; padding:7px 12px; box-shadow:0 1px 2px rgba(0,0,0,0.03);'>"
        f"<div style='display:flex; align-items:center; gap:8px;'>"
        f"<span style='display:inline-block; width:10px; height:10px; border-radius:50%; "
        f"background:{color}; box-shadow:0 0 5px {color}99;'></span>"
        f"<span style='font-weight:700; font-size:0.83rem; letter-spacing:0.02em;'>{sev}</span>"
        f"</div>"
        f"<span style='background:rgba(128,128,128,0.12); font-weight:700; font-size:0.82rem; "
        f"padding:2px 8px; border-radius:6px; border:1px solid rgba(128,128,128,0.18); min-width:24px; text-align:center;'>{count}</span>"
        f"</div>"
    )



with st.sidebar:
    st.subheader("SOC Console")

    with st.expander("Connection", expanded=not st.session_state.auto_connected):
        api_base = st.text_input("API base URL", value="http://127.0.0.1:8000")
        refresh_clicked = st.button("Refresh", use_container_width=True)

        if not st.session_state.auto_connected or refresh_clicked:
            refresh_connection(api_base)
            st.session_state.auto_connected = True

        if st.session_state.health and st.session_state.health.get("ok"):
            st.success("Connected")
        elif st.session_state.health_error:
            st.error(f"Unreachable: {st.session_state.health_error}")
        elif st.session_state.health is not None:
            st.warning(f"Config error: {_hide_urls(str(st.session_state.health.get('config_error')))}")

        if st.session_state.sources_error:
            st.error(f"Could not load log list: {st.session_state.sources_error}")

    st.divider()
    source = st.radio(
        "Source", SOURCES, format_func=lambda s: SOURCE_LABELS[s],
        horizontal=True, key="selected_source",
    )

    files = files_for(source)
    if st.session_state.sources is not None:
        folder_display = "demo" if source == "overall" else source
        st.caption(f"{len(files)} file(s) in data/{folder_display}/")

    log_mode = st.radio("Log", ["Latest", "Choose file"], horizontal=True)

    selected_file = None
    if files:
        if log_mode == "Latest":
            selected_file = files[0]["name"]
            st.caption(f"Latest: {selected_file}")
        else:
            names = [f["name"] for f in files]
            selected_file = st.selectbox("File", names, label_visibility="collapsed")
    else:
        selected_file = st.text_input("File name", value="", placeholder="e.g. Sysmon_UACME_56.jsonl")

    st.divider()
    max_events = st.number_input(
        "Max events per run", min_value=1, max_value=500, value=DEFAULT_MAX_EVENTS, step=10,
        help="Caps how many events from the file are sent for analysis in one click.",
    )

    st.divider()
    run_clicked = st.button("Analyze", use_container_width=True, type="primary")

    if st.button("Clear results", use_container_width=True):
        st.session_state.findings = []
        st.rerun()

    health = st.session_state.health
    if health and (health.get("topology") or (health.get("rag") or {}).get("count_by_kind")):
        with st.expander("Model topology & RAG index", expanded=False):
            topo = health.get("topology", {}) or {}
            if topo:
                st.table(
                    [{"role": role, "provider": info.get("provider", "?"), "model": info.get("model", "?")}
                     for role, info in topo.items()]
                )
            counts = (health.get("rag", {}) or {}).get("count_by_kind", {}) or {}
            if counts:
                st.table([{"kind": k, "count": v} for k, v in counts.items()])

st.title("SOC Multi-Agent Console")
st.caption("AD · Endpoint · Network · Web → Correlation")

error_box = st.empty()

if run_clicked:
    if not selected_file:
        error_box.error("No file selected (check the connection, or type a file name).")
    else:
        with st.spinner("Analyzing..."):
            try:
                body = {"source": source, "file": selected_file, "limit": int(max_events)}
                resp = requests.post(f"{api_base}/analyze/batch", json=body, timeout=600)
                if not resp.ok:
                    raise ValueError(api_error_detail(resp))
                data = resp.json()
                ts = datetime.now().strftime("%H:%M:%S")
                new_items = []
                for f in data.get("findings", []):
                    new_items.append(
                        {"domain": f.get("domain"), "result": f.get("result", {}),
                         "origin": f.get("origin"), "is_correlation": False, "ts": ts,
                         "file": selected_file}
                    )
                if data.get("correlation"):
                    new_items.insert(
                        0,
                        {"domain": "CorrelationAgent", "result": data["correlation"],
                         "origin": None, "is_correlation": True, "ts": ts,
                         "file": selected_file},
                    )
                st.session_state.findings = new_items
                st.session_state.last_run_file = selected_file
                st.rerun()
            except requests.exceptions.RequestException as exc:
                error_box.error(f"Request failed: {_hide_urls(str(exc))}")
            except ValueError as exc:
                error_box.error(_hide_urls(str(exc)))

st.subheader("Results")

ALL_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

visible_findings: list = []

if not st.session_state.findings:
    st.info("No results yet. Pick a source and a file on the left, then click Analyze.")
else:
    st.caption(f"{st.session_state.last_run_file}")

    sev_counts = {s: 0 for s in ALL_SEVERITIES}
    for item in st.session_state.findings:
        s = str((item["result"] or {}).get("severity", "LOW")).upper()
        if s in sev_counts:
            sev_counts[s] += 1

    severity_filter = st.pills(
        "Filter by Severity",
        options=ALL_SEVERITIES,
        default=["CRITICAL", "HIGH", "MEDIUM"],
        format_func=lambda s: f"{SEVERITY_ICONS.get(s, '')} {s} · {sev_counts[s]}",
        selection_mode="multi",
        label_visibility="collapsed",
        key="severity_pills_filter",
    )

    active_severities = set(severity_filter or [])
    visible_findings = [
        item for item in st.session_state.findings
        if item.get("is_correlation")
        or str((item["result"] or {}).get("severity", "LOW")).upper() in active_severities
    ]
    st.caption(f"Showing {len(visible_findings)} of {len(st.session_state.findings)} results")
    if not visible_findings:
        st.info("Nothing matches the current filter — click the Severity pills above to show results.")

for item in visible_findings:
    result = item["result"] or {}
    severity = str(result.get("severity", "LOW")).upper()
    verdict = str(result.get("verdict", "insufficient_evidence"))
    agent_label = result.get("agent", item["domain"] or "Agent")
    code = result.get("event_code")
    impact = result.get("impact_score", 0)

    with st.container(border=True):
        head_cols = st.columns([4, 1.6, 1.6])
        with head_cols[0]:
            title = f"**{agent_label}**"
            if code:
                title += f"  ·  event_code `{code}`"
            if item.get("is_correlation"):
                title += "  ·  correlation"
            st.markdown(title)
        with head_cols[1]:
            st.markdown(
                badge(f"{severity} · {impact}/10", SEVERITY_COLOR.get(severity, "#6b7280")),
                unsafe_allow_html=True,
            )
        with head_cols[2]:
            st.markdown(
                badge(verdict.replace("_", " "), VERDICT_COLOR.get(verdict, "#6b7280")),
                unsafe_allow_html=True,
            )

        st.write(result.get("reasoning", ""))
        if result.get("llm_error"):
            st.caption(f"LLM error: {result['llm_error']}")

        detail_cols = st.columns(3)
        with detail_cols[0]:
            st.markdown("**Evidence**")
            evidence = result.get("evidence") or []
            st.markdown("\n".join(f"- {e}" for e in evidence) if evidence else "_none_")

        with detail_cols[1]:
            st.markdown("**Recommended actions**")
            actions = result.get("recommended_actions") or []
            st.markdown("\n".join(f"- {a}" for a in actions) if actions else "_none_")

        with detail_cols[2]:
            st.markdown("**Playbook references**")
            refs = result.get("playbook_references") or []
            st.markdown("\n".join(f"- {r}" for r in refs) if refs else "_none_")
