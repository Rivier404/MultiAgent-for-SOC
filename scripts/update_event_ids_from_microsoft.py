from __future__ import annotations

"""Build data/event_ids.json from Microsoft Learn pages.

The script treats Sigma EventID values only as candidates. An ID is written to the
catalog only if an official learn.microsoft.com event page is fetched successfully
and the fetched page explicitly contains that Event ID.
"""

import argparse
import datetime as dt
import hashlib
import html as html_lib
import json
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CANDIDATES = ROOT / "rag" / "knowledge" / "sigma_event_candidates.json"
DEFAULT_OUT = ROOT / "data" / "event_ids.json"
OFFICIAL_HOST = "learn.microsoft.com"
URL_TEMPLATES = (
    "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-{event_id}",
    "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{event_id}",
)


def strip_tags(value: str) -> str:
    value = re.sub(r"<script\b.*?</script>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<style\b.*?</style>", " ", value, flags=re.I | re.S)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html_lib.unescape(value)
    return re.sub(r"\s+", " ", value).strip()


def extract_title(html: str) -> str:
    h1 = re.search(r"<h1\b[^>]*>(.*?)</h1>", html, flags=re.I | re.S)
    if h1:
        return strip_tags(h1.group(1))
    title = re.search(r"<title\b[^>]*>(.*?)</title>", html, flags=re.I | re.S)
    return strip_tags(title.group(1)) if title else ""


def extract_description(html: str, event_id: str) -> str | None:
    meta = re.search(r'<meta\s+name=["\']description["\']\s+content=["\'](.*?)["\']', html, flags=re.I | re.S)
    if meta:
        value = strip_tags(meta.group(1))
        if value and event_id in strip_tags(html):
            return value[:1200]
    pos = html.lower().find("</h1>")
    tail = html[pos + 5:] if pos >= 0 else html
    for p in re.findall(r"<p\b[^>]*>(.*?)</p>", tail, flags=re.I | re.S):
        text = strip_tags(p)
        if len(text) >= 40:
            return text[:1200]
    return None


def infer_domains_and_category(title: str) -> tuple[list[str], str]:
    t = title.lower()
    identity_terms = ("logon", "account", "kerberos", "credential", "group", "user", "domain", "ticket")
    domains = ["endpoint"]
    if any(x in t for x in identity_terms):
        domains.insert(0, "ad")
    if "logon" in t or "authentication" in t or "kerberos" in t:
        category = "Authentication"
    elif "process" in t:
        category = "Process Creation"
    elif "account" in t or "user" in t or "group" in t:
        category = "Account Management"
    elif "policy" in t or "audit" in t:
        category = "Policy Change"
    elif "object" in t or "file" in t or "registry" in t:
        category = "Object Access"
    elif "privilege" in t:
        category = "Privilege Use"
    else:
        category = "Windows Security Auditing"
    return domains, category


def fetch_verified(event_id: str, timeout: int, session: requests.Session) -> dict | None:
    for template in URL_TEMPLATES:
        url = template.format(event_id=event_id)
        if urlparse(url).hostname != OFFICIAL_HOST:
            continue
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent": "SOC-EventID-Sync/1.0"})
        except requests.RequestException:
            continue
        if r.status_code != 200 or urlparse(r.url).hostname != OFFICIAL_HOST:
            continue
        body_text = strip_tags(r.text)
        title = extract_title(r.text)
        if event_id not in body_text:
            continue
        if event_id not in title and f"event {event_id}" not in body_text.lower():
            continue
        domains, category = infer_domains_and_category(title)
        return {
            "name": title or f"Windows Security Event {event_id}",
            "description": extract_description(r.text, event_id),
            "category": category,
            "domains": domains,
            "source": "Microsoft Learn",
            "source_url": r.url,
            "verification_status": "verified_live",
            "verified_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_sha256": hashlib.sha256(r.content).hexdigest(),
        }
    return None


def load_candidates(path: Path, explicit: list[str]) -> list[str]:
    ids = [str(x).strip() for x in explicit if str(x).strip()]
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        ids.extend(str(x.get("event_id")) for x in data.get("candidates", []) if x.get("event_id"))
    out = []
    for eid in ids:
        if re.fullmatch(r"\d{3,5}", eid) and eid not in out:
            out.append(eid)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="Build authoritative Windows Event-ID catalog from Microsoft Learn")
    ap.add_argument("--candidate-file", type=Path, default=DEFAULT_CANDIDATES)
    ap.add_argument("--event-id", nargs="*", default=[])
    ap.add_argument("--max-events", type=int, default=80)
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    candidates = load_candidates(args.candidate_file, args.event_id)[: max(1, args.max_events)]
    if not candidates:
        raise SystemExit("No candidate Event IDs found")

    session = requests.Session()
    verified: dict[str, dict] = {}
    for idx, eid in enumerate(candidates, 1):
        print(f"[{idx}/{len(candidates)}] Microsoft Learn Event {eid} ...", end=" ", flush=True)
        meta = fetch_verified(eid, args.timeout, session)
        if meta:
            verified[eid] = meta
            print("OK")
        else:
            print("SKIP")

    if not verified:
        raise SystemExit("No Microsoft Learn Event-ID pages were verified; existing catalog was left unchanged.")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.output.with_suffix(args.output.suffix + ".tmp")
    tmp.write_text(json.dumps(verified, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(args.output)
    print(f"Wrote {len(verified)} verified Event IDs to {args.output}")


if __name__ == "__main__":
    main()
