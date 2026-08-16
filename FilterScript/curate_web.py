import json
import os
from collections import defaultdict, Counter

INPUT_FILE = r"C:\Users\admin\Downloads\LogsThings\Data\Processed\Web_Logs\http.jsonl"
OUTPUT_FILE = r"C:\Users\admin\Downloads\LogsThings\Data\Demo\web_demo.jsonl"

TARGET_TOTAL = 150
PER_GROUP = 20

GROUPS = [
    "normal_get",
    "normal_post",
    "head",
    "http_404",
    "http_304",
    "http_500",
    "scanner",
    "suspicious_uri",
    "script_endpoint",
    "other",
]


def parse_raw_log(raw):
    fields = {}

    for part in raw.split(", "):
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key] = value

    return fields


def get_group(event):
    fields = parse_raw_log(event.get("raw_log", ""))

    method = fields.get("method", "").upper()
    uri = fields.get("uri", "")
    user_agent = fields.get("user_agent", "").lower()

    try:
        status = int(fields.get("status_code", "0"))
    except ValueError:
        status = 0

    # Scanner / automated security tools
    scanner_keywords = [
        "nmap", "masscan", "nikto", "sqlmap",
        "nessus", "acunetix", "openvas", "burp", "zap"
    ]

    if any(x in user_agent for x in scanner_keywords):
        return "scanner"

    # HTTP status
    if status == 404:
        return "http_404"

    if status == 304:
        return "http_304"

    if status >= 500:
        return "http_500"

    # Suspicious URI
    uri_lower = uri.lower()

    suspicious_keywords = [
        "../", "..\\", "%2e%2e", "%252e",
        "/etc/passwd", "cmd.exe", "powershell",
        "wget", "curl", "union select", "select%20",
        "select+", "xp_cmdshell", "<script",
        "javascript:", "base64", "passwd",
        "boot.ini", "win.ini"
    ]

    if any(x in uri_lower for x in suspicious_keywords):
        return "suspicious_uri"

    # Script / executable endpoints
    script_extensions = [
        ".php", ".cgi", ".asp", ".aspx",
        ".jsp", ".exe", ".pl", ".py", ".sh"
    ]

    if any(x in uri_lower for x in script_extensions):
        return "script_endpoint"

    if method == "HEAD":
        return "head"

    if method == "GET":
        return "normal_get"

    if method == "POST":
        return "normal_post"

    return "other"


def collect_candidates():
    buckets = defaultdict(list)
    total = 0
    invalid = 0

    print("=" * 70)
    print("WEB DATA CURATOR")
    print("=" * 70)
    print(f"Input : {INPUT_FILE}")
    print(f"Target: {TARGET_TOTAL}")
    print()

    with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue

            total += 1

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue

            group = get_group(event)

            if len(buckets[group]) < PER_GROUP:
                buckets[group].append(event)

            if total % 100_000 == 0:
                print(
                    f"Processed={total:,} | "
                    f"Invalid={invalid:,}"
                )

    print()
    print(f"Total processed: {total:,}")
    print(f"Invalid JSON   : {invalid:,}")

    return buckets


def select_events(buckets):
    selected = []

    for group in GROUPS:
        selected.extend(buckets.get(group, [])[:PER_GROUP])

    return selected[:TARGET_TOTAL]


def save_events(events):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for event in events:
            f.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )

    selected_counter = Counter(
        get_group(event) for event in events
    )

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"Selected events : {len(events)}")
    print(f"Output          : {OUTPUT_FILE}")
    print()
    print("Selected distribution:")

    for group in GROUPS:
        print(
            f"  {group:<20}"
            f"{selected_counter[group]:>4}"
        )

    print("=" * 70)


def main():
    if not os.path.isfile(INPUT_FILE):
        print("[ERROR] Không tìm thấy input:")
        print(INPUT_FILE)
        return

    buckets = collect_candidates()
    events = select_events(buckets)

    if not events:
        print("[ERROR] Không lấy được event nào.")
        return

    save_events(events)


if __name__ == "__main__":
    main()
