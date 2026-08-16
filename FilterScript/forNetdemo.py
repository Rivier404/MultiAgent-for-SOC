import json
import os
from collections import defaultdict, Counter

INPUT_FILE = r"C:\Users\admin\Downloads\LogsThings\Data\Processed\Network_Logs\conn.jsonl"
OUTPUT_FILE = r"C:\Users\admin\Downloads\LogsThings\Data\Demo\network_demo.jsonl"

TARGET_TOTAL = 150
PER_GROUP = 20

GROUPS = [
    "tcp_normal",
    "tcp_failed",
    "tcp_other",
    "udp",
    "icmp",
    "http",
    "ssl",
    "other_service",
    "unusual_port",
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

    proto = fields.get("proto", "").lower()
    service = fields.get("service", "").lower()
    state = fields.get("conn_state", "").upper()

    try:
        dest_port = int(fields.get("id.resp_p", "0"))
    except ValueError:
        dest_port = 0

    if proto == "icmp":
        return "icmp"

    if proto == "udp":
        return "udp"

    if service == "http":
        return "http"

    if service == "ssl":
        return "ssl"

    if proto == "tcp":
        if state in {"S0", "REJ"}:
            return "tcp_failed"

        if state in {"OTH", "RSTO", "RSTR"}:
            return "tcp_other"

        if state == "SF":
            common_ports = {
                20, 21, 22, 23, 25, 53, 80, 110,
                111, 123, 135, 139, 143, 389, 443,
                445, 587, 636, 993, 995, 1433,
                3306, 3389, 5432, 5900, 8080
            }

            if dest_port in common_ports:
                return "tcp_normal"

            return "unusual_port"

    if service not in {"", "-", "none"}:
        return "other_service"

    return "tcp_other"


def collect_candidates():
    buckets = defaultdict(list)
    total = 0
    invalid = 0

    print("=" * 70)
    print("NETWORK DATA CURATOR")
    print("=" * 70)
    print(f"Input : {INPUT_FILE}")
    print(f"Target: {TARGET_TOTAL}")
    print()

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as f:

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
        events = buckets.get(group, [])
        selected.extend(events[:PER_GROUP])

    return selected[:TARGET_TOTAL]


def save_events(events, buckets):
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as f:

        for event in events:
            f.write(
                json.dumps(
                    event,
                    ensure_ascii=False
                ) + "\n"
            )

    selected_counter = Counter(
        get_group(event)
        for event in events
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
            f"  {group:<18} "
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

    save_events(events, buckets)


if __name__ == "__main__":
    main()
