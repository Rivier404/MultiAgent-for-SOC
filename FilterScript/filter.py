import os
import json
import ipaddress

import xmltodict


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = r"C:\Users\admin\Downloads\LogsThings\Data"

SOURCE_DIR = os.path.join(
    BASE_DIR,
    "Raw",
    "AD"
)

DEST_AD = os.path.join(
    BASE_DIR,
    "Processed",
    "AD_Logs"
)

DEST_ENDPOINT = os.path.join(
    BASE_DIR,
    "Processed",
    "Endpoint_Logs"
)


# ============================================================
# EVTX IMPORT
# ============================================================

try:
    from Evtx.Evtx import Evtx
except ImportError:
    print("[ERROR] Không import được python-evtx.")
    print()
    print("Cài bằng:")
    print("    python -m pip install python-evtx")
    raise


# ============================================================
# DIRECTORY
# ============================================================

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ============================================================
# CLEAN VALUE
# ============================================================

def clean_value(value):
    """
    Chuyển giá trị XML về string sạch.
    """

    if value is None:
        return None

    if isinstance(value, dict):

        if "#text" in value:
            return clean_value(value["#text"])

        return None

    if isinstance(value, list):

        if len(value) > 0:
            return clean_value(value[0])

        return None

    value = str(value).strip()

    if value == "":
        return None

    return value


# ============================================================
# GET EVENT ID
# ============================================================

def get_event_code(system):
    """
    Lấy Windows Event ID thật.

    Ví dụ:
        4624
        4625
        4688
        1
        3
        10
    """

    event_id = system.get("EventID")

    if isinstance(event_id, dict):
        event_id = event_id.get("#text")

    event_id = clean_value(event_id)

    if event_id is None:
        return None

    # Chuyển "4624" -> 4624
    try:
        return int(event_id)
    except ValueError:
        return event_id


# ============================================================
# GET EVENT DATA
# ============================================================

def get_event_data(event_data):
    """
    Chuyển:

        <Data Name="IpAddress">192.168.1.45</Data>

    thành:

        {
            "IpAddress": "192.168.1.45"
        }
    """

    result = {}

    if not isinstance(event_data, dict):
        return result

    data = event_data.get("Data")

    if data is None:
        return result

    # --------------------------------------------------------
    # Nhiều Data
    # --------------------------------------------------------

    if isinstance(data, list):

        for item in data:

            if not isinstance(item, dict):
                continue

            name = item.get("@Name")
            value = item.get("#text")

            if name:
                result[str(name)] = clean_value(value)

    # --------------------------------------------------------
    # Một Data
    # --------------------------------------------------------

    elif isinstance(data, dict):

        name = data.get("@Name")
        value = data.get("#text")

        if name:
            result[str(name)] = clean_value(value)

    return result


# ============================================================
# VALIDATE IP
# ============================================================

def is_valid_ip(value):
    """
    Kiểm tra value có phải IPv4/IPv6 hợp lệ không.
    """

    if value is None:
        return False

    value = str(value).strip()

    if value in [
        "-",
        "",
        "::1",
        "127.0.0.1"
    ]:
        return False

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


# ============================================================
# FIND IP
# ============================================================

def find_ip(event_data, possible_keys):
    """
    Tìm IP theo danh sách field.
    """

    if not isinstance(event_data, dict):
        return None

    for key in possible_keys:

        value = event_data.get(key)

        if value is None:
            continue

        value = clean_value(value)

        if is_valid_ip(value):
            return value

    return None


# ============================================================
# BUILD RAW LOG
# ============================================================

def build_raw_log(
    event_code,
    provider,
    channel,
    computer,
    event_data
):
    """
    Tạo raw_log từ Windows Event.
    """

    parts = []

    if event_code is not None:
        parts.append(
            f"EventID={event_code}"
        )

    if provider:
        parts.append(
            f"Provider={provider}"
        )

    if channel:
        parts.append(
            f"Channel={channel}"
        )

    if computer:
        parts.append(
            f"Computer={computer}"
        )

    # EventData
    for key, value in event_data.items():

        if value is None:
            continue

        parts.append(
            f"{key}={value}"
        )

    return ", ".join(parts)


# ============================================================
# PARSE EVENT
# ============================================================

def parse_event(
    xml_string,
    record_number
):

    parsed = xmltodict.parse(
        xml_string
    )

    event = parsed.get(
        "Event",
        {}
    )

    if not isinstance(event, dict):
        return None

    # ========================================================
    # SYSTEM
    # ========================================================

    system = event.get(
        "System",
        {}
    )

    if not isinstance(system, dict):
        return None

    # ========================================================
    # EVENT CODE
    # ========================================================

    event_code = get_event_code(
        system
    )

    # ========================================================
    # CHANNEL
    # ========================================================

    channel = clean_value(
        system.get("Channel")
    )

    if not channel:
        return None

    channel_lower = channel.lower()

    # ========================================================
    # CLASSIFY LOG
    # ========================================================

    if channel_lower == "security":

        log_source = "ad"

        event_prefix = "EVT-AD"

    elif channel_lower == (
        "microsoft-windows-sysmon/operational"
    ):

        log_source = "endpoint"

        event_prefix = "EVT-ENDPOINT"

    else:

        # Không lấy các channel khác
        return None

    # ========================================================
    # PROVIDER
    # ========================================================

    provider = system.get(
        "Provider"
    )

    if isinstance(provider, dict):

        provider_name = provider.get(
            "@Name"
        )

    else:

        provider_name = provider

    provider_name = clean_value(
        provider_name
    )

    # ========================================================
    # COMPUTER
    # ========================================================

    computer = clean_value(
        system.get("Computer")
    )

    # ========================================================
    # TIMESTAMP
    # ========================================================

    time_created = system.get(
        "TimeCreated"
    )

    timestamp = None

    if isinstance(time_created, dict):

        timestamp = time_created.get(
            "@SystemTime"
        )

    timestamp = clean_value(
        timestamp
    )

    # ========================================================
    # EVENT DATA
    # ========================================================

    event_data = get_event_data(
        event.get(
            "EventData",
            {}
        )
    )

    # ========================================================
    # SOURCE IP
    # ========================================================

    source_ip = find_ip(
        event_data,
        [
            "SourceIp",
            "SourceIP",
            "SourceAddress",
            "IpAddress",
            "ClientAddress",
            "ClientIP",
            "SourceNetworkAddress",
            "RemoteAddress",
            "RemoteIp",
            "RemoteIP",
            "src_ip"
        ]
    )

    # ========================================================
    # DESTINATION IP
    # ========================================================

    dest_ip = find_ip(
        event_data,
        [
            "DestinationIp",
            "DestinationIP",
            "DestinationAddress",
            "DestIp",
            "DestIP",
            "TargetIp",
            "TargetIP",
            "ServerIp",
            "ServerIP",
            "dst_ip"
        ]
    )

    # ========================================================
    # EVENT ID UNIQUE
    # ========================================================

    event_id = (
        f"{event_prefix}-{record_number}"
    )

    # ========================================================
    # RAW LOG
    # ========================================================

    raw_log = build_raw_log(
        event_code=event_code,
        provider=provider_name,
        channel=channel,
        computer=computer,
        event_data=event_data
    )

    # ========================================================
    # FINAL NORMALIZED EVENT
    # ========================================================

    normalized = {
        "event_id": event_id,
        "event_code": event_code,
        "timestamp": timestamp,
        "log_source": log_source,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "raw_log": raw_log
    }

    return normalized


# ============================================================
# PROCESS ONE EVTX
# ============================================================

def process_evtx(file_path):

    filename = os.path.basename(
        file_path
    )

    print()
    print("=" * 70)
    print(
        f"[*] Processing: {filename}"
    )
    print("=" * 70)

    ad_events = []
    endpoint_events = []

    total_events = 0
    skipped_events = 0
    parse_errors = 0

    try:

        with Evtx(file_path) as log:

            for record in log.records():

                total_events += 1

                try:

                    xml_string = record.xml()

                    normalized = parse_event(
                        xml_string=xml_string,
                        record_number=record.record_num()
                    )

                    if normalized is None:

                        skipped_events += 1

                        continue

                    if normalized["log_source"] == "ad":

                        ad_events.append(
                            normalized
                        )

                    elif normalized["log_source"] == "endpoint":

                        endpoint_events.append(
                            normalized
                        )

                except Exception as e:

                    parse_errors += 1

                    print(
                        f"[!] Record "
                        f"{record.record_num()} "
                        f"lỗi: {e}"
                    )

    except Exception as e:

        print(
            f"[ERROR] Không đọc được file: "
            f"{filename}"
        )

        print(e)

        return None

    print(
        f"[*] Total events : {total_events}"
    )

    print(
        f"[*] AD events    : {len(ad_events)}"
    )

    print(
        f"[*] Endpoint     : {len(endpoint_events)}"
    )

    print(
        f"[*] Skipped      : {skipped_events}"
    )

    print(
        f"[*] Parse errors : {parse_errors}"
    )

    return {
        "ad": ad_events,
        "endpoint": endpoint_events,
        "total": total_events,
        "skipped": skipped_events,
        "errors": parse_errors
    }


# ============================================================
# WRITE JSONL
# ============================================================

def write_jsonl(
    events,
    output_file
):

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        for event in events:

            json.dump(
                event,
                f,
                ensure_ascii=False
            )

            f.write("\n")


# ============================================================
# PROCESS ALL EVTX
# ============================================================

def process_all():

    ensure_dir(
        DEST_AD
    )

    ensure_dir(
        DEST_ENDPOINT
    )

    total_files = 0
    successful_files = 0

    total_events = 0
    total_ad = 0
    total_endpoint = 0
    total_skipped = 0
    total_errors = 0

    print("=" * 70)
    print(
        "EVTX -> NORMALIZED JSONL"
    )
    print("=" * 70)

    print(
        f"[*] Source: {SOURCE_DIR}"
    )

    # ========================================================
    # SCAN DIRECTORY
    # ========================================================

    for root, _, files in os.walk(
        SOURCE_DIR
    ):

        for filename in files:

            if not filename.lower().endswith(
                ".evtx"
            ):
                continue

            total_files += 1

            file_path = os.path.join(
                root,
                filename
            )

            result = process_evtx(
                file_path
            )

            if result is None:
                continue

            successful_files += 1

            total_events += result["total"]

            total_skipped += result["skipped"]

            total_errors += result["errors"]

            total_ad += len(
                result["ad"]
            )

            total_endpoint += len(
                result["endpoint"]
            )

            # =================================================
            # OUTPUT NAME
            # =================================================

            base_name = os.path.splitext(
                filename
            )[0]

            # =================================================
            # AD OUTPUT
            # =================================================

            if result["ad"]:

                output_file = os.path.join(
                    DEST_AD,
                    base_name + ".jsonl"
                )

                write_jsonl(
                    result["ad"],
                    output_file
                )

                print(
                    f"[+] AD -> {output_file}"
                )

            # =================================================
            # ENDPOINT OUTPUT
            # =================================================

            if result["endpoint"]:

                output_file = os.path.join(
                    DEST_ENDPOINT,
                    base_name + ".jsonl"
                )

                write_jsonl(
                    result["endpoint"],
                    output_file
                )

                print(
                    f"[+] Endpoint -> {output_file}"
                )

    # ========================================================
    # SUMMARY
    # ========================================================

    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)

    print(
        f"EVTX files       : {total_files}"
    )

    print(
        f"Processed files  : {successful_files}"
    )

    print(
        f"Total events     : {total_events}"
    )

    print(
        f"AD events        : {total_ad}"
    )

    print(
        f"Endpoint events  : {total_endpoint}"
    )

    print(
        f"Skipped events   : {total_skipped}"
    )

    print(
        f"Parse errors     : {total_errors}"
    )

    print()
    print(
        f"AD output        : {DEST_AD}"
    )

    print(
        f"Endpoint output  : {DEST_ENDPOINT}"
    )

    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    process_all()