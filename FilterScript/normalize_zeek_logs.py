import os
import json
import ipaddress
from datetime import datetime, timezone


# ============================================================
# CONFIG
# ============================================================

BASE_DIR = r"C:\Users\admin\Downloads\LogsThings\Data"

SOURCE_WEB = os.path.join(BASE_DIR, "Raw", "Webserver")

DEST_WEB = os.path.join(BASE_DIR, "Processed", "Web_Logs")


# ============================================================
# DIRECTORY
# ============================================================

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)


# ============================================================
# CLEAN / VALIDATE
# ============================================================

def clean_value(value):
    if value is None:
        return None

    value = str(value).strip()

    if value in ("", "-", "(empty)", "null", "None"):
        return None

    return value


def is_valid_ip(value):
    value = clean_value(value)

    if value is None:
        return False

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_ip(value):
    value = clean_value(value)

    if value is None:
        return None

    return value if is_valid_ip(value) else None


# ============================================================
# TIMESTAMP
# ============================================================

def normalize_timestamp(value):
    """
    Zeek timestamp:
        1331901000.000000

    -> ISO 8601 UTC.
    """

    value = clean_value(value)

    if value is None:
        return None

    try:
        epoch = float(value)
        return datetime.fromtimestamp(
            epoch,
            tz=timezone.utc
        ).isoformat()

    except (ValueError, TypeError, OverflowError):
        return str(value)


# ============================================================
# ZEEK LINE PARSER
# ============================================================

def split_zeek_line(line):
    """
    Zeek conn.log/http.log sử dụng whitespace/tab.
    Parser này gom các khoảng trắng liên tiếp và hỗ trợ
    value có dấu quote.
    """

    fields = []
    current = []
    in_quotes = False
    escape = False

    for char in line.rstrip("\r\n"):

        if escape:
            current.append(char)
            escape = False
            continue

        if char == "\\" and in_quotes:
            current.append(char)
            escape = True
            continue

        if char == '"':
            in_quotes = not in_quotes
            continue

        if char in (" ", "\t") and not in_quotes:
            if current:
                fields.append("".join(current))
                current = []
        else:
            current.append(char)

    if current:
        fields.append("".join(current))

    return fields


# ============================================================
# EVENT ID
# ============================================================

def build_event_id(prefix, uid, line_number):
    uid = clean_value(uid)

    if uid:
        return f"EVT-{prefix}-{uid}"

    return f"EVT-{prefix}-{line_number}"


# ============================================================
# RAW LOG
# ============================================================

def build_raw_log(data, ordered_keys):
    parts = []

    for key in ordered_keys:
        value = data.get(key)

        if value is None:
            value = "-"

        parts.append(f"{key}={value}")

    return ", ".join(parts)


# ============================================================
# NETWORK / conn.log
# ============================================================




# ============================================================
# WEB / http.log
# ============================================================

WEB_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "trans_depth",
    "method",
    "host",
    "uri",
    "referrer",
    "user_agent",
    "request_body_len",
    "response_body_len",
    "status_code",
    "status_msg",
    "info_code",
    "info_msg",
    "tags",
    "username",
    "password",
    "proxied",
    "orig_fuids",
    "orig_mime_types",
    "resp_fuids",
    "resp_mime_types",
]


def parse_web_line(line, line_number):

    fields = split_zeek_line(line)

    if len(fields) < len(WEB_FIELDS):
        return None, (
            f"Expected {len(WEB_FIELDS)} fields, "
            f"got {len(fields)}"
        )

    if len(fields) > len(WEB_FIELDS):
        fields = (
            fields[:len(WEB_FIELDS) - 1]
            + [" ".join(fields[len(WEB_FIELDS) - 1:])]
        )

    data = dict(zip(WEB_FIELDS, fields))

    event_code = clean_value(
        data["status_code"]
    )

    if event_code is not None:
        try:
            event_code = int(event_code)
        except ValueError:
            pass

    event = {
        "event_id": build_event_id(
            "WEB",
            data["uid"],
            line_number
        ),

        # HTTP status code được giữ ở event_code.
        "event_code": event_code,

        "timestamp": normalize_timestamp(
            data["ts"]
        ),

        "log_source": "web",

        "source_ip": normalize_ip(
            data["id.orig_h"]
        ),

        "dest_ip": normalize_ip(
            data["id.resp_h"]
        ),

        "raw_log": build_raw_log(
            data,
            WEB_FIELDS
        ),
    }

    return event, None


# ============================================================
# PROCESS ONE FILE
# ============================================================

def process_file(
    file_path,
    output_file,
    error_file,
    log_type
):

    parser = (
        parse_network_line
        if log_type == "network"
        else parse_web_line
    )

    total = 0
    normalized = 0
    errors = 0
    missing_source_ip = 0
    missing_dest_ip = 0

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="replace"
    ) as fin, open(
        output_file,
        "w",
        encoding="utf-8"
    ) as fout, open(
        error_file,
        "w",
        encoding="utf-8"
    ) as ferr:

        for line_number, line in enumerate(fin, 1):

            line = line.rstrip("\r\n")

            # Bỏ dòng rỗng
            if not line.strip():
                continue

            # Bỏ header/comment của Zeek
            if line.startswith("#"):
                continue

            total += 1

            try:

                event, error = parser(
                    line,
                    line_number
                )

                if error is not None:

                    errors += 1

                    json.dump(
                        {
                            "line_number": line_number,
                            "error": error,
                            "raw_line": line
                        },
                        ferr,
                        ensure_ascii=False
                    )

                    ferr.write("\n")
                    continue

                json.dump(
                    event,
                    fout,
                    ensure_ascii=False
                )

                fout.write("\n")

                normalized += 1

                if event["source_ip"] is None:
                    missing_source_ip += 1

                if event["dest_ip"] is None:
                    missing_dest_ip += 1

                if total % 100_000 == 0:
                    print(
                        f"    [{log_type.upper()}] "
                        f"Processed={total:,} | "
                        f"Normalized={normalized:,} | "
                        f"Errors={errors:,}"
                    )

            except Exception as e:

                errors += 1

                json.dump(
                    {
                        "line_number": line_number,
                        "error": str(e),
                        "raw_line": line
                    },
                    ferr,
                    ensure_ascii=False
                )

                ferr.write("\n")

    return {
        "total": total,
        "normalized": normalized,
        "errors": errors,
        "missing_source_ip": missing_source_ip,
        "missing_dest_ip": missing_dest_ip,
    }


# ============================================================
# PROCESS DIRECTORY
# ============================================================

def process_directory(
    source_dir,
    destination_dir,
    log_type
):

    ensure_dir(destination_dir)

    print()
    print("=" * 70)
    print(f"{log_type.upper()} -> NORMALIZED JSONL")
    print("=" * 70)

    if not os.path.exists(source_dir):
        print(f"[ERROR] Không tồn tại: {source_dir}")
        return

    files = []

    for root, _, filenames in os.walk(source_dir):

        for filename in filenames:

            # Không xử lý Zone.Identifier
            if filename.endswith(":Zone.Identifier"):
                continue

            if filename.lower().endswith(
                (".log", ".txt", ".tsv")
            ):
                files.append(
                    os.path.join(root, filename)
                )

    if not files:
        print("[!] Không tìm thấy file log.")
        return

    total_files = 0
    total_records = 0
    total_normalized = 0
    total_errors = 0
    total_missing_source = 0
    total_missing_dest = 0

    for file_path in files:

        total_files += 1

        filename = os.path.basename(file_path)
        base_name = os.path.splitext(filename)[0]

        output_file = os.path.join(
            destination_dir,
            base_name + ".jsonl"
        )

        error_file = os.path.join(
            destination_dir,
            base_name + "_errors.jsonl"
        )

        print()
        print(f"[*] File: {file_path}")

        result = process_file(
            file_path,
            output_file,
            error_file,
            log_type
        )

        total_records += result["total"]
        total_normalized += result["normalized"]
        total_errors += result["errors"]
        total_missing_source += result["missing_source_ip"]
        total_missing_dest += result["missing_dest_ip"]

        print(f"[+] Output: {output_file}")

        if result["errors"] > 0:
            print(f"[!] Errors: {error_file}")

    print()
    print("=" * 70)
    print(f"{log_type.upper()} SUMMARY")
    print("=" * 70)
    print(f"Files              : {total_files}")
    print(f"Total records      : {total_records:,}")
    print(f"Normalized         : {total_normalized:,}")
    print(f"Errors             : {total_errors:,}")
    print(f"Missing source_ip  : {total_missing_source:,}")
    print(f"Missing dest_ip    : {total_missing_dest:,}")
    print(f"Output directory   : {destination_dir}")
    print("=" * 70)


# ============================================================
# MAIN
# ============================================================

def process_all():

    

    process_directory(
        SOURCE_WEB,
        DEST_WEB,
        "web"
    )


if __name__ == "__main__":
    process_all()
