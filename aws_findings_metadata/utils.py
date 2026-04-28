from __future__ import annotations

import csv
import json
import re
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .aws_deps import BotoCoreError, ClientError
from .constants import RESOURCE_PREFIXES, RETRYABLE_ERROR_CODES

def detect_encoding(path: Path) -> str:
    with path.open("rb") as handle:
        prefix = handle.read(4)
    if prefix.startswith(b"\xff\xfe"):
        return "utf-16"
    if prefix.startswith(b"\xfe\xff"):
        return "utf-16"
    if prefix.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    return "utf-16-le"


def normalize_headers(raw_headers: Iterable[str]) -> list[str]:
    return [header.strip().lstrip("\ufeff") for header in raw_headers]


def optional_index(headers: list[str], name: str) -> int | None:
    try:
        return headers.index(name)
    except ValueError:
        return None


def load_profile_map(profile_map_file: str | Path) -> dict[str, str]:
    path = Path(profile_map_file)
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Profile map JSON must be an object mapping account IDs to profile names")
        return {str(account_id): str(profile) for account_id, profile in data.items()}

    mapping: dict[str, str] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            account_id = row.get("account_id") or row.get("Account ID") or row.get("account")
            profile = row.get("profile") or row.get("profile_name") or row.get("Profile")
            if account_id and profile:
                mapping[account_id.strip()] = profile.strip()
    return mapping


def detect_resource_type(resource_id: str) -> str:
    if resource_id.startswith("arn:"):
        parsed = parse_arn(resource_id)
        service = parsed.get("service") or "arn"
        resource = parsed.get("resource") or ""
        resource_kind = re.split(r"[:/]", resource, maxsplit=1)[0] if resource else "resource"
        return f"{service}_{resource_kind}".replace("-", "_")
    for prefix, resource_type in RESOURCE_PREFIXES.items():
        if resource_id.startswith(prefix):
            return resource_type
    return "unknown"


def parse_arn(arn: str) -> dict[str, str]:
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        return {}
    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account": parts[4],
        "resource": parts[5],
    }


def tags_to_dict(tags: Iterable[dict[str, Any]]) -> dict[str, str]:
    output: dict[str, str] = {}
    for tag in tags or []:
        key = tag.get("Key") or tag.get("key")
        value = tag.get("Value") if "Value" in tag else tag.get("value", "")
        if key is not None:
            output[str(key)] = "" if value is None else str(value)
    return output


def nested_name(value: dict[str, Any] | None) -> Any:
    if isinstance(value, dict):
        return value.get("Name")
    return None


def nested_arn(value: dict[str, Any] | None) -> Any:
    if isinstance(value, dict):
        return value.get("Arn")
    return None


def make_json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): make_json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [make_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [make_json_safe(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value


def is_retryable_aws_error(exc: Exception) -> bool:
    code = aws_error_code(exc)
    if code in RETRYABLE_ERROR_CODES:
        return True
    return isinstance(exc, BotoCoreError) and "timed out" in str(exc).lower()


def aws_error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return str(exc.response.get("Error", {}).get("Code", ""))
    return exc.__class__.__name__


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def format_duration(seconds: float) -> str:
    total = int(seconds)
    hours, remainder = divmod(total, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def print_progress(run_started: float, message: str) -> None:
    print(f"[{format_duration(time.monotonic() - run_started)}] {message}", flush=True)
