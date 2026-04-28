from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .utils import make_json_safe, utc_now_iso

class ActivityLogger:
    def __init__(self, log_file: str | Path):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.log_file.open("a", encoding="utf-8")

    def close(self) -> None:
        self._handle.close()

    def event(
        self,
        level: str,
        agent: str,
        event_name: str,
        message: str,
        *,
        duration_ms: int | None = None,
        account_id: str = "",
        account_name: str = "",
        region: str = "",
        resource_id: str = "",
        vuln_title: str = "",
        severity: str = "",
        error_code: str = "",
        error_details: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "timestamp_utc": utc_now_iso(),
            "level": level,
            "agent": agent,
            "account_id": account_id,
            "account_name": account_name,
            "region": region,
            "resource_id": resource_id,
            "vuln_title": vuln_title,
            "severity": severity,
            "event_name": event_name,
            "duration_ms": duration_ms,
            "message": message,
            "error_code": error_code,
            "error_details": error_details,
        }
        if extra:
            record["extra"] = make_json_safe(extra)
        self._handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        self._handle.flush()


