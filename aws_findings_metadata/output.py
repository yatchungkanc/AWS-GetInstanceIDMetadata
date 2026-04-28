from __future__ import annotations

import csv
import json
from pathlib import Path

from .activity_log import ActivityLogger
from .constants import OUTPUT_COLUMNS
from .models import FindingItem, MetadataResult, WorkGroup
from .utils import make_json_safe, utc_now_iso

class FindingsOutputAgent:
    name = "FindingsOutputAgent"

    def __init__(self, logger: ActivityLogger, output_file: str | Path):
        self.logger = logger
        self.output_file = Path(output_file)
        self.output_file.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.output_file.open("w", encoding="utf-8", newline="")
        self._writer = csv.DictWriter(self._handle, fieldnames=OUTPUT_COLUMNS)
        self._writer.writeheader()
        self._handle.flush()

    def close(self) -> None:
        self._handle.close()

    def write_row(self, item: FindingItem, group: WorkGroup, result: MetadataResult) -> None:
        row = {
            "account_id": item.account_id,
            "account_name": item.account_name,
            "region": item.region,
            "vuln_title": item.vuln_title,
            "severity": item.severity,
            "resource_id": item.resource_id,
            "resource_type": result.resource_type,
            "resource_name": result.resource_name,
            "metadata_status": result.metadata_status,
            "metadata_error": result.metadata_error,
            "tags_json": json.dumps(make_json_safe(result.tags), ensure_ascii=False, separators=(",", ":")),
            "metadata_json": json.dumps(make_json_safe(result.metadata), ensure_ascii=False, separators=(",", ":")),
            "group_key": group.group_key,
            "group_item_count": len(group.items),
            "processed_at_utc": utc_now_iso(),
            **item.source_fields,
        }
        self._writer.writerow(row)
        self._handle.flush()
        self.logger.event(
            "INFO",
            self.name,
            "output_row_written",
            "Output row written",
            account_id=item.account_id,
            account_name=item.account_name,
            region=item.region,
            resource_id=item.resource_id,
            vuln_title=item.vuln_title,
            severity=item.severity,
            extra={"output_file": str(self.output_file), "metadata_status": result.metadata_status},
        )


