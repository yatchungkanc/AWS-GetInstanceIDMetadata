from __future__ import annotations

import csv
import time
from collections import OrderedDict
from pathlib import Path

from .activity_log import ActivityLogger
from .models import FindingItem, WorkGroup
from .utils import detect_encoding, elapsed_ms, normalize_headers, optional_index

class FindingsIngestionAgent:
    name = "FindingsIngestionAgent"

    def __init__(self, logger: ActivityLogger):
        self.logger = logger

    def parse(self, input_file: str | Path, limit: int | None = None) -> list[WorkGroup]:
        started = time.monotonic()
        input_path = Path(input_file)
        self.logger.event(
            "INFO",
            self.name,
            "file_parse_started",
            f"Parsing {input_path}",
            extra={"input_file": str(input_path)},
        )

        encoding = detect_encoding(input_path)
        groups: OrderedDict[tuple[str, str, str], WorkGroup] = OrderedDict()
        valid_rows = 0
        skipped_rows = 0

        with input_path.open("r", encoding=encoding, newline="") as handle:
            reader = csv.reader(handle, delimiter="\t")
            try:
                raw_headers = next(reader)
            except StopIteration:
                raise ValueError(f"{input_path} is empty")

            headers = normalize_headers(raw_headers)
            indexes = self._resolve_indexes(headers)
            self.logger.event(
                "INFO",
                self.name,
                "headers_resolved",
                "Resolved source headers",
                extra={"encoding": encoding, "headers": headers, "indexes": indexes},
            )

            for row_number, row in enumerate(reader, start=2):
                if limit is not None and valid_rows >= limit:
                    break
                if not any(cell.strip() for cell in row):
                    skipped_rows += 1
                    continue
                try:
                    item = self._row_to_item(row, indexes)
                except ValueError as exc:
                    skipped_rows += 1
                    self.logger.event(
                        "WARN",
                        self.name,
                        "row_skipped",
                        f"Skipped row {row_number}",
                        error_code="invalid_row",
                        error_details=str(exc),
                        extra={"row_number": row_number},
                    )
                    continue

                key = (item.account_id, item.vuln_title, item.severity)
                if key not in groups:
                    group_key = "|".join(key)
                    groups[key] = WorkGroup(
                        account_id=item.account_id,
                        account_name=item.account_name,
                        vuln_title=item.vuln_title,
                        severity=item.severity,
                        group_key=group_key,
                    )
                    self.logger.event(
                        "INFO",
                        self.name,
                        "group_created",
                        "Created finding group",
                        account_id=item.account_id,
                        account_name=item.account_name,
                        vuln_title=item.vuln_title,
                        severity=item.severity,
                        extra={"group_key": group_key},
                    )
                groups[key].items.append(item)
                valid_rows += 1

        duration_ms = elapsed_ms(started)
        self.logger.event(
            "INFO",
            self.name,
            "file_parse_completed",
            "Completed source parsing",
            duration_ms=duration_ms,
            extra={
                "input_file": str(input_path),
                "encoding": encoding,
                "valid_rows": valid_rows,
                "skipped_rows": skipped_rows,
                "groups": len(groups),
            },
        )
        return list(groups.values())

    def _resolve_indexes(self, headers: list[str]) -> dict[str, int]:
        def required(name: str) -> int:
            try:
                return headers.index(name)
            except ValueError as exc:
                raise ValueError(f"Missing required column: {name}") from exc

        resource_index = required("Resource ID")
        region_index = next(
            (idx for idx in range(resource_index + 1, len(headers)) if headers[idx] == "Region"),
            None,
        )
        if region_index is None:
            raise ValueError("Missing Region column after Resource ID")

        return {
            "account_id": required("Account ID"),
            "account_name": required("Account Name"),
            "finding_id": optional_index(headers, "Finding ID"),
            "resource_id": resource_index,
            "region": region_index,
            "vuln_title": required("Vuln Title"),
            "severity": required("Severity Level"),
            "status": optional_index(headers, "Status"),
            "bu_id": optional_index(headers, "BU ID"),
            "first_detected": optional_index(headers, "First Detected (Cloud Config Findings)"),
            "vuln_id": optional_index(headers, "Id (Cloud Config Vulns)"),
            "last_detected": optional_index(headers, "Last Detected (Cloud Config Findings)"),
        }

    def _row_to_item(self, row: list[str], indexes: dict[str, int]) -> FindingItem:
        def get(field: str) -> str:
            idx = indexes[field]
            if idx is None or idx >= len(row):
                return ""
            return row[idx].strip()

        required = {
            "Account ID": get("account_id"),
            "Account Name": get("account_name"),
            "Resource ID": get("resource_id"),
            "Region": get("region"),
            "Vuln Title": get("vuln_title"),
            "Severity Level": get("severity"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise ValueError(f"Missing required values: {', '.join(missing)}")

        source_fields = {
            "finding_id": get("finding_id"),
            "status": get("status"),
            "bu_id": get("bu_id"),
            "first_detected": get("first_detected"),
            "vuln_id": get("vuln_id"),
            "last_detected": get("last_detected"),
        }
        return FindingItem(
            account_id=required["Account ID"],
            account_name=required["Account Name"],
            resource_id=required["Resource ID"],
            region=required["Region"],
            vuln_title=required["Vuln Title"],
            severity=required["Severity Level"],
            source_fields=source_fields,
        )


