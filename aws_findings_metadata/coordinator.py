from __future__ import annotations

import time
from collections import OrderedDict
from pathlib import Path

from .activity_log import ActivityLogger
from .ingestion import FindingsIngestionAgent
from .metadata import AwsResourceMetadataAgent
from .models import MetadataResult, SessionContext, WorkGroup
from .output import FindingsOutputAgent
from .session import AwsAccountSessionAgent
from .utils import aws_error_code, detect_resource_type, elapsed_ms, format_duration, print_progress

class FindingsMetadataCoordinator:
    name = "FindingsMetadataCoordinator"

    def __init__(
        self,
        ingestion_agent: FindingsIngestionAgent,
        session_agent: AwsAccountSessionAgent,
        metadata_agent: AwsResourceMetadataAgent,
        output_agent: FindingsOutputAgent,
        logger: ActivityLogger,
        *,
        dry_run: bool = False,
    ):
        self.ingestion_agent = ingestion_agent
        self.session_agent = session_agent
        self.metadata_agent = metadata_agent
        self.output_agent = output_agent
        self.logger = logger
        self.dry_run = dry_run

    def run(self, input_file: str | Path, limit: int | None = None) -> dict[str, int]:
        run_started = time.monotonic()
        groups = self.ingestion_agent.parse(input_file, limit=limit)
        groups = sorted(
            groups,
            key=lambda group: (
                group.account_id,
                group.vuln_title,
                group.severity,
                min((item.region for item in group.items), default=""),
                min((item.resource_id for item in group.items), default=""),
            ),
        )

        grouped_by_account: OrderedDict[tuple[str, str], list[WorkGroup]] = OrderedDict()
        for group in groups:
            grouped_by_account.setdefault((group.account_id, group.account_name), []).append(group)

        total_resources = sum(len(group.items) for group in groups)
        summary = {
            "accounts": len(grouped_by_account),
            "groups": len(groups),
            "resources": total_resources,
            "ok": 0,
            "failed": 0,
        }
        processed_resources = 0

        for account_number, ((account_id, account_name), account_groups) in enumerate(grouped_by_account.items(), 1):
            account_started = time.monotonic()
            session_context: SessionContext | None = None
            account_items = sum(len(group.items) for group in account_groups)
            if not self.dry_run:
                try:
                    session_context = self.session_agent.ensure_account(account_id, account_name)
                except Exception as exc:
                    self.logger.event(
                        "ERROR",
                        self.name,
                        "account_session_failed",
                        "AWS account session failed",
                        account_id=account_id,
                        account_name=account_name,
                        error_code=aws_error_code(exc),
                        error_details=str(exc),
                    )
                    for group in account_groups:
                        for item in group.items:
                            result = MetadataResult(
                                resource_type=detect_resource_type(item.resource_id),
                                resource_name="",
                                metadata_status="account_auth_error",
                                metadata_error=str(exc),
                            )
                            self.output_agent.write_row(item, group, result)
                            summary["failed"] += 1
                            processed_resources += 1
                    print_progress(
                        run_started,
                        f"account {account_id} {account_name} auth failed; skipped {account_items} resources",
                    )
                    continue

            for group_number, group in enumerate(account_groups, 1):
                group_started = time.monotonic()
                group_failed = 0
                for item_number, item in enumerate(
                    sorted(group.items, key=lambda row: (row.region, row.resource_id)),
                    1,
                ):
                    item_started = time.monotonic()
                    if self.dry_run:
                        result = MetadataResult(
                            resource_type=detect_resource_type(item.resource_id),
                            resource_name="",
                            metadata_status="dry_run",
                            metadata_error="AWS metadata collection skipped because --dry-run was set",
                        )
                    else:
                        result = self.metadata_agent.collect(session_context, item)

                    self.output_agent.write_row(item, group, result)
                    if result.metadata_status == "ok":
                        summary["ok"] += 1
                    else:
                        summary["failed"] += 1
                        group_failed += 1
                    processed_resources += 1
                    print_progress(
                        run_started,
                        (
                            f"resource {item.resource_id} {item.region} "
                            f"metadata_status={result.metadata_status} "
                            f"duration_ms={elapsed_ms(item_started)} "
                            f"processed={processed_resources}/{total_resources}"
                        ),
                    )

                print_progress(
                    run_started,
                    (
                        f"group {group.severity} \"{group.vuln_title}\" complete "
                        f"account={account_id} group={group_number}/{len(account_groups)} "
                        f"resources={len(group.items)} failed={group_failed} "
                        f"duration_ms={elapsed_ms(group_started)}"
                    ),
                )

            print_progress(
                run_started,
                (
                    f"account {account_id} {account_name} complete "
                    f"{account_number}/{len(grouped_by_account)} accounts "
                    f"resources={account_items} duration_ms={elapsed_ms(account_started)}"
                ),
            )

        self.logger.event(
            "INFO",
            self.name,
            "run_completed",
            "Run complete",
            duration_ms=elapsed_ms(run_started),
            extra=summary,
        )
        print_progress(
            run_started,
            (
                "Run complete "
                f"duration={format_duration(time.monotonic() - run_started)} "
                f"accounts={summary['accounts']} groups={summary['groups']} "
                f"resources={summary['resources']} ok={summary['ok']} failed={summary['failed']}"
            ),
        )
        return summary


