from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from .activity_log import ActivityLogger
from .coordinator import FindingsMetadataCoordinator
from .ingestion import FindingsIngestionAgent
from .metadata import AwsResourceMetadataAgent
from .output import FindingsOutputAgent
from .session import AwsAccountSessionAgent

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enrich AWS vulnerability findings with resource metadata and tags.")
    parser.add_argument("--input-file", default="[Table] All Findings_data-4.csv")
    parser.add_argument("--output-file", help="Output CSV path. Defaults to output/enriched-findings-<timestamp>.csv.")
    parser.add_argument("--log-file", help="JSONL log path. Defaults to logs/enriched-findings-<timestamp>.jsonl.")
    parser.add_argument(
        "--aws-profile-strategy",
        default="account_id_profile",
        choices=["account_id_profile", "named_profile_map", "sso_account_role", "default"],
    )
    parser.add_argument("--profile-map-file")
    parser.add_argument("--default-region", default="us-east-1")
    parser.add_argument("--max-retries", type=int, default=3)
    parser.add_argument("--retry-backoff-seconds", type=float, default=1.0)
    parser.add_argument("--dry-run", action="store_true", help="Parse and write output without calling AWS APIs.")
    parser.add_argument("--no-sso-login", action="store_true", help="Do not run aws sso login when credentials fail.")
    parser.add_argument(
        "--no-interactive-account-switch",
        action="store_true",
        help="Do not pause for manual default credential switching when no usable profile is available.",
    )
    parser.add_argument("--limit", type=int, help="Process only the first N valid source rows.")
    return parser


def default_run_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def resolve_output_paths(
    output_file: str | None,
    log_file: str | None,
    *,
    timestamp: str | None = None,
) -> tuple[Path, Path]:
    run_timestamp = timestamp or default_run_timestamp()
    resolved_output = Path(output_file) if output_file else Path("output") / f"enriched-findings-{run_timestamp}.csv"
    resolved_log = Path(log_file) if log_file else Path("logs") / f"enriched-findings-{run_timestamp}.jsonl"
    return resolved_output, resolved_log


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    output_file, log_file = resolve_output_paths(args.output_file, args.log_file)
    logger = ActivityLogger(log_file)
    output_agent: FindingsOutputAgent | None = None
    try:
        ingestion_agent = FindingsIngestionAgent(logger)
        session_agent = AwsAccountSessionAgent(
            logger,
            profile_strategy=args.aws_profile_strategy,
            profile_map_file=args.profile_map_file,
            default_region=args.default_region,
            auto_sso_login=not args.no_sso_login,
            interactive_account_switch=not args.no_interactive_account_switch,
        )
        metadata_agent = AwsResourceMetadataAgent(
            logger,
            max_retries=args.max_retries,
            retry_backoff_seconds=args.retry_backoff_seconds,
        )
        output_agent = FindingsOutputAgent(logger, output_file)
        coordinator = FindingsMetadataCoordinator(
            ingestion_agent,
            session_agent,
            metadata_agent,
            output_agent,
            logger,
            dry_run=args.dry_run,
        )
        coordinator.run(args.input_file, limit=args.limit)
        return 0
    finally:
        if output_agent is not None:
            output_agent.close()
        logger.close()
