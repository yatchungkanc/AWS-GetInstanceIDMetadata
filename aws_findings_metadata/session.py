from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .activity_log import ActivityLogger
from .aws_deps import boto3
from .models import SessionContext
from .utils import aws_error_code, elapsed_ms, load_profile_map

class AwsAccountSessionAgent:
    name = "AwsAccountSessionAgent"

    def __init__(
        self,
        logger: ActivityLogger,
        *,
        profile_strategy: str,
        profile_map_file: str | Path | None = None,
        default_region: str = "us-east-1",
        auto_sso_login: bool = True,
        interactive_account_switch: bool = True,
    ):
        self.logger = logger
        self.profile_strategy = profile_strategy
        self.default_region = default_region
        self.auto_sso_login = auto_sso_login
        self.interactive_account_switch = interactive_account_switch
        self.profile_map = load_profile_map(profile_map_file) if profile_map_file else {}

    def ensure_account(self, account_id: str, account_name: str) -> SessionContext:
        if boto3 is None:
            raise RuntimeError("boto3 is required for AWS metadata collection. Install requirements.txt.")

        started = time.monotonic()
        self.logger.event(
            "INFO",
            self.name,
            "account_session_check_started",
            "Checking AWS account session",
            account_id=account_id,
            account_name=account_name,
            extra={"profile_strategy": self.profile_strategy},
        )

        current_context = self._current_default_context(account_id, account_name)
        if current_context is not None:
            self.logger.event(
                "INFO",
                self.name,
                "account_session_ready",
                "Reusing current default AWS credentials",
                duration_ms=elapsed_ms(started),
                account_id=account_id,
                account_name=account_name,
                extra={"profile_name": None, "credential_source": "default"},
            )
            return current_context

        profile_error: Exception | None = None
        try:
            profile_name = self._resolve_profile(account_id)
        except Exception as exc:
            profile_name = None
            profile_error = exc
            self.logger.event(
                "INFO",
                self.name,
                "profile_resolution_unavailable",
                "No configured AWS profile was resolved for this account",
                account_id=account_id,
                account_name=account_name,
                error_code=aws_error_code(exc),
                error_details=str(exc),
            )

        if profile_name:
            try:
                profile_context = self._profile_context(profile_name, account_id, account_name, started)
                if profile_context is not None:
                    return profile_context
            except Exception as exc:
                profile_error = exc
                self.logger.event(
                    "INFO",
                    self.name,
                    "profile_session_unavailable",
                    "Configured profile credentials are unavailable",
                    account_id=account_id,
                    account_name=account_name,
                    error_code=aws_error_code(exc),
                    error_details=str(exc),
                    extra={"profile_name": profile_name},
                )

        prompted_context = self._interactive_account_resolution(
            account_id,
            account_name,
            previous_error=profile_error,
            started=started,
        )
        if prompted_context is not None:
            return prompted_context

        if profile_error is not None:
            raise profile_error

        raise RuntimeError(
            f"Default AWS credentials are not for account {account_id}. "
            "Switch/login to that account or enable interactive account switching."
        )

    def _profile_context(
        self,
        profile_name: str,
        account_id: str,
        account_name: str,
        started: float,
    ) -> SessionContext | None:
        session = self._new_session(profile_name)
        try:
            identity = self._get_identity(session)
        except Exception as first_exc:
            if self.auto_sso_login:
                self._attempt_sso_login(profile_name, account_id, account_name, str(first_exc))
                session = self._new_session(profile_name)
                identity = self._get_identity(session)
            else:
                raise

        actual_account = str(identity.get("Account", ""))
        if actual_account != account_id:
            self.logger.event(
                "INFO",
                self.name,
                "profile_session_account_mismatch",
                "Configured profile credentials are for a different account",
                account_id=account_id,
                account_name=account_name,
                extra={
                    "profile_name": profile_name,
                    "current_account": actual_account,
                    "identity_arn": identity.get("Arn", ""),
                },
            )
            return None

        self.logger.event(
            "INFO",
            self.name,
            "account_session_ready",
            "AWS account session ready",
            duration_ms=elapsed_ms(started),
            account_id=account_id,
            account_name=account_name,
            extra={"profile_name": profile_name, "identity_arn": identity.get("Arn", "")},
        )
        return SessionContext(
            account_id=account_id,
            profile_name=profile_name,
            session=session,
            verified=True,
            credential_source="profile" if profile_name else "default",
        )

    def _interactive_account_resolution(
        self,
        account_id: str,
        account_name: str,
        *,
        previous_error: Exception | None,
        started: float,
    ) -> SessionContext | None:
        if not self.interactive_account_switch or not sys.stdin.isatty():
            return None

        self.logger.event(
            "INFO",
            self.name,
            "interactive_account_switch_requested",
            "Waiting for user to choose or switch AWS credentials",
            account_id=account_id,
            account_name=account_name,
            error_code=aws_error_code(previous_error) if previous_error else "",
            error_details=str(previous_error) if previous_error else "",
        )
        profiles = self._available_profiles()

        while True:
            print(
                "\n"
                f"AWS credentials are not currently for account {account_id} ({account_name}).",
                flush=True,
            )
            if profiles:
                print("\nAvailable AWS profiles:", flush=True)
                for index, profile in enumerate(profiles, 1):
                    print(f"  {index}. {profile}", flush=True)
                print(
                    "\nChoose a profile by number/name, or press Enter after switching default credentials manually.",
                    flush=True,
                )
            else:
                print(
                    "\nNo AWS profiles were found. Switch/login using your normal AWS method in another terminal, "
                    "then press Enter here.",
                    flush=True,
                )
            print("Type 'q' to skip this account.", flush=True)

            choice = input("AWS credential choice: ").strip()
            if choice.lower() in {"q", "quit", "skip"}:
                raise RuntimeError(f"User skipped authentication for account {account_id}")

            if choice:
                selected_profile = self._resolve_profile_choice(choice, profiles)
                if selected_profile is None:
                    print(f"Invalid profile choice: {choice}", flush=True)
                    continue

                try:
                    context = self._profile_context(selected_profile, account_id, account_name, started)
                except Exception as exc:
                    print(f"Profile {selected_profile} could not be used: {exc}", flush=True)
                    self.logger.event(
                        "WARN",
                        self.name,
                        "interactive_profile_failed",
                        "Selected AWS profile could not be used",
                        account_id=account_id,
                        account_name=account_name,
                        error_code=aws_error_code(exc),
                        error_details=str(exc),
                        extra={"profile_name": selected_profile},
                    )
                    continue

                if context is None:
                    print(
                        f"Profile {selected_profile} is not for account {account_id}; choose another profile.",
                        flush=True,
                    )
                    continue

                self.logger.event(
                    "INFO",
                    self.name,
                    "account_session_ready",
                    "Using interactively selected AWS profile",
                    duration_ms=elapsed_ms(started),
                    account_id=account_id,
                    account_name=account_name,
                    extra={"profile_name": selected_profile, "credential_source": "profile"},
                )
                return context

            context = self._current_default_context(account_id, account_name)
            if context is None:
                print(
                    f"Default AWS credentials still do not resolve to account {account_id}.",
                    flush=True,
                )
                continue

            self.logger.event(
                "INFO",
                self.name,
                "account_session_ready",
                "Reusing default AWS credentials after interactive switch",
                duration_ms=elapsed_ms(started),
                account_id=account_id,
                account_name=account_name,
                extra={"profile_name": None, "credential_source": "default"},
            )
            return context

    def _available_profiles(self) -> list[str]:
        try:
            return sorted(boto3.Session().available_profiles)
        except Exception:
            return []

    def _resolve_profile_choice(self, choice: str, profiles: list[str]) -> str | None:
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(profiles):
                return profiles[index - 1]
            return None
        if choice in profiles:
            return choice
        return None

    def _current_default_context(self, account_id: str, account_name: str) -> SessionContext | None:
        try:
            session = self._new_session(None)
            identity = self._get_identity(session)
        except Exception as exc:
            self.logger.event(
                "INFO",
                self.name,
                "default_session_unavailable",
                "Current default AWS credentials are unavailable",
                account_id=account_id,
                account_name=account_name,
                error_code=aws_error_code(exc),
                error_details=str(exc),
            )
            return None

        actual_account = str(identity.get("Account", ""))
        if actual_account != account_id:
            self.logger.event(
                "INFO",
                self.name,
                "default_session_account_mismatch",
                "Current default AWS credentials are for a different account",
                account_id=account_id,
                account_name=account_name,
                extra={"current_account": actual_account, "identity_arn": identity.get("Arn", "")},
            )
            return None

        return SessionContext(
            account_id=account_id,
            profile_name=None,
            session=session,
            verified=True,
            credential_source="default",
        )

    def _resolve_profile(self, account_id: str) -> str | None:
        if self.profile_strategy == "account_id_profile":
            return account_id
        if self.profile_strategy in {"named_profile_map", "sso_account_role"}:
            profile = self.profile_map.get(account_id)
            if not profile:
                raise RuntimeError(f"No AWS profile mapping found for account {account_id}")
            return profile
        if self.profile_strategy == "default":
            return None
        raise ValueError(f"Unsupported profile strategy: {self.profile_strategy}")

    def _new_session(self, profile_name: str | None) -> Any:
        if profile_name:
            return boto3.Session(profile_name=profile_name, region_name=self.default_region)
        return boto3.Session(region_name=self.default_region)

    def _get_identity(self, session: Any) -> dict[str, Any]:
        return session.client("sts", region_name=self.default_region).get_caller_identity()

    def _attempt_sso_login(
        self,
        profile_name: str,
        account_id: str,
        account_name: str,
        previous_error: str,
    ) -> None:
        started = time.monotonic()
        command = ["aws", "sso", "login", "--profile", profile_name]
        self.logger.event(
            "INFO",
            self.name,
            "account_sso_login_started",
            "Attempting AWS SSO login",
            account_id=account_id,
            account_name=account_name,
            error_details=previous_error,
            extra={"command": command},
        )
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0:
            raise RuntimeError(
                f"aws sso login failed for profile {profile_name}: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )
        self.logger.event(
            "INFO",
            self.name,
            "account_sso_login_completed",
            "AWS SSO login completed",
            duration_ms=elapsed_ms(started),
            account_id=account_id,
            account_name=account_name,
        )


