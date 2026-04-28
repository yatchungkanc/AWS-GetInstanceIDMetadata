from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FindingItem:
    account_id: str
    account_name: str
    resource_id: str
    region: str
    vuln_title: str
    severity: str
    source_fields: dict[str, str] = field(default_factory=dict)


@dataclass
class WorkGroup:
    account_id: str
    account_name: str
    vuln_title: str
    severity: str
    group_key: str
    items: list[FindingItem] = field(default_factory=list)


@dataclass
class SessionContext:
    account_id: str
    profile_name: str | None
    session: Any
    verified: bool
    credential_source: str


@dataclass
class MetadataResult:
    resource_type: str
    resource_name: str
    metadata_status: str
    metadata_error: str
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
