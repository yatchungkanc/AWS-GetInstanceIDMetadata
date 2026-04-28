from __future__ import annotations

from collections import OrderedDict

RETRYABLE_ERROR_CODES = {
    "RequestLimitExceeded",
    "Throttling",
    "ThrottlingException",
    "TooManyRequestsException",
    "ProvisionedThroughputExceededException",
    "RequestTimeout",
    "RequestTimeoutException",
    "InternalError",
    "InternalFailure",
    "ServiceUnavailable",
    "Unavailable",
}


RESOURCE_PREFIXES = OrderedDict(
    [
        ("eipalloc-", "elastic_ip_allocation"),
        ("subnet-", "subnet"),
        ("snap-", "ebs_snapshot"),
        ("vol-", "ebs_volume"),
        ("eni-", "network_interface"),
        ("ami-", "ami"),
        ("sg-", "security_group"),
        ("vpc-", "vpc"),
        ("rtb-", "route_table"),
        ("acl-", "network_acl"),
        ("nat-", "nat_gateway"),
        ("lt-", "launch_template"),
        ("i-", "ec2_instance"),
    ]
)


OUTPUT_COLUMNS = [
    "account_id",
    "account_name",
    "region",
    "vuln_title",
    "severity",
    "resource_id",
    "resource_type",
    "resource_name",
    "metadata_status",
    "metadata_error",
    "tags_json",
    "metadata_json",
    "group_key",
    "group_item_count",
    "processed_at_utc",
    "finding_id",
    "status",
    "bu_id",
    "first_detected",
    "vuln_id",
    "last_detected",
]

