from __future__ import annotations

import time
from typing import Any, Callable

from .activity_log import ActivityLogger
from .models import FindingItem, MetadataResult, SessionContext
from .utils import (
    aws_error_code,
    detect_resource_type,
    elapsed_ms,
    is_retryable_aws_error,
    make_json_safe,
    nested_arn,
    nested_name,
    tags_to_dict,
)

class AwsResourceMetadataAgent:
    name = "AwsResourceMetadataAgent"

    def __init__(self, logger: ActivityLogger, *, max_retries: int = 3, retry_backoff_seconds: float = 1.0):
        self.logger = logger
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

    def collect(self, session_context: SessionContext, item: FindingItem) -> MetadataResult:
        started = time.monotonic()
        resource_type = detect_resource_type(item.resource_id)
        self.logger.event(
            "INFO",
            self.name,
            "resource_metadata_started",
            "Collecting resource metadata",
            account_id=item.account_id,
            account_name=item.account_name,
            region=item.region,
            resource_id=item.resource_id,
            vuln_title=item.vuln_title,
            severity=item.severity,
            extra={"resource_type": resource_type},
        )

        try:
            result = self._collect_by_type(session_context.session, item, resource_type)
            self.logger.event(
                "INFO",
                self.name,
                "resource_metadata_completed",
                "Resource metadata collected",
                duration_ms=elapsed_ms(started),
                account_id=item.account_id,
                account_name=item.account_name,
                region=item.region,
                resource_id=item.resource_id,
                vuln_title=item.vuln_title,
                severity=item.severity,
                extra={"resource_type": result.resource_type, "metadata_status": result.metadata_status},
            )
            return result
        except Exception as exc:
            error_code = aws_error_code(exc)
            self.logger.event(
                "ERROR",
                self.name,
                "resource_metadata_failed",
                "Resource metadata collection failed",
                duration_ms=elapsed_ms(started),
                account_id=item.account_id,
                account_name=item.account_name,
                region=item.region,
                resource_id=item.resource_id,
                vuln_title=item.vuln_title,
                severity=item.severity,
                error_code=error_code,
                error_details=str(exc),
                extra={"resource_type": resource_type},
            )
            return MetadataResult(
                resource_type=resource_type,
                resource_name="",
                metadata_status="error",
                metadata_error=f"{error_code}: {exc}" if error_code else str(exc),
            )

    def _collect_by_type(self, session: Any, item: FindingItem, resource_type: str) -> MetadataResult:
        if resource_type == "ec2_instance":
            return self._ec2_instance(session, item)
        if resource_type == "ebs_volume":
            return self._ec2_describe_one(session, item, resource_type, "describe_volumes", "VolumeIds", "Volumes")
        if resource_type == "ebs_snapshot":
            return self._ec2_describe_one(session, item, resource_type, "describe_snapshots", "SnapshotIds", "Snapshots")
        if resource_type == "security_group":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_security_groups", "GroupIds", "SecurityGroups"
            )
        if resource_type == "network_interface":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_network_interfaces", "NetworkInterfaceIds", "NetworkInterfaces"
            )
        if resource_type == "ami":
            return self._ec2_describe_one(session, item, resource_type, "describe_images", "ImageIds", "Images")
        if resource_type == "subnet":
            return self._ec2_describe_one(session, item, resource_type, "describe_subnets", "SubnetIds", "Subnets")
        if resource_type == "vpc":
            return self._ec2_describe_one(session, item, resource_type, "describe_vpcs", "VpcIds", "Vpcs")
        if resource_type == "route_table":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_route_tables", "RouteTableIds", "RouteTables"
            )
        if resource_type == "network_acl":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_network_acls", "NetworkAclIds", "NetworkAcls"
            )
        if resource_type == "nat_gateway":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_nat_gateways", "NatGatewayIds", "NatGateways"
            )
        if resource_type == "elastic_ip_allocation":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_addresses", "AllocationIds", "Addresses"
            )
        if resource_type == "launch_template":
            return self._ec2_describe_one(
                session, item, resource_type, "describe_launch_templates", "LaunchTemplateIds", "LaunchTemplates"
            )
        if item.resource_id.startswith("arn:"):
            return self._arn_tags(session, item, resource_type)
        return MetadataResult(
            resource_type=resource_type,
            resource_name="",
            metadata_status="not_found_or_unsupported",
            metadata_error="Resource type is not supported by this implementation",
        )

    def _ec2_instance(self, session: Any, item: FindingItem) -> MetadataResult:
        ec2 = session.client("ec2", region_name=item.region)
        response = self._with_retries(
            lambda: ec2.describe_instances(InstanceIds=[item.resource_id]),
            item=item,
            operation_name="ec2.describe_instances",
        )
        instances = [
            instance
            for reservation in response.get("Reservations", [])
            for instance in reservation.get("Instances", [])
        ]
        if not instances:
            return MetadataResult("ec2_instance", "", "not_found_or_unsupported", "Instance was not found")
        instance = instances[0]
        tags = tags_to_dict(instance.get("Tags", []))
        metadata = {
            "instance_id": instance.get("InstanceId"),
            "state": nested_name(instance.get("State")),
            "private_ip_address": instance.get("PrivateIpAddress"),
            "public_ip_address": instance.get("PublicIpAddress"),
            "instance_type": instance.get("InstanceType"),
            "image_id": instance.get("ImageId"),
            "launch_time": instance.get("LaunchTime"),
            "vpc_id": instance.get("VpcId"),
            "subnet_id": instance.get("SubnetId"),
            "security_groups": instance.get("SecurityGroups", []),
            "iam_instance_profile_arn": nested_arn(instance.get("IamInstanceProfile")),
            "platform_details": instance.get("PlatformDetails"),
        }
        return MetadataResult(
            resource_type="ec2_instance",
            resource_name=tags.get("Name", ""),
            metadata_status="ok",
            metadata_error="",
            tags=tags,
            metadata=make_json_safe(metadata),
        )

    def _ec2_describe_one(
        self,
        session: Any,
        item: FindingItem,
        resource_type: str,
        method_name: str,
        id_parameter: str,
        result_key: str,
    ) -> MetadataResult:
        ec2 = session.client("ec2", region_name=item.region)
        method = getattr(ec2, method_name)
        response = self._with_retries(
            lambda: method(**{id_parameter: [item.resource_id]}),
            item=item,
            operation_name=f"ec2.{method_name}",
        )
        records = response.get(result_key, [])
        if not records:
            return MetadataResult(resource_type, "", "not_found_or_unsupported", "Resource was not found")
        record = records[0]
        tags = tags_to_dict(record.get("Tags", []))
        name = tags.get("Name", record.get("Name", ""))
        return MetadataResult(
            resource_type=resource_type,
            resource_name=name,
            metadata_status="ok",
            metadata_error="",
            tags=tags,
            metadata=make_json_safe(record),
        )

    def _arn_tags(self, session: Any, item: FindingItem, resource_type: str) -> MetadataResult:
        client = session.client("resourcegroupstaggingapi", region_name=item.region)
        response = self._with_retries(
            lambda: client.get_resources(ResourceARNList=[item.resource_id]),
            item=item,
            operation_name="resourcegroupstaggingapi.get_resources",
        )
        mappings = response.get("ResourceTagMappingList", [])
        if not mappings:
            return MetadataResult(resource_type, "", "not_found_or_unsupported", "ARN was not found by tagging API")
        tags = tags_to_dict(mappings[0].get("Tags", []))
        return MetadataResult(
            resource_type=resource_type,
            resource_name=tags.get("Name", ""),
            metadata_status="ok",
            metadata_error="",
            tags=tags,
            metadata=make_json_safe(mappings[0]),
        )

    def _with_retries(self, operation: Callable[[], Any], *, item: FindingItem, operation_name: str) -> Any:
        attempt = 0
        while True:
            try:
                return operation()
            except Exception as exc:
                attempt += 1
                if attempt > self.max_retries or not is_retryable_aws_error(exc):
                    raise
                sleep_seconds = self.retry_backoff_seconds * (2 ** (attempt - 1))
                self.logger.event(
                    "WARN",
                    self.name,
                    "resource_metadata_retry",
                    f"Retrying {operation_name}",
                    account_id=item.account_id,
                    account_name=item.account_name,
                    region=item.region,
                    resource_id=item.resource_id,
                    vuln_title=item.vuln_title,
                    severity=item.severity,
                    error_code=aws_error_code(exc),
                    error_details=str(exc),
                    extra={"attempt": attempt, "sleep_seconds": sleep_seconds},
                )
                time.sleep(sleep_seconds)


