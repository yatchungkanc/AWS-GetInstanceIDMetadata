# AWS Findings Metadata Enrichment Agents

## Purpose

Build an agent workflow that reads `[Table] All Findings_data-4.csv`, groups vulnerability findings, logs into or switches between AWS accounts, enriches each resource with AWS metadata and tags, and writes a consolidated CSV output while continuing past errors.

The source file is named `.csv`, but the observed format is UTF-16 little-endian text with tab-separated columns and quoted multiline fields. The parser must not assume UTF-8 or comma delimiters.

## Source Columns

Required input columns:

- `Account ID`
- `Account Name`
- `Resource ID`
- first `Region` column after `Resource ID`
- `Vuln Title`
- `Severity Level`

Optional input columns that may be preserved when available:

- `Finding ID`
- `Status`
- `BU ID`
- `First Detected (Cloud Config Findings)`
- `Id (Cloud Config Vulns)`
- `Last Detected (Cloud Config Findings)`

The file contains a duplicate `Region` column. The workflow must use the first `Region` column following `Resource ID` as the resource region. If the parser renames duplicate headers, document the resolved field names in logs.

## Recommended Agent Topology

Use one coordinator and four focused worker agents:

- `FindingsIngestionAgent`
- `AwsAccountSessionAgent`
- `AwsResourceMetadataAgent`
- `FindingsOutputAgent`
- `FindingsMetadataCoordinator`

This can also be implemented as a single process with these as internal modules. The contract boundaries below should remain the same either way.

## Shared Runtime Inputs

- `input_file`: path to the findings file.
- `output_file`: path for enriched CSV output.
- `log_file`: path for structured activity and error logs.
- `aws_profile_strategy`: one of:
  - `account_id_profile`: AWS CLI profile name equals the 12-digit account ID.
  - `named_profile_map`: config maps account IDs to profile names.
  - `sso_account_role`: config provides SSO start URL, region, account ID, and role name.
- `profile_map_file`: optional mapping file for `named_profile_map`.
- `max_retries`: default `3`.
- `retry_backoff_seconds`: default exponential backoff starting at `1`.
- `continue_on_error`: must default to `true`.

## Shared Output Record

Every resource item should produce one output row, even when metadata lookup fails.

Required output columns:

- `account_id`
- `account_name`
- `region`
- `vuln_title`
- `severity`
- `resource_id`
- `resource_type`
- `resource_name`
- `metadata_status`
- `metadata_error`
- `tags_json`
- `metadata_json`
- `group_key`
- `group_item_count`
- `processed_at_utc`

Recommended preserved source columns:

- `finding_id`
- `status`
- `bu_id`
- `first_detected`
- `vuln_id`
- `last_detected`

`tags_json` must be a JSON object of tag key/value pairs. `metadata_json` must be compact JSON containing the most relevant service-specific metadata returned by AWS APIs.

## FindingsIngestionAgent

### Responsibility

Parse the source findings file and create normalized grouped work units.

### Behavior

1. Detect file encoding. Prefer BOM detection; fall back to UTF-16 little-endian for this input.
2. Parse as tab-delimited CSV with quote handling and multiline field support.
3. Normalize header names by trimming whitespace and preserving enough information to disambiguate duplicates.
4. Extract `Account ID`, `Account Name`, `Resource ID`, first resource `Region`, `Vuln Title`, and `Severity Level`.
5. Validate required fields for every row.
6. Group valid rows by:
   - `Account ID`
   - `Vuln Title`
   - `Severity Level`
7. Preserve individual resource rows inside each group.
8. Emit parse warnings for missing optional fields, duplicate columns, blank rows, or invalid records.
9. Do not stop on bad rows. Mark invalid rows as skipped and continue.

### Output

Returns grouped work units:

```json
{
  "account_id": "023759106857",
  "account_name": "aws-rt-data-platform-prod",
  "vuln_title": "EC2 Instance Does Not Have CrowdStrike Installed",
  "severity": "Critical",
  "group_key": "023759106857|EC2 Instance Does Not Have CrowdStrike Installed|Critical",
  "items": [
    {
      "resource_id": "i-04c6926d36d2bf6c8",
      "region": "us-east-2",
      "source_fields": {}
    }
  ]
}
```

## AwsAccountSessionAgent

### Responsibility

Ensure the workflow is authenticated into the AWS account currently being processed.

### Behavior

1. Resolve the AWS CLI profile or SSO session for the target `account_id`.
2. Check whether credentials are already valid by calling `sts:GetCallerIdentity`.
3. If valid credentials already match the target account, reuse them.
4. If credentials are valid but belong to a different account, switch to the resolved profile for the target account.
5. If credentials are missing or expired, perform the configured login flow:
   - AWS SSO: run or trigger `aws sso login --profile <profile>`.
   - Static or assumed-role profile: refresh according to the local AWS CLI/provider chain.
6. After login or switch, verify `sts:GetCallerIdentity` returns the expected `Account`.
7. Return a session context containing account ID, profile name, credential source, and verification status.
8. Log all account switches and login attempts.
9. On account login failure, mark every item in that account group as failed with `metadata_status=account_auth_error`, then continue with the next account.

### Required IAM Permissions

Minimum AWS permissions depend on resource types. The implementation should request read-only access, including:

- `sts:GetCallerIdentity`
- `ec2:DescribeInstances`
- `ec2:DescribeTags`
- `ec2:DescribeVolumes`
- `ec2:DescribeSnapshots`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkInterfaces`
- `elasticloadbalancing:Describe*`
- `rds:Describe*`
- `resourcegroupstaggingapi:GetResources`
- `tag:GetResources`

## AwsResourceMetadataAgent

### Responsibility

Use each resource ID and region to collect resource metadata and all tags. If the resource is an EC2 instance, identify the instance name.

### Resource Type Detection

Detect resource type in this order:

1. If `resource_id` is an ARN, parse partition, service, region, account, resource type, and resource identifier from the ARN.
2. If the ID starts with a known AWS prefix, infer the service:
   - `i-`: EC2 instance
   - `vol-`: EBS volume
   - `snap-`: EBS snapshot
   - `sg-`: EC2 security group
   - `eni-`: EC2 network interface
   - `ami-`: EC2 AMI
   - `subnet-`: VPC subnet
   - `vpc-`: VPC
   - `rtb-`: route table
   - `acl-`: network ACL
   - `nat-`: NAT gateway
   - `eipalloc-`: Elastic IP allocation
   - `lt-`: EC2 launch template
3. If the type cannot be inferred, attempt generic tag lookup where possible and return `resource_type=unknown`.

### EC2 Instance Metadata

For EC2 instance IDs:

1. Call `ec2:DescribeInstances` with `InstanceIds=[resource_id]` in the finding region.
2. Extract:
   - instance ID
   - instance state
   - private IP
   - public IP
   - instance type
   - image ID
   - launch time
   - VPC ID
   - subnet ID
   - security group IDs and names
   - IAM instance profile ARN
   - platform details
   - tags
3. Derive `resource_name` from tag `Name` when present.
4. Store all instance tags in `tags_json`.
5. Store the selected metadata in `metadata_json`.

### Non-EC2 Metadata

For known non-EC2 resource IDs, call the most specific describe API available and collect tags from the returned object or `DescribeTags`/Resource Groups Tagging API.

For unknown resources:

1. Try Resource Groups Tagging API only when an ARN can be constructed or supplied.
2. If metadata cannot be found, return an output record with `metadata_status=not_found_or_unsupported`.
3. Include the error or unsupported reason in `metadata_error`.

### Error Handling

For every item:

1. Retry throttling and transient AWS errors up to `max_retries`.
2. Do not retry permanent errors such as malformed IDs or access denied, unless the AWS SDK classifies them as retryable.
3. Return a failed metadata result instead of throwing to the coordinator.
4. Continue to the next resource after logging the failure.

## FindingsOutputAgent

### Responsibility

Write enriched records to CSV and maintain structured logs.

### CSV Output Behavior

1. Create the output directory if needed.
2. Write a header row once.
3. Append one row per source finding item.
4. Quote CSV fields according to RFC 4180.
5. Encode output as UTF-8.
6. Flush periodically so partial results survive long runs.

### Logging Behavior

Write structured JSON Lines logs with:

- timestamp UTC
- level
- agent
- account ID
- account name
- region
- resource ID
- vuln title
- severity
- event name
- duration milliseconds
- message
- error code
- error details

Required events:

- `file_parse_started`
- `file_parse_completed`
- `group_created`
- `account_session_check_started`
- `account_session_ready`
- `account_session_failed`
- `resource_metadata_started`
- `resource_metadata_completed`
- `resource_metadata_failed`
- `output_row_written`
- `run_completed`

## FindingsMetadataCoordinator

### Responsibility

Orchestrate the complete workflow across all accounts and groups.

### Flow

1. Start run timer.
2. Ask `FindingsIngestionAgent` to parse and group the input file.
3. Sort work by `Account ID`, then `Vuln Title`, then `Severity`, then `Region`, then `Resource ID` for deterministic output.
4. For each account:
   - Start account timer.
   - Ask `AwsAccountSessionAgent` to login or switch to the account.
   - If account auth fails, emit failed rows for that account and continue to the next account.
5. For each group in the account:
   - Start group timer.
   - Process each item with `AwsResourceMetadataAgent`.
   - Send each result to `FindingsOutputAgent` immediately.
6. Continue processing until all accounts and all groups have been attempted.
7. Emit final summary to console and logs.

### Console Progress

Display progress with timing at account, group, and item levels. Use concise single-line updates suitable for long runs:

```text
[00:03:14] account 023759106857 aws-rt-data-platform-prod 2/18 groups, 57/421 resources processed
[00:03:16] resource i-04c6926d36d2bf6c8 us-east-2 metadata_status=ok duration_ms=842
[00:03:20] group Critical "EC2 Instance Does Not Have CrowdStrike Installed" complete resources=14 failed=1 duration_ms=6118
```

Final console summary:

```text
Run complete duration=00:42:11 accounts=18 groups=43 resources=3564 ok=3490 failed=74 output=output/enriched-findings-20260428T084933Z.csv log=logs/enriched-findings-20260428T084933Z.jsonl
```

## Acceptance Criteria

- The source file is parsed correctly as UTF-16 little-endian, tab-delimited data.
- Required fields are extracted from every valid row.
- Findings are grouped by `Account ID`, `Vuln Title`, and `Severity Level`.
- Every account is attempted.
- Existing valid AWS sessions are reused.
- The workflow switches account context when processing a different account.
- EC2 instance IDs are enriched with instance metadata, tags, and `Name` tag as `resource_name`.
- Non-EC2 resources are enriched when supported and otherwise produce clear failure rows.
- Errors are logged and do not stop the run.
- Output CSV contains one row per input finding item.
- Console progress includes elapsed time and per-account/group/resource counts.
