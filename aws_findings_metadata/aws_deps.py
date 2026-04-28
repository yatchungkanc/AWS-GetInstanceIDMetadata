from __future__ import annotations

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover - exercised only on machines without boto3.
    boto3 = None
    BotoCoreError = Exception
    ClientError = Exception
