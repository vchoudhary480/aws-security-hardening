"""
S3 audit tests using moto to mock the AWS S3 API.
"""

import sys
import json
from pathlib import Path
import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import s3_audit


@pytest.fixture
def s3_client():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        yield client


def _make_bucket(client, name="test-bucket"):
    client.create_bucket(Bucket=name)
    return name


def test_bucket_without_encryption_flagged(s3_client):
    name = _make_bucket(s3_client)
    auditor = s3_audit.S3Auditor(client=s3_client)
    auditor.check_encryption(name)
    assert any("encryption" in f.issue.lower() for f in auditor.findings)
    assert auditor.findings[0].severity == "HIGH"


def test_bucket_with_encryption_clean(s3_client):
    name = _make_bucket(s3_client)
    s3_client.put_bucket_encryption(
        Bucket=name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    auditor = s3_audit.S3Auditor(client=s3_client)
    auditor.check_encryption(name)
    assert auditor.findings == []


def test_bucket_without_versioning_flagged(s3_client):
    name = _make_bucket(s3_client)
    auditor = s3_audit.S3Auditor(client=s3_client)
    auditor.check_versioning(name)
    assert any(f.severity == "MEDIUM" for f in auditor.findings)


def test_wildcard_bucket_policy_flagged(s3_client):
    name = _make_bucket(s3_client)
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{name}/*",
        }],
    }
    s3_client.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    auditor = s3_audit.S3Auditor(client=s3_client)
    auditor.check_bucket_policy(name)
    assert any(f.severity == "CRITICAL" for f in auditor.findings)
