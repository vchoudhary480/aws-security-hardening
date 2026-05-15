"""
IAM audit tests using moto to mock the AWS IAM API.
"""

import sys
from pathlib import Path
import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import iam_audit


@pytest.fixture
def iam_client():
    with mock_aws():
        client = boto3.client("iam", region_name="us-east-1")
        yield client


def _create_user(client, username: str) -> None:
    client.create_user(UserName=username)


def test_user_with_no_mfa_flagged(iam_client):
    """A user without MFA should produce a HIGH finding."""
    _create_user(iam_client, "alice")
    auditor = iam_audit.IAMAuditor(client=iam_client)
    auditor.check_user_mfa("alice")
    assert len(auditor.findings) == 1
    assert auditor.findings[0].severity == "HIGH"
    assert "MFA" in auditor.findings[0].issue


def test_user_with_mfa_clean(iam_client):
    """A user with MFA should produce no findings."""
    _create_user(iam_client, "bob")
    # Create and attach a virtual MFA device
    iam_client.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")
    # moto marks MFA as present once the device exists and is associated
    # Use enable_mfa_device to wire it to the user
    serial = f"arn:aws:iam::123456789012:mfa/bob-mfa"
    iam_client.enable_mfa_device(
        UserName="bob",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    auditor = iam_audit.IAMAuditor(client=iam_client)
    auditor.check_user_mfa("bob")
    assert auditor.findings == []


def test_old_access_key_flagged(iam_client):
    """An access key older than 90 days should produce a MEDIUM finding."""
    from datetime import datetime, timezone, timedelta
    from unittest.mock import patch

    _create_user(iam_client, "charlie")
    iam_client.create_access_key(UserName="charlie")

    # Mock datetime.now so the key appears 100 days old
    fake_now = datetime.now(timezone.utc) + timedelta(days=100)
    with patch("iam_audit.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        auditor = iam_audit.IAMAuditor(client=iam_client)
        auditor.check_access_keys("charlie")

    assert any(f.severity == "MEDIUM" for f in auditor.findings)


def test_fresh_access_key_clean(iam_client):
    """A brand-new access key should produce no finding."""
    _create_user(iam_client, "dave")
    iam_client.create_access_key(UserName="dave")
    auditor = iam_audit.IAMAuditor(client=iam_client)
    auditor.check_access_keys("dave")
    assert auditor.findings == []
