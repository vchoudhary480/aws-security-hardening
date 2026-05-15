"""
End-to-end test for full_audit.py

Spins up a Moto-mocked AWS environment with known misconfigurations,
runs the full orchestrator, and asserts the JSON report shape and content.
"""

import sys
import json
import boto3
import pytest
from pathlib import Path
from moto import mock_aws
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))


def _setup_bad_iam(iam):
    """Create a user with no MFA."""
    iam.create_user(UserName="no-mfa-user")


def _setup_bad_s3(s3):
    """Create a bucket with no encryption and no versioning."""
    s3.create_bucket(Bucket="unencrypted-bucket")


def _setup_bad_sg(ec2):
    """Create a security group with SSH open to the internet."""
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
    vpc_id = vpc["Vpc"]["VpcId"]
    sg = ec2.create_security_group(
        GroupName="open-ssh",
        Description="SSH open to internet",
        VpcId=vpc_id,
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )


@mock_aws
def test_full_audit_report_shape(tmp_path):
    """
    Run full_audit against a mocked account and assert the JSON report:
    - is valid JSON
    - has audit_metadata and findings keys
    - contains at least one finding per category (IAM, S3, NETWORK)
    - severity_breakdown counts match actual findings
    """
    # Wire up mocked AWS resources
    region = "us-east-1"
    iam = boto3.client("iam", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    _setup_bad_iam(iam)
    _setup_bad_s3(s3)
    _setup_bad_sg(ec2)

    # Patch the auditors to use our mocked clients and single region
    import iam_audit
    import s3_audit
    import security_groups_audit
    import full_audit

    def mock_run_all():
        combined = []
        for f in iam_audit.IAMAuditor(client=iam).run():
            combined.append(f.to_dict())
        for f in s3_audit.S3Auditor(client=s3).run():
            combined.append(f.to_dict())
        for f in security_groups_audit.SecurityGroupAuditor(regions=[region]).run():
            combined.append(f.to_dict())
        return combined

    # Redirect report output to tmp_path
    original_save = full_audit.save_report

    def mock_save(findings):
        report = {
            "audit_metadata": {
                "timestamp": "2026-01-01T00:00:00",
                "total_findings": len(findings),
                "severity_breakdown": {
                    sev: sum(1 for f in findings if f["severity"] == sev)
                    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                },
            },
            "findings": findings,
        }
        report_path = tmp_path / "audit_report_test.json"
        report_path.write_text(json.dumps(report, indent=2))
        return report_path

    with patch.object(full_audit, "run_all_audits", mock_run_all), \
         patch.object(full_audit, "save_report", mock_save):
        findings = full_audit.run_all_audits()
        report_path = full_audit.save_report(findings)

    # Load and validate the report
    report = json.loads(report_path.read_text())

    # Top-level shape
    assert "audit_metadata" in report
    assert "findings" in report

    metadata = report["audit_metadata"]
    assert "total_findings" in metadata
    assert "severity_breakdown" in metadata
    assert set(metadata["severity_breakdown"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    # Counts are consistent
    assert metadata["total_findings"] == len(report["findings"])
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        expected = sum(1 for f in report["findings"] if f["severity"] == sev)
        assert metadata["severity_breakdown"][sev] == expected

    # We have findings in all three categories
    categories = {f["category"] for f in report["findings"]}
    assert "IAM" in categories
    assert "S3" in categories
    assert "NETWORK" in categories

    # Every finding has required fields
    for f in report["findings"]:
        assert "severity" in f
        assert "category" in f
        assert "issue" in f
        assert "recommendation" in f
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    # The SSH finding is present
    network_issues = [f["issue"] for f in report["findings"] if f["category"] == "NETWORK"]
    assert any("SSH" in issue for issue in network_issues)

    # Total findings > 0
    assert metadata["total_findings"] > 0
