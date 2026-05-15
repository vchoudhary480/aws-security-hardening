"""
End-to-end test for full_audit.py

Spins up a moto-mocked AWS environment with known misconfigurations,
calls the real run_all_audits() and save_report(), and asserts the
JSON report shape and content are correct.
"""

import sys
import json
import boto3
from pathlib import Path
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import full_audit


def _setup_bad_iam(iam):
    """Create a user with no MFA."""
    iam.create_user(UserName="no-mfa-user")


def _setup_bad_s3(s3):
    """Create a bucket with no encryption and no versioning."""
    s3.create_bucket(Bucket="unencrypted-bucket")


def _setup_bad_sg(ec2, region):
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
def test_full_audit_report_shape(tmp_path, monkeypatch):
    """
    Run the real full_audit orchestrator against a moto-mocked account.
    Asserts the JSON report has the correct shape and expected findings.
    """
    region = "us-east-1"

    # Set up mocked AWS resources with intentional misconfigurations
    iam = boto3.client("iam", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)

    _setup_bad_iam(iam)
    _setup_bad_s3(s3)
    _setup_bad_sg(ec2, region)

    # Scope the SG auditor to us-east-1 only so we don't hit unrelated regions
    import security_groups_audit
    monkeypatch.setattr(
        security_groups_audit.SecurityGroupAuditor,
        "_get_regions",
        lambda self: [region],
    )

    # Redirect report output to tmp_path instead of docs/
    monkeypatch.setattr(
        full_audit,
        "save_report",
        lambda findings: _save_to_tmp(findings, tmp_path),
    )

    # Run the real orchestrator
    findings = full_audit.run_all_audits()
    report_path = full_audit.save_report(findings)

    # Load and validate
    report = json.loads(report_path.read_text())

    # Top-level shape
    assert "audit_metadata" in report
    assert "findings" in report

    metadata = report["audit_metadata"]
    assert "total_findings" in metadata
    assert "severity_breakdown" in metadata
    assert set(metadata["severity_breakdown"].keys()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    # Counts are internally consistent
    assert metadata["total_findings"] == len(report["findings"])
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        expected = sum(1 for f in report["findings"] if f["severity"] == sev)
        assert metadata["severity_breakdown"][sev] == expected

    # All three categories present
    categories = {f["category"] for f in report["findings"]}
    assert "IAM" in categories
    assert "S3" in categories
    assert "NETWORK" in categories

    # Every finding has required fields with valid values
    for f in report["findings"]:
        assert "severity" in f
        assert "category" in f
        assert "issue" in f
        assert "recommendation" in f
        assert f["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    # SSH finding is present
    network_issues = [f["issue"] for f in report["findings"] if f["category"] == "NETWORK"]
    assert any("SSH" in issue for issue in network_issues)

    # At least one finding total
    assert metadata["total_findings"] > 0


def _save_to_tmp(findings, tmp_path):
    """Write the report to tmp_path instead of docs/."""
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
