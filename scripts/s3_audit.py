"""
S3 Bucket Security Audit Script

Scans every bucket in the account for:
- Public access exposure (any block-public-access flag missing)
- Default encryption configuration
- Versioning state
- Server access logging
- Bucket policies that permit wildcard principals

Usage: python s3_audit.py
"""

from dataclasses import dataclass, field, asdict
import json
import boto3
from botocore.exceptions import ClientError


@dataclass
class Finding:
    severity: str
    category: str
    resource: str
    issue: str
    recommendation: str
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(d.pop("extra", {}))
        return d


class S3Auditor:
    def __init__(self, client=None):
        self.s3 = client or boto3.client("s3")
        self.findings: list[Finding] = []

    def _add(self, severity: str, bucket: str, issue: str, recommendation: str) -> None:
        self.findings.append(Finding(
            severity=severity,
            category="S3",
            resource=bucket,
            issue=issue,
            recommendation=recommendation,
            extra={"bucket": bucket},
        ))

    def check_public_access_block(self, bucket_name: str) -> None:
        """All four block-public-access flags should be True."""
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response["PublicAccessBlockConfiguration"]
            required = [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
            missing = [flag for flag in required if not config.get(flag, False)]
            if missing:
                self._add(
                    "HIGH", bucket_name,
                    f"Block public access flags missing: {', '.join(missing)}",
                    "Enable all four block-public-access flags on this bucket",
                )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchPublicAccessBlockConfiguration":
                self._add(
                    "HIGH", bucket_name,
                    "No public access block configured",
                    "Configure public access block (all four flags = true)",
                )
            else:
                print(f"  [ERROR] Could not check public access for {bucket_name}: {e}")

    def check_encryption(self, bucket_name: str) -> None:
        """Confirm default server-side encryption is configured."""
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                self._add(
                    "HIGH", bucket_name,
                    "No default encryption configured",
                    "Enable AES256 default encryption on this bucket",
                )
            else:
                print(f"  [ERROR] Could not check encryption for {bucket_name}: {e}")

    def check_versioning(self, bucket_name: str) -> None:
        """Versioning should be Enabled for buckets holding important data."""
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = response.get("Status", "Disabled")
            if status != "Enabled":
                self._add(
                    "MEDIUM", bucket_name,
                    f"Versioning is {status}",
                    "Enable versioning to protect against accidental deletion or ransomware",
                )
        except ClientError as e:
            print(f"  [ERROR] Could not check versioning for {bucket_name}: {e}")

    def check_logging(self, bucket_name: str) -> None:
        """Server access logging should be enabled for audit trail purposes."""
        try:
            response = self.s3.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in response:
                self._add(
                    "LOW", bucket_name,
                    "Server access logging not enabled",
                    "Enable access logging to track who accessed the bucket",
                )
        except ClientError as e:
            print(f"  [ERROR] Could not check logging for {bucket_name}: {e}")

    def check_bucket_policy(self, bucket_name: str) -> None:
        """Inspect the bucket policy for wildcard principal grants."""
        try:
            response = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response["Policy"])
            for statement in policy.get("Statement", []):
                principal = statement.get("Principal")
                effect = statement.get("Effect", "Allow")
                sid = statement.get("Sid", "unnamed")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    self._add(
                        "CRITICAL", bucket_name,
                        f"Bucket policy allows wildcard principal (statement {sid})",
                        "Restrict principal to specific AWS accounts, services, or IAM users",
                    )
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                print(f"  [ERROR] Could not check policy for {bucket_name}: {e}")

    def run(self) -> list[Finding]:
        """Run all checks against every bucket in the account."""
        print("=" * 70)
        print("S3 BUCKET SECURITY AUDIT")
        print("=" * 70)

        response = self.s3.list_buckets()
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            name = bucket["Name"]
            print(f"\nAuditing bucket: {name}")
            self.check_public_access_block(name)
            self.check_encryption(name)
            self.check_versioning(name)
            self.check_logging(name)
            self.check_bucket_policy(name)

        print(f"\nAudited {len(buckets)} bucket(s)")
        self.print_report()
        return self.findings

    def print_report(self) -> None:
        """Group findings by severity and print a report."""
        print("\n" + "=" * 70)
        print("FINDINGS REPORT")
        print("=" * 70)

        if not self.findings:
            print("\n[CLEAN] No security issues found.")
            return

        by_severity: dict[str, list[Finding]] = {
            "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []
        }
        for f in self.findings:
            by_severity[f.severity].append(f)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            issues = by_severity[severity]
            if issues:
                print(f"\n[{severity}] {len(issues)} finding(s):")
                for f in issues:
                    print(f"  Bucket: {f.resource}")
                    print(f"    Issue: {f.issue}")
                    print(f"    Fix:   {f.recommendation}")

        unique_buckets = len({f.resource for f in self.findings})
        print(f"\nTOTAL: {len(self.findings)} finding(s) across {unique_buckets} bucket(s)")


def run_audit(client=None) -> list[Finding]:
    auditor = S3Auditor(client=client)
    return auditor.run()


if __name__ == "__main__":
    run_audit()
