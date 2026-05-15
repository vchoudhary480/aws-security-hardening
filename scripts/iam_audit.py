"""
IAM Security Audit Script
Scans all IAM users for common security issues:
- Missing MFA
- Old access keys (>90 days)
- Inactive console passwords (>90 days)

Usage: python iam_audit.py
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional
import boto3
from botocore.exceptions import ClientError

# Configurable thresholds
ACCESS_KEY_AGE_LIMIT_DAYS = 90
PASSWORD_INACTIVITY_LIMIT_DAYS = 90


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


class IAMAuditor:
    def __init__(self, client=None):
        self.iam = client or boto3.client("iam")
        self.findings: list[Finding] = []

    def check_user_mfa(self, username: str) -> None:
        """Check if a given IAM user has MFA enabled."""
        try:
            response = self.iam.list_mfa_devices(UserName=username)
            if not response.get("MFADevices"):
                self.findings.append(Finding(
                    severity="HIGH",
                    category="IAM",
                    resource=username,
                    issue="No MFA device configured",
                    recommendation="Enable MFA on this user immediately",
                    extra={"user": username},
                ))
        except ClientError as e:
            print(f"  [ERROR] Could not check MFA for {username}: {e}")

    def check_access_keys(self, username: str) -> None:
        """Check for access keys older than the threshold."""
        try:
            response = self.iam.list_access_keys(UserName=username)
            for key in response.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days
                if age_days > ACCESS_KEY_AGE_LIMIT_DAYS:
                    self.findings.append(Finding(
                        severity="MEDIUM",
                        category="IAM",
                        resource=username,
                        issue=f"Access key {key_id[:8]}... is {age_days} days old",
                        recommendation=f"Rotate this access key (>{ACCESS_KEY_AGE_LIMIT_DAYS} days old)",
                        extra={"user": username},
                    ))
        except ClientError as e:
            print(f"  [ERROR] Could not check keys for {username}: {e}")

    def check_console_password_age(self, username: str) -> None:
        """Check whether the user's console password has been used recently."""
        try:
            user_info = self.iam.get_user(UserName=username)
            password_last_used: Optional[datetime] = user_info["User"].get("PasswordLastUsed")
            if password_last_used:
                days_since_use = (datetime.now(timezone.utc) - password_last_used).days
                if days_since_use > PASSWORD_INACTIVITY_LIMIT_DAYS:
                    self.findings.append(Finding(
                        severity="LOW",
                        category="IAM",
                        resource=username,
                        issue=f"Console password not used in {days_since_use} days",
                        recommendation="Consider deactivating or removing console access",
                        extra={"user": username},
                    ))
        except ClientError as e:
            print(f"  [ERROR] Could not check password age for {username}: {e}")

    def run(self) -> list[Finding]:
        """Run all checks against every IAM user in the account."""
        print("=" * 70)
        print("IAM SECURITY AUDIT")
        print("=" * 70)

        paginator = self.iam.get_paginator("list_users")
        user_count = 0

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                user_count += 1
                print(f"\nAuditing user: {username}")
                self.check_user_mfa(username)
                self.check_access_keys(username)
                self.check_console_password_age(username)

        print(f"\nAudited {user_count} user(s)")
        self.print_report()
        return self.findings

    def print_report(self) -> None:
        """Output findings grouped by severity."""
        print("\n" + "=" * 70)
        print("FINDINGS REPORT")
        print("=" * 70)

        if not self.findings:
            print("\n[CLEAN] No security issues found.")
            return

        by_severity: dict[str, list[Finding]] = {"HIGH": [], "MEDIUM": [], "LOW": []}
        for f in self.findings:
            by_severity[f.severity].append(f)

        for severity in ["HIGH", "MEDIUM", "LOW"]:
            issues = by_severity[severity]
            if issues:
                print(f"\n[{severity}] {len(issues)} finding(s):")
                for f in issues:
                    print(f"  User: {f.resource}")
                    print(f"    Issue: {f.issue}")
                    print(f"    Fix:   {f.recommendation}")

        unique_resources = len({f.resource for f in self.findings})
        print(f"\nTOTAL: {len(self.findings)} finding(s) across {unique_resources} user(s)")


# Module-level convenience for backwards compatibility with full_audit.py
def run_audit(client=None) -> list[Finding]:
    auditor = IAMAuditor(client=client)
    return auditor.run()


if __name__ == "__main__":
    run_audit()
