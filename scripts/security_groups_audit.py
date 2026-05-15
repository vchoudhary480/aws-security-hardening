"""
EC2 Security Group Audit Script

Scans every security group across ALL regions for risky inbound rules:
- Admin ports (SSH 22, RDP 3389) open to 0.0.0.0/0 or ::/0
- Database ports open to the internet
- Any port open to the internet (catch-all MEDIUM)
- Large port ranges (potential lateral-movement risk)

Usage: python security_groups_audit.py
"""

from dataclasses import dataclass, field, asdict
from typing import Optional
import boto3
from botocore.exceptions import ClientError

# Ports treated as critical-risk if exposed to the internet
ADMIN_PORTS: dict[int, str] = {22: "SSH", 3389: "RDP"}

# Database ports treated as high-risk if exposed to the internet
DATABASE_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}

LARGE_RANGE_THRESHOLD = 100


@dataclass
class Finding:
    severity: str
    category: str
    resource: str
    issue: str
    recommendation: str
    region: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.update(d.pop("extra", {}))
        return d


def _is_public_cidr(cidr: str) -> bool:
    """Return True if the CIDR effectively exposes the rule to the internet."""
    return cidr in ("0.0.0.0/0", "::/0")


def _public_cidrs_from_rule(rule: dict) -> list[str]:
    """Extract every internet-facing CIDR from a rule (IPv4 + IPv6)."""
    result = []
    for r in rule.get("IpRanges", []):
        if _is_public_cidr(r.get("CidrIp", "")):
            result.append(r["CidrIp"])
    for r in rule.get("Ipv6Ranges", []):
        if _is_public_cidr(r.get("CidrIpv6", "")):
            result.append(r["CidrIpv6"])
    return result


def _port_matches(from_port: int, to_port: int, target: int) -> bool:
    """Return True if target falls within the inclusive port range."""
    return from_port <= target <= to_port


def analyze_rule(sg_id: str, sg_name: str, rule: dict, region: str) -> list[Finding]:
    """
    Analyze a single inbound rule and return any findings.

    Each finding type is tracked explicitly so the catch-all MEDIUM check
    never fires on a port already captured by a more specific rule.
    """
    from_port: Optional[int] = rule.get("FromPort")
    to_port: Optional[int] = rule.get("ToPort")
    protocol: str = rule.get("IpProtocol", "unknown")

    public_cidrs = _public_cidrs_from_rule(rule)
    if not public_cidrs:
        return []

    results: list[Finding] = []
    cidr_str = ", ".join(public_cidrs)

    # "All traffic" rule (protocol = -1)
    if protocol == "-1":
        results.append(Finding(
            severity="CRITICAL",
            category="NETWORK",
            resource=sg_name,
            region=region,
            issue="ALL traffic (all ports, all protocols) open to the internet",
            recommendation="Restrict to specific ports and trusted source IPs",
            extra={"sg_id": sg_id, "sg_name": sg_name},
        ))
        return results

    if from_port is None or to_port is None:
        return results

    port_range_size = to_port - from_port + 1
    flagged_ports: set[int] = set()

    # Admin ports (SSH / RDP) — CRITICAL
    for port, name in ADMIN_PORTS.items():
        if _port_matches(from_port, to_port, port):
            results.append(Finding(
                severity="CRITICAL",
                category="NETWORK",
                resource=sg_name,
                region=region,
                issue=f"{name} (port {port}) open to {cidr_str}",
                recommendation=(
                    f"Restrict {name} to your IP address or use "
                    "AWS Systems Manager Session Manager instead"
                ),
                extra={"sg_id": sg_id, "sg_name": sg_name},
            ))
            flagged_ports.add(port)

    # Database ports — HIGH
    for port, name in DATABASE_PORTS.items():
        if _port_matches(from_port, to_port, port):
            results.append(Finding(
                severity="HIGH",
                category="NETWORK",
                resource=sg_name,
                region=region,
                issue=f"{name} database port ({port}) open to {cidr_str}",
                recommendation="Databases should never be directly exposed to the internet",
                extra={"sg_id": sg_id, "sg_name": sg_name},
            ))
            flagged_ports.add(port)

    # Large port range — LOW
    if port_range_size > LARGE_RANGE_THRESHOLD:
        results.append(Finding(
            severity="LOW",
            category="NETWORK",
            resource=sg_name,
            region=region,
            issue=(
                f"Large port range exposed: {from_port}-{to_port} "
                f"({port_range_size} ports) to {cidr_str}"
            ),
            recommendation="Narrow the port range to only what is required",
            extra={"sg_id": sg_id, "sg_name": sg_name},
        ))

    # Catch-all MEDIUM: any internet-exposed port not already covered above
    # We check whether the *entire* range consists only of already-flagged ports.
    # A single-port rule (from_port == to_port) is flagged only if that exact
    # port wasn't already captured.  A range rule produces the catch-all unless
    # every port in the range is in flagged_ports (uncommon for large ranges,
    # but correct for e.g. a rule that is exactly {22, 3389}).
    entire_range = set(range(from_port, to_port + 1))
    already_fully_covered = entire_range.issubset(flagged_ports)

    if not already_fully_covered and port_range_size <= LARGE_RANGE_THRESHOLD:
        range_str = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
        results.append(Finding(
            severity="MEDIUM",
            category="NETWORK",
            resource=sg_name,
            region=region,
            issue=f"Port {range_str} ({protocol}) open to {cidr_str}",
            recommendation="Restrict source CIDR to known IP ranges",
            extra={"sg_id": sg_id, "sg_name": sg_name},
        ))

    return results


class SecurityGroupAuditor:
    def __init__(self, regions: Optional[list[str]] = None):
        """
        Args:
            regions: explicit list of regions to scan. If None, discovers all
                     enabled regions automatically via ec2.describe_regions().
        """
        self._regions = regions
        self.findings: list[Finding] = []

    def _get_regions(self) -> list[str]:
        if self._regions:
            return self._regions
        ec2 = boto3.client("ec2", region_name="us-east-1")
        response = ec2.describe_regions(Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}])
        return [r["RegionName"] for r in response["Regions"]]

    def audit_region(self, region: str) -> None:
        """Audit all security groups in a single region."""
        ec2 = boto3.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            sg_count = 0
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg.get("GroupName", "unnamed")
                    sg_count += 1
                    for rule in sg.get("IpPermissions", []):
                        self.findings.extend(analyze_rule(sg_id, sg_name, rule, region))
            print(f"  [{region}] Audited {sg_count} security group(s)")
        except ClientError as e:
            print(f"  [{region}] ERROR: {e}")

    def run(self) -> list[Finding]:
        """Scan security groups across all regions and return findings."""
        print("=" * 70)
        print("SECURITY GROUP AUDIT (all regions)")
        print("=" * 70)

        regions = self._get_regions()
        print(f"\nScanning {len(regions)} region(s)...\n")
        for region in regions:
            self.audit_region(region)

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
                    print(f"  SG: {f.resource} ({f.extra.get('sg_id', '')}) [{f.region}]")
                    print(f"    Issue: {f.issue}")
                    print(f"    Fix:   {f.recommendation}")

        unique_sgs = len({f.extra.get("sg_id") for f in self.findings})
        print(f"\nTOTAL: {len(self.findings)} finding(s) across {unique_sgs} security group(s)")


def run_audit(regions: Optional[list[str]] = None) -> list[Finding]:
    auditor = SecurityGroupAuditor(regions=regions)
    return auditor.run()


if __name__ == "__main__":
    run_audit()
