"""
AWS Security Audit Orchestrator

Runs all three audit modules (IAM, S3, Security Groups) and produces:
- A consolidated console summary
- A timestamped JSON report in ../docs/

Exit codes:
  0 = no findings
  1 = findings detected (suitable for CI/CD pipelines)

Usage: python full_audit.py
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import iam_audit
import s3_audit
import security_groups_audit


def run_all_audits() -> list[dict]:
    print("\n" + "#" * 70)
    print("# AWS SECURITY HARDENING - FULL ACCOUNT AUDIT")
    print(f"# Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("#" * 70)

    combined: list[dict] = []

    print("\n[1/3] Running IAM audit...")
    for f in iam_audit.run_audit():
        combined.append(f.to_dict())

    print("\n[2/3] Running S3 audit...")
    for f in s3_audit.run_audit():
        combined.append(f.to_dict())

    print("\n[3/3] Running Security Groups audit (all regions)...")
    for f in security_groups_audit.run_audit():
        combined.append(f.to_dict())

    return combined


def print_summary(findings: list[dict]) -> None:
    """Print a clean executive-summary table to the console."""
    print("\n" + "=" * 70)
    print("EXECUTIVE SUMMARY")
    print("=" * 70)

    if not findings:
        print("\n[CLEAN] All security checks passed. No findings.")
        return

    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    category_counts: dict[str, int] = {"IAM": 0, "S3": 0, "NETWORK": 0}

    for f in findings:
        severity_counts[f["severity"]] += 1
        category_counts[f.get("category", "UNKNOWN")] = category_counts.get(f.get("category", "UNKNOWN"), 0) + 1

    print(f"\nTotal findings: {len(findings)}")
    print("\nBy severity:")
    for severity, count in severity_counts.items():
        if count > 0:
            print(f"  {severity:10s} {count}")

    print("\nBy category:")
    for category, count in category_counts.items():
        if count > 0:
            print(f"  {category:10s} {count}")

    critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
    if critical_high:
        print("\n" + "-" * 70)
        print("CRITICAL & HIGH PRIORITY ITEMS:")
        print("-" * 70)
        for f in critical_high:
            resource = f.get("resource", "unknown")
            print(f"\n  [{f['severity']}] {f.get('category', '')} - {resource}")
            print(f"    {f['issue']}")
            print(f"    -> {f['recommendation']}")


def save_report(findings: list[dict]) -> Path:
    """Save a timestamped JSON report under ../docs/."""
    docs_dir = Path(__file__).parent.parent / "docs"
    docs_dir.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = docs_dir / f"audit_report_{timestamp}.json"

    report = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(findings),
            "severity_breakdown": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            },
        },
        "findings": findings,
    }

    report_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\n[OK] Report saved to: {report_path}")
    return report_path


if __name__ == "__main__":
    findings = run_all_audits()
    print_summary(findings)
    save_report(findings)
    sys.exit(1 if findings else 0)
