"""
Security group audit tests — covers the analyze_rule() logic using plain dicts,
no AWS API mocking needed for unit-level rule analysis.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
from security_groups_audit import analyze_rule

REGION = "us-east-1"


def _rule(from_port, to_port, protocol="tcp", cidr="0.0.0.0/0"):
    return {
        "FromPort": from_port,
        "ToPort": to_port,
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": cidr}],
        "Ipv6Ranges": [],
    }


def test_ssh_open_to_internet_is_critical():
    findings = analyze_rule("sg-001", "test-sg", _rule(22, 22), REGION)
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities


def test_rdp_open_to_internet_is_critical():
    findings = analyze_rule("sg-002", "test-sg", _rule(3389, 3389), REGION)
    assert any(f.severity == "CRITICAL" and "RDP" in f.issue for f in findings)


def test_mysql_open_to_internet_is_high():
    findings = analyze_rule("sg-003", "test-sg", _rule(3306, 3306), REGION)
    assert any(f.severity == "HIGH" and "MySQL" in f.issue for f in findings)


def test_large_port_range_is_low():
    findings = analyze_rule("sg-004", "test-sg", _rule(8000, 9000), REGION)
    assert any(f.severity == "LOW" and "Large port range" in f.issue for f in findings)


def test_private_cidr_produces_no_findings():
    rule = _rule(22, 22, cidr="10.0.0.0/8")
    findings = analyze_rule("sg-005", "test-sg", rule, REGION)
    assert findings == []


def test_all_traffic_rule_is_critical():
    rule = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": [],
    }
    findings = analyze_rule("sg-006", "test-sg", rule, REGION)
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "ALL traffic" in findings[0].issue


def test_ssh_rule_does_not_double_count_as_medium():
    """Port 22 should be CRITICAL only — not also a MEDIUM catch-all."""
    findings = analyze_rule("sg-007", "test-sg", _rule(22, 22), REGION)
    severities = [f.severity for f in findings]
    assert "CRITICAL" in severities
    assert "MEDIUM" not in severities


def test_catch_all_medium_for_unknown_port():
    """A non-privileged single port should produce a MEDIUM finding."""
    findings = analyze_rule("sg-008", "test-sg", _rule(8080, 8080), REGION)
    assert any(f.severity == "MEDIUM" for f in findings)


def test_slash_8_cidr_not_flagged():
    """A /8 CIDR is not 0.0.0.0/0, so our current check should not flag it.
    This documents a known gap — in a future version, check for large CIDRs."""
    rule = _rule(22, 22, cidr="1.0.0.0/8")
    findings = analyze_rule("sg-009", "test-sg", rule, REGION)
    # Current version: no finding (known limitation, documented)
    assert findings == []
