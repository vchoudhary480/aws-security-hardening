# CIS AWS Foundations Benchmark v1.4 — Control Mapping

This table maps each audit check in this project to the corresponding CIS AWS Foundations Benchmark v1.4 control. Controls marked ✅ are implemented; controls marked ⬜ are noted as out of scope for this project.

## Section 1 — Identity and Access Management

| CIS Control | Description | Status | Script / Check |
|---|---|---|---|
| 1.4 | Ensure no root account access key exists | ✅ | `iam_audit.py` — `check_access_keys()` flags any key on root |
| 1.5 | Ensure MFA is enabled for the root account | ✅ | `iam_audit.py` — `check_user_mfa()` |
| 1.10 | Ensure MFA is enabled for all IAM users that have a console password | ✅ | `iam_audit.py` — `check_user_mfa()` applied to every user |
| 1.12 | Ensure credentials unused for 90 days or greater are disabled | ✅ | `iam_audit.py` — `check_console_password_age()` |
| 1.14 | Ensure access keys are rotated every 90 days or less | ✅ | `iam_audit.py` — `check_access_keys()`, threshold = 90 days |
| 1.16 | Ensure IAM policies are attached only to groups or roles | ⬜ | Out of scope — no programmatic check; lab uses group-based policy |
| 1.22 | Ensure IAM policies that allow full `"*:*"` administrative privileges are not created | ⬜ | Out of scope — noted in Security Decisions |

## Section 2 — Storage (S3)

| CIS Control | Description | Status | Script / Check |
|---|---|---|---|
| 2.1.1 | Ensure S3 Bucket Policy is set to deny HTTP requests | ⬜ | Out of scope for this project iteration |
| 2.1.2 | Ensure MFA Delete is enabled on S3 buckets | ⬜ | Out of scope |
| 2.1.5 | Ensure that S3 Buckets are configured with Block Public Access | ✅ | `s3_audit.py` — `check_public_access_block()`, all 4 flags checked |
| 2.1.5 | Ensure all S3 buckets have encryption configured | ✅ | `s3_audit.py` — `check_encryption()` |
| 2.1.5 | Ensure S3 bucket access logging is enabled | ✅ | `s3_audit.py` — `check_logging()` |
| 2.1.5 | Detect wildcard principal in S3 bucket policies | ✅ | `s3_audit.py` — `check_bucket_policy()` — flags `Principal: "*"` |

## Section 3 — Logging

| CIS Control | Description | Status | Script / Check |
|---|---|---|---|
| 3.1 | Ensure CloudTrail is enabled in all regions | ✅ | Manually configured — multi-region trail, validated via `aws cloudtrail describe-trails` |
| 3.2 | Ensure CloudTrail log file validation is enabled | ✅ | Enabled at trail creation (`--enable-log-file-validation`) |
| 3.4 | Ensure CloudTrail trails are integrated with CloudWatch Logs | ⬜ | Out of scope |
| 3.7 | Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket | ✅ | `s3_audit.py` — `check_logging()` covers the logs bucket |

## Section 4 — Monitoring

| CIS Control | Description | Status | Script / Check |
|---|---|---|---|
| 4.1–4.15 | CloudWatch metric filters and alarms | ⬜ | Out of scope — CloudWatch alarms not configured in this lab |

## Section 5 — Networking

| CIS Control | Description | Status | Script / Check |
|---|---|---|---|
| 5.2 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 22 | ✅ | `security_groups_audit.py` — CRITICAL finding, all regions |
| 5.3 | Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389 | ✅ | `security_groups_audit.py` — CRITICAL finding, all regions |
| 5.4 | Ensure the default security group of every VPC restricts all traffic | ✅ | `security_groups_audit.py` — flags all-traffic rules (`protocol = -1`) |

---

*Benchmark reference: CIS Amazon Web Services Foundations Benchmark v1.4.0 (released 2022)*
