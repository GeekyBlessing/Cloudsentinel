"""
cloudsentinel.scanner.rules.aws_s3
====================================
S3 security rules — CIS AWS Foundations Benchmark v1.5 Section 2.1

Rules implemented
-----------------
CS-S3-001  Bucket publicly accessible (Block Public Access disabled)
CS-S3-002  Server-side encryption disabled
CS-S3-003  Access logging disabled
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import SecurityRule

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class S3BucketPublicAccess(SecurityRule):
    """
    CS-S3-001 — CIS 2.1.5
    Ensure S3 bucket Block Public Access is enabled at bucket level.

    Why it matters
    --------------
    Public S3 buckets are one of the most common causes of cloud data
    breaches. Automated scanners (GrayhatWarfare, Bucket Finder) enumerate
    public buckets continuously. A single misconfigured bucket can expose
    the entire data lake.
    """
    rule_id      = "CS-S3-001"
    title        = "S3 bucket is publicly accessible"
    description  = (
        "The S3 bucket does not have Block Public Access enabled. "
        "Public buckets allow unauthenticated read/write access from "
        "the internet, enabling data collection and exfiltration without "
        "any AWS credentials."
    )
    severity     = "CRITICAL"
    service      = "S3"
    cis_control  = "CIS 2.1.5"
    nist_control = "PR.AC-3"
    soc2_control = "CC6.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            log.error("Failed to list S3 buckets: %s", e)
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            try:
                pab = s3.get_public_access_block(Bucket=name)
                config = pab["PublicAccessBlockConfiguration"]

                # All four settings must be True for full protection
                fully_blocked = all([
                    config.get("BlockPublicAcls",       False),
                    config.get("IgnorePublicAcls",      False),
                    config.get("BlockPublicPolicy",     False),
                    config.get("RestrictPublicBuckets", False),
                ])

                if not fully_blocked:
                    # Identify which specific settings are misconfigured
                    issues = []
                    if not config.get("BlockPublicAcls"):
                        issues.append("BlockPublicAcls=false")
                    if not config.get("IgnorePublicAcls"):
                        issues.append("IgnorePublicAcls=false")
                    if not config.get("BlockPublicPolicy"):
                        issues.append("BlockPublicPolicy=false")
                    if not config.get("RestrictPublicBuckets"):
                        issues.append("RestrictPublicBuckets=false")

                    findings.append(self._finding(
                        resource_id  = name,
                        resource_arn = f"arn:aws:s3:::{name}",
                        extra={
                            "is_public":          True,
                            "has_sensitive_data": self._infer_sensitive(name),
                            "detail":             ", ".join(issues),
                            "remediation_steps": [
                                f"Navigate to S3 → {name} → Permissions → Block Public Access.",
                                "Enable all four Block Public Access settings.",
                                "Review and remove any public bucket policies or ACLs.",
                                "Audit what data is in the bucket and classify appropriately.",
                            ],
                            "remediation_cli": (
                                f"aws s3api put-public-access-block \\\n"
                                f"  --bucket {name} \\\n"
                                f"  --public-access-block-configuration "
                                f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                                f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                            ),
                        }
                    ))

            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                # No block public access config at all — bucket is unprotected
                findings.append(self._finding(
                    resource_id  = name,
                    resource_arn = f"arn:aws:s3:::{name}",
                    extra={
                        "is_public":  True,
                        "detail":     "No Block Public Access configuration exists",
                        "remediation_steps": [
                            "Block Public Access configuration is entirely absent.",
                            f"Run: aws s3api put-public-access-block --bucket {name} "
                            "--public-access-block-configuration "
                            "BlockPublicAcls=true,IgnorePublicAcls=true,"
                            "BlockPublicPolicy=true,RestrictPublicBuckets=true",
                        ],
                        "remediation_cli": (
                            f"aws s3api put-public-access-block \\\n"
                            f"  --bucket {name} \\\n"
                            f"  --public-access-block-configuration "
                            f"BlockPublicAcls=true,IgnorePublicAcls=true,"
                            f"BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        ),
                    }
                ))
            except Exception as e:
                log.warning("Could not check public access for bucket %s: %s", name, e)

        return findings

    @staticmethod
    def _infer_sensitive(bucket_name: str) -> bool:
        """
        Infer whether a bucket likely holds sensitive data from its name.
        Not authoritative — tags are the proper source of truth.
        Used as a fallback when tags aren't available.
        """
        sensitive_keywords = {
            "prod", "production", "pii", "sensitive", "backup",
            "db", "database", "logs", "audit", "finance", "billing",
            "data", "lake", "warehouse", "archive",
        }
        name_lower = bucket_name.lower()
        return any(kw in name_lower for kw in sensitive_keywords)


class S3EncryptionDisabled(SecurityRule):
    """
    CS-S3-002 — CIS 2.1.1
    Ensure S3 bucket default encryption is enabled.

    Why it matters
    --------------
    Unencrypted S3 objects are readable by any principal with s3:GetObject —
    including overprivileged Lambda roles, compromised EC2 instance profiles,
    and misconfigured cross-account policies. Encryption at rest is a baseline
    defence-in-depth control that costs nothing to enable.
    """
    rule_id      = "CS-S3-002"
    title        = "S3 bucket server-side encryption is disabled"
    description  = (
        "The S3 bucket does not have default server-side encryption configured. "
        "Objects stored without encryption are readable by any identity with "
        "s3:GetObject permission, including compromised or overprivileged roles."
    )
    severity     = "MEDIUM"
    service      = "S3"
    cis_control  = "CIS 2.1.1"
    nist_control = "PR.DS-1"
    soc2_control = "CC9.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            log.error("Failed to list S3 buckets for encryption check: %s", e)
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            try:
                enc = s3.get_bucket_encryption(Bucket=name)
                rules = (
                    enc.get("ServerSideEncryptionConfiguration", {})
                    .get("Rules", [])
                )
                if not rules:
                    raise ValueError("Empty encryption rules")

                # Check encryption algorithm — AES256 is acceptable, aws:kms is preferred
                algo = (
                    rules[0]
                    .get("ApplyServerSideEncryptionByDefault", {})
                    .get("SSEAlgorithm", "")
                )
                if algo not in ("AES256", "aws:kms"):
                    findings.append(self._finding(
                        resource_id  = name,
                        resource_arn = f"arn:aws:s3:::{name}",
                        extra={
                            "detail": f"Unknown encryption algorithm: {algo}",
                            "remediation_steps": [
                                f"Enable default encryption on bucket {name}.",
                                "Preferred: aws:kms with a customer-managed KMS key.",
                                "Acceptable minimum: AES256 (SSE-S3).",
                            ],
                            "remediation_cli": (
                                f"aws s3api put-bucket-encryption \\\n"
                                f"  --bucket {name} \\\n"
                                f"  --server-side-encryption-configuration "
                                f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":"
                                f"{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'"
                            ),
                        }
                    ))

            except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                findings.append(self._finding(
                    resource_id  = name,
                    resource_arn = f"arn:aws:s3:::{name}",
                    extra={
                        "detail": "No default encryption configuration found",
                        "remediation_steps": [
                            f"Enable default encryption on bucket {name}.",
                            "Use aws:kms with a customer-managed key for highest security.",
                            "AES256 (SSE-S3) is the minimum acceptable standard.",
                        ],
                        "remediation_cli": (
                            f"aws s3api put-bucket-encryption \\\n"
                            f"  --bucket {name} \\\n"
                            f"  --server-side-encryption-configuration "
                            f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":"
                            f"{{\"SSEAlgorithm\":\"aws:kms\"}}}}]}}'"
                        ),
                    }
                ))
            except Exception as e:
                log.warning("Could not check encryption for bucket %s: %s", name, e)

        return findings


class S3LoggingDisabled(SecurityRule):
    """
    CS-S3-003 — CIS 2.1.4
    Ensure S3 bucket access logging is enabled.

    Why it matters
    --------------
    S3 access logs record every request made to a bucket. Without them,
    data exfiltration leaves no forensic evidence in S3 itself. CloudTrail
    data events are a separate (and chargeable) mechanism — access logging
    is the free baseline that should always be enabled on sensitive buckets.
    """
    rule_id      = "CS-S3-003"
    title        = "S3 bucket access logging is disabled"
    description  = (
        "The S3 bucket does not have server access logging enabled. "
        "Without access logs, there is no record of who accessed, "
        "downloaded, or deleted objects — making forensic investigation "
        "after a data breach impossible."
    )
    severity     = "MEDIUM"
    service      = "S3"
    cis_control  = "CIS 2.1.4"
    nist_control = "DE.CM-3"
    soc2_control = "CC7.2"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        s3 = session.client("s3")

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except Exception as e:
            log.error("Failed to list S3 buckets for logging check: %s", e)
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            try:
                logging_config = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in logging_config:
                    findings.append(self._finding(
                        resource_id  = name,
                        resource_arn = f"arn:aws:s3:::{name}",
                        extra={
                            "detail": "Access logging is not enabled",
                            "remediation_steps": [
                                f"Create a dedicated logging bucket e.g. {name}-access-logs.",
                                f"Enable access logging: set target bucket to {name}-access-logs.",
                                "Ensure the logging bucket itself has appropriate retention.",
                                "Consider enabling CloudTrail S3 data events for API-level logging.",
                            ],
                            "remediation_cli": (
                                f"# First create the logging bucket\n"
                                f"aws s3api create-bucket --bucket {name}-access-logs "
                                f"--region {region}\n\n"
                                f"# Enable logging\n"
                                f"aws s3api put-bucket-logging \\\n"
                                f"  --bucket {name} \\\n"
                                f"  --bucket-logging-status "
                                f"'{{\"LoggingEnabled\":{{\"TargetBucket\":"
                                f"\"{name}-access-logs\",\"TargetPrefix\":\"{name}/\"}}}}'"
                            ),
                        }
                    ))
            except Exception as e:
                log.warning("Could not check logging for bucket %s: %s", name, e)

        return findings