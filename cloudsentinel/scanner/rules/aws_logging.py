"""
cloudsentinel.scanner.rules.aws_logging
=========================================
Logging and monitoring rules — CIS AWS Foundations Benchmark v1.5 Section 3

Rules implemented
-----------------
CS-LOG-001  CloudTrail disabled in region
CS-LOG-002  CloudTrail log file validation disabled
CS-LOG-003  VPC Flow Logs disabled
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import SecurityRule

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class CloudTrailDisabled(SecurityRule):
    """
    CS-LOG-001 — CIS 3.1
    Ensure CloudTrail is enabled in all regions.

    Why it matters
    --------------
    CloudTrail is the primary audit log for all AWS API activity.
    Disabling it is T1562.008 (Impair Defenses: Disable Cloud Logs)
    verbatim — it's the first action sophisticated threat actors take
    after gaining initial access to eliminate forensic evidence before
    conducting further operations.
    """
    rule_id      = "CS-LOG-001"
    title        = "CloudTrail is disabled in this region"
    description  = (
        "No active CloudTrail trail is logging API activity in this region. "
        "Without CloudTrail, all IAM changes, S3 access, EC2 launches, and "
        "other API calls produce no audit records. Forensic investigation "
        "after an incident becomes impossible."
    )
    severity     = "HIGH"
    service      = "CloudTrail"
    cis_control  = "CIS 3.1"
    nist_control = "DE.CM-3"
    soc2_control = "CC7.2"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        ct = session.client("cloudtrail")

        try:
            trails = ct.describe_trails(
                includeShadowTrails=False
            ).get("trailList", [])

            # Check if any trail is actively logging in this region
            active_trails = []
            for trail in trails:
                try:
                    status = ct.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging", False):
                        active_trails.append(trail["TrailARN"])
                except Exception as e:
                    log.warning(
                        "Could not get status for trail %s: %s",
                        trail.get("TrailARN"), e
                    )

            if not active_trails:
                findings.append(self._finding(
                    resource_id  = f"cloudtrail:{region}",
                    resource_arn = (
                        f"arn:aws:cloudtrail:{region}:{account_id}:trail"
                    ),
                    extra={
                        "detail": (
                            f"No active CloudTrail trail found in {region}. "
                            f"{len(trails)} trail(s) exist but none are logging."
                            if trails else
                            f"No CloudTrail trails configured in {region}."
                        ),
                        "remediation_steps": [
                            "Create a multi-region CloudTrail trail.",
                            "Enable log file validation.",
                            "Store logs in a dedicated, access-controlled S3 bucket.",
                            "Enable CloudWatch Logs integration for real-time alerting.",
                            "Consider enabling S3 and Lambda data events for full coverage.",
                        ],
                        "remediation_cli": (
                            f"# Create S3 bucket for CloudTrail logs\n"
                            f"aws s3api create-bucket \\\n"
                            f"  --bucket cloudtrail-logs-{account_id} \\\n"
                            f"  --region {region}\n\n"
                            f"# Create multi-region trail\n"
                            f"aws cloudtrail create-trail \\\n"
                            f"  --name cloudsentinel-audit-trail \\\n"
                            f"  --s3-bucket-name cloudtrail-logs-{account_id} \\\n"
                            f"  --is-multi-region-trail \\\n"
                            f"  --enable-log-file-validation\n\n"
                            f"# Start logging\n"
                            f"aws cloudtrail start-logging \\\n"
                            f"  --name cloudsentinel-audit-trail"
                        ),
                    }
                ))

        except Exception as e:
            log.error("Failed to describe CloudTrail trails in %s: %s", region, e)

        return findings


class CloudTrailValidationDisabled(SecurityRule):
    """
    CS-LOG-002 — CIS 3.2
    Ensure CloudTrail log file validation is enabled.

    Why it matters
    --------------
    Without log file validation, an attacker with S3 write access can
    silently delete or modify CloudTrail log files after the fact.
    Log file validation uses SHA-256 hashing and RSA signing to create
    a digest file that proves log integrity — tampering is detectable.
    """
    rule_id      = "CS-LOG-002"
    title        = "CloudTrail log file validation is disabled"
    description  = (
        "CloudTrail log file validation is not enabled on this trail. "
        "Without validation, log files in S3 can be silently modified or "
        "deleted by an attacker with S3 write access. There is no integrity "
        "hash to verify against, making tampered logs indistinguishable "
        "from authentic ones."
    )
    severity     = "MEDIUM"
    service      = "CloudTrail"
    cis_control  = "CIS 3.2"
    nist_control = "PR.DS-6"
    soc2_control = "CC7.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        ct = session.client("cloudtrail")

        try:
            trails = ct.describe_trails(
                includeShadowTrails=False
            ).get("trailList", [])

            for trail in trails:
                if not trail.get("LogFileValidationEnabled", False):
                    trail_name = trail.get("Name", trail["TrailARN"])
                    findings.append(self._finding(
                        resource_id  = trail_name,
                        resource_arn = trail["TrailARN"],
                        extra={
                            "detail": (
                                f"Trail {trail_name} has "
                                f"LogFileValidationEnabled=false"
                            ),
                            "remediation_steps": [
                                f"Enable log file validation on trail {trail_name}.",
                                "This creates digest files signed with RSA-2048.",
                                "Validation can be checked with: "
                                "aws cloudtrail validate-logs",
                            ],
                            "remediation_cli": (
                                f"aws cloudtrail update-trail \\\n"
                                f"  --name {trail_name} \\\n"
                                f"  --enable-log-file-validation"
                            ),
                        }
                    ))

        except Exception as e:
            log.error(
                "Failed to check CloudTrail validation in %s: %s", region, e
            )

        return findings


class VPCFlowLogsDisabled(SecurityRule):
    """
    CS-LOG-003 — CIS 3.9
    Ensure VPC flow logging is enabled in all VPCs.

    Why it matters
    --------------
    VPC Flow Logs are the primary network visibility mechanism in AWS.
    Without them, C2 traffic, internal port scanning, and lateral movement
    within the VPC produce no network-level forensic evidence. An attacker
    can move freely between EC2 instances with no network trace.
    """
    rule_id      = "CS-LOG-003"
    title        = "VPC Flow Logs are disabled"
    description  = (
        "This VPC does not have flow logging enabled. Without VPC Flow Logs, "
        "there is no network-level visibility into traffic between instances. "
        "C2 callbacks, lateral movement, and data exfiltration over the network "
        "leave no forensic evidence."
    )
    severity     = "MEDIUM"
    service      = "VPC"
    cis_control  = "CIS 3.9"
    nist_control = "DE.CM-1"
    soc2_control = "CC7.2"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        ec2 = session.client("ec2")

        try:
            # Get all VPCs in region
            vpcs = ec2.describe_vpcs().get("Vpcs", [])

            # Get all flow logs in region
            flow_logs     = ec2.describe_flow_logs().get("FlowLogs", [])
            logged_vpc_ids = {
                fl["ResourceId"]
                for fl in flow_logs
                if fl.get("FlowLogStatus") == "ACTIVE"
            }

            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                if vpc_id not in logged_vpc_ids:
                    # Get VPC name from tags if available
                    vpc_name = next(
                        (t["Value"] for t in vpc.get("Tags", [])
                         if t["Key"] == "Name"),
                        vpc_id
                    )
                    findings.append(self._finding(
                        resource_id  = vpc_id,
                        resource_arn = (
                            f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}"
                        ),
                        extra={
                            "detail": (
                                f"VPC {vpc_name} ({vpc_id}) has no active "
                                f"flow logs"
                            ),
                            "remediation_steps": [
                                f"Enable VPC Flow Logs for {vpc_id}.",
                                "Publish to CloudWatch Logs for real-time analysis.",
                                "Alternatively publish to S3 for cost-effective retention.",
                                "Enable ALL traffic (ACCEPT and REJECT) not just REJECT.",
                                "Consider enabling flow logs at ENI level for granularity.",
                            ],
                            "remediation_cli": (
                                f"# Create CloudWatch log group first\n"
                                f"aws logs create-log-group \\\n"
                                f"  --log-group-name /aws/vpc/flowlogs/{vpc_id}\n\n"
                                f"# Enable flow logs\n"
                                f"aws ec2 create-flow-logs \\\n"
                                f"  --resource-type VPC \\\n"
                                f"  --resource-ids {vpc_id} \\\n"
                                f"  --traffic-type ALL \\\n"
                                f"  --log-destination-type cloud-watch-logs \\\n"
                                f"  --log-group-name /aws/vpc/flowlogs/{vpc_id} \\\n"
                                f"  --deliver-logs-permission-arn "
                                f"arn:aws:iam::{account_id}:role/flowlogs-role"
                            ),
                        }
                    ))

        except Exception as e:
            log.error(
                "Failed to check VPC Flow Logs in %s: %s", region, e
            )

        return findings