"""
cloudsentinel.remediation.actions.logging
==========================================
Automated remediation actions for logging findings.

Actions implemented
-------------------
CS-LOG-002  Enable CloudTrail log file validation
CS-LOG-003  Enable VPC Flow Logs
"""
from __future__ import annotations

import logging

from .iam import RemediationResult

log = logging.getLogger(__name__)


class LoggingRemediationActions:
    """Executes logging remediation actions."""

    def remediate_cs_log_002(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-LOG-002 — Enable CloudTrail log file validation.

        Enables SHA-256 + RSA log file validation on the trail.
        Creates digest files alongside log files in S3 — these
        can be verified with: aws cloudtrail validate-logs
        """
        trail_name = resource_id
        ct         = session.client("cloudtrail")

        before = self._get_trail_config(ct, trail_name)

        try:
            ct.update_trail(
                Name                    = trail_name,
                EnableLogFileValidation = True,
            )

            after = self._get_trail_config(ct, trail_name)
            log.info(
                "Log file validation enabled on trail %s", trail_name
            )

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enabled log file validation on CloudTrail trail "
                    f"'{trail_name}'. "
                    f"SHA-256 digest files will now be created alongside "
                    f"log files. Verify with: "
                    f"aws cloudtrail validate-logs --trail-arn <arn>"
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enable log validation on %s: %s", trail_name, e
            )
            return RemediationResult(
                success      = False,
                action_taken = (
                    f"Attempted to enable log validation on {trail_name}"
                ),
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    def remediate_cs_log_003(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-LOG-003 — Enable VPC Flow Logs.

        Creates VPC Flow Logs publishing to CloudWatch Logs.
        Creates the log group and IAM role if they don't exist.
        Captures ALL traffic (ACCEPT and REJECT).
        """
        vpc_id = resource_id
        ec2    = session.client("ec2")
        iam    = session.client("iam")
        logs   = session.client("logs")
        region = session.region_name or "eu-north-1"

        log_group_name = f"/aws/vpc/flowlogs/{vpc_id}"
        role_name      = f"cloudsentinel-flowlogs-{vpc_id}"

        before = {"flow_logs_enabled": False, "vpc_id": vpc_id}

        try:
            # Create CloudWatch log group
            try:
                logs.create_log_group(logGroupName=log_group_name)
                log.info("Created log group %s", log_group_name)
            except logs.exceptions.ResourceAlreadyExistsException:
                pass

            # Create or get IAM role for flow logs
            role_arn = self._ensure_flowlogs_role(iam, role_name, account_id)

            # Enable flow logs
            ec2.create_flow_logs(
                ResourceType            = "VPC",
                ResourceIds             = [vpc_id],
                TrafficType             = "ALL",
                LogDestinationType      = "cloud-watch-logs",
                LogGroupName            = log_group_name,
                DeliverLogsPermissionArn = role_arn,
            )

            after = {
                "flow_logs_enabled": True,
                "log_group":         log_group_name,
                "traffic_type":      "ALL",
                "role_arn":          role_arn,
            }
            log.info("VPC Flow Logs enabled for %s", vpc_id)

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enabled VPC Flow Logs for {vpc_id}. "
                    f"All traffic (ACCEPT + REJECT) logged to "
                    f"CloudWatch Logs group '{log_group_name}'."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enable VPC Flow Logs for %s: %s", vpc_id, e
            )
            return RemediationResult(
                success      = False,
                action_taken = (
                    f"Attempted to enable VPC Flow Logs for {vpc_id}"
                ),
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_trail_config(self, ct, trail_name: str) -> dict:
        """Capture current CloudTrail configuration."""
        try:
            trails = ct.describe_trails(
                trailNameList=[trail_name]
            ).get("trailList", [])
            if trails:
                return {
                    "log_file_validation": trails[0].get(
                        "LogFileValidationEnabled", False
                    )
                }
        except Exception:
            pass
        return {}

    def _ensure_flowlogs_role(
        self, iam, role_name: str, account_id: str
    ) -> str:
        """Create IAM role for VPC Flow Logs delivery if it doesn't exist."""
        import json

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect":    "Allow",
                "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                "Action":    "sts:AssumeRole",
            }]
        }

        permissions_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "*",
            }]
        }

        try:
            role = iam.get_role(RoleName=role_name)
            return role["Role"]["Arn"]
        except iam.exceptions.NoSuchEntityException:
            pass

        try:
            role = iam.create_role(
                RoleName                 = role_name,
                AssumeRolePolicyDocument = json.dumps(trust_policy),
                Description              = "CloudSentinel VPC Flow Logs delivery role",
            )
            iam.put_role_policy(
                RoleName       = role_name,
                PolicyName     = "FlowLogsDelivery",
                PolicyDocument = json.dumps(permissions_policy),
            )
            log.info("Created flow logs IAM role %s", role_name)
            return role["Role"]["Arn"]
        except Exception as e:
            log.error("Failed to create flow logs role: %s", e)
            raise