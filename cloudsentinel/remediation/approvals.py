"""
cloudsentinel.remediation.approvals
=====================================
Approval workflow for HIGH severity remediations.

Flow
----
1. Remediation engine identifies HIGH finding
2. Approval request created and stored
3. Notification sent (SNS/Slack/email)
4. Approver reviews and approves/rejects via API
5. On approval — remediation executes
6. On rejection — finding suppressed with reason

Design
------
- Approval requests stored in DynamoDB with 24h TTL
- Expired requests auto-reject (finding remains OPEN)
- Each request has a unique token for out-of-band approval
- Full audit trail written regardless of outcome
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import boto3

log = logging.getLogger(__name__)

APPROVAL_TTL_SECONDS = 24 * 60 * 60   # 24 hours to approve


class ApprovalStatus(str, Enum):
    PENDING  = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED  = "EXPIRED"


@dataclass
class ApprovalRequest:
    """
    Approval request for a HIGH severity remediation.
    Stored in DynamoDB and sent to approvers via SNS.
    """
    finding_id:   str
    rule_id:      str
    title:        str
    resource_id:  str
    resource_arn: str
    account_id:   str
    region:       str
    action_desc:  str          # plain-English description of what will be done
    risk_score:   float
    blast_radius: float
    status:       ApprovalStatus = ApprovalStatus.PENDING
    token:        str = field(default="")
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_at:   Optional[str] = None
    decided_by:   Optional[str] = None
    reject_reason: Optional[str] = None

    def __post_init__(self):
        if not self.token:
            payload = f"{self.finding_id}:{self.requested_at}"
            self.token = hashlib.sha256(payload.encode()).hexdigest()[:24]

    def to_dynamodb_item(self) -> dict:
        return {
            "token":        self.token,
            "finding_id":   self.finding_id,
            "rule_id":      self.rule_id,
            "title":        self.title,
            "resource_id":  self.resource_id,
            "resource_arn": self.resource_arn,
            "account_id":   self.account_id,
            "region":       self.region,
            "action_desc":  self.action_desc,
            "risk_score":   str(self.risk_score),
            "blast_radius": str(self.blast_radius),
            "status":       self.status.value,
            "requested_at": self.requested_at,
            "decided_at":   self.decided_at or "",
            "decided_by":   self.decided_by or "",
            "reject_reason": self.reject_reason or "",
            "ttl":          int(time.time()) + APPROVAL_TTL_SECONDS,
        }

    def is_expired(self) -> bool:
        requested = datetime.fromisoformat(
            self.requested_at.replace("Z", "+00:00")
        )
        age = (datetime.now(timezone.utc) - requested).total_seconds()
        return age > APPROVAL_TTL_SECONDS


class ApprovalWorkflow:
    """
    Manages approval requests for HIGH severity remediations.
    Sends notifications via SNS when configured.
    """

    def __init__(
        self,
        table_name: Optional[str] = None,
        sns_topic:  Optional[str] = None,
        region:     Optional[str] = None,
    ) -> None:
        self.table_name = table_name or os.environ.get(
            "APPROVALS_TABLE", "cloudsentinel-approvals-prod"
        )
        self.sns_topic = sns_topic or os.environ.get("APPROVAL_SNS_TOPIC", "")
        self.region    = region or os.environ.get("AWS_REGION", "eu-north-1")
        self._table    = None
        self._sns      = None
        self._init_clients()

    def _init_clients(self) -> None:
        try:
            dynamodb    = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        except Exception as e:
            log.warning("Approvals table unavailable: %s", e)

        if self.sns_topic:
            try:
                self._sns = boto3.client("sns", region_name=self.region)
            except Exception as e:
                log.warning("SNS unavailable: %s", e)

    def request_approval(self, request: ApprovalRequest) -> str:
        """
        Submit an approval request.
        Returns approval token for tracking.
        Sends SNS notification if configured.
        """
        log.info(
            "Approval requested for %s (%s) — token: %s",
            request.finding_id, request.title, request.token
        )

        # Store in DynamoDB
        if self._table:
            try:
                self._table.put_item(Item=request.to_dynamodb_item())
            except Exception as e:
                log.error("Failed to store approval request: %s", e)

        # Send SNS notification
        if self._sns and self.sns_topic:
            self._notify(request)

        return request.token

    def get_request(self, token: str) -> Optional[ApprovalRequest]:
        """Retrieve an approval request by token."""
        if not self._table:
            return None
        try:
            response = self._table.get_item(Key={"token": token})
            item = response.get("Item")
            if not item:
                return None
            return ApprovalRequest(
                finding_id   = item["finding_id"],
                rule_id      = item["rule_id"],
                title        = item["title"],
                resource_id  = item["resource_id"],
                resource_arn = item["resource_arn"],
                account_id   = item["account_id"],
                region       = item["region"],
                action_desc  = item["action_desc"],
                risk_score   = float(item["risk_score"]),
                blast_radius = float(item["blast_radius"]),
                status       = ApprovalStatus(item["status"]),
                token        = item["token"],
                requested_at = item["requested_at"],
                decided_at   = item.get("decided_at") or None,
                decided_by   = item.get("decided_by") or None,
                reject_reason = item.get("reject_reason") or None,
            )
        except Exception as e:
            log.error("Failed to get approval request %s: %s", token, e)
            return None

    def approve(self, token: str, approved_by: str) -> bool:
        """Approve a pending remediation request."""
        return self._decide(token, ApprovalStatus.APPROVED, approved_by)

    def reject(self, token: str, rejected_by: str, reason: str) -> bool:
        """Reject a pending remediation request."""
        return self._decide(
            token, ApprovalStatus.REJECTED, rejected_by, reason
        )

    def _decide(
        self,
        token:      str,
        status:     ApprovalStatus,
        decided_by: str,
        reason:     Optional[str] = None,
    ) -> bool:
        if not self._table:
            return False
        try:
            now = datetime.now(timezone.utc).isoformat()
            update_expr = (
                "SET #s = :status, decided_at = :now, decided_by = :by"
            )
            expr_names  = {"#s": "status"}
            expr_values = {
                ":status": status.value,
                ":now":    now,
                ":by":     decided_by,
            }
            if reason:
                update_expr += ", reject_reason = :reason"
                expr_values[":reason"] = reason

            self._table.update_item(
                Key={"token": token},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
            log.info(
                "Approval request %s %s by %s",
                token, status.value, decided_by
            )
            return True
        except Exception as e:
            log.error("Failed to decide on approval %s: %s", token, e)
            return False

    def _notify(self, request: ApprovalRequest) -> None:
        """Send SNS notification for approval request."""
        message = {
            "type":        "REMEDIATION_APPROVAL_REQUIRED",
            "token":       request.token,
            "finding_id":  request.finding_id,
            "title":       request.title,
            "resource":    request.resource_id,
            "risk_score":  request.risk_score,
            "action":      request.action_desc,
            "approve_url": f"POST /api/v1/remediations/{request.token}/approve",
            "reject_url":  f"POST /api/v1/remediations/{request.token}/reject",
            "expires_in":  "24 hours",
        }
        try:
            self._sns.publish(
                TopicArn = self.sns_topic,
                Subject  = (
                    f"[CloudSentinel] Approval Required: {request.title}"
                ),
                Message  = json.dumps(message, indent=2),
            )
            log.info("SNS notification sent for token %s", request.token)
        except Exception as e:
            log.error("Failed to send SNS notification: %s", e)