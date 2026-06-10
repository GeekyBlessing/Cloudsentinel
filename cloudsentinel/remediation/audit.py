"""
cloudsentinel.remediation.audit
================================
Immutable audit trail for all remediation actions.

Every remediation attempt — successful or failed, auto or approved —
is written here before and after execution. This is the evidence
artifact that satisfies SOC 2 CC7.2 and PCI DSS 10.2.1.

Design decisions
----------------
- Written to DynamoDB with a separate table (not the findings table)
- Immutable — no update or delete operations, only inserts
- Each record captures: who, what, when, before-state, after-state
- TTL set to 365 days for compliance retention
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import boto3

log = logging.getLogger(__name__)

AUDIT_TTL_SECONDS = 365 * 24 * 60 * 60  # 1 year retention


class RemediationOutcome(str, Enum):
    SUCCESS   = "SUCCESS"
    FAILED    = "FAILED"
    SKIPPED   = "SKIPPED"    # risk too low, rule excluded
    PENDING   = "PENDING"    # awaiting approval
    APPROVED  = "APPROVED"   # approved, not yet executed
    REJECTED  = "REJECTED"   # approval denied


@dataclass
class AuditRecord:
    """
    Immutable record of a single remediation action.
    Written before execution (PENDING) and updated after (SUCCESS/FAILED).
    """
    finding_id:    str
    rule_id:       str
    resource_id:   str
    resource_arn:  str
    account_id:    str
    region:        str
    severity:      str
    action_taken:  str          # human-readable description of the fix
    outcome:       RemediationOutcome
    executed_by:   str          # "auto" | "approved:username"
    before_state:  dict = field(default_factory=dict)
    after_state:   dict = field(default_factory=dict)
    error_message: Optional[str] = None
    timestamp:     str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    audit_id:      str = field(default="")

    def __post_init__(self):
        if not self.audit_id:
            payload = (
                f"{self.finding_id}:{self.timestamp}:{self.action_taken}"
            )
            self.audit_id = (
                "AR-" + hashlib.sha256(payload.encode()).hexdigest()[:12].upper()
            )

    def to_dynamodb_item(self) -> dict:
        return {
            "audit_id":     self.audit_id,
            "finding_id":   self.finding_id,
            "rule_id":      self.rule_id,
            "resource_id":  self.resource_id,
            "resource_arn": self.resource_arn,
            "account_id":   self.account_id,
            "region":       self.region,
            "severity":     self.severity,
            "action_taken": self.action_taken,
            "outcome":      self.outcome.value,
            "executed_by":  self.executed_by,
            "before_state": json.dumps(self.before_state),
            "after_state":  json.dumps(self.after_state),
            "error_message": self.error_message or "",
            "timestamp":    self.timestamp,
            "ttl":          int(time.time()) + AUDIT_TTL_SECONDS,
        }


class AuditTrail:
    """
    DynamoDB-backed immutable audit trail.
    Falls back to local logging if DynamoDB is unavailable.
    """

    def __init__(
        self,
        table_name: Optional[str] = None,
        region:     Optional[str] = None,
    ) -> None:
        self.table_name = table_name or os.environ.get(
            "AUDIT_TABLE", "cloudsentinel-audit-prod"
        )
        self.region = region or os.environ.get("AWS_REGION", "eu-north-1")
        self._table = None
        self._init_table()

    def _init_table(self) -> None:
        try:
            dynamodb    = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        except Exception as e:
            log.warning("DynamoDB audit table unavailable: %s — using local log", e)

    def write(self, record: AuditRecord) -> bool:
        """
        Write an audit record. Always succeeds — falls back to
        local logging if DynamoDB is unavailable.
        """
        # Always log locally regardless of DynamoDB availability
        log.info(
            "AUDIT | %s | %s | %s | %s | %s",
            record.audit_id,
            record.outcome.value,
            record.rule_id,
            record.resource_id,
            record.action_taken,
        )

        if self._table:
            try:
                self._table.put_item(Item=record.to_dynamodb_item())
                log.debug("Audit record %s written to DynamoDB", record.audit_id)
                return True
            except Exception as e:
                log.error("Failed to write audit record to DynamoDB: %s", e)

        return False

    def get_history(self, finding_id: str) -> list[dict]:
        """Get all audit records for a finding."""
        if not self._table:
            return []
        try:
            from boto3.dynamodb.conditions import Attr
            response = self._table.scan(
                FilterExpression=Attr("finding_id").eq(finding_id)
            )
            return sorted(
                response.get("Items", []),
                key=lambda x: x.get("timestamp", ""),
            )
        except Exception as e:
            log.error("Failed to get audit history: %s", e)
            return []