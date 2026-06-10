"""
cloudsentinel.storage.dynamodb
================================
DynamoDB persistence layer for CloudSentinel findings.

Responsibilities
----------------
- Upsert findings (insert new, update last_seen if duplicate fingerprint)
- List findings with optional filters (cloud, severity, status, tactic)
- Get single finding by ID
- Update finding status (OPEN → REMEDIATED | SUPPRESSED)
- Auto-set TTL for remediated findings (90-day expiry)

Table design
------------
PK:  finding_id  (SHA-256 fingerprint)
GSI: account-severity-index  (account_id + severity)
GSI: cloud-status-index      (cloud + status)
TTL: ttl field (Unix timestamp) — auto-expires remediated findings
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key

log = logging.getLogger(__name__)

# 90 days in seconds — remediated findings expire after this
REMEDIATED_TTL_SECONDS = 90 * 24 * 60 * 60


class FindingStore:
    """
    DynamoDB-backed store for CloudSentinel findings.

    Uses conditional writes to implement upsert logic:
    - New finding: full insert with all fields
    - Duplicate (same fingerprint): only update last_seen and status
    """

    def __init__(
        self,
        table_name: Optional[str] = None,
        region:     Optional[str] = None,
    ) -> None:
        self.table_name = table_name or os.environ.get(
            "FINDINGS_TABLE", "cloudsentinel-findings-prod"
        )
        self.region = region or os.environ.get("AWS_REGION", "eu-north-1")

        self._dynamodb = boto3.resource("dynamodb", region_name=self.region)
        self._table    = self._dynamodb.Table(self.table_name)
        log.info(
            "FindingStore initialised: table=%s region=%s",
            self.table_name, self.region
        )

    # ── Write operations ──────────────────────────────────────────────────────

    def upsert(self, finding) -> bool:
        """
        Insert a new finding or update last_seen if it already exists.

        Uses DynamoDB conditional expression to differentiate:
        - First seen: full insert
        - Subsequent scans: update last_seen only (preserves suppression state)

        Parameters
        ----------
        finding: Finding model instance or dict

        Returns True on success, False on failure.
        """
        try:
            # Accept both Finding model instances and raw dicts
            if hasattr(finding, "to_dynamodb_item"):
                item = finding.to_dynamodb_item()
            else:
                item = dict(finding)
                item["finding_id"] = item.pop("id", item.get("finding_id", ""))

            now_iso = datetime.now(timezone.utc).isoformat()

            # Try conditional insert first (new finding)
            try:
                self._table.put_item(
                    Item=item,
                    ConditionExpression=Attr("finding_id").not_exists(),
                )
                log.info("New finding inserted: %s", item["finding_id"])
                return True

            except self._dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
                # Finding already exists — update last_seen only
                self._table.update_item(
                    Key={"finding_id": item["finding_id"]},
                    UpdateExpression=(
                        "SET last_seen = :last_seen, "
                        "risk_score = :risk_score"
                    ),
                    ExpressionAttributeValues={
                        ":last_seen":  now_iso,
                        ":risk_score": str(item.get("risk_score", 0)),
                    },
                )
                log.debug("Finding updated: %s", item["finding_id"])
                return True

        except Exception as e:
            log.error("Failed to upsert finding: %s", e)
            return False

    def update_status(
        self,
        finding_id: str,
        status:     str,
        reason:     Optional[str] = None,
    ) -> bool:
        """
        Update finding status to OPEN, REMEDIATED, or SUPPRESSED.

        Sets TTL automatically when marking as REMEDIATED so the
        finding auto-expires from DynamoDB after 90 days.
        """
        try:
            update_expr   = "SET #s = :status, last_seen = :now"
            expr_names    = {"#s": "status"}
            expr_values   = {
                ":status": status,
                ":now":    datetime.now(timezone.utc).isoformat(),
            }

            if status == "REMEDIATED":
                update_expr += ", #ttl = :ttl"
                expr_names["#ttl"] = "ttl"
                expr_values[":ttl"] = int(time.time()) + REMEDIATED_TTL_SECONDS

            if reason:
                update_expr += ", suppressed_reason = :reason"
                expr_values[":reason"] = reason

            self._table.update_item(
                Key={"finding_id": finding_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )
            log.info(
                "Finding %s status updated to %s", finding_id, status
            )
            return True

        except Exception as e:
            log.error(
                "Failed to update status for %s: %s", finding_id, e
            )
            return False

    # ── Read operations ───────────────────────────────────────────────────────

    def get(self, finding_id: str) -> Optional[dict]:
        """Retrieve a single finding by ID. Returns None if not found."""
        try:
            response = self._table.get_item(
                Key={"finding_id": finding_id}
            )
            item = response.get("Item")
            if item:
                item["id"] = item.pop("finding_id")
            return item
        except Exception as e:
            log.error("Failed to get finding %s: %s", finding_id, e)
            return None

    def list(
        self,
        cloud:    Optional[str] = None,
        severity: Optional[str] = None,
        service:  Optional[str] = None,
        status:   Optional[str] = None,
        tactic:   Optional[str] = None,
        limit:    int = 200,
    ) -> list[dict]:
        """
        List findings with optional filters.

        Uses GSI when possible for efficiency:
        - cloud + status  → cloud-status-index
        - Fallback        → full scan with filter expressions
        """
        try:
            # Use GSI if filtering by cloud + status
            if cloud and status:
                response = self._table.query(
                    IndexName="cloud-status-index",
                    KeyConditionExpression=(
                        Key("cloud").eq(cloud.upper()) &
                        Key("status").eq(status.upper())
                    ),
                    Limit=limit,
                )
                items = response.get("Items", [])

            else:
                # Fall back to scan with filter expressions
                filter_parts = []
                expr_values  = {}
                expr_names   = {}

                if cloud:
                    filter_parts.append("#cloud = :cloud")
                    expr_names["#cloud"]   = "cloud"
                    expr_values[":cloud"]  = cloud.upper()

                if severity:
                    filter_parts.append("#sev = :sev")
                    expr_names["#sev"]   = "severity"
                    expr_values[":sev"]  = severity.upper()

                if service:
                    filter_parts.append("#svc = :svc")
                    expr_names["#svc"]   = "service"
                    expr_values[":svc"]  = service

                if status:
                    filter_parts.append("#st = :st")
                    expr_names["#st"]   = "status"
                    expr_values[":st"]  = status.upper()

                scan_kwargs: dict = {"Limit": limit}
                if filter_parts:
                    scan_kwargs["FilterExpression"] = " AND ".join(
                        filter_parts
                    )
                    scan_kwargs["ExpressionAttributeNames"]  = expr_names
                    scan_kwargs["ExpressionAttributeValues"] = expr_values

                response = self._table.scan(**scan_kwargs)
                items    = response.get("Items", [])

            # Post-filter by tactic (stored inside nested mitre list)
            if tactic:
                items = [
                    i for i in items
                    if tactic in [
                        m.get("tactic_id")
                        for m in i.get("mitre", [])
                    ]
                ]

            # Normalise finding_id → id
            for item in items:
                if "finding_id" in item:
                    item["id"] = item.pop("finding_id")

            log.debug("Listed %d findings", len(items))
            return items

        except Exception as e:
            log.error("Failed to list findings: %s", e)
            return []

    def count_by_severity(self, account_id: Optional[str] = None) -> dict:
        """
        Return finding counts grouped by severity.
        Used by the /posture API endpoint.
        """
        counts = {
            "CRITICAL": 0, "HIGH": 0,
            "MEDIUM":   0, "LOW":  0, "INFO": 0,
        }
        try:
            findings = self.list(status="OPEN", limit=1000)
            for f in findings:
                sev = f.get("severity", "INFO").upper()
                if sev in counts:
                    counts[sev] += 1
        except Exception as e:
            log.error("Failed to count findings by severity: %s", e)
        return counts

    def delete_suppressed(self, older_than_days: int = 365) -> int:
        """
        Hard-delete suppressed
        Hard-delete suppressed findings older than N days.
        Intended for periodic cleanup jobs — not called during normal scanning.
        Returns count of deleted items.
        """
        deleted = 0
        cutoff  = datetime.now(timezone.utc).timestamp() - (
            older_than_days * 86400
        )
        try:
            findings = self.list(status="SUPPRESSED", limit=1000)
            for f in findings:
                first_seen = f.get("first_seen", "")
                if first_seen:
                    ts = datetime.fromisoformat(
                        first_seen.replace("Z", "+00:00")
                    ).timestamp()
                    if ts < cutoff:
                        self._table.delete_item(
                            Key={"finding_id": f.get("id", f.get("finding_id"))}
                        )
                        deleted += 1
            log.info("Deleted %d old suppressed findings", deleted)
        except Exception as e:
            log.error("Failed to delete suppressed findings: %s", e)
        return deleted