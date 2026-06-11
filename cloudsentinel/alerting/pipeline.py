"""
cloudsentinel.alerting.pipeline
=================================
Alert routing pipeline for CloudSentinel findings.

Severity routing
----------------
CRITICAL → immediate Slack alert (individual message)
HIGH     → immediate Slack alert (individual message)
MEDIUM   → batched digest (collected, sent hourly)
LOW/INFO → no alert (stored in DynamoDB only)

Each alert is enriched with MITRE context before sending.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from ..models.finding import Finding, Severity
from .slack import SlackNotifier, SlackAlert

log = logging.getLogger(__name__)


@dataclass
class AlertPipelineResult:
    """Result of running the alert pipeline over a set of findings."""
    total:       int = 0
    alerted:     int = 0
    deduplicated: int = 0
    suppressed:  int = 0   # MEDIUM/LOW held for digest
    failed:      int = 0
    digest_queue: list[SlackAlert] = field(default_factory=list)


class AlertPipeline:
    """
    Routes findings to the appropriate alert channel based on severity.

    Usage
    -----
    pipeline = AlertPipeline()
    result   = pipeline.process(findings)

    # Send any queued digest alerts
    pipeline.flush_digest()
    """

    def __init__(
        self,
        webhook_url:        Optional[str] = None,
        immediate_severities: set[str] = None,
        digest_severities:    set[str] = None,
    ) -> None:
        self.notifier = SlackNotifier(webhook_url=webhook_url)

        # Severities that get immediate individual alerts
        self.immediate = immediate_severities or {"CRITICAL", "HIGH"}

        # Severities batched into digest
        self.digest = digest_severities or {"MEDIUM"}

        # Queue for digest alerts
        self._digest_queue: list[SlackAlert] = []

        log.info(
            "AlertPipeline initialised: immediate=%s digest=%s",
            self.immediate, self.digest
        )

    def process(self, findings: list[Finding]) -> AlertPipelineResult:
        """
        Process a list of findings through the alert pipeline.
        CRITICAL/HIGH → immediate Slack alert
        MEDIUM        → queued for digest
        LOW/INFO      → suppressed
        """
        result = AlertPipelineResult(total=len(findings))

        for finding in findings:
            sev = finding.severity.value

            if sev in self.immediate:
                alert   = self._build_alert(finding)
                sent    = self.notifier.send(alert)
                if sent:
                    result.alerted += 1
                else:
                    # Could be deduplicated or failed
                    result.deduplicated += 1

            elif sev in self.digest:
                alert = self._build_alert(finding)
                self._digest_queue.append(alert)
                result.suppressed += 1

            else:
                # LOW/INFO — no alert
                result.suppressed += 1
                log.debug(
                    "Suppressed %s alert for %s",
                    sev, finding.rule_id
                )

        log.info(
            "Alert pipeline: %d total, %d alerted, %d deduplicated, "
            "%d queued for digest",
            result.total, result.alerted,
            result.deduplicated, len(self._digest_queue)
        )
        result.digest_queue = list(self._digest_queue)
        return result

    def flush_digest(self) -> bool:
        """
        Send all queued MEDIUM findings as a digest message.
        Call this after processing a batch of findings.
        """
        if not self._digest_queue:
            log.debug("Digest queue empty — nothing to send")
            return True

        success = self.notifier.send_digest(self._digest_queue)
        if success:
            log.info(
                "Digest sent: %d findings", len(self._digest_queue)
            )
            self._digest_queue.clear()
        return success

    def notify_remediation(
        self,
        finding_id: str,
        rule_id:    str,
        title:      str,
        resource:   str,
        action:     str,
    ) -> bool:
        """Send a remediation completion notification."""
        return self.notifier.send_remediation_complete(
            finding_id = finding_id,
            rule_id    = rule_id,
            title      = title,
            resource   = resource,
            action     = action,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_alert(self, finding: Finding) -> SlackAlert:
        """Convert a Finding into a SlackAlert."""
        # Get unique tactic names from MITRE mappings
        tactic_names = list(dict.fromkeys(
            m.tactic_name for m in finding.mitre
        ))

        # Get remediation steps
        steps = []
        if finding.remediation and finding.remediation.steps:
            steps = finding.remediation.steps

        return SlackAlert(
            finding_id   = finding.id,
            rule_id      = finding.rule_id,
            title        = finding.title,
            severity     = finding.severity.value,
            risk_score   = finding.risk_score,
            blast_radius = finding.blast_radius.score,
            resource_id  = finding.resource_id,
            account_id   = finding.account_id,
            region       = finding.region,
            service      = finding.service,
            ttp_ids      = finding.ttp_ids,
            tactic_names = tactic_names,
            remediation  = steps,
        )