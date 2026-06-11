"""
cloudsentinel.alerting.slack
==============================
Slack alerting for CloudSentinel findings.

Sends richly formatted Block Kit messages with:
- Severity color coding
- MITRE ATT&CK techniques
- Blast radius score
- Direct remediation steps
- Deduplication (same finding won't alert twice in 24h)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# Severity color map for Slack attachment sidebar
SEVERITY_COLORS = {
    "CRITICAL": "#E53E3E",   # red
    "HIGH":     "#DD6B20",   # orange
    "MEDIUM":   "#D69E2E",   # yellow
    "LOW":      "#38A169",   # green
    "INFO":     "#3182CE",   # blue
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "🔵",
}


@dataclass
class SlackAlert:
    """A single Slack alert derived from a finding."""
    finding_id:   str
    rule_id:      str
    title:        str
    severity:     str
    risk_score:   float
    blast_radius: float
    resource_id:  str
    account_id:   str
    region:       str
    service:      str
    ttp_ids:      list[str]
    tactic_names: list[str]
    remediation:  list[str]
    timestamp:    str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_slack_payload(self) -> dict:
        """
        Build a Slack Block Kit payload.
        Uses attachments for color-coded severity sidebar.
        """
        emoji    = SEVERITY_EMOJI.get(self.severity, "⚪")
        color    = SEVERITY_COLORS.get(self.severity, "#718096")
        ttps_str = " · ".join(self.ttp_ids) if self.ttp_ids else "None"
        tactics  = " → ".join(self.tactic_names) if self.tactic_names else "None"
        fix      = self.remediation[0] if self.remediation else "See documentation"

        return {
            "text": f"{emoji} *CloudSentinel Alert* — {self.severity}",
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"{emoji} {self.severity} — {self.title}",
                                "emoji": True,
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Risk Score*\n`{self.risk_score}/10`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Blast Radius*\n`{self.blast_radius}/100`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Service*\n`{self.service}`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Region*\n`{self.region}`"
                                },
                            ]
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Resource*\n`{self.resource_id}`"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Account*\n`{self.account_id}`"
                                },
                            ]
                        },
                        {
                            "type": "divider"
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"*🎯 MITRE ATT&CK*\n"
                                    f"Techniques: `{ttps_str}`\n"
                                    f"Kill chain: {tactics}"
                                )
                            }
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*🔧 Immediate Action*\n{fix}"
                            }
                        },
                        {
                            "type": "context",
                            "elements": [
                                {
                                    "type": "mrkdwn",
                                    "text": (
                                        f"Finding ID: `{self.finding_id}` · "
                                        f"Rule: `{self.rule_id}` · "
                                        f"{self.timestamp[:19].replace('T', ' ')} UTC"
                                    )
                                }
                            ]
                        }
                    ]
                }
            ]
        }


class SlackNotifier:
    """
    Sends CloudSentinel findings to Slack with deduplication.

    Deduplication: same finding_id won't alert more than once
    per 24 hours. Tracked in memory (production: use Redis/DynamoDB).
    """

    def __init__(
        self,
        webhook_url: Optional[str] = None,
        dedup_window_hours: int = 24,
    ) -> None:
        self.webhook_url = webhook_url or os.environ.get(
            "SLACK_WEBHOOK_URL", ""
        )
        self.dedup_window = dedup_window_hours * 3600
        self._sent: dict[str, float] = {}   # finding_id → last sent timestamp

        if not self.webhook_url:
            log.warning(
                "SLACK_WEBHOOK_URL not set — Slack alerts disabled"
            )

    def send(self, alert: SlackAlert) -> bool:
        """
        Send a Slack alert with deduplication.
        Returns True if sent, False if deduplicated or failed.
        """
        if not self.webhook_url:
            log.warning("No webhook URL — skipping Slack alert")
            return False

        # Deduplication check
        if self._is_duplicate(alert.finding_id):
            log.debug(
                "Deduplicated alert for finding %s", alert.finding_id
            )
            return False

        payload = alert.to_slack_payload()
        success = self._post(payload)

        if success:
            self._sent[alert.finding_id] = time.time()
            log.info(
                "Slack alert sent: %s (%s)",
                alert.finding_id, alert.severity
            )

        return success

    def send_digest(self, alerts: list[SlackAlert]) -> bool:
        """
        Send a digest of MEDIUM/LOW findings as a single message.
        Used for batched hourly notifications.
        """
        if not alerts or not self.webhook_url:
            return False

        # Filter already-sent
        new_alerts = [
            a for a in alerts
            if not self._is_duplicate(a.finding_id)
        ]
        if not new_alerts:
            log.debug("All digest alerts already sent")
            return False

        rows = "\n".join([
            f"• {SEVERITY_EMOJI.get(a.severity,'⚪')} "
            f"`{a.severity}` {a.title} — `{a.resource_id}`"
            for a in new_alerts[:10]   # cap at 10 per digest
        ])

        payload = {
            "text": f"📋 *CloudSentinel Digest* — {len(new_alerts)} finding(s)",
            "attachments": [{
                "color": "#718096",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"📋 Security Digest — {len(new_alerts)} findings",
                            "emoji": True,
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": rows,
                        }
                    },
                    {
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": (
                                f"Account scan completed · "
                                f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC"
                            )
                        }]
                    }
                ]
            }]
        }

        success = self._post(payload)
        if success:
            for a in new_alerts:
                self._sent[a.finding_id] = time.time()
        return success

    def send_remediation_complete(
        self,
        finding_id: str,
        rule_id:    str,
        title:      str,
        resource:   str,
        action:     str,
    ) -> bool:
        """Send a remediation completion notification."""
        if not self.webhook_url:
            return False

        payload = {
            "text": "✅ *CloudSentinel* — Remediation Complete",
            "attachments": [{
                "color": "#38A169",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "✅ Remediation Complete",
                            "emoji": True,
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Finding*\n{title}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Resource*\n`{resource}`"
                            },
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Action taken*\n{action}"
                        }
                    },
                    {
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": (
                                f"Finding ID: `{finding_id}` · "
                                f"Rule: `{rule_id}` · "
                                f"Auto-remediated by CloudSentinel"
                            )
                        }]
                    }
                ]
            }]
        }
        return self._post(payload)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _is_duplicate(self, finding_id: str) -> bool:
        last_sent = self._sent.get(finding_id)
        if last_sent is None:
            return False
        return (time.time() - last_sent) < self.dedup_window

    def _post(self, payload: dict) -> bool:
        """POST payload to Slack webhook."""
        try:
            data = json.dumps(payload).encode("utf-8")
            req  = urllib.request.Request(
                self.webhook_url,
                data    = data,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode()
                if body == "ok":
                    return True
                log.error("Slack webhook returned: %s", body)
                return False

        except urllib.error.HTTPError as e:
            log.error("Slack webhook HTTP error %s: %s", e.code, e.read())
            return False
        except Exception as e:
            log.error("Slack webhook failed: %s", e)
            return False