"""
cloudsentinel.remediation.engine
==================================
CloudSentinel automated remediation engine.

Remediation tiers
-----------------
CRITICAL (9.0+) → Auto-remediate immediately, write audit trail
HIGH (7.0-8.9)  → Request approval via SNS, execute on approval
MEDIUM/LOW      → Generate remediation plan only, no execution

Safety controls
---------------
- Dry-run mode: generates plan without executing (default for testing)
- Excluded rules: rules that should never auto-remediate
- Re-scan after remediation: verifies fix was effective
- Full audit trail: every action written to DynamoDB before/after
- Rollback hints: every action documents how to reverse it
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from ..models.finding import Finding, FindingStatus, Severity
from .audit import AuditRecord, AuditTrail, RemediationOutcome
from .approvals import ApprovalRequest, ApprovalWorkflow
from .actions.iam        import IAMRemediationActions, RemediationResult
from .actions.s3         import S3RemediationActions
from .actions.ec2        import EC2RemediationActions
from .actions.logging    import LoggingRemediationActions
from .actions.encryption import EncryptionRemediationActions

log = logging.getLogger(__name__)

# Rules that should NEVER auto-remediate regardless of severity
# (destructive or high-blast-radius actions requiring human review)
EXCLUDED_FROM_AUTO = {
    "CS-IAM-003",   # Wildcard policy — removing could break applications
    "CS-S3-002",    # S3 encryption — re-encryption requires downtime
    "CS-ENC-002",   # RDS encryption — requires instance replacement
    "CS-LOG-001",   # CloudTrail — needs S3 bucket setup first
}

# Risk score threshold for auto-remediation
AUTO_REMEDIATE_THRESHOLD = 9.0
APPROVAL_REQUIRED_THRESHOLD = 7.0


@dataclass
class RemediationPlan:
    """
    Plan generated before execution.
    Shown to operators for review regardless of auto/manual mode.
    """
    finding_id:    str
    rule_id:       str
    title:         str
    severity:      str
    risk_score:    float
    resource_id:   str
    tier:          str          # AUTO | APPROVAL | PLAN_ONLY
    action_desc:   str          # what will be done
    rollback_hint: str          # how to reverse it
    excluded:      bool = False
    exclusion_reason: str = ""


@dataclass
class RemediationReport:
    """Summary of a remediation run across multiple findings."""
    total:          int = 0
    auto_executed:  int = 0
    pending_approval: int = 0
    plan_only:      int = 0
    succeeded:      int = 0
    failed:         int = 0
    excluded:       int = 0
    plans:          list[RemediationPlan] = field(default_factory=list)
    errors:         list[str] = field(default_factory=list)
    generated_at:   str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def summary(self) -> dict:
        return {
            "total":            self.total,
            "auto_executed":    self.auto_executed,
            "pending_approval": self.pending_approval,
            "plan_only":        self.plan_only,
            "succeeded":        self.succeeded,
            "failed":           self.failed,
            "excluded":         self.excluded,
            "generated_at":     self.generated_at,
        }


# ── Action registry ───────────────────────────────────────────────────────────
# Maps rule_id → (action_class_instance, method_name)

def _build_action_registry() -> dict:
    iam  = IAMRemediationActions()
    s3   = S3RemediationActions()
    ec2  = EC2RemediationActions()
    lg   = LoggingRemediationActions()
    enc  = EncryptionRemediationActions()

    return {
        "CS-IAM-002": (iam, "remediate_cs_iam_002"),
        "CS-IAM-004": (iam, "remediate_cs_iam_004"),
        "CS-S3-001":  (s3,  "remediate_cs_s3_001"),
        "CS-S3-003":  (s3,  "remediate_cs_s3_003"),
        "CS-EC2-001": (ec2, "remediate_cs_ec2_001"),
        "CS-EC2-002": (ec2, "remediate_cs_ec2_002"),
        "CS-EC2-003": (ec2, "remediate_cs_ec2_003"),
        "CS-LOG-002": (lg,  "remediate_cs_log_002"),
        "CS-LOG-003": (lg,  "remediate_cs_log_003"),
        "CS-ENC-001": (enc, "remediate_cs_enc_001"),
    }


ACTION_REGISTRY = _build_action_registry()

ACTION_DESCRIPTIONS = {
    "CS-IAM-002": (
        "Attach MFA enforcement policy to IAM user — "
        "blocks console access without MFA",
        "Remove policy CloudSentinel-RequireMFA-{resource} from user"
    ),
    "CS-IAM-004": (
        "Deactivate stale access key — key becomes inactive immediately",
        "Reactivate key via: aws iam update-access-key --status Active"
    ),
    "CS-S3-001": (
        "Enable all four S3 Block Public Access settings on bucket",
        "Disable via: aws s3api delete-public-access-block --bucket {resource}"
    ),
    "CS-S3-003": (
        "Enable S3 access logging to dedicated {resource}-cs-logs bucket",
        "Disable via: aws s3api put-bucket-logging with empty LoggingEnabled"
    ),
    "CS-EC2-001": (
        "Revoke unrestricted SSH (0.0.0.0/0) from security group",
        "Re-add with restricted CIDR via aws ec2 authorize-security-group-ingress"
    ),
    "CS-EC2-002": (
        "Revoke unrestricted RDP (0.0.0.0/0) from security group",
        "Re-add with restricted CIDR via aws ec2 authorize-security-group-ingress"
    ),
    "CS-EC2-003": (
        "Enforce IMDSv2 — set HttpTokens=required on EC2 instance",
        "Revert via: aws ec2 modify-instance-metadata-options --http-tokens optional"
    ),
    "CS-LOG-002": (
        "Enable CloudTrail log file validation on trail",
        "Disable via: aws cloudtrail update-trail --no-enable-log-file-validation"
    ),
    "CS-LOG-003": (
        "Enable VPC Flow Logs (ALL traffic) to CloudWatch Logs",
        "Delete via: aws ec2 delete-flow-logs --flow-log-ids <id>"
    ),
    "CS-ENC-001": (
        "Enable EBS encryption by default at account level for region",
        "Disable via: aws ec2 disable-ebs-encryption-by-default"
    ),
}


class RemediationEngine:
    """
    Orchestrates automated remediation across findings.

    Usage
    -----
    engine = RemediationEngine(dry_run=True)   # plan only
    engine = RemediationEngine(dry_run=False)  # execute

    report = engine.remediate_findings(findings, session)
    print(report.summary())
    """

    def __init__(
        self,
        dry_run:         bool = True,
        audit_table:     Optional[str] = None,
        approvals_table: Optional[str] = None,
        sns_topic:       Optional[str] = None,
    ) -> None:
        self.dry_run  = dry_run
        self.audit    = AuditTrail(table_name=audit_table)
        self.approvals = ApprovalWorkflow(
            table_name = approvals_table,
            sns_topic  = sns_topic,
        )
        log.info(
            "RemediationEngine initialised: dry_run=%s", dry_run
        )

    def remediate_findings(
        self,
        findings: list[Finding],
        session,
    ) -> RemediationReport:
        """
        Process a list of findings and remediate based on tier.

        CRITICAL → auto-execute (unless excluded)
        HIGH     → request approval
        MEDIUM+  → plan only
        """
        report = RemediationReport(total=len(findings))

        for finding in findings:
            if finding.status != FindingStatus.OPEN:
                continue

            plan = self._build_plan(finding)
            report.plans.append(plan)

            if plan.excluded:
                report.excluded += 1
                log.info(
                    "Skipping %s — excluded: %s",
                    finding.rule_id, plan.exclusion_reason
                )
                continue

            if plan.tier == "AUTO":
                report.auto_executed += 1
                if not self.dry_run:
                    result = self._execute(finding, session, plan)
                    if result.success:
                        report.succeeded += 1
                    else:
                        report.failed += 1
                        report.errors.append(
                            f"{finding.id}: {result.error}"
                        )
                else:
                    log.info(
                        "[DRY RUN] Would auto-remediate: %s", finding.title
                    )

            elif plan.tier == "APPROVAL":
                report.pending_approval += 1
                if not self.dry_run:
                    self._request_approval(finding, plan)
                else:
                    log.info(
                        "[DRY RUN] Would request approval: %s",
                        finding.title
                    )

            else:
                report.plan_only += 1
                log.info(
                    "Plan only (no action): %s", finding.title
                )

        log.info(
            "Remediation complete: %d total, %d auto, %d approval, "
            "%d plan-only, %d succeeded, %d failed",
            report.total, report.auto_executed, report.pending_approval,
            report.plan_only, report.succeeded, report.failed,
        )
        return report

    def _build_plan(self, finding: Finding) -> RemediationPlan:
        """Build a remediation plan for a single finding."""
        rule_id     = finding.rule_id
        risk_score  = finding.risk_score
        resource_id = finding.resource_id

        # Check if rule is excluded
        if rule_id in EXCLUDED_FROM_AUTO:
            return RemediationPlan(
                finding_id    = finding.id,
                rule_id       = rule_id,
                title         = finding.title,
                severity      = finding.severity.value,
                risk_score    = risk_score,
                resource_id   = resource_id,
                tier          = "EXCLUDED",
                action_desc   = "Manual remediation required",
                rollback_hint = "N/A",
                excluded      = True,
                exclusion_reason = (
                    "Rule excluded from auto-remediation — "
                    "potential application impact requires human review"
                ),
            )

        # Check if we have an action for this rule
        if rule_id not in ACTION_REGISTRY:
            return RemediationPlan(
                finding_id    = finding.id,
                rule_id       = rule_id,
                title         = finding.title,
                severity      = finding.severity.value,
                risk_score    = risk_score,
                resource_id   = resource_id,
                tier          = "PLAN_ONLY",
                action_desc   = "No automated action available for this rule",
                rollback_hint = "N/A",
            )

        # Determine tier
        if risk_score >= AUTO_REMEDIATE_THRESHOLD:
            tier = "AUTO"
        elif risk_score >= APPROVAL_REQUIRED_THRESHOLD:
            tier = "APPROVAL"
        else:
            tier = "PLAN_ONLY"

        desc, rollback = ACTION_DESCRIPTIONS.get(
            rule_id,
            ("Automated fix available", "See AWS documentation")
        )
        action_desc   = desc.replace("{resource}", resource_id)
        rollback_hint = rollback.replace("{resource}", resource_id)

        return RemediationPlan(
            finding_id    = finding.id,
            rule_id       = rule_id,
            title         = finding.title,
            severity      = finding.severity.value,
            risk_score    = risk_score,
            resource_id   = resource_id,
            tier          = tier,
            action_desc   = action_desc,
            rollback_hint = rollback_hint,
        )

    def _execute(
        self,
        finding: Finding,
        session,
        plan:    RemediationPlan,
    ) -> RemediationResult:
        """Execute a remediation action and write audit record."""
        action_obj, method_name = ACTION_REGISTRY[finding.rule_id]
        method = getattr(action_obj, method_name)

        log.info(
            "Executing remediation: %s on %s",
            finding.rule_id, finding.resource_id
        )

        result = method(session, finding.resource_id, finding.account_id)

        # Write audit record
        self.audit.write(AuditRecord(
            finding_id   = finding.id,
            rule_id      = finding.rule_id,
            resource_id  = finding.resource_id,
            resource_arn = finding.resource_arn or "",
            account_id   = finding.account_id,
            region       = finding.region,
            severity     = finding.severity.value,
            action_taken = result.action_taken,
            outcome      = (
                RemediationOutcome.SUCCESS
                if result.success
                else RemediationOutcome.FAILED
            ),
            executed_by  = "auto",
            before_state = result.before_state,
            after_state  = result.after_state,
            error_message = result.error,
        ))

        return result

    def _request_approval(
        self,
        finding: Finding,
        plan:    RemediationPlan,
    ) -> str:
        """Create and send an approval request for a HIGH finding."""
        request = ApprovalRequest(
            finding_id   = finding.id,
            rule_id      = finding.rule_id,
            title        = finding.title,
            resource_id  = finding.resource_id,
            resource_arn = finding.resource_arn or "",
            account_id   = finding.account_id,
            region       = finding.region,
            action_desc  = plan.action_desc,
            risk_score   = finding.risk_score,
            blast_radius = finding.blast_radius.score,
        )

        # Write pending audit record
        self.audit.write(AuditRecord(
            finding_id   = finding.id,
            rule_id      = finding.rule_id,
            resource_id  = finding.resource_id,
            resource_arn = finding.resource_arn or "",
            account_id   = finding.account_id,
            region       = finding.region,
            severity     = finding.severity.value,
            action_taken = plan.action_desc,
            outcome      = RemediationOutcome.PENDING,
            executed_by  = f"pending-approval:{request.token}",
            before_state = {},
            after_state  = {},
        ))

        token = self.approvals.request_approval(request)
        log.info(
            "Approval requested for %s — token: %s",
            finding.id, token
        )
        return token