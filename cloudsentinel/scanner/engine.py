"""
cloudsentinel.scanner.engine
==============================
CloudSentinel scan engine — orchestrates multi-account, multi-region
scanning and enriches findings with MITRE ATT&CK, risk scores, and
compliance controls.

Scan flow
---------
1. Assume scanner role in target account (or use default credentials)
2. Run global rules (IAM, S3) once per account
3. Run regional rules in parallel across configured regions
4. Enrich every raw finding with MITRE, risk, compliance
5. Upsert enriched findings to DynamoDB
6. Return structured Finding objects to caller
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

import boto3

from ..enrichment.compliance import ComplianceMapper
from ..enrichment.mitre      import MitreEnrichmentEngine
from ..enrichment.risk       import RiskScoringEngine
from ..models.finding        import (
    BlastRadius, CloudProvider, ComplianceControl,
    Finding, FindingStatus, MitreMapping, RemediationGuide, Severity,
)
from ..storage.dynamodb import FindingStore

# ── Register all rules ────────────────────────────────────────────────────────
from .rules.aws_iam        import (
    RootAccountAccessKeys, MFANotEnabled,
    WildcardIAMPolicy, AccessKeyNotRotated,
)
from .rules.aws_s3         import (
    S3BucketPublicAccess, S3EncryptionDisabled, S3LoggingDisabled,
)
from .rules.aws_ec2        import (
    UnrestrictedSSH, UnrestrictedRDP, IMDSv1Enabled,
)
from .rules.aws_logging    import (
    CloudTrailDisabled, CloudTrailValidationDisabled, VPCFlowLogsDisabled,
)
from .rules.aws_encryption import (
    EBSEncryptionDisabled, RDSEncryptionDisabled,
)

log = logging.getLogger(__name__)

# ── Rule registry ─────────────────────────────────────────────────────────────
# Global rules run once per account (region-agnostic services)
GLOBAL_RULES = [
    RootAccountAccessKeys(),
    MFANotEnabled(),
    WildcardIAMPolicy(),
    AccessKeyNotRotated(),
    S3BucketPublicAccess(),
    S3EncryptionDisabled(),
    S3LoggingDisabled(),
]

# Regional rules run once per region in parallel
REGIONAL_RULES = [
    UnrestrictedSSH(),
    UnrestrictedRDP(),
    IMDSv1Enabled(),
    CloudTrailDisabled(),
    CloudTrailValidationDisabled(),
    VPCFlowLogsDisabled(),
    EBSEncryptionDisabled(),
    RDSEncryptionDisabled(),
]

ALL_RULES = GLOBAL_RULES + REGIONAL_RULES


class ScanResult:
    """Summary of a completed scan."""

    def __init__(
        self,
        account_id:  str,
        findings:    list[Finding],
        scan_start:  datetime,
        scan_end:    datetime,
        errors:      list[str],
    ) -> None:
        self.account_id  = account_id
        self.findings    = findings
        self.scan_start  = scan_start
        self.scan_end    = scan_end
        self.errors      = errors
        self.duration_s  = (scan_end - scan_start).total_seconds()

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def summary(self) -> dict:
        return {
            "account_id":  self.account_id,
            "total":       self.total,
            "critical":    self.critical,
            "high":        self.high,
            "duration_s":  round(self.duration_s, 2),
            "errors":      len(self.errors),
            "scan_start":  self.scan_start.isoformat(),
            "scan_end":    self.scan_end.isoformat(),
        }


class ScanEngine:
    """
    Orchestrates CloudSentinel scans across accounts and regions.

    Usage
    -----
    engine = ScanEngine(regions=["eu-north-1", "eu-west-1"])

    # Scan using default AWS credentials
    result = engine.scan_account()

    # Scan by assuming a cross-account role
    result = engine.scan_account(role_arn="arn:aws:iam::123456789012:role/CloudSentinelScanner-prod")

    # Persist findings to DynamoDB
    result = engine.scan_account(persist=True)
    """

    def __init__(
        self,
        regions:       Optional[list[str]] = None,
        max_workers:   int = 5,
        persist:       bool = True,
    ) -> None:
        self.regions     = regions or ["eu-north-1", "eu-west-1", "us-east-1"]
        self.max_workers = max_workers
        self.persist     = persist

        self.mitre_eng = MitreEnrichmentEngine()
        self.risk_eng  = RiskScoringEngine()
        self.comp_map  = ComplianceMapper()
        self.store     = FindingStore() if persist else None

        log.info(
            "ScanEngine initialised: regions=%s workers=%d persist=%s",
            self.regions, max_workers, persist,
        )

    def scan_account(
        self,
        profile:  Optional[str] = None,
        role_arn: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan a single AWS account.

        Parameters
        ----------
        profile:  AWS CLI profile name (uses default if None)
        role_arn: Cross-account role to assume before scanning

        Returns
        -------
        ScanResult with enriched Finding objects
        """
        scan_start = datetime.now(timezone.utc)
        session    = self._get_session(profile, role_arn)
        account_id = self._get_account_id(session)

        log.info("Starting scan of account %s", account_id)

        raw_findings: list[dict] = []
        errors:       list[str]  = []

        # ── Global rules ──────────────────────────────────────────────────────
        for rule in GLOBAL_RULES:
            try:
                hits = rule.check(session, account_id, "global")
                for h in hits:
                    h["account_id"] = account_id
                    h["region"]     = "global"
                    h["cloud"]      = "AWS"
                raw_findings.extend(hits)
                if hits:
                    log.info(
                        "  %s [global]: %d finding(s)", rule.rule_id, len(hits)
                    )
            except Exception as e:
                err = f"{rule.rule_id} [global]: {e}"
                log.error(err)
                errors.append(err)

        # ── Regional rules (parallel) ─────────────────────────────────────────
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(
                    self._scan_region, rule, session, account_id, region
                ): (rule.rule_id, region)
                for rule in REGIONAL_RULES
                for region in self.regions
            }

            for future in as_completed(futures):
                rule_id, region = futures[future]
                try:
                    hits = future.result()
                    raw_findings.extend(hits)
                    if hits:
                        log.info(
                            "  %s [%s]: %d finding(s)",
                            rule_id, region, len(hits)
                        )
                except Exception as e:
                    err = f"{rule_id} [{region}]: {e}"
                    log.error(err)
                    errors.append(err)

        # ── Enrich all findings ───────────────────────────────────────────────
        log.info(
            "Enriching %d raw findings for account %s",
            len(raw_findings), account_id
        )
        enriched: list[Finding] = []
        for raw in raw_findings:
            try:
                finding = self._enrich(raw)
                enriched.append(finding)

                # Persist to DynamoDB if enabled
                if self.persist and self.store:
                    self.store.upsert(finding)

            except Exception as e:
                err = f"Enrichment failed for {raw.get('rule_id','?')}: {e}"
                log.error(err)
                errors.append(err)

        scan_end = datetime.now(timezone.utc)
        result   = ScanResult(
            account_id = account_id,
            findings   = enriched,
            scan_start = scan_start,
            scan_end   = scan_end,
            errors     = errors,
        )

        log.info(
            "Scan complete for %s: %d findings (%d critical, %d high) "
            "in %.1fs with %d errors",
            account_id, result.total, result.critical,
            result.high, result.duration_s, len(errors),
        )
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _scan_region(
        self,
        rule,
        session,
        account_id: str,
        region:     str,
    ) -> list[dict]:
        """Run a single rule against a single region."""
        creds = session.get_credentials().get_frozen_credentials()
        regional_session = boto3.Session(
            aws_access_key_id     = creds.access_key,
            aws_secret_access_key = creds.secret_key,
            aws_session_token     = creds.token,
            region_name           = region,
        )
        hits = rule.check(regional_session, account_id, region)
        for h in hits:
            h["account_id"] = account_id
            h["region"]     = region
            h["cloud"]      = "AWS"
        return hits

    def _enrich(self, raw: dict) -> Finding:
        """
        Apply MITRE, risk scoring, and compliance enrichment to a raw finding.
        Converts raw dict → fully enriched Finding model.
        """
        rule_id  = raw["rule_id"]
        severity = raw["severity"]

        # MITRE enrichment
        ttp_maps = self.mitre_eng.enrich(rule_id)
        tech_ids = [m["technique_id"] for m in ttp_maps]

        # Risk scoring
        risk = self.risk_eng.score(
            severity           = severity,
            technique_ids      = tech_ids,
            resource_type      = raw.get("service", ""),
            is_public          = raw.get("is_public", False),
            has_sensitive_data = raw.get("has_sensitive_data", False),
            resource_tags      = raw.get("resource_tags", {}),
        )

        # Compliance controls
        controls = self.comp_map.get_controls(rule_id)

        # Remediation guide
        remediation = RemediationGuide(
            summary    = raw.get("title", ""),
            steps      = raw.get("remediation_steps", []),
            cli_command = raw.get("remediation_cli", ""),
        )

        return Finding(
            rule_id      = rule_id,
            title        = raw["title"],
            description  = raw["description"],
            cloud        = CloudProvider.AWS,
            account_id   = raw.get("account_id", ""),
            region       = raw.get("region", ""),
            service      = raw.get("service", ""),
            resource_id  = raw.get("resource_id", ""),
            resource_arn = raw.get("resource_arn", ""),
            severity     = Severity(severity),
            risk_score   = risk.risk_score,
            blast_radius = BlastRadius(
                score              = risk.blast_score,
                affected_services  = risk.affected_services,
                lateral_movement   = risk.lateral_movement,
                data_exfil_risk    = risk.data_exfil_risk,
                privilege_esc_risk = risk.privilege_esc_risk,
                rationale          = risk.rationale,
            ),
            mitre = [
                MitreMapping(
                    tactic_id        = m["tactic_id"],
                    tactic_name      = m["tactic_name"],
                    technique_id     = m["technique_id"],
                    technique_name   = m["technique_name"],
                    kill_chain_phase = m.get("kill_chain_phase"),
                )
                for m in ttp_maps
            ],
            controls = [
                ComplianceControl(**c) for c in controls
            ],
            remediation = remediation,
        )

    def _get_session(
        self,
        profile:  Optional[str],
        role_arn: Optional[str],
    ) -> boto3.Session:
        """Get a boto3 session, optionally assuming a cross-account role."""
        if role_arn:
            log.info("Assuming role: %s", role_arn)
            sts   = boto3.client("sts")
            creds = sts.assume_role(
                RoleArn         = role_arn,
                RoleSessionName = "CloudSentinelScan",
                DurationSeconds = 3600,
            )["Credentials"]
            return boto3.Session(
                aws_access_key_id     = creds["AccessKeyId"],
                aws_secret_access_key = creds["SecretAccessKey"],
                aws_session_token     = creds["SessionToken"],
            )
        return boto3.Session(profile_name=profile)

    def _get_account_id(self, session: boto3.Session) -> str:
        """Get the AWS account ID for the current session."""
        try:
            return session.client("sts").get_caller_identity()["Account"]
        except Exception as e:
            log.error("Failed to get account ID: %s", e)
            return "unknown"