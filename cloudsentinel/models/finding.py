"""
cloudsentinel.models.finding
============================
Canonical finding model for CloudSentinel CSPM.

Every security finding — regardless of cloud provider, rule, or severity —
is normalised into this single Pydantic model before storage or API response.
SHA-256 fingerprinting ensures identical findings are deduplicated across scans.

Design decisions
----------------
- `computed_field` keeps ttp_ids/tactic_ids derived, never out of sync
- BlastRadius is a nested model so it can be queried independently via GSI
- `remediation_cli` stores a runnable CLI snippet for 1-click remediation
- TTL field is set at model level so DynamoDB can auto-expire old findings
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, computed_field, field_validator

log = logging.getLogger(__name__)


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

    @property
    def numeric(self) -> int:
        """Numeric weight for sorting and scoring."""
        return {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}[self.value]


class FindingStatus(str, Enum):
    OPEN       = "OPEN"
    SUPPRESSED = "SUPPRESSED"
    REMEDIATED = "REMEDIATED"


class CloudProvider(str, Enum):
    AWS   = "AWS"
    AZURE = "AZURE"
    GCP   = "GCP"


# ── Nested models ─────────────────────────────────────────────────────────────

class MitreMapping(BaseModel):
    """
    Single MITRE ATT&CK® technique mapping.
    One finding can map to multiple techniques across multiple tactics.
    """
    tactic_id:        str   # e.g. TA0001
    tactic_name:      str   # e.g. Initial Access
    technique_id:     str   # e.g. T1078
    technique_name:   str   # e.g. Valid Accounts
    kill_chain_phase: Optional[str] = None  # e.g. initial-access

    @field_validator("tactic_id")
    @classmethod
    def validate_tactic_id(cls, v: str) -> str:
        if not v.startswith("TA"):
            raise ValueError(f"tactic_id must start with 'TA', got: {v}")
        return v

    @field_validator("technique_id")
    @classmethod
    def validate_technique_id(cls, v: str) -> str:
        if not v.startswith("T"):
            raise ValueError(f"technique_id must start with 'T', got: {v}")
        return v


class ComplianceControl(BaseModel):
    """Maps a finding to a specific control within a compliance framework."""
    framework:   str   # CIS | NIST_CSF | SOC2 | PCI_DSS
    control_id:  str   # e.g. CIS 1.4 | PR.AC-1 | CC6.1
    description: str   # human-readable control title
    requirement: str   # what the control requires


class BlastRadius(BaseModel):
    """
    Blast radius assessment for a finding.

    Captures the potential damage surface if this misconfiguration
    is successfully exploited — used for prioritisation beyond severity.
    """
    score:              float = Field(ge=0, le=100)
    affected_services:  list[str]
    lateral_movement:   bool   # can attacker move to other resources?
    data_exfil_risk:    bool   # is data exfiltration possible?
    privilege_esc_risk: bool   # can attacker escalate privileges?
    rationale:          str    # human-readable explanation of score


class RemediationGuide(BaseModel):
    """Structured remediation with multiple formats for different audiences."""
    summary:       str          # one-sentence fix
    steps:         list[str]    # ordered step-by-step instructions
    cli_command:   Optional[str] = None   # runnable AWS/az/gcloud command
    console_path:  Optional[str] = None   # e.g. "IAM → Users → MFA"
    terraform_fix: Optional[str] = None   # HCL snippet
    references:    list[str] = Field(default_factory=list)  # docs URLs


# ── Core finding model ────────────────────────────────────────────────────────

class Finding(BaseModel):
    """
    Canonical CloudSentinel finding.

    Fingerprinted by SHA-256 of (rule_id, cloud, account_id, resource_id).
    Identical findings across scans are deduplicated — only last_seen updates.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    id:      str = Field(default="", description="SHA-256 fingerprint, auto-generated")
    rule_id: str = Field(description="Unique rule identifier e.g. CS-IAM-001")
    title:   str
    description: str

    # ── Cloud context ─────────────────────────────────────────────────────────
    cloud:         CloudProvider
    account_id:    str
    region:        str
    service:       str   # e.g. IAM, S3, EC2
    resource_id:   str   # short identifier
    resource_arn:  Optional[str] = None
    resource_tags: dict[str, str] = Field(
        default_factory=dict,
        description="AWS resource tags — used to infer data classification"
    )

    # ── Risk ──────────────────────────────────────────────────────────────────
    severity:     Severity
    risk_score:   float = Field(ge=0, le=10, description="Composite 0-10 risk score")
    blast_radius: BlastRadius

    # ── Threat intel ──────────────────────────────────────────────────────────
    mitre:   list[MitreMapping] = Field(default_factory=list)
    cve_ids: list[str]          = Field(default_factory=list)

    # ── Compliance ────────────────────────────────────────────────────────────
    controls: list[ComplianceControl] = Field(default_factory=list)

    # ── Remediation ───────────────────────────────────────────────────────────
    remediation: Optional[RemediationGuide] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────
    status:            FindingStatus = FindingStatus.OPEN
    first_seen:        datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_seen:         datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    suppressed_reason: Optional[str] = None
    ttl:               Optional[int] = Field(
        default=None,
        description="Unix timestamp for DynamoDB TTL auto-expiry"
    )

    # ── Auto-generated fields ─────────────────────────────────────────────────

    def model_post_init(self, _: object) -> None:
        """Generate SHA-256 fingerprint if not already set."""
        if not self.id:
            payload = (
                f"{self.rule_id}:{self.cloud.value}:"
                f"{self.account_id}:{self.resource_id}"
            )
            self.id = (
                "F-" + hashlib.sha256(payload.encode()).hexdigest()[:12].upper()
            )
            log.debug("Generated finding ID %s for rule %s", self.id, self.rule_id)

    @computed_field
    @property
    def ttp_ids(self) -> list[str]:
        """Flat list of all technique IDs mapped to this finding."""
        return [m.technique_id for m in self.mitre]

    @computed_field
    @property
    def tactic_ids(self) -> list[str]:
        """Deduplicated list of tactic IDs (a finding may span multiple tactics)."""
        return list({m.tactic_id for m in self.mitre})

    @computed_field
    @property
    def is_public_facing(self) -> bool:
        """True if the finding involves an internet-exposed resource."""
        public_indicators = {"0.0.0.0/0", "::/0", "public", "internet"}
        desc_lower = self.description.lower()
        return any(ind in desc_lower for ind in public_indicators)

    @computed_field
    @property
    def severity_numeric(self) -> int:
        """Numeric severity for sorting (5=CRITICAL → 1=INFO)."""
        return self.severity.numeric

    def mark_remediated(self) -> None:
        """Transition finding to REMEDIATED status."""
        self.status   = FindingStatus.REMEDIATED
        self.last_seen = datetime.now(timezone.utc)
        log.info("Finding %s marked as REMEDIATED", self.id)

    def suppress(self, reason: str) -> None:
        """Suppress a finding with a mandatory reason."""
        if not reason or len(reason.strip()) < 10:
            raise ValueError("Suppression reason must be at least 10 characters")
        self.status            = FindingStatus.SUPPRESSED
        self.suppressed_reason = reason.strip()
        self.last_seen         = datetime.now(timezone.utc)
        log.info("Finding %s suppressed: %s", self.id, reason)

    def to_dynamodb_item(self) -> dict:
        """
        Serialise finding to a DynamoDB-compatible dict.
        Converts enums to strings and datetimes to ISO format.
        """
        data = self.model_dump(mode="json")
        data["finding_id"] = data.pop("id")   # DynamoDB PK
        data["cloud"]      = self.cloud.value
        data["severity"]   = self.severity.value
        data["status"]     = self.status.value
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"]  = self.last_seen.isoformat()
        return data

    @classmethod
    def from_dynamodb_item(cls, item: dict) -> "Finding":
        """Deserialise a DynamoDB item back into a Finding."""
        item["id"] = item.pop("finding_id", item.get("id", ""))
        return cls.model_validate(item)
