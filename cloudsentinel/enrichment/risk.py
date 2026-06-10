"""
cloudsentinel.enrichment.risk
=============================
Risk scoring and blast radius engine.

Every finding gets a composite risk score (0-10) and a blast radius (0-100).
These two numbers drive prioritisation in the dashboard — severity alone is
not enough because a MEDIUM finding on a public-facing resource with a
lateral movement path is more dangerous than a HIGH finding on an isolated
dev instance.

Scoring formula
---------------
    risk_score = min((base_severity + ttp_boost) × exposure_multiplier, 10.0)

    base_severity   → 9.0 / 7.0 / 5.0 / 3.0 / 1.0 by severity tier
    ttp_boost       → +0.15 per high-impact technique (capped contribution)
    exposure_mult   → ×1.3 if public-facing, ×1.2 if sensitive data present

Blast radius factors
--------------------
    base            → severity × 6
    lateral_move    → +10 if techniques enable lateral movement
    data_exfil      → +15 if techniques enable data exfiltration
    priv_esc        → +15 if techniques enable privilege escalation
    public_exposure → +10 if resource is internet-facing
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# ── Scoring constants ─────────────────────────────────────────────────────────

BASE_SEVERITY_SCORE: dict[str, float] = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   5.0,
    "LOW":      3.0,
    "INFO":     1.0,
}

# Techniques with direct, weaponisable impact get a score boost
HIGH_IMPACT_TECHNIQUES: set[str] = {
    "T1078",   # Valid Accounts — broad access with existing credentials
    "T1190",   # Exploit Public-Facing Application
    "T1552",   # Unsecured Credentials — direct credential theft
    "T1530",   # Data from Cloud Storage — direct exfil path
    "T1548",   # Abuse Elevation Control — direct privesc
    "T1562",   # Impair Defenses — blinding defenders
    "T1528",   # Steal Application Access Token
}

# Technique sets for blast radius classification
LATERAL_MOVEMENT_TECHNIQUES: set[str] = {
    "T1021",   # Remote Services
    "T1570",   # Lateral Tool Transfer
    "T1534",   # Internal Spearphishing
    "T1210",   # Exploitation of Remote Services
}

DATA_EXFIL_TECHNIQUES: set[str] = {
    "T1530",   # Data from Cloud Storage
    "T1537",   # Transfer Data to Cloud Account
    "T1048",   # Exfiltration Over Alternative Protocol
    "T1567",   # Exfiltration Over Web Service
    "T1020",   # Automated Exfiltration
    "T1213",   # Data from Information Repositories
}

PRIVESC_TECHNIQUES: set[str] = {
    "T1548",   # Abuse Elevation Control Mechanism
    "T1068",   # Exploitation for Privilege Escalation
    "T1134",   # Access Token Manipulation
    "T1078",   # Valid Accounts (used for escalation context)
}


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class RiskResult:
    """
    Output of the risk scoring engine for a single finding.
    Fed directly into the Finding.blast_radius model.
    """
    risk_score:         float          # 0.0 – 10.0
    blast_score:        float          # 0.0 – 100.0
    lateral_movement:   bool
    data_exfil_risk:    bool
    privilege_esc_risk: bool
    affected_services:  list[str] = field(default_factory=list)
    rationale:          str = ""

    def __post_init__(self) -> None:
        # Enforce bounds — defensive check against edge cases
        self.risk_score  = round(max(0.0, min(10.0, self.risk_score)), 1)
        self.blast_score = round(max(0.0, min(100.0, self.blast_score)), 1)


# ── Scoring engine ────────────────────────────────────────────────────────────

class RiskScoringEngine:
    """
    Computes composite risk score and blast radius for a finding.

    Designed to be called by the scan engine after MITRE enrichment,
    so technique_ids are already resolved before scoring runs.
    """

    def score(
        self,
        severity:           str,
        technique_ids:      list[str],
        resource_type:      str,
        is_public:          bool = False,
        has_sensitive_data: bool = False,
        resource_tags:      dict[str, str] | None = None,
    ) -> RiskResult:
        """
        Compute risk score and blast radius.

        Parameters
        ----------
        severity:           CRITICAL | HIGH | MEDIUM | LOW | INFO
        technique_ids:      ATT&CK technique IDs from MITRE enrichment
        resource_type:      AWS service name e.g. S3, IAM, EC2
        is_public:          True if resource is internet-accessible
        has_sensitive_data: True if resource holds PII/secrets/financial data
        resource_tags:      AWS tags — used to infer data classification
        """
        resource_tags = resource_tags or {}

        # Auto-detect sensitive data from tags if not explicitly set
        if not has_sensitive_data:
            sensitive_tag_values = {"pii", "sensitive", "confidential",
                                    "restricted", "financial", "phi"}
            tag_values = {v.lower() for v in resource_tags.values()}
            has_sensitive_data = bool(tag_values & sensitive_tag_values)

        # ── Base score from severity ──────────────────────────────────────────
        base = BASE_SEVERITY_SCORE.get(severity.upper(), 5.0)

        # ── TTP boost ─────────────────────────────────────────────────────────
        ttp_set   = set(technique_ids)
        ttp_boost = sum(
            0.15 for t in ttp_set if t in HIGH_IMPACT_TECHNIQUES
        )
        # Cap boost at 1.5 to prevent inflation from many techniques
        ttp_boost = min(ttp_boost, 1.5)

        # ── Exposure multiplier ───────────────────────────────────────────────
        exposure = 1.0
        if is_public:           exposure += 0.3
        if has_sensitive_data:  exposure += 0.2

        # ── Final risk score ──────────────────────────────────────────────────
        risk_score = min((base + ttp_boost) * exposure, 10.0)

        # ── Blast radius classification ───────────────────────────────────────
        lateral  = bool(ttp_set & LATERAL_MOVEMENT_TECHNIQUES)
        exfil    = bool(ttp_set & DATA_EXFIL_TECHNIQUES)
        privesc  = bool(ttp_set & PRIVESC_TECHNIQUES)

        blast = base * 6.0
        if lateral:  blast += 10.0
        if exfil:    blast += 15.0
        if privesc:  blast += 15.0
        if is_public: blast += 10.0
        if has_sensitive_data: blast += 5.0
        blast_score = min(blast, 100.0)

        # ── Affected services ─────────────────────────────────────────────────
        services = [resource_type]
        if lateral: services += ["EC2", "VPC", "IAM"]
        if exfil:   services += ["S3", "KMS"]
        if privesc: services += ["IAM", "STS"]
        affected_services = list(set(services))

        # ── Human-readable rationale ──────────────────────────────────────────
        rationale = self._build_rationale(
            severity, base, ttp_boost, exposure,
            risk_score, blast_score,
            lateral, exfil, privesc, is_public,
        )

        log.debug(
            "Risk scored: severity=%s risk=%.1f blast=%.1f lateral=%s exfil=%s privesc=%s",
            severity, risk_score, blast_score, lateral, exfil, privesc,
        )

        return RiskResult(
            risk_score         = risk_score,
            blast_score        = blast_score,
            lateral_movement   = lateral,
            data_exfil_risk    = exfil,
            privilege_esc_risk = privesc,
            affected_services  = affected_services,
            rationale          = rationale,
        )

    def _build_rationale(
        self,
        severity:    str,
        base:        float,
        ttp_boost:   float,
        exposure:    float,
        risk_score:  float,
        blast_score: float,
        lateral:     bool,
        exfil:       bool,
        privesc:     bool,
        is_public:   bool,
    ) -> str:
        parts = [
            f"Base severity {severity} ({base}/10).",
        ]
        if ttp_boost > 0:
            parts.append(
                f"High-impact ATT&CK techniques add +{ttp_boost:.2f} to score."
            )
        if exposure > 1.0:
            parts.append(
                f"Exposure multiplier ×{exposure:.1f} applied "
                f"({'public-facing' if is_public else 'sensitive data'})."
            )
        parts.append(
            f"Final risk score: {risk_score:.1f}/10 | "
            f"Blast radius: {blast_score:.0f}/100."
        )
        impact_flags = []
        if lateral: impact_flags.append("lateral movement path exists")
        if exfil:   impact_flags.append("data exfiltration is achievable")
        if privesc: impact_flags.append("privilege escalation path exists")
        if impact_flags:
            parts.append(f"Impact flags: {', '.join(impact_flags)}.")

        return " ".join(parts)