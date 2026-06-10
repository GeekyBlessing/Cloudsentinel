"""
cloudsentinel.enrichment.compliance
=====================================
Compliance framework mapper.

Maps CloudSentinel rules to controls across:
- CIS AWS Foundations Benchmark v1.5
- NIST Cybersecurity Framework (CSF)
- SOC 2 Type II (Trust Service Criteria)
- PCI DSS v4.0

Design decisions
----------------
- Each rule maps to controls in ALL applicable frameworks simultaneously
- posture_summary() gives per-framework pass/fail counts for the dashboard
- Controls are immutable dataclasses — never mutated after definition
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)


# ── Control definition ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Control:
    framework:   str   # CIS | NIST_CSF | SOC2 | PCI_DSS
    control_id:  str   # e.g. CIS 1.4
    description: str   # control title
    requirement: str   # what the control requires


# ── Master control library ────────────────────────────────────────────────────

CONTROLS: dict[str, list[Control]] = {

    # ── IAM ───────────────────────────────────────────────────────────────────

    "CS-IAM-001": [
        Control("CIS",      "CIS 1.4",   "Root account access keys",
                "Ensure no root account access keys exist"),
        Control("NIST_CSF", "PR.AC-1",   "Identity and credential management",
                "Identities and credentials are managed for authorised devices and users"),
        Control("SOC2",     "CC6.2",     "Logical access controls",
                "Prior to issuing system credentials, the entity registers and authorises users"),
        Control("PCI_DSS",  "PCI 8.2.1", "User account management",
                "All user IDs and authentication mechanisms are managed"),
    ],

    "CS-IAM-002": [
        Control("CIS",      "CIS 1.10",  "MFA for console users",
                "Ensure MFA is enabled for all IAM users with console access"),
        Control("NIST_CSF", "PR.AC-7",   "Authentication",
                "Users, devices, and other assets are authenticated commensurate with risk"),
        Control("SOC2",     "CC6.1",     "Logical access security",
                "The entity implements logical access security to protect against threats"),
        Control("PCI_DSS",  "PCI 8.3.1", "Multi-factor authentication",
                "MFA is incorporated for all non-console access into the cardholder environment"),
    ],

    "CS-IAM-003": [
        Control("CIS",      "CIS 1.16",  "IAM policies — least privilege",
                "Ensure IAM policies are attached only to groups or roles"),
        Control("NIST_CSF", "PR.AC-4",   "Access permissions",
                "Access permissions and authorisations are managed incorporating least privilege"),
        Control("SOC2",     "CC6.3",     "Access provisioning",
                "The entity authorises, modifies, or removes access based on roles"),
        Control("PCI_DSS",  "PCI 7.1.1", "Least privilege access",
                "Access rights are granted to only the least amount of data and privileges needed"),
    ],

    "CS-IAM-004": [
        Control("CIS",      "CIS 1.14",  "Access key rotation",
                "Ensure access keys are rotated every 90 days or less"),
        Control("NIST_CSF", "PR.AC-1",   "Credential management",
                "Identities and credentials are issued, managed, verified, revoked"),
        Control("SOC2",     "CC6.1",     "Credential lifecycle",
                "The entity restricts logical access to information assets"),
        Control("PCI_DSS",  "PCI 8.3.9", "Credential rotation",
                "Passwords/passphrases for user accounts are changed at least every 90 days"),
    ],

    # ── S3 ────────────────────────────────────────────────────────────────────

    "CS-S3-001": [
        Control("CIS",      "CIS 2.1.5", "S3 Block Public Access",
                "Ensure S3 bucket policy is set to deny HTTP requests"),
        Control("NIST_CSF", "PR.AC-3",   "Remote access management",
                "Remote access is managed to prevent unauthorised access"),
        Control("SOC2",     "CC6.1",     "Public access controls",
                "The entity restricts logical access to information assets"),
        Control("PCI_DSS",  "PCI 1.3.2", "Restrict inbound traffic",
                "Restrict inbound traffic to only that which is necessary"),
    ],

    "CS-S3-002": [
        Control("CIS",      "CIS 2.1.1", "S3 server-side encryption",
                "Ensure all S3 buckets employ encryption at rest"),
        Control("NIST_CSF", "PR.DS-1",   "Data at rest protection",
                "Data at rest is protected"),
        Control("SOC2",     "CC9.1",     "Risk mitigation",
                "The entity identifies, selects, and develops risk mitigation activities"),
        Control("PCI_DSS",  "PCI 3.5.1", "Encryption of stored data",
                "Primary account numbers are secured with strong cryptography"),
    ],

    "CS-S3-003": [
        Control("CIS",      "CIS 2.1.4", "S3 access logging",
                "Ensure S3 bucket access logging is enabled"),
        Control("NIST_CSF", "DE.CM-3",   "Personnel activity monitoring",
                "Personnel activity is monitored to detect cybersecurity events"),
        Control("SOC2",     "CC7.2",     "Security event monitoring",
                "The entity monitors system components for anomalies"),
        Control("PCI_DSS",  "PCI 10.2.1","Audit log implementation",
                "Audit logs capture all individual user access to cardholder data"),
    ],

    # ── EC2 ───────────────────────────────────────────────────────────────────

    "CS-EC2-001": [
        Control("CIS",      "CIS 5.2",   "No unrestricted SSH",
                "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"),
        Control("NIST_CSF", "PR.AC-5",   "Network integrity protection",
                "Network integrity is protected incorporating network segregation"),
        Control("SOC2",     "CC6.6",     "Boundary protection",
                "The entity implements controls to prevent unauthorised access"),
        Control("PCI_DSS",  "PCI 1.3.1", "Restrict inbound internet traffic",
                "Restrict inbound traffic from the internet to only necessary components"),
    ],

    "CS-EC2-002": [
        Control("CIS",      "CIS 5.3",   "No unrestricted RDP",
                "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389"),
        Control("NIST_CSF", "PR.AC-5",   "Network integrity protection",
                "Network integrity is protected incorporating network segregation"),
        Control("SOC2",     "CC6.6",     "Boundary protection",
                "The entity implements controls to prevent unauthorised access"),
        Control("PCI_DSS",  "PCI 1.3.1", "Restrict inbound internet traffic",
                "Restrict inbound traffic to only necessary components"),
    ],

    "CS-EC2-003": [
        Control("CIS",      "CIS 5.6",   "IMDSv2 enforcement",
                "Ensure EC2 metadata service only allows IMDSv2"),
        Control("NIST_CSF", "PR.AC-3",   "Remote access management",
                "Remote access is managed"),
        Control("SOC2",     "CC6.1",     "Logical access security",
                "The entity implements logical access security measures"),
        Control("PCI_DSS",  "PCI 6.4.1", "Public-facing application protection",
                "Public-facing web applications are protected against known attacks"),
    ],

    # ── Logging ───────────────────────────────────────────────────────────────

    "CS-LOG-001": [
        Control("CIS",      "CIS 3.1",   "CloudTrail enabled in all regions",
                "Ensure CloudTrail is enabled in all regions"),
        Control("NIST_CSF", "DE.CM-3",   "Activity monitoring",
                "Personnel activity is monitored to detect cybersecurity events"),
        Control("SOC2",     "CC7.2",     "Monitoring controls",
                "The entity monitors system components for anomalies"),
        Control("PCI_DSS",  "PCI 10.1",  "Audit trail implementation",
                "Implement audit trails to link all access to system components"),
    ],

    "CS-LOG-002": [
        Control("CIS",      "CIS 3.2",   "CloudTrail log validation",
                "Ensure CloudTrail log file validation is enabled"),
        Control("NIST_CSF", "PR.DS-6",   "Integrity checking",
                "Integrity checking mechanisms are used to verify software and firmware"),
        Control("SOC2",     "CC7.1",     "Log integrity",
                "The entity uses detection and monitoring procedures"),
        Control("PCI_DSS",  "PCI 10.5.2","Log modification protection",
                "Audit log files are protected to prevent modifications"),
    ],

    "CS-LOG-003": [
        Control("CIS",      "CIS 3.9",   "VPC Flow Logs enabled",
                "Ensure VPC flow logging is enabled in all VPCs"),
        Control("NIST_CSF", "DE.CM-1",   "Network monitoring",
                "The network is monitored to detect potential cybersecurity events"),
        Control("SOC2",     "CC7.2",     "Network monitoring",
                "The entity monitors system components for anomalies"),
        Control("PCI_DSS",  "PCI 10.2.1","Network access logging",
                "Implement audit logs to capture all access to network resources"),
    ],

    # ── Encryption ────────────────────────────────────────────────────────────

    "CS-ENC-001": [
        Control("CIS",      "CIS 2.2.1", "EBS volume encryption",
                "Ensure EBS volume encryption is enabled by default"),
        Control("NIST_CSF", "PR.DS-1",   "Data at rest protection",
                "Data at rest is protected"),
        Control("SOC2",     "CC9.1",     "Encryption controls",
                "The entity identifies and develops risk mitigation activities"),
        Control("PCI_DSS",  "PCI 3.5.1", "Storage encryption",
                "Primary account numbers are secured with strong cryptography"),
    ],

    "CS-ENC-002": [
        Control("CIS",      "CIS 2.3.1", "RDS encryption at rest",
                "Ensure all RDS instances have encryption at rest enabled"),
        Control("NIST_CSF", "PR.DS-1",   "Data at rest protection",
                "Data at rest is protected"),
        Control("SOC2",     "CC9.1",     "Database encryption",
                "The entity identifies and develops risk mitigation activities"),
        Control("PCI_DSS",  "PCI 3.5.1", "Database encryption",
                "Stored cardholder data is protected with strong cryptography"),
    ],

    # ── Lambda ────────────────────────────────────────────────────────────────

    "CS-LAM-001": [
        Control("CIS",      "CIS 1.16",  "Lambda least privilege",
                "Ensure Lambda execution roles follow least privilege"),
        Control("NIST_CSF", "PR.AC-4",   "Access permission management",
                "Access permissions incorporating least privilege are managed"),
        Control("SOC2",     "CC6.3",     "Access provisioning",
                "The entity authorises access based on roles and responsibilities"),
        Control("PCI_DSS",  "PCI 7.1.1", "Least privilege",
                "Access rights are granted to only the least amount needed"),
    ],
}

# ── Framework totals (for posture % calculation) ──────────────────────────────
# Total number of unique controls per framework that CloudSentinel covers
FRAMEWORK_TOTALS: dict[str, int] = {
    "CIS":      57,
    "NIST_CSF": 23,
    "SOC2":     31,
    "PCI_DSS":  44,
}


# ── Compliance mapper ─────────────────────────────────────────────────────────

class ComplianceMapper:
    """
    Maps rules to compliance controls and computes posture scores
    per framework based on open findings.
    """

    def get_controls(self, rule_id: str) -> list[dict]:
        """Return compliance controls for a rule as serialisable dicts."""
        controls = CONTROLS.get(rule_id, [])
        if not controls:
            log.debug("No compliance controls mapped for rule %s", rule_id)
        return [
            {
                "framework":   c.framework,
                "control_id":  c.control_id,
                "description": c.description,
                "requirement": c.requirement,
            }
            for c in controls
        ]

    def posture_summary(self, findings: list[dict]) -> dict[str, dict]:
        """
        Compute per-framework compliance posture from open findings.

        Returns a dict like:
        {
            "CIS": {
                "total": 57,
                "failing": 4,
                "passing": 53,
                "pass_pct": 93,
                "failing_controls": ["CIS 1.4", "CIS 1.10", ...]
            },
            ...
        }
        """
        # Collect all failing control IDs per framework from open findings
        failing: dict[str, set[str]] = {fw: set() for fw in FRAMEWORK_TOTALS}

        open_findings = [f for f in findings if f.get("status") == "OPEN"]

        for finding in open_findings:
            rule_id = finding.get("rule_id", "")
            for control in CONTROLS.get(rule_id, []):
                fw = control.framework
                if fw in failing:
                    failing[fw].add(control.control_id)

        # Build summary
        summary = {}
        for fw, total in FRAMEWORK_TOTALS.items():
            fail_count = len(failing[fw])
            pass_count = total - fail_count
            summary[fw] = {
                "total":            total,
                "failing":          fail_count,
                "passing":          pass_count,
                "pass_pct":         round((pass_count / total) * 100, 1),
                "failing_controls": sorted(failing[fw]),
            }
            log.debug(
                "Framework %s: %d/%d passing (%.1f%%)",
                fw, pass_count, total, summary[fw]["pass_pct"]
            )

        return summary

    def get_frameworks_for_rule(self, rule_id: str) -> list[str]:
        """Return list of frameworks a rule maps to."""
        return list({c.framework for c in CONTROLS.get(rule_id, [])})