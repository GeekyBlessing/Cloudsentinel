"""
cloudsentinel.enrichment.mitre
==============================
MITRE ATT&CK® Enterprise enrichment engine.

Responsibilities
----------------
1. Map every CloudSentinel rule to ATT&CK techniques
2. Explain why the misconfiguration enables each technique
3. Construct a kill chain from a set of open findings
4. Identify the highest-risk tactic progression an attacker could follow
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger(__name__)


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class TechniqueMapping:
    tactic_id:       str
    tactic_name:     str
    technique_id:    str
    technique_name:  str
    relevance:       str
    subtechnique_id: Optional[str] = None


@dataclass
class AttackStep:
    tactic_id:   str
    tactic_name: str
    order:       int
    techniques:  list = field(default_factory=list)
    findings:    list = field(default_factory=list)


@dataclass
class KillChain:
    steps:          list
    total_tactics:  int
    highest_impact: str
    narrative:      str


# ── Tactic ordering & names ───────────────────────────────────────────────────

TACTIC_ORDER: dict[str, int] = {
    "TA0001": 1,  "TA0002": 2,  "TA0003": 3,
    "TA0004": 4,  "TA0005": 5,  "TA0006": 6,
    "TA0007": 7,  "TA0008": 8,  "TA0009": 9,
    "TA0010": 10, "TA0040": 11,
}

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}


# ── Rule → TTP mapping table ──────────────────────────────────────────────────

RULE_TTP_MAP: dict[str, list[TechniqueMapping]] = {

    "CS-IAM-001": [
        TechniqueMapping(
            "TA0001", "Initial Access", "T1078", "Valid Accounts",
            relevance=(
                "Root access keys provide unconditional initial access — they bypass "
                "SCPs, permission boundaries, and cannot be restricted by any IAM policy."
            ),
            subtechnique_id="T1078.004",
        ),
        TechniqueMapping(
            "TA0004", "Privilege Escalation", "T1078", "Valid Accounts",
            relevance=(
                "Root is the ceiling of AWS privilege. Compromise of root keys "
                "eliminates the need for any privilege escalation technique."
            ),
            subtechnique_id="T1078.004",
        ),
        TechniqueMapping(
            "TA0006", "Credential Access", "T1552", "Unsecured Credentials",
            relevance=(
                "Root access keys stored in code or CI/CD env vars are a high-value "
                "target. Unlike IAM user keys, root keys cannot be scoped after issuance."
            ),
        ),
    ],

    "CS-IAM-002": [
        TechniqueMapping(
            "TA0001", "Initial Access", "T1078", "Valid Accounts",
            relevance=(
                "Without MFA, a stolen or brute-forced password grants immediate "
                "console access. Credential stuffing attacks succeed instantly."
            ),
            subtechnique_id="T1078.004",
        ),
        TechniqueMapping(
            "TA0006", "Credential Access", "T1528", "Steal Application Access Token",
            relevance=(
                "Console sessions without MFA produce session tokens that can be "
                "hijacked and replayed without ever knowing the password."
            ),
        ),
    ],

    "CS-IAM-003": [
        TechniqueMapping(
            "TA0004", "Privilege Escalation", "T1548",
            "Abuse Elevation Control Mechanism",
            relevance=(
                "A principal with Action:* can call iam:CreatePolicyVersion to "
                "self-escalate to admin — a well-documented AWS privesc path."
            ),
        ),
        TechniqueMapping(
            "TA0003", "Persistence", "T1098", "Account Manipulation",
            relevance=(
                "iam:* permissions allow creating backdoor IAM users or access keys "
                "that survive incident response if not specifically hunted."
            ),
        ),
    ],

    "CS-IAM-004": [
        TechniqueMapping(
            "TA0006", "Credential Access", "T1552", "Unsecured Credentials",
            relevance=(
                "Long-lived keys increase the exploitation window. Keys leaked in a "
                "git commit months ago remain valid if never rotated."
            ),
        ),
        TechniqueMapping(
            "TA0003", "Persistence", "T1098", "Account Manipulation",
            relevance=(
                "Stale keys give persistent access without creating new credentials, "
                "making detection harder since no new IAM activity appears."
            ),
        ),
    ],

    "CS-S3-001": [
        TechniqueMapping(
            "TA0009", "Collection", "T1530", "Data from Cloud Storage",
            relevance=(
                "A public S3 bucket requires zero authentication. Automated scanners "
                "like GrayhatWarfare continuously enumerate public buckets."
            ),
        ),
        TechniqueMapping(
            "TA0010", "Exfiltration", "T1537",
            "Transfer Data to Cloud Account",
            relevance=(
                "An attacker can sync a public bucket to an external AWS account "
                "with a single CLI command, bypassing GuardDuty anomaly alerts."
            ),
        ),
    ],

    "CS-S3-002": [
        TechniqueMapping(
            "TA0009", "Collection", "T1530", "Data from Cloud Storage",
            relevance=(
                "Unencrypted objects are readable by any overprivileged role, "
                "misconfigured cross-account policy, or compromised EC2 profile."
            ),
        ),
    ],

    "CS-S3-003": [
        TechniqueMapping(
            "TA0005", "Defense Evasion", "T1070", "Indicator Removal",
            relevance=(
                "Without S3 access logs, exfiltration leaves no trace. An attacker "
                "downloading terabytes produces zero forensic artifacts."
            ),
        ),
    ],

    "CS-EC2-001": [
        TechniqueMapping(
            "TA0001", "Initial Access", "T1190",
            "Exploit Public-Facing Application",
            relevance=(
                "Port 22 open to the internet is indexed by Shodan within minutes "
                "of instance launch and targeted by automated scanners constantly."
            ),
        ),
        TechniqueMapping(
            "TA0001", "Initial Access", "T1133", "External Remote Services",
            relevance=(
                "Weak credentials, exposed private keys, or SSH agent hijacking "
                "all become viable when port 22 is reachable from the internet."
            ),
        ),
    ],

    "CS-EC2-002": [
        TechniqueMapping(
            "TA0001", "Initial Access", "T1190",
            "Exploit Public-Facing Application",
            relevance=(
                "RDP is the most exploited initial access vector in ransomware. "
                "BlueKeep (CVE-2019-0708) targets open RDP with unauthenticated RCE."
            ),
        ),
        TechniqueMapping(
            "TA0008", "Lateral Movement", "T1021", "Remote Services",
            relevance=(
                "Open RDP between instances enables lateral movement using native "
                "Windows functionality that blends with legitimate traffic."
            ),
        ),
    ],

    "CS-EC2-003": [
        TechniqueMapping(
            "TA0006", "Credential Access", "T1552", "Unsecured Credentials",
            relevance=(
                "IMDSv1 requires no session token — any HTTP GET to 169.254.169.254 "
                "returns role credentials. This is exactly how the Capital One "
                "breach (2019) worked via SSRF."
            ),
        ),
        TechniqueMapping(
            "TA0004", "Privilege Escalation", "T1548",
            "Abuse Elevation Control Mechanism",
            relevance=(
                "Stolen instance role credentials with iam:PassRole or ec2:* "
                "enable full account compromise from a simple SSRF vulnerability."
            ),
        ),
    ],

    "CS-LOG-001": [
        TechniqueMapping(
            "TA0005", "Defense Evasion", "T1562", "Impair Defenses",
            relevance=(
                "Disabling CloudTrail is T1562.008 verbatim — the first action "
                "taken by sophisticated actors after initial access."
            ),
            subtechnique_id="T1562.008",
        ),
        TechniqueMapping(
            "TA0005", "Defense Evasion", "T1070", "Indicator Removal",
            relevance=(
                "With CloudTrail disabled, all subsequent API calls produce no "
                "log entries. Forensic investigation becomes impossible."
            ),
        ),
    ],

    "CS-LOG-002": [
        TechniqueMapping(
            "TA0005", "Defense Evasion", "T1070", "Indicator Removal",
            relevance=(
                "Without log validation, an attacker with S3 write access can "
                "silently delete CloudTrail files with no detectable integrity breach."
            ),
        ),
    ],

    "CS-LOG-003": [
        TechniqueMapping(
            "TA0005", "Defense Evasion", "T1562", "Impair Defenses",
            relevance=(
                "VPC Flow Logs are the primary network visibility layer. Without "
                "them, C2 traffic and lateral movement leave no network evidence."
            ),
            subtechnique_id="T1562.008",
        ),
        TechniqueMapping(
            "TA0008", "Lateral Movement", "T1570", "Lateral Tool Transfer",
            relevance=(
                "Unmonitored VPC traffic hides tool transfer between instances — "
                "implants can move freely with no network forensic trace."
            ),
        ),
    ],

    "CS-ENC-001": [
        TechniqueMapping(
            "TA0009", "Collection", "T1530", "Data from Cloud Storage",
            relevance=(
                "Unencrypted EBS snapshots can be shared externally. An attacker "
                "with ec2:ModifySnapshotAttribute can exfiltrate the full disk image."
            ),
        ),
    ],

    "CS-ENC-002": [
        TechniqueMapping(
            "TA0009", "Collection", "T1213",
            "Data from Information Repositories",
            relevance=(
                "Unencrypted RDS snapshots expose the full database. An attacker "
                "with rds:RestoreDBInstanceFromDBSnapshot owns production data."
            ),
        ),
    ],

    "CS-LAM-001": [
        TechniqueMapping(
            "TA0004", "Privilege Escalation", "T1548",
            "Abuse Elevation Control Mechanism",
            relevance=(
                "A Lambda with iam:* can be exploited via code injection to execute "
                "arbitrary IAM operations under the function's privileged identity."
            ),
        ),
        TechniqueMapping(
            "TA0003", "Persistence", "T1505",
            "Server Software Component",
            relevance=(
                "Compromised Lambda code persists across invocations. A backdoored "
                "handler exfiltrates payloads and executes C2 callbacks on every run."
            ),
        ),
    ],
}


# ── Enrichment engine ─────────────────────────────────────────────────────────

class MitreEnrichmentEngine:
    """
    Maps CloudSentinel rules to MITRE ATT&CK® techniques and
    constructs adversary kill chains from sets of open findings.
    """

    def enrich(self, rule_id: str) -> list[dict]:
        """Return ATT&CK mappings for a rule. Empty list for unmapped rules."""
        mappings = RULE_TTP_MAP.get(rule_id, [])
        if not mappings:
            log.debug("No MITRE mappings for rule %s", rule_id)
            return []
        return [
            {
                "tactic_id":       m.tactic_id,
                "tactic_name":     m.tactic_name,
                "technique_id":    m.technique_id,
                "technique_name":  m.technique_name,
                "kill_chain_phase": m.tactic_name.lower().replace(" ", "-"),
                "relevance":       m.relevance,
                "subtechnique_id": m.subtechnique_id,
            }
            for m in mappings
        ]

    def get_tactics_for_rule(self, rule_id: str) -> list[str]:
        """Return tactic IDs for a rule — used by risk scorer."""
        return list({m.tactic_id for m in RULE_TTP_MAP.get(rule_id, [])})

    def get_techniques_for_rule(self, rule_id: str) -> list[str]:
        """Return technique IDs for a rule — used by risk scorer."""
        return [m.technique_id for m in RULE_TTP_MAP.get(rule_id, [])]

    def build_kill_chain(self, findings: list[dict]) -> KillChain:
        """
        Construct an ordered kill chain from open findings.
        Shows which ATT&CK tactics an attacker could progress through
        given the current misconfiguration surface.
        """
        active: dict[str, AttackStep] = {}

        for finding in findings:
            if finding.get("status") != "OPEN":
                continue
            for mapping in finding.get("mitre", []):
                tid = mapping["tactic_id"]
                if tid not in active:
                    active[tid] = AttackStep(
                        tactic_id   = tid,
                        tactic_name = TACTIC_NAMES.get(tid, tid),
                        order       = TACTIC_ORDER.get(tid, 99),
                    )
                active[tid].techniques.append({
                    "technique_id":  mapping["technique_id"],
                    "technique_name": mapping["technique_name"],
                    "relevance":     mapping.get("relevance", ""),
                })
                active[tid].findings.append(finding.get("id", ""))

        steps = sorted(active.values(), key=lambda s: s.order)
        highest = steps[-1].tactic_name if steps else "None"
        narrative = self._build_narrative(steps, findings)

        log.info(
            "Kill chain: %d active tactics, furthest reach: %s",
            len(steps), highest
        )
        return KillChain(
            steps          = steps,
            total_tactics  = len(steps),
            highest_impact = highest,
            narrative      = narrative,
        )

    def _build_narrative(self, steps: list, findings: list[dict]) -> str:
        """Generate plain-English adversary narrative for reports."""
        if not steps:
            return "No active attack paths identified."

        tactic_names = [s.tactic_name for s in steps]
        critical = [
            f["title"] for f in findings
            if f.get("severity") in ("CRITICAL", "HIGH")
            and f.get("status") == "OPEN"
        ]

        parts = [
            f"Based on {len(findings)} open findings, an adversary could progress "
            f"through {len(steps)} ATT&CK tactic(s): "
            f"{' → '.join(tactic_names)}.",
        ]
        if critical:
            parts.append(
                f"Critical exposures enabling this path: "
                f"{'; '.join(critical[:3])}."
            )
        if steps[-1].order >= 9:
            parts.append(
                "The path reaches Collection/Exfiltration — "
                "data loss is a realistic outcome without immediate remediation."
            )
        elif steps[-1].order >= 4:
            parts.append(
                "The path reaches Privilege Escalation — "
                "full account takeover is achievable from this posture."
            )
        return " ".join(parts)