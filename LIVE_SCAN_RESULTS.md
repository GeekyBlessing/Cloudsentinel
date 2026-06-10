# CloudSentinel Live Scan Results

```
======================================================================
CLOUDSENTINEL LIVE SCAN CASE STUDY
Account:  358487322954
Region:   eu-north-1
Duration: 21.2s
Findings: 6 (0 critical, 1 high)
======================================================================

Finding #1 — IAM user with console access does not have MFA enabled
  ID:         F-9990428773E0
  Severity:   HIGH
  Risk Score: 7.3/10
  Resource:   landing-zone-main
  Region:     global
  Blast:      57.0/100
  Exfil Risk: False
  Privesc:    True
  Lateral:    False
  TTPs:
    [TA0001] T1078 — Valid Accounts
    [TA0006] T1528 — Steal Application Access Token
  Compliance:
    [CIS] CIS 1.10
    [NIST_CSF] PR.AC-7
    [SOC2] CC6.1
    [PCI_DSS] PCI 8.3.1
  Fix: Navigate to IAM → Users → landing-zone-main → Security credentials.
----------------------------------------------------------------------

Finding #2 — S3 bucket access logging is disabled
  ID:         F-50021DD2E39B
  Severity:   MEDIUM
  Risk Score: 5.0/10
  Resource:   aws-cloudtrail-logs-358487322954-dfff53e1
  Region:     global
  Blast:      30.0/100
  Exfil Risk: False
  Privesc:    False
  Lateral:    False
  TTPs:
    [TA0005] T1070 — Indicator Removal
  Compliance:
    [CIS] CIS 2.1.4
    [NIST_CSF] DE.CM-3
    [SOC2] CC7.2
    [PCI_DSS] PCI 10.2.1
  Fix: Create a dedicated logging bucket e.g. aws-cloudtrail-logs-358487322954-dfff53e1-access-logs.
----------------------------------------------------------------------

Finding #3 — S3 bucket access logging is disabled
  ID:         F-C9B72BF3FC24
  Severity:   MEDIUM
  Risk Score: 5.0/10
  Resource:   security-ou-templates-358487322954-eu-north-1
  Region:     global
  Blast:      30.0/100
  Exfil Risk: False
  Privesc:    False
  Lateral:    False
  TTPs:
    [TA0005] T1070 — Indicator Removal
  Compliance:
    [CIS] CIS 2.1.4
    [NIST_CSF] DE.CM-3
    [SOC2] CC7.2
    [PCI_DSS] PCI 10.2.1
  Fix: Create a dedicated logging bucket e.g. security-ou-templates-358487322954-eu-north-1-access-logs.
----------------------------------------------------------------------

Finding #4 — CloudTrail log file validation is disabled
  ID:         F-6822AF23A118
  Severity:   MEDIUM
  Risk Score: 5.0/10
  Resource:   security-lab-trail
  Region:     eu-north-1
  Blast:      30.0/100
  Exfil Risk: False
  Privesc:    False
  Lateral:    False
  TTPs:
    [TA0005] T1070 — Indicator Removal
  Compliance:
    [CIS] CIS 3.2
    [NIST_CSF] PR.DS-6
    [SOC2] CC7.1
    [PCI_DSS] PCI 10.5.2
  Fix: Enable log file validation on trail security-lab-trail.
----------------------------------------------------------------------

Finding #5 — VPC Flow Logs are disabled
  ID:         F-B6EF9FCF5B77
  Severity:   MEDIUM
  Risk Score: 5.2/10
  Resource:   vpc-01d65581b753477cb
  Region:     eu-north-1
  Blast:      40.0/100
  Exfil Risk: False
  Privesc:    False
  Lateral:    True
  TTPs:
    [TA0005] T1562 — Impair Defenses
    [TA0008] T1570 — Lateral Tool Transfer
  Compliance:
    [CIS] CIS 3.9
    [NIST_CSF] DE.CM-1
    [SOC2] CC7.2
    [PCI_DSS] PCI 10.2.1
  Fix: Enable VPC Flow Logs for vpc-01d65581b753477cb.
----------------------------------------------------------------------

Finding #6 — EBS volume encryption is disabled
  ID:         F-BB9AB0764FEA
  Severity:   MEDIUM
  Risk Score: 5.2/10
  Resource:   ebs-default:eu-north-1
  Region:     eu-north-1
  Blast:      45.0/100
  Exfil Risk: True
  Privesc:    False
  Lateral:    False
  TTPs:
    [TA0009] T1530 — Data from Cloud Storage
  Compliance:
    [CIS] CIS 2.2.1
    [NIST_CSF] PR.DS-1
    [SOC2] CC9.1
    [PCI_DSS] PCI 3.5.1
  Fix: Enable EBS encryption by default at account level.
----------------------------------------------------------------------

KILL CHAIN ANALYSIS
Active tactics:  5
Highest impact:  Collection
Narrative: Based on 6 open findings, an adversary could progress through 5 ATT&CK tactic(s): Initial Access → Defense Evasion → Credential Access → Lateral Movement → Collection. Critical exposures enabling this path: IAM user with console access does not have MFA enabled. The path reaches Collection/Exfiltration — data loss is a realistic outcome without immediate remediation.

Tactic progression:
  [1] Initial Access
      T1078 — Valid Accounts
  [5] Defense Evasion
      T1070 — Indicator Removal
      T1070 — Indicator Removal
      T1070 — Indicator Removal
      T1562 — Impair Defenses
  [6] Credential Access
      T1528 — Steal Application Access Token
  [8] Lateral Movement
      T1570 — Lateral Tool Transfer
  [9] Collection
      T1530 — Data from Cloud Storage
```
## Post-Remediation Scan

| Finding | Status |
|---------|--------|
| CloudTrail log validation | REMEDIATED ✓ |
| EBS encryption by default | REMEDIATED ✓ |
| IAM user without MFA | Pending approval |
| S3 access logging (×2) | Plan generated |
| VPC Flow Logs | Plan generated |

**Total findings reduced: 6 → 4**