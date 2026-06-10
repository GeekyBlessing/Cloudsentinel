# CloudSentinel CSPM

> Multi-cloud security posture management with MITRE ATT&CK® threat
> enrichment, blast radius scoring, and compliance mapping across
> CIS, NIST CSF, SOC 2, and PCI DSS.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Tests](https://img.shields.io/badge/Tests-142%20passing-brightgreen)
![Coverage](https://img.shields.io/badge/Coverage-80%25%2B-green)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## What makes this different

Most CSPM tools tell you *what* is misconfigured. CloudSentinel tells
you *what an attacker can do with it*.

Every finding is enriched with:

- **MITRE ATT&CK® technique mappings** — with a plain-English explanation
  of why this specific misconfiguration enables this specific technique
- **Blast radius score** — quantifies lateral movement paths, data
  exfiltration risk, and privilege escalation potential
- **Kill chain construction** — given a set of open findings, CloudSentinel
  reconstructs the furthest an adversary could progress through the
  ATT&CK kill chain
- **Compliance controls** — every finding maps to CIS, NIST CSF, SOC 2,
  and PCI DSS simultaneously

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     React Dashboard                          │
│  Overview │ Findings │ ATT&CK Heatmap │ Compliance          │
└─────────────────────┬───────────────────────────────────────┘
                      │ REST API
┌─────────────────────▼───────────────────────────────────────┐
│                   FastAPI Backend                            │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ Scan Engine │  │ MITRE Engine │  │ Risk Scorer      │   │
│  │ 15 rules    │  │ 30+ technique│  │ Composite 0-10   │   │
│  │ AWS live    │  │ mappings     │  │ Blast radius     │   │
│  │ Azure stub  │  │ Kill chain   │  │ Exposure mult    │   │
│  │ GCP stub    │  │ constructor  │  │                  │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Compliance Mapper: CIS │ NIST CSF │ SOC 2 │ PCI DSS  │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              DynamoDB Findings Store                         │
│  SHA-256 fingerprinting │ GSI filtering │ TTL auto-expiry   │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Terraform IaC                               │
│  Scanner IAM role │ DynamoDB │ Lambda │ EventBridge │ KMS   │
└─────────────────────────────────────────────────────────────┘
```
---

## Attack scenarios detected

### Scenario 1 — The SSRF-to-Account-Takeover path
*Modelled on the Capital One breach (2019)*

**Misconfigurations:** IMDSv1 enabled + overprivileged Lambda role

**Attack path:**
1. Attacker finds SSRF vulnerability in web application on EC2
2. IMDSv1 (CS-EC2-003) allows unauthenticated GET to `169.254.169.254`
3. Instance role credentials returned — no session token required
4. Role has `iam:*` wildcard (CS-IAM-003) — privilege escalation trivial
5. Attacker calls `iam:CreatePolicyVersion` to attach AdministratorAccess
6. Full account takeover achieved from a single SSRF vulnerability

**ATT&CK techniques enabled:**
- T1552 — Unsecured Credentials (IMDSv1 credential theft)
- T1548 — Abuse Elevation Control Mechanism (wildcard IAM escalation)
- T1098 — Account Manipulation (persistent backdoor IAM user created)

**CloudSentinel detection:** Both CS-EC2-003 and CS-IAM-003 flagged
as HIGH with privilege escalation blast radius. Kill chain shows
Credential Access → Privilege Escalation → Persistence.

---

### Scenario 2 — The Silent Data Exfiltration path
*Public S3 + disabled logging = no forensic evidence*

**Misconfigurations:** S3 public access + S3 logging disabled + CloudTrail disabled

**Attack path:**
1. Automated scanner (GrayhatWarfare) discovers public S3 bucket (CS-S3-001)
2. Attacker syncs entire bucket to external AWS account — zero authentication
3. S3 access logging disabled (CS-S3-003) — no S3-level forensic evidence
4. CloudTrail disabled (CS-LOG-001) — no API-level audit trail
5. Exfiltration of entire data lake produces zero detectable artifacts
6. Breach discovered weeks later via third-party notification

**ATT&CK techniques enabled:**
- T1530 — Data from Cloud Storage (unauthenticated bucket access)
- T1537 — Transfer Data to Cloud Account (sync to attacker account)
- T1070 — Indicator Removal (no logs = no evidence)

**CloudSentinel detection:** All three rules flagged. Kill chain reaches
Exfiltration with data exfiltration blast radius flag. Narrative explicitly
states data loss is a realistic outcome.

---

### Scenario 3 — The Ransomware Staging path
*Open RDP + no VPC flow logs = lateral movement in the dark*

**Misconfigurations:** Unrestricted RDP + VPC Flow Logs disabled + EBS unencrypted

**Attack path:**
1. Shodan indexes RDP port 3389 open to 0.0.0.0/0 (CS-EC2-002)
2. Attacker brute-forces or credential-stuffs RDP credentials
3. VPC Flow Logs disabled (CS-LOG-003) — lateral movement invisible
4. Attacker moves to other EC2 instances using internal RDP
5. Ransomware deployed — EBS volumes unencrypted (CS-ENC-001)
6. Snapshots exfiltrated to attacker account before encryption

**ATT&CK techniques enabled:**
- T1190 — Exploit Public-Facing Application (open RDP)
- T1021 — Remote Services (internal RDP lateral movement)
- T1570 — Lateral Tool Transfer (ransomware staging, no network logs)
- T1530 — Data from Cloud Storage (unencrypted snapshot exfiltration)

**CloudSentinel detection:** Three rules flagged across EC2, VPC, and
EBS. Kill chain spans Initial Access → Lateral Movement → Collection.
Blast radius flags both lateral movement and data exfiltration paths.

---

## Security rules

| Rule ID | Title | Severity | Service | CIS |
|---------|-------|----------|---------|-----|
| CS-IAM-001 | Root account has active access keys | CRITICAL | IAM | 1.4 |
| CS-IAM-002 | IAM user without MFA has console access | HIGH | IAM | 1.10 |
| CS-IAM-003 | IAM policy grants wildcard permissions | HIGH | IAM | 1.16 |
| CS-IAM-004 | Access key not rotated in 90+ days | MEDIUM | IAM | 1.14 |
| CS-S3-001 | S3 bucket publicly accessible | CRITICAL | S3 | 2.1.5 |
| CS-S3-002 | S3 encryption disabled | MEDIUM | S3 | 2.1.1 |
| CS-S3-003 | S3 access logging disabled | MEDIUM | S3 | 2.1.4 |
| CS-EC2-001 | Unrestricted SSH (0.0.0.0/0) | HIGH | EC2 | 5.2 |
| CS-EC2-002 | Unrestricted RDP (0.0.0.0/0) | HIGH | EC2 | 5.3 |
| CS-EC2-003 | IMDSv1 enabled | HIGH | EC2 | 5.6 |
| CS-LOG-001 | CloudTrail disabled | HIGH | CloudTrail | 3.1 |
| CS-LOG-002 | CloudTrail log validation disabled | MEDIUM | CloudTrail | 3.2 |
| CS-LOG-003 | VPC Flow Logs disabled | MEDIUM | VPC | 3.9 |
| CS-ENC-001 | EBS encryption disabled | MEDIUM | EBS | 2.2.1 |
| CS-ENC-002 | RDS encryption disabled | HIGH | RDS | 2.3.1 |
---

## Quick start

```bash
# Clone and install
git clone https://github.com/GeekyBlessing/cloudsentinel
cd cloudsentinel
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run against your AWS account (read-only)
export PYTHONPATH=$(pwd)
python3 -c "
from cloudsentinel.scanner.engine import ScanEngine
engine = ScanEngine(regions=['eu-north-1'], persist=False)
result = engine.scan_account()
print(result.summary())
for f in result.findings:
    print(f'{f.severity.value:<8} {f.risk_score}/10  {f.title}')
"

# Start the API
uvicorn cloudsentinel.main:app --reload --port 8000

# Run with Docker
docker-compose up
```

---

## Running tests

```bash
# Full suite
python3 -m pytest tests/ -v

# With coverage
python3 -m pytest tests/ --cov=cloudsentinel --cov-report=term-missing

# Single module
python3 -m pytest tests/test_mitre.py -v
```

**142 tests across 6 modules. Zero failures.**

---

## Infrastructure deployment

```bash
cd terraform/

# Initialise
terraform init

# Preview
terraform plan -var="account_id=YOUR_ACCOUNT_ID"

# Deploy
terraform apply -var="account_id=YOUR_ACCOUNT_ID"
```

---

## Project structure
---

## Author

**Toriola Opeyemi** — Cloud Security Engineer
[LinkedIn](https://linkedin.com/in/toriola-opeyemi) ·
[GitHub](https://github.com/GeekyBlessing)

