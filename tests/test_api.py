"""
tests/test_api.py
=================
Tests for the FastAPI endpoints.
Uses TestClient — no real AWS or DynamoDB calls.
"""
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient
from fastapi.testclient import TestClient


# ── App fixture with mocked dependencies ─────────────────────────────────────

@pytest.fixture
def client():
    """
    Create a TestClient with all external dependencies mocked.
    FindingStore and ScanEngine are patched so no AWS calls are made.
    """
    with patch("cloudsentinel.main.store") as mock_store, patch("cloudsentinel.main.FindingStore") as mock_store_cls, \
         patch("cloudsentinel.main.ScanEngine")   as mock_engine_cls:

        # Configure mock store
        mock_store = MagicMock()
        mock_store.list.return_value   = MOCK_FINDINGS
        mock_store.get.return_value    = MOCK_FINDINGS[0]
        mock_store.upsert.return_value = True
        mock_store.update_status.return_value = True
        mock_store_cls.return_value = mock_store

        # Configure mock engine
        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.total   = 2
        mock_result.summary.return_value = {
            "account_id": "123456789012",
            "total":      2,
            "critical":   1,
            "high":       1,
            "duration_s": 5.2,
            "errors":     0,
        }
        mock_engine.scan_account.return_value = mock_result
        mock_engine_cls.return_value = mock_engine

        from cloudsentinel.main import app
        yield TestClient(app)


# ── Mock data ─────────────────────────────────────────────────────────────────

MOCK_FINDINGS = [
    {
        "id":          "F-ABC123DEF456",
        "rule_id":     "CS-IAM-001",
        "title":       "Root account has active access keys",
        "description": "Test description",
        "cloud":       "AWS",
        "account_id":  "123456789012",
        "region":      "global",
        "service":     "IAM",
        "resource_id": "arn:aws:iam::123456789012:root",
        "severity":    "CRITICAL",
        "risk_score":  9.4,
        "status":      "OPEN",
        "blast_radius": {
            "score":              95.0,
            "affected_services":  ["IAM", "STS"],
            "lateral_movement":   False,
            "data_exfil_risk":    False,
            "privilege_esc_risk": True,
            "rationale":          "Test rationale",
        },
        "mitre": [
            {
                "tactic_id":      "TA0001",
                "tactic_name":    "Initial Access",
                "technique_id":   "T1078",
                "technique_name": "Valid Accounts",
            }
        ],
        "controls":    [],
        "remediation": None,
        "first_seen":  "2026-06-01T00:00:00+00:00",
        "last_seen":   "2026-06-10T00:00:00+00:00",
    },
    {
        "id":          "F-DEF456GHI789",
        "rule_id":     "CS-S3-001",
        "title":       "S3 bucket is publicly accessible",
        "description": "Test description",
        "cloud":       "AWS",
        "account_id":  "123456789012",
        "region":      "eu-north-1",
        "service":     "S3",
        "resource_id": "my-public-bucket",
        "severity":    "CRITICAL",
        "risk_score":  9.8,
        "status":      "OPEN",
        "blast_radius": {
            "score":              98.0,
            "affected_services":  ["S3", "KMS"],
            "lateral_movement":   False,
            "data_exfil_risk":    True,
            "privilege_esc_risk": False,
            "rationale":          "Test rationale",
        },
        "mitre": [
            {
                "tactic_id":      "TA0009",
                "tactic_name":    "Collection",
                "technique_id":   "T1530",
                "technique_name": "Data from Cloud Storage",
            }
        ],
        "controls":    [],
        "remediation": None,
        "first_seen":  "2026-06-01T00:00:00+00:00",
        "last_seen":   "2026-06-10T00:00:00+00:00",
    },
]


# ── Health ────────────────────────────────────────────────────────────────────

class TestHealth:

    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_response_fields(self, client):
        r = client.get("/health")
        data = r.json()
        assert data["status"]  == "ok"
        assert data["service"] == "cloudsentinel"
        assert "version"    in data
        assert "timestamp"  in data

    def test_health_version(self, client):
        r = client.get("/health")
        assert r.json()["version"] == "2.1.0"


# ── Posture ───────────────────────────────────────────────────────────────────

class TestPosture:

    def test_posture_returns_200(self, client):
        r = client.get("/api/v1/posture")
        assert r.status_code == 200

    def test_posture_has_required_fields(self, client):
        r    = client.get("/api/v1/posture")
        data = r.json()
        assert "total_open"      in data
        assert "avg_risk_score"  in data
        assert "severity_counts" in data
        assert "cloud_breakdown" in data
        assert "kill_chain"      in data
        assert "compliance"      in data
        assert "generated_at"    in data

    def test_posture_severity_counts_structure(self, client):
        r      = client.get("/api/v1/posture")
        counts = r.json()["severity_counts"]
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in counts

    def test_posture_kill_chain_structure(self, client):
        r     = client.get("/api/v1/posture")
        chain = r.json()["kill_chain"]
        assert "total_tactics"  in chain
        assert "highest_impact" in chain
        assert "narrative"      in chain
        assert "steps"          in chain


# ── Findings ──────────────────────────────────────────────────────────────────

class TestFindings:

    def test_list_findings_returns_200(self, client):
        r = client.get("/api/v1/findings")
        assert r.status_code == 200

    def test_list_findings_structure(self, client):
        r    = client.get("/api/v1/findings")
        data = r.json()
        assert "findings" in data
        assert "total"    in data
        assert "filters"  in data

    def test_list_findings_total_matches(self, client):
        r    = client.get("/api/v1/findings")
        data = r.json()
        assert data["total"] == len(data["findings"])

    def test_list_findings_with_filters(self, client):
        r = client.get(
            "/api/v1/findings",
            params={"cloud": "AWS", "severity": "CRITICAL", "status": "OPEN"}
        )
        assert r.status_code == 200
        data = r.json()
        assert data["filters"]["cloud"]    == "AWS"
        assert data["filters"]["severity"] == "CRITICAL"

    def test_get_finding_returns_200(self, client):
        r = client.get("/api/v1/findings/F-ABC123DEF456")
        assert r.status_code == 200

    def test_get_finding_not_found(self, client):
        with patch("cloudsentinel.main.store") as mock_store:
            mock_store.get.return_value = None
            r = client.get("/api/v1/findings/F-NONEXISTENT")
            assert r.status_code == 404

    def test_list_findings_limit_param(self, client):
        r = client.get("/api/v1/findings", params={"limit": 10})
        assert r.status_code == 200

    def test_list_findings_invalid_limit(self, client):
        r = client.get("/api/v1/findings", params={"limit": 0})
        assert r.status_code == 422   # FastAPI validation error


# ── Status updates ────────────────────────────────────────────────────────────

class TestStatusUpdate:

    def test_mark_remediated(self, client):
        r = client.patch(
            "/api/v1/findings/F-ABC123DEF456/status",
            json={"status": "REMEDIATED"}
        )
        assert r.status_code == 200
        assert r.json()["status"] == "REMEDIATED"

    def test_suppress_with_reason(self, client):
        r = client.patch(
            "/api/v1/findings/F-ABC123DEF456/status",
            json={
                "status": "SUPPRESSED",
                "reason": "Accepted risk — dev environment only"
            }
        )
        assert r.status_code == 200

    def test_suppress_without_reason_fails(self, client):
        r = client.patch(
            "/api/v1/findings/F-ABC123DEF456/status",
            json={"status": "SUPPRESSED", "reason": "short"}
        )
        assert r.status_code == 400

    def test_invalid_status_rejected(self, client):
        r = client.patch(
            "/api/v1/findings/F-ABC123DEF456/status",
            json={"status": "DELETED"}
        )
        assert r.status_code == 400

    def test_reopen_finding(self, client):
        r = client.patch(
            "/api/v1/findings/F-ABC123DEF456/status",
            json={"status": "OPEN"}
        )
        assert r.status_code == 200
        assert r.json()["status"] == "OPEN"


# ── Scans ─────────────────────────────────────────────────────────────────────

class TestScans:

    def test_trigger_scan_returns_202(self, client):
        r = client.post(
            "/api/v1/scans",
            json={"account_id": "123456789012"}
        )
        assert r.status_code == 200

    def test_trigger_scan_returns_scan_id(self, client):
        r    = client.post(
            "/api/v1/scans",
            json={"account_id": "123456789012"}
        )
        data = r.json()
        assert "scan_id"    in data
        assert "account_id" in data
        assert "status"     in data
        assert data["status"] == "RUNNING"

    def test_get_scan_not_found(self, client):
        r = client.get("/api/v1/scans/nonexistent-scan-id")
        assert r.status_code == 404

    def test_get_scan_after_trigger(self, client):
        # Trigger a scan
        trigger = client.post(
            "/api/v1/scans",
            json={"account_id": "123456789012"}
        )
        scan_id = trigger.json()["scan_id"]

        # Retrieve it
        r = client.get(f"/api/v1/scans/{scan_id}")
        assert r.status_code == 200
        assert r.json()["scan_id"] == scan_id


# ── Attack path ───────────────────────────────────────────────────────────────

class TestAttackPath:

    def test_attack_path_returns_200(self, client):
        r = client.get("/api/v1/attack-path")
        assert r.status_code == 200

    def test_attack_path_structure(self, client):
        r    = client.get("/api/v1/attack-path")
        data = r.json()
        assert "total_tactics"  in data
        assert "highest_impact" in data
        assert "narrative"      in data
        assert "steps"          in data
        assert "generated_at"   in data

    def test_attack_path_with_cloud_filter(self, client):
        r = client.get("/api/v1/attack-path", params={"cloud": "AWS"})
        assert r.status_code == 200


# ── Compliance ────────────────────────────────────────────────────────────────

class TestCompliance:

    def test_compliance_returns_200(self, client):
        r = client.get("/api/v1/compliance")
        assert r.status_code == 200

    def test_compliance_has_all_frameworks(self, client):
        r    = client.get("/api/v1/compliance")
        data = r.json()
        assert "frameworks" in data
        for fw in ["CIS", "NIST_CSF", "SOC2", "PCI_DSS"]:
            assert fw in data["frameworks"]

    def test_compliance_single_framework(self, client):
        r = client.get("/api/v1/compliance", params={"framework": "CIS"})
        assert r.status_code == 200
        assert "CIS" in r.json()

    def test_compliance_invalid_framework(self, client):
        r = client.get("/api/v1/compliance", params={"framework": "INVALID"})
        assert r.status_code == 400