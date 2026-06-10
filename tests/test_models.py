"""
tests/test_models.py
====================
Tests for the canonical Finding model.
Covers fingerprinting, validation, serialisation, and lifecycle methods.
"""
import pytest
from datetime import datetime, timezone
from cloudsentinel.models.finding import (
    Finding, Severity, FindingStatus, CloudProvider,
    BlastRadius, MitreMapping, ComplianceControl, RemediationGuide,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

def make_blast_radius(**kwargs) -> BlastRadius:
    defaults = dict(
        score              = 75.0,
        affected_services  = ["IAM", "STS"],
        lateral_movement   = False,
        data_exfil_risk    = False,
        privilege_esc_risk = True,
        rationale          = "Test rationale",
    )
    return BlastRadius(**{**defaults, **kwargs})


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        rule_id      = "CS-IAM-001",
        title        = "Root account has active access keys",
        description  = "Test description",
        cloud        = CloudProvider.AWS,
        account_id   = "123456789012",
        region       = "global",
        service      = "IAM",
        resource_id  = "arn:aws:iam::123456789012:root",
        severity     = Severity.CRITICAL,
        risk_score   = 9.4,
        blast_radius = make_blast_radius(),
    )
    return Finding(**{**defaults, **kwargs})


# ── Fingerprinting ────────────────────────────────────────────────────────────

class TestFingerprinting:

    def test_id_auto_generated(self):
        f = make_finding()
        assert f.id.startswith("F-")
        assert len(f.id) == 14   # "F-" + 12 hex chars + padding

    def test_same_inputs_same_id(self):
        f1 = make_finding()
        f2 = make_finding()
        assert f1.id == f2.id

    def test_different_resource_different_id(self):
        f1 = make_finding(resource_id="resource-A")
        f2 = make_finding(resource_id="resource-B")
        assert f1.id != f2.id

    def test_different_account_different_id(self):
        f1 = make_finding(account_id="111111111111")
        f2 = make_finding(account_id="222222222222")
        assert f1.id != f2.id

    def test_explicit_id_not_overwritten(self):
        f = make_finding(id="F-CUSTOM123456")
        assert f.id == "F-CUSTOM123456"


# ── Severity ──────────────────────────────────────────────────────────────────

class TestSeverity:

    def test_numeric_ordering(self):
        assert Severity.CRITICAL.numeric > Severity.HIGH.numeric
        assert Severity.HIGH.numeric    > Severity.MEDIUM.numeric
        assert Severity.MEDIUM.numeric  > Severity.LOW.numeric
        assert Severity.LOW.numeric     > Severity.INFO.numeric

    def test_severity_numeric_on_finding(self):
        f = make_finding(severity=Severity.CRITICAL)
        assert f.severity_numeric == 5

    def test_all_severities_valid(self):
        for sev in Severity:
            f = make_finding(severity=sev)
            assert f.severity == sev


# ── Computed fields ───────────────────────────────────────────────────────────

class TestComputedFields:

    def test_ttp_ids_empty_by_default(self):
        f = make_finding()
        assert f.ttp_ids == []

    def test_ttp_ids_populated(self):
        f = make_finding(mitre=[
            MitreMapping(
                tactic_id      = "TA0001",
                tactic_name    = "Initial Access",
                technique_id   = "T1078",
                technique_name = "Valid Accounts",
            ),
            MitreMapping(
                tactic_id      = "TA0006",
                tactic_name    = "Credential Access",
                technique_id   = "T1552",
                technique_name = "Unsecured Credentials",
            ),
        ])
        assert set(f.ttp_ids) == {"T1078", "T1552"}

    def test_tactic_ids_deduplicated(self):
        # Same tactic, two techniques — should appear once
        f = make_finding(mitre=[
            MitreMapping(
                tactic_id="TA0001", tactic_name="Initial Access",
                technique_id="T1078", technique_name="Valid Accounts",
            ),
            MitreMapping(
                tactic_id="TA0001", tactic_name="Initial Access",
                technique_id="T1190", technique_name="Exploit Public App",
            ),
        ])
        assert f.tactic_ids.count("TA0001") == 1

    def test_is_public_facing_from_description(self):
        f = make_finding(
            description="Security group allows 0.0.0.0/0 ingress on port 22"
        )
        assert f.is_public_facing is True

    def test_is_not_public_facing(self):
        f = make_finding(description="EBS volume is not encrypted at rest")
        assert f.is_public_facing is False


# ── Lifecycle ─────────────────────────────────────────────────────────────────

class TestLifecycle:

    def test_default_status_open(self):
        f = make_finding()
        assert f.status == FindingStatus.OPEN

    def test_mark_remediated(self):
        f = make_finding()
        f.mark_remediated()
        assert f.status == FindingStatus.REMEDIATED

    def test_suppress_valid_reason(self):
        f = make_finding()
        f.suppress("Accepted risk — dev environment only")
        assert f.status == FindingStatus.SUPPRESSED
        assert f.suppressed_reason == "Accepted risk — dev environment only"

    def test_suppress_short_reason_raises(self):
        f = make_finding()
        with pytest.raises(ValueError, match="at least 10 characters"):
            f.suppress("too short")

    def test_suppress_empty_reason_raises(self):
        f = make_finding()
        with pytest.raises(ValueError):
            f.suppress("")


# ── Serialisation ─────────────────────────────────────────────────────────────

class TestSerialisation:

    def test_to_dynamodb_item_has_finding_id(self):
        f    = make_finding()
        item = f.to_dynamodb_item()
        assert "finding_id" in item
        assert "id" not in item

    def test_to_dynamodb_item_enums_are_strings(self):
        f    = make_finding()
        item = f.to_dynamodb_item()
        assert isinstance(item["cloud"],    str)
        assert isinstance(item["severity"], str)
        assert isinstance(item["status"],   str)

    def test_from_dynamodb_item_roundtrip(self):
        original = make_finding()
        item     = original.to_dynamodb_item()
        restored = Finding.from_dynamodb_item(item)
        assert restored.id         == original.id
        assert restored.severity   == original.severity
        assert restored.risk_score == original.risk_score

    def test_risk_score_bounds(self):
        with pytest.raises(Exception):
            make_finding(risk_score=11.0)   # exceeds max
        with pytest.raises(Exception):
            make_finding(risk_score=-1.0)   # below min


# ── Blast radius ──────────────────────────────────────────────────────────────

class TestBlastRadius:

    def test_blast_radius_fields(self):
        br = make_blast_radius(
            lateral_movement   = True,
            data_exfil_risk    = True,
            privilege_esc_risk = True,
        )
        assert br.lateral_movement   is True
        assert br.data_exfil_risk    is True
        assert br.privilege_esc_risk is True

    def test_blast_radius_score_on_finding(self):
        f = make_finding(blast_radius=make_blast_radius(score=90.0))
        assert f.blast_radius.score == 90.0