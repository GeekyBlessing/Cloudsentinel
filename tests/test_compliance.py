"""
tests/test_compliance.py
========================
Tests for the compliance framework mapper.
Covers control lookups, posture calculations, and framework coverage.
"""
import pytest
from cloudsentinel.enrichment.compliance import (
    ComplianceMapper,
    CONTROLS,
    FRAMEWORK_TOTALS,
)


@pytest.fixture
def mapper():
    return ComplianceMapper()


@pytest.fixture
def open_findings():
    return [
        {"rule_id": "CS-IAM-001", "status": "OPEN"},
        {"rule_id": "CS-IAM-002", "status": "OPEN"},
        {"rule_id": "CS-S3-001",  "status": "OPEN"},
        {"rule_id": "CS-LOG-001", "status": "OPEN"},
    ]


@pytest.fixture
def mixed_findings():
    return [
        {"rule_id": "CS-IAM-001", "status": "OPEN"},
        {"rule_id": "CS-IAM-002", "status": "REMEDIATED"},
        {"rule_id": "CS-S3-001",  "status": "SUPPRESSED"},
    ]


# ── Control lookups ───────────────────────────────────────────────────────────

class TestControlLookups:

    def test_known_rule_returns_controls(self, mapper):
        controls = mapper.get_controls("CS-IAM-001")
        assert len(controls) > 0

    def test_unknown_rule_returns_empty(self, mapper):
        assert mapper.get_controls("CS-UNKNOWN-999") == []

    def test_control_has_required_fields(self, mapper):
        controls = mapper.get_controls("CS-IAM-001")
        for c in controls:
            assert "framework"   in c
            assert "control_id"  in c
            assert "description" in c
            assert "requirement" in c

    def test_control_descriptions_not_empty(self, mapper):
        """Expert requirement — every control must have real descriptions."""
        for rule_id in CONTROLS:
            controls = mapper.get_controls(rule_id)
            for c in controls:
                assert len(c["description"]) > 10, (
                    f"Rule {rule_id} control {c['control_id']} "
                    f"has empty description"
                )
                assert len(c["requirement"]) > 10, (
                    f"Rule {rule_id} control {c['control_id']} "
                    f"has empty requirement"
                )

    def test_all_rules_have_all_four_frameworks(self, mapper):
        """Every rule should map to CIS, NIST, SOC2, and PCI."""
        for rule_id in CONTROLS:
            frameworks = mapper.get_frameworks_for_rule(rule_id)
            assert "CIS"      in frameworks, f"{rule_id} missing CIS"
            assert "NIST_CSF" in frameworks, f"{rule_id} missing NIST_CSF"
            assert "SOC2"     in frameworks, f"{rule_id} missing SOC2"
            assert "PCI_DSS"  in frameworks, f"{rule_id} missing PCI_DSS"

    def test_get_frameworks_for_rule(self, mapper):
        frameworks = mapper.get_frameworks_for_rule("CS-IAM-001")
        assert len(frameworks) > 0
        assert all(isinstance(f, str) for f in frameworks)


# ── Posture summary ───────────────────────────────────────────────────────────

class TestPostureSummary:

    def test_posture_returns_all_frameworks(self, mapper, open_findings):
        summary = mapper.posture_summary(open_findings)
        assert "CIS"      in summary
        assert "NIST_CSF" in summary
        assert "SOC2"     in summary
        assert "PCI_DSS"  in summary

    def test_posture_summary_fields(self, mapper, open_findings):
        summary = mapper.posture_summary(open_findings)
        for fw, data in summary.items():
            assert "total"            in data
            assert "failing"          in data
            assert "passing"          in data
            assert "pass_pct"         in data
            assert "failing_controls" in data

    def test_passing_plus_failing_equals_total(self, mapper, open_findings):
        summary = mapper.posture_summary(open_findings)
        for fw, data in summary.items():
            assert data["passing"] + data["failing"] == data["total"], (
                f"{fw}: passing({data['passing']}) + "
                f"failing({data['failing']}) != total({data['total']})"
            )

    def test_pass_pct_between_0_and_100(self, mapper, open_findings):
        summary = mapper.posture_summary(open_findings)
        for fw, data in summary.items():
            assert 0 <= data["pass_pct"] <= 100, (
                f"{fw} pass_pct out of range: {data['pass_pct']}"
            )

    def test_no_findings_gives_100_pct(self, mapper):
        summary = mapper.posture_summary([])
        for fw, data in summary.items():
            assert data["pass_pct"] == 100.0
            assert data["failing"]  == 0

    def test_remediated_findings_not_counted(self, mapper, mixed_findings):
        """Only OPEN findings should reduce compliance score."""
        summary_mixed = mapper.posture_summary(mixed_findings)
        summary_open  = mapper.posture_summary([
            {"rule_id": "CS-IAM-001", "status": "OPEN"}
        ])
        # Both should show same failure since only CS-IAM-001 is OPEN
        assert (
            summary_mixed["CIS"]["failing_controls"] ==
            summary_open["CIS"]["failing_controls"]
        )

    def test_failing_controls_are_sorted(self, mapper, open_findings):
        summary = mapper.posture_summary(open_findings)
        for fw, data in summary.items():
            controls = data["failing_controls"]
            assert controls == sorted(controls), (
                f"{fw} failing controls are not sorted"
            )

    def test_framework_totals_are_positive(self):
        for fw, total in FRAMEWORK_TOTALS.items():
            assert total > 0, f"{fw} total is not positive"

    def test_open_findings_reduce_score(self, mapper):
        no_findings   = mapper.posture_summary([])
        with_findings = mapper.posture_summary([
            {"rule_id": "CS-IAM-001", "status": "OPEN"},
            {"rule_id": "CS-S3-001",  "status": "OPEN"},
        ])
        for fw in ["CIS", "NIST_CSF", "SOC2", "PCI_DSS"]:
            assert (
                with_findings[fw]["pass_pct"] <=
                no_findings[fw]["pass_pct"]
            )