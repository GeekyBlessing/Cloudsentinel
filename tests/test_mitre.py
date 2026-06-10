"""
tests/test_mitre.py
====================
Tests for the MITRE ATT&CK enrichment engine.
Covers technique mappings, kill chain construction, and narratives.
"""
import pytest
from cloudsentinel.enrichment.mitre import (
    MitreEnrichmentEngine,
    RULE_TTP_MAP,
    TACTIC_ORDER,
    TACTIC_NAMES,
)


@pytest.fixture
def engine():
    return MitreEnrichmentEngine()


@pytest.fixture
def open_findings():
    return [
        {
            "id": "F-001", "title": "Root keys active",
            "severity": "CRITICAL", "status": "OPEN",
            "mitre": [
                {
                    "tactic_id": "TA0001", "tactic_name": "Initial Access",
                    "technique_id": "T1078", "technique_name": "Valid Accounts",
                    "relevance": "test",
                },
                {
                    "tactic_id": "TA0006", "tactic_name": "Credential Access",
                    "technique_id": "T1552", "technique_name": "Unsecured Credentials",
                    "relevance": "test",
                },
            ],
        },
        {
            "id": "F-002", "title": "S3 bucket public",
            "severity": "CRITICAL", "status": "OPEN",
            "mitre": [
                {
                    "tactic_id": "TA0009", "tactic_name": "Collection",
                    "technique_id": "T1530", "technique_name": "Data from Cloud Storage",
                    "relevance": "test",
                },
                {
                    "tactic_id": "TA0010", "tactic_name": "Exfiltration",
                    "technique_id": "T1537", "technique_name": "Transfer to Cloud Account",
                    "relevance": "test",
                },
            ],
        },
        {
            "id": "F-003", "title": "Remediated finding",
            "severity": "HIGH", "status": "REMEDIATED",
            "mitre": [
                {
                    "tactic_id": "TA0040", "tactic_name": "Impact",
                    "technique_id": "T1485", "technique_name": "Data Destruction",
                    "relevance": "test",
                },
            ],
        },
    ]


# ── Enrichment ────────────────────────────────────────────────────────────────

class TestEnrichment:

    def test_known_rule_returns_mappings(self, engine):
        mappings = engine.enrich("CS-IAM-001")
        assert len(mappings) > 0

    def test_unknown_rule_returns_empty(self, engine):
        assert engine.enrich("CS-UNKNOWN-999") == []

    def test_mapping_has_required_fields(self, engine):
        mappings = engine.enrich("CS-IAM-001")
        for m in mappings:
            assert "tactic_id"      in m
            assert "tactic_name"    in m
            assert "technique_id"   in m
            assert "technique_name" in m
            assert "kill_chain_phase" in m
            assert "relevance"      in m

    def test_tactic_ids_start_with_TA(self, engine):
        mappings = engine.enrich("CS-IAM-001")
        for m in mappings:
            assert m["tactic_id"].startswith("TA")

    def test_technique_ids_start_with_T(self, engine):
        mappings = engine.enrich("CS-IAM-001")
        for m in mappings:
            assert m["technique_id"].startswith("T")

    def test_relevance_is_not_empty(self, engine):
        """Expert-level requirement — every mapping explains WHY."""
        for rule_id in RULE_TTP_MAP:
            mappings = engine.enrich(rule_id)
            for m in mappings:
                assert len(m["relevance"]) > 20, (
                    f"Rule {rule_id} technique {m['technique_id']} "
                    f"has weak relevance: '{m['relevance']}'"
                )

    def test_all_rules_have_mappings(self, engine):
        """Every registered rule must have at least one MITRE mapping."""
        from cloudsentinel.scanner.engine import ALL_RULES
        for rule in ALL_RULES:
            mappings = engine.enrich(rule.rule_id)
            assert len(mappings) > 0, (
                f"Rule {rule.rule_id} has no MITRE mappings"
            )

    def test_get_tactics_for_rule(self, engine):
        tactics = engine.get_tactics_for_rule("CS-IAM-001")
        assert len(tactics) > 0
        assert all(t.startswith("TA") for t in tactics)

    def test_get_techniques_for_rule(self, engine):
        techniques = engine.get_techniques_for_rule("CS-S3-001")
        assert "T1530" in techniques


# ── Kill chain ────────────────────────────────────────────────────────────────

class TestKillChain:

    def test_kill_chain_from_findings(self, engine, open_findings):
        chain = engine.build_kill_chain(open_findings)
        assert chain.total_tactics > 0

    def test_remediated_findings_excluded(self, engine, open_findings):
        """REMEDIATED findings must not contribute to kill chain."""
        chain_with    = engine.build_kill_chain(open_findings)
        chain_without = engine.build_kill_chain(
            [f for f in open_findings if f["status"] == "OPEN"]
        )
        # Impact tactic (TA0040) only in remediated finding
        impact_in_with    = any(s.tactic_id == "TA0040" for s in chain_with.steps)
        impact_in_without = any(s.tactic_id == "TA0040" for s in chain_without.steps)
        assert not impact_in_with
        assert not impact_in_without

    def test_steps_ordered_by_kill_chain(self, engine, open_findings):
        chain = engine.build_kill_chain(open_findings)
        orders = [s.order for s in chain.steps]
        assert orders == sorted(orders)

    def test_empty_findings_returns_empty_chain(self, engine):
        chain = engine.build_kill_chain([])
        assert chain.total_tactics == 0
        assert chain.highest_impact == "None"

    def test_narrative_is_meaningful(self, engine, open_findings):
        chain = engine.build_kill_chain(open_findings)
        assert len(chain.narrative) > 50
        assert "ATT&CK" in chain.narrative or "tactic" in chain.narrative

    def test_highest_impact_is_furthest_tactic(self, engine, open_findings):
        chain = engine.build_kill_chain(open_findings)
        # Exfiltration (order 10) should be furthest
        assert chain.highest_impact == "Exfiltration"

    def test_tactic_order_coverage(self):
        """All 11 core ATT&CK tactics must be in TACTIC_ORDER."""
        expected_tactics = {
            "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
            "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0040"
        }
        assert expected_tactics.issubset(set(TACTIC_ORDER.keys()))

    def test_tactic_names_match_order(self):
        """Every tactic in TACTIC_ORDER must have a name in TACTIC_NAMES."""
        for tactic_id in TACTIC_ORDER:
            assert tactic_id in TACTIC_NAMES, (
                f"{tactic_id} in TACTIC_ORDER but missing from TACTIC_NAMES"
            )