"""
tests/test_risk.py
==================
Tests for the risk scoring and blast radius engine.
Covers scoring formula, blast radius classification, and edge cases.
"""
import pytest
from cloudsentinel.enrichment.risk import (
    RiskScoringEngine,
    RiskResult,
    BASE_SEVERITY_SCORE,
    HIGH_IMPACT_TECHNIQUES,
    LATERAL_MOVEMENT_TECHNIQUES,
    DATA_EXFIL_TECHNIQUES,
    PRIVESC_TECHNIQUES,
)


@pytest.fixture
def engine():
    return RiskScoringEngine()


# ── Base scoring ──────────────────────────────────────────────────────────────

class TestBaseScoring:

    def test_critical_scores_highest(self, engine):
        r = engine.score("CRITICAL", [], "IAM")
        assert r.risk_score >= 9.0

    def test_info_scores_lowest(self, engine):
        r = engine.score("INFO", [], "IAM")
        assert r.risk_score <= 2.0

    def test_severity_ordering(self, engine):
        scores = {
            sev: engine.score(sev, [], "IAM").risk_score
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        }
        assert scores["CRITICAL"] > scores["HIGH"]
        assert scores["HIGH"]     > scores["MEDIUM"]
        assert scores["MEDIUM"]   > scores["LOW"]
        assert scores["LOW"]      > scores["INFO"]

    def test_score_never_exceeds_10(self, engine):
        r = engine.score(
            "CRITICAL",
            list(HIGH_IMPACT_TECHNIQUES),
            "IAM",
            is_public          = True,
            has_sensitive_data = True,
        )
        assert r.risk_score <= 10.0

    def test_score_never_below_zero(self, engine):
        r = engine.score("INFO", [], "EC2")
        assert r.risk_score >= 0.0

    def test_blast_score_never_exceeds_100(self, engine):
        r = engine.score(
            "CRITICAL",
            list(HIGH_IMPACT_TECHNIQUES |
                 LATERAL_MOVEMENT_TECHNIQUES |
                 DATA_EXFIL_TECHNIQUES |
                 PRIVESC_TECHNIQUES),
            "IAM",
            is_public          = True,
            has_sensitive_data = True,
        )
        assert r.blast_score <= 100.0

    def test_blast_score_never_below_zero(self, engine):
        r = engine.score("INFO", [], "EC2")
        assert r.blast_score >= 0.0


# ── TTP boost ─────────────────────────────────────────────────────────────────

class TestTTPBoost:

    def test_high_impact_techniques_boost_score(self, engine):
        base   = engine.score("HIGH", [],        "IAM").risk_score
        boosted = engine.score("HIGH", ["T1078"], "IAM").risk_score
        assert boosted > base

    def test_boost_capped_at_1_5(self, engine):
        """Many high-impact techniques should not push score above 10."""
        r = engine.score(
            "MEDIUM",
            list(HIGH_IMPACT_TECHNIQUES),  # all high-impact techniques
            "IAM",
        )
        assert r.risk_score <= 10.0

    def test_unknown_techniques_no_boost(self, engine):
        base    = engine.score("HIGH", [],             "IAM").risk_score
        unknown = engine.score("HIGH", ["T9999"], "IAM").risk_score
        assert base == unknown


# ── Exposure multiplier ───────────────────────────────────────────────────────

class TestExposureMultiplier:

    def test_public_increases_score(self, engine):
        private = engine.score("HIGH", ["T1078"], "EC2", is_public=False).risk_score
        public  = engine.score("HIGH", ["T1078"], "EC2", is_public=True).risk_score
        assert public > private

    def test_sensitive_data_increases_score(self, engine):
        normal    = engine.score("HIGH", [], "S3", has_sensitive_data=False).risk_score
        sensitive = engine.score("HIGH", [], "S3", has_sensitive_data=True).risk_score
        assert sensitive > normal

    def test_public_and_sensitive_highest(self, engine):
        base   = engine.score("HIGH", ["T1078"], "S3").risk_score
        public = engine.score("HIGH", ["T1078"], "S3", is_public=True).risk_score
        both   = engine.score(
            "HIGH", ["T1078"], "S3",
            is_public=True, has_sensitive_data=True
        ).risk_score
        assert both >= public >= base

    def test_sensitive_inferred_from_tags(self, engine):
        normal = engine.score("MEDIUM", [], "S3").risk_score
        tagged = engine.score(
            "MEDIUM", [], "S3",
            resource_tags={"DataClassification": "PII"}
        ).risk_score
        assert tagged > normal


# ── Blast radius classification ───────────────────────────────────────────────

class TestBlastRadius:

    def test_lateral_movement_detected(self, engine):
        r = engine.score("HIGH", ["T1021"], "EC2")
        assert r.lateral_movement is True

    def test_no_lateral_movement(self, engine):
        r = engine.score("HIGH", ["T1530"], "S3")
        assert r.lateral_movement is False

    def test_data_exfil_detected(self, engine):
        r = engine.score("HIGH", ["T1530"], "S3")
        assert r.data_exfil_risk is True

    def test_no_data_exfil(self, engine):
        r = engine.score("HIGH", ["T1021"], "EC2")
        assert r.data_exfil_risk is False

    def test_privesc_detected(self, engine):
        r = engine.score("HIGH", ["T1548"], "IAM")
        assert r.privilege_esc_risk is True

    def test_no_privesc(self, engine):
        r = engine.score("LOW", ["T1070"], "CloudTrail")
        assert r.privilege_esc_risk is False

    def test_affected_services_includes_resource(self, engine):
        r = engine.score("HIGH", [], "RDS")
        assert "RDS" in r.affected_services

    def test_lateral_movement_adds_services(self, engine):
        r = engine.score("HIGH", ["T1021"], "EC2")
        assert "IAM" in r.affected_services
        assert "VPC" in r.affected_services

    def test_exfil_adds_s3_service(self, engine):
        r = engine.score("HIGH", ["T1530"], "S3")
        assert "S3" in r.affected_services


# ── Rationale ─────────────────────────────────────────────────────────────────

class TestRationale:

    def test_rationale_always_present(self, engine):
        r = engine.score("MEDIUM", [], "EC2")
        assert len(r.rationale) > 20

    def test_rationale_mentions_severity(self, engine):
        r = engine.score("CRITICAL", [], "IAM")
        assert "CRITICAL" in r.rationale

    def test_rationale_mentions_blast_radius(self, engine):
        r = engine.score("HIGH", [], "S3")
        assert "blast" in r.rationale.lower() or "Blast" in r.rationale

    def test_rationale_mentions_impact_flags(self, engine):
        r = engine.score("HIGH", ["T1548"], "IAM")
        assert "privilege" in r.rationale.lower()


# ── RiskResult bounds enforcement ─────────────────────────────────────────────

class TestRiskResultBounds:

    def test_risk_result_clamps_score(self):
        r = RiskResult(
            risk_score         = 15.0,   # over max
            blast_score        = 50.0,
            lateral_movement   = False,
            data_exfil_risk    = False,
            privilege_esc_risk = False,
        )
        assert r.risk_score == 10.0

    def test_risk_result_clamps_blast(self):
        r = RiskResult(
            risk_score         = 5.0,
            blast_score        = 150.0,  # over max
            lateral_movement   = False,
            data_exfil_risk    = False,
            privilege_esc_risk = False,
        )
        assert r.blast_score == 100.0

    def test_risk_result_clamps_negative(self):
        r = RiskResult(
            risk_score         = -5.0,   # below min
            blast_score        = -10.0,  # below min
            lateral_movement   = False,
            data_exfil_risk    = False,
            privilege_esc_risk = False,
        )
        assert r.risk_score  == 0.0
        assert r.blast_score == 0.0