"""
tests/test_rules.py
====================
Tests for all AWS security rules.
Uses mocked boto3 clients — no real AWS calls needed.
"""
import pytest
from unittest.mock import MagicMock, patch
from cloudsentinel.scanner.rules.aws_iam import (
    RootAccountAccessKeys, MFANotEnabled,
    WildcardIAMPolicy, AccessKeyNotRotated,
)
from cloudsentinel.scanner.rules.aws_s3 import (
    S3BucketPublicAccess, S3EncryptionDisabled, S3LoggingDisabled,
)
from cloudsentinel.scanner.rules.aws_ec2 import (
    UnrestrictedSSH, UnrestrictedRDP, IMDSv1Enabled,
)
from cloudsentinel.scanner.rules.aws_logging import (
    CloudTrailDisabled, CloudTrailValidationDisabled, VPCFlowLogsDisabled,
)
from cloudsentinel.scanner.rules.aws_encryption import (
    EBSEncryptionDisabled, RDSEncryptionDisabled,
)
from datetime import datetime, timezone, timedelta


ACCOUNT_ID = "123456789012"
REGION     = "eu-north-1"


def make_session(service_responses: dict) -> MagicMock:
    """
    Build a mock boto3 session that returns configured responses
    for specific service clients.
    """
    session = MagicMock()
    clients = {}

    def get_client(service, **kwargs):
        if service not in clients:
            clients[service] = MagicMock()
            # Apply configured responses
            for method, response in service_responses.get(service, {}).items():
                if isinstance(response, Exception):
                    getattr(clients[service], method).side_effect = response
                else:
                    getattr(clients[service], method).return_value = response
        return clients[service]

    session.client.side_effect = get_client
    session.region_name = REGION
    return session


# ── IAM Rules ─────────────────────────────────────────────────────────────────

class TestRootAccountAccessKeys:

    def test_finds_root_keys_present(self):
        session = make_session({"iam": {
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 1}
            }
        }})
        rule     = RootAccountAccessKeys()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["rule_id"]  == "CS-IAM-001"

    def test_no_finding_when_no_root_keys(self):
        session = make_session({"iam": {
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 0}
            }
        }})
        rule     = RootAccountAccessKeys()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 0

    def test_finding_has_remediation_steps(self):
        session = make_session({"iam": {
            "get_account_summary": {
                "SummaryMap": {"AccountAccessKeysPresent": 2}
            }
        }})
        rule     = RootAccountAccessKeys()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings[0]["remediation_steps"]) > 0

    def test_handles_api_error_gracefully(self):
        session = make_session({"iam": {
            "get_account_summary": Exception("Access denied")
        }})
        rule     = RootAccountAccessKeys()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert findings == []


class TestMFANotEnabled:

    def _make_mfa_session(self, has_mfa: bool) -> MagicMock:
        session  = MagicMock()
        iam      = MagicMock()
        session.client.return_value = iam

        # Paginator returns one user
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "UserDetailList": [{
                "UserName": "test-user",
                "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/test-user",
            }]
        }]
        iam.get_paginator.return_value = paginator

        # User has console access
        iam.get_login_profile.return_value = {"LoginProfile": {}}

        # MFA status
        iam.list_mfa_devices.return_value = {
            "MFADevices": [{"SerialNumber": "arn:mfa:device"}] if has_mfa else []
        }

        # Exception class for NoSuchEntityException
        iam.exceptions.NoSuchEntityException = type(
            "NoSuchEntityException", (Exception,), {}
        )
        return session

    def test_finds_user_without_mfa(self):
        session  = self._make_mfa_session(has_mfa=False)
        rule     = MFANotEnabled()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CS-IAM-002"

    def test_no_finding_when_mfa_enabled(self):
        session  = self._make_mfa_session(has_mfa=True)
        rule     = MFANotEnabled()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 0


class TestAccessKeyNotRotated:

    def test_finds_stale_key(self):
        session  = MagicMock()
        iam      = MagicMock()
        session.client.return_value = iam

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Users": [{"UserName": "old-user",
                       "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/old-user"}]
        }]
        iam.get_paginator.return_value = paginator

        stale_date = datetime.now(timezone.utc) - timedelta(days=100)
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status":      "Active",
                "CreateDate":  stale_date,
            }]
        }

        rule     = AccessKeyNotRotated()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 1
        assert "100 days" in findings[0]["detail"]

    def test_no_finding_for_fresh_key(self):
        session  = MagicMock()
        iam      = MagicMock()
        session.client.return_value = iam

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Users": [{"UserName": "new-user",
                       "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/new-user"}]
        }]
        iam.get_paginator.return_value = paginator

        fresh_date = datetime.now(timezone.utc) - timedelta(days=30)
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status":      "Active",
                "CreateDate":  fresh_date,
            }]
        }

        rule     = AccessKeyNotRotated()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 0

    def test_inactive_keys_ignored(self):
        session  = MagicMock()
        iam      = MagicMock()
        session.client.return_value = iam

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Users": [{"UserName": "user",
                       "Arn": f"arn:aws:iam::{ACCOUNT_ID}:user/user"}]
        }]
        iam.get_paginator.return_value = paginator

        stale_date = datetime.now(timezone.utc) - timedelta(days=200)
        iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{
                "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                "Status":      "Inactive",   # inactive — should be ignored
                "CreateDate":  stale_date,
            }]
        }

        rule     = AccessKeyNotRotated()
        findings = rule.check(session, ACCOUNT_ID, "global")
        assert len(findings) == 0


# ── S3 Rules ──────────────────────────────────────────────────────────────────

class TestS3BucketPublicAccess:

    def test_finds_public_bucket(self):
        session = MagicMock()
        s3      = MagicMock()
        session.client.return_value = s3

        s3.list_buckets.return_value = {
            "Buckets": [{"Name": "my-public-bucket"}]
        }
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls":       False,
                "IgnorePublicAcls":      False,
                "BlockPublicPolicy":     False,
                "RestrictPublicBuckets": False,
            }
        }
        s3.exceptions.NoSuchPublicAccessBlockConfiguration = type(
            "NoSuchPublicAccessBlockConfiguration", (Exception,), {}
        )

        rule     = S3BucketPublicAccess()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 1
        assert findings[0]["is_public"] is True

    def test_no_finding_when_fully_blocked(self):
        session = MagicMock()
        s3      = MagicMock()
        session.client.return_value = s3

        s3.list_buckets.return_value = {
            "Buckets": [{"Name": "secure-bucket"}]
        }
        s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls":       True,
                "IgnorePublicAcls":      True,
                "BlockPublicPolicy":     True,
                "RestrictPublicBuckets": True,
            }
        }
        s3.exceptions.NoSuchPublicAccessBlockConfiguration = type(
            "NoSuchPublicAccessBlockConfiguration", (Exception,), {}
        )

        rule     = S3BucketPublicAccess()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0

    def test_infers_sensitive_from_name(self):
        rule = S3BucketPublicAccess()
        assert rule._infer_sensitive("prod-data-lake")    is True
        assert rule._infer_sensitive("my-random-bucket")  is False
        assert rule._infer_sensitive("backup-2024")        is True


# ── EC2 Rules ─────────────────────────────────────────────────────────────────

class TestUnrestrictedSSH:

    def test_finds_open_ssh(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2
        session.region_name = REGION

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "SecurityGroups": [{
                "GroupId":   "sg-12345",
                "GroupName": "wide-open",
                "OwnerId":   ACCOUNT_ID,
                "IpPermissions": [{
                    "FromPort":   22,
                    "ToPort":     22,
                    "IpProtocol": "tcp",
                    "IpRanges":   [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                }]
            }]
        }]
        ec2.get_paginator.return_value = paginator

        rule     = UnrestrictedSSH()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 1
        assert findings[0]["is_public"] is True

    def test_no_finding_for_restricted_ssh(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2
        session.region_name = REGION

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "SecurityGroups": [{
                "GroupId":   "sg-secure",
                "GroupName": "restricted",
                "OwnerId":   ACCOUNT_ID,
                "IpPermissions": [{
                    "FromPort":   22,
                    "ToPort":     22,
                    "IpProtocol": "tcp",
                    "IpRanges":   [{"CidrIp": "10.0.0.0/8"}],
                    "Ipv6Ranges": [],
                }]
            }]
        }]
        ec2.get_paginator.return_value = paginator

        rule     = UnrestrictedSSH()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0


class TestIMDSv1Enabled:

    def test_finds_imdsv1_instance(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{
                "Instances": [{
                    "InstanceId":      "i-1234567890abcdef0",
                    "State":           {"Name": "running"},
                    "MetadataOptions": {"HttpTokens": "optional"},
                }]
            }]
        }]
        ec2.get_paginator.return_value = paginator

        rule     = IMDSv1Enabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 1
        assert "IMDSv1" in findings[0]["detail"] or "optional" in findings[0]["detail"]

    def test_no_finding_when_imdsv2_enforced(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{
                "Instances": [{
                    "InstanceId":      "i-secure",
                    "State":           {"Name": "running"},
                    "MetadataOptions": {"HttpTokens": "required"},
                }]
            }]
        }]
        ec2.get_paginator.return_value = paginator

        rule     = IMDSv1Enabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0

    def test_stopped_instances_ignored(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "Reservations": [{
                "Instances": [{
                    "InstanceId":      "i-stopped",
                    "State":           {"Name": "stopped"},
                    "MetadataOptions": {"HttpTokens": "optional"},
                }]
            }]
        }]
        ec2.get_paginator.return_value = paginator

        rule     = IMDSv1Enabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0


# ── Logging Rules ─────────────────────────────────────────────────────────────

class TestCloudTrailDisabled:

    def test_finds_no_active_trail(self):
        session = MagicMock()
        ct      = MagicMock()
        session.client.return_value = ct

        ct.describe_trails.return_value = {"trailList": []}

        rule     = CloudTrailDisabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "CS-LOG-001"

    def test_no_finding_when_trail_active(self):
        session = MagicMock()
        ct      = MagicMock()
        session.client.return_value = ct

        ct.describe_trails.return_value = {"trailList": [{
            "TrailARN": f"arn:aws:cloudtrail:{REGION}:{ACCOUNT_ID}:trail/main",
            "Name":     "main",
        }]}
        ct.get_trail_status.return_value = {"IsLogging": True}

        rule     = CloudTrailDisabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0


class TestVPCFlowLogsDisabled:

    def test_finds_vpc_without_flow_logs(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2

        ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-12345", "Tags": []}]
        }
        ec2.describe_flow_logs.return_value = {"FlowLogs": []}

        rule     = VPCFlowLogsDisabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 1

    def test_no_finding_when_flow_logs_active(self):
        session = MagicMock()
        ec2     = MagicMock()
        session.client.return_value = ec2

        ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-12345", "Tags": []}]
        }
        ec2.describe_flow_logs.return_value = {
            "FlowLogs": [{
                "ResourceId":    "vpc-12345",
                "FlowLogStatus": "ACTIVE",
            }]
        }

        rule     = VPCFlowLogsDisabled()
        findings = rule.check(session, ACCOUNT_ID, REGION)
        assert len(findings) == 0


# ── Rule base class ───────────────────────────────────────────────────────────

class TestRuleBase:

    def test_all_rules_have_required_attributes(self):
        from cloudsentinel.scanner.engine import ALL_RULES
        for rule in ALL_RULES:
            assert hasattr(rule, "rule_id"),     f"{rule} missing rule_id"
            assert hasattr(rule, "title"),       f"{rule} missing title"
            assert hasattr(rule, "description"), f"{rule} missing description"
            assert hasattr(rule, "severity"),    f"{rule} missing severity"
            assert hasattr(rule, "service"),     f"{rule} missing service"

    def test_all_severities_are_valid(self):
        from cloudsentinel.scanner.engine import ALL_RULES
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        for rule in ALL_RULES:
            assert rule.severity in valid, (
                f"{rule.rule_id} has invalid severity: {rule.severity}"
            )

    def test_all_rule_ids_unique(self):
        from cloudsentinel.scanner.engine import ALL_RULES
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs detected"

    def test_rule_repr(self):
        rule = RootAccountAccessKeys()
        assert "CS-IAM-001" in repr(rule)
        assert "CRITICAL"   in repr(rule)