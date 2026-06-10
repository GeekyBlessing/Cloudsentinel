"""
cloudsentinel.scanner.rules.aws_iam
=====================================
IAM security rules — CIS AWS Foundations Benchmark v1.5 Section 1

Rules implemented
-----------------
CS-IAM-001  Root account has active access keys
CS-IAM-002  MFA not enabled for IAM users with console access
CS-IAM-003  IAM policy grants wildcard (*) permissions
CS-IAM-004  Access keys not rotated in 90+ days
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from .base import SecurityRule

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class RootAccountAccessKeys(SecurityRule):
    """
    CS-IAM-001 — CIS 1.4
    Ensure no root account access keys exist.

    Why it matters
    --------------
    Root access keys bypass all SCPs, permission boundaries, and IAM
    policies. A single leaked root key grants complete, unrestricted
    account ownership. There is no legitimate use case for root access
    keys — all automation should use IAM roles.
    """
    rule_id      = "CS-IAM-001"
    title        = "Root account has active access keys"
    description  = (
        "The AWS root account has one or more active access keys. "
        "Root keys bypass all permission boundaries, SCPs, and IAM policies. "
        "If leaked, they grant unconditional full account access with no "
        "way to restrict or audit usage beyond key deletion."
    )
    severity     = "CRITICAL"
    service      = "IAM"
    cis_control  = "CIS 1.4"
    nist_control = "PR.AC-1"
    soc2_control = "CC6.2"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        iam = session.client("iam")

        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(self._finding(
                    resource_id  = f"arn:aws:iam::{account_id}:root",
                    resource_arn = f"arn:aws:iam::{account_id}:root",
                    extra={
                        "has_sensitive_data": True,
                        "detail": (
                            f"{summary['AccountAccessKeysPresent']} "
                            f"active root access key(s) found"
                        ),
                        "remediation_steps": [
                            "Sign in to the AWS Console as root.",
                            "Navigate to IAM → Security credentials (top-right menu).",
                            "Under 'Access keys' — delete ALL root access keys.",
                            "Verify no automation depends on root keys (none should).",
                            "Enable root account MFA if not already enabled.",
                        ],
                        "remediation_cli": (
                            "# Root keys cannot be deleted via CLI.\n"
                            "# Must use AWS Console as root user.\n\n"
                            "# Verify root key status:\n"
                            "aws iam get-account-summary \\\n"
                            "  --query "
                            "'SummaryMap.AccountAccessKeysPresent'"
                        ),
                    }
                ))
        except Exception as e:
            log.error("Failed to check root account keys: %s", e)

        return findings


class MFANotEnabled(SecurityRule):
    """
    CS-IAM-002 — CIS 1.10
    Ensure MFA is enabled for all IAM users with console access.

    Why it matters
    --------------
    IAM users with console access and no MFA are one stolen or
    brute-forced password away from full account access. This is one
    of the most commonly exploited misconfigurations in cloud breaches.
    Credential stuffing attacks against AWS console logins are automated
    and continuous.
    """
    rule_id      = "CS-IAM-002"
    title        = "IAM user with console access does not have MFA enabled"
    description  = (
        "An IAM user has console (password) access but no MFA device configured. "
        "Without MFA, a stolen or guessed password grants immediate console "
        "access. Credential stuffing, phishing, and brute-force attacks are "
        "all viable without MFA as a second factor."
    )
    severity     = "HIGH"
    service      = "IAM"
    cis_control  = "CIS 1.10"
    nist_control = "PR.AC-7"
    soc2_control = "CC6.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        iam = session.client("iam")

        try:
            paginator = iam.get_paginator("get_account_authorization_details")
            for page in paginator.paginate(Filter=["User"]):
                for user in page.get("UserDetailList", []):
                    username = user["UserName"]

                    # Check if user has console access (login profile)
                    try:
                        iam.get_login_profile(UserName=username)
                    except iam.exceptions.NoSuchEntityException:
                        continue   # No console access — skip

                    # Check MFA devices
                    mfa = iam.list_mfa_devices(UserName=username)
                    if not mfa.get("MFADevices"):
                        findings.append(self._finding(
                            resource_id  = username,
                            resource_arn = user["Arn"],
                            extra={
                                "detail": (
                                    f"User {username} has console access "
                                    f"but no MFA device configured"
                                ),
                                "remediation_steps": [
                                    f"Navigate to IAM → Users → {username} "
                                    f"→ Security credentials.",
                                    "Under MFA — click Assign MFA device.",
                                    "Choose Virtual MFA (Authenticator app) or Hardware MFA.",
                                    "Enforce MFA via IAM policy using "
                                    "aws:MultiFactorAuthPresent condition.",
                                    "Consider using an SCP to deny all actions "
                                    "without MFA across the organisation.",
                                ],
                                "remediation_cli": (
                                    f"# Check current MFA status\n"
                                    f"aws iam list-mfa-devices \\\n"
                                    f"  --user-name {username}\n\n"
                                    f"# Attach a policy requiring MFA\n"
                                    f"aws iam attach-user-policy \\\n"
                                    f"  --user-name {username} \\\n"
                                    f"  --policy-arn "
                                    f"arn:aws:iam::aws:policy/IAMUserMFAEnabled"
                                ),
                            }
                        ))
        except Exception as e:
            log.error("Failed to check MFA status: %s", e)

        return findings


class WildcardIAMPolicy(SecurityRule):
    """
    CS-IAM-003 — CIS 1.16
    Ensure IAM policies do not grant wildcard (*) permissions.

    Why it matters
    --------------
    Policies with Action:* enable privilege escalation via iam:CreatePolicyVersion,
    iam:AttachRolePolicy, or sts:AssumeRole. This is one of the most documented
    AWS privilege escalation paths (Rhino Security Labs). A compromised identity
    with wildcard permissions can escalate to full administrator in one API call.
    """
    rule_id      = "CS-IAM-003"
    title        = "IAM policy grants wildcard (*) action permissions"
    description  = (
        "A customer-managed IAM policy grants Action:* or Action:service:* "
        "permissions. Wildcard permissions enable privilege escalation by allowing "
        "the identity to call iam:CreatePolicyVersion, iam:AttachRolePolicy, "
        "or sts:AssumeRole to self-elevate to administrator."
    )
    severity     = "HIGH"
    service      = "IAM"
    cis_control  = "CIS 1.16"
    nist_control = "PR.AC-4"
    soc2_control = "CC6.3"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        import json as _json
        findings = []
        iam = session.client("iam")

        try:
            paginator = iam.get_paginator("list_policies")
            # Only check customer-managed policies (Scope=Local)
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    try:
                        version = iam.get_policy_version(
                            PolicyArn  = policy["Arn"],
                            VersionId  = policy["DefaultVersionId"],
                        )
                        doc   = version["PolicyVersion"]["Document"]
                        stmts = doc.get("Statement", [])
                        if isinstance(stmts, dict):
                            stmts = [stmts]

                        for stmt in stmts:
                            if stmt.get("Effect") != "Allow":
                                continue

                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]

                            # Flag wildcard actions
                            wildcards = [
                                a for a in actions
                                if a == "*" or a.endswith(":*")
                            ]
                            if wildcards:
                                findings.append(self._finding(
                                    resource_id  = policy["PolicyName"],
                                    resource_arn = policy["Arn"],
                                    extra={
                                        "detail": (
                                            f"Policy {policy['PolicyName']} "
                                            f"contains wildcard actions: "
                                            f"{', '.join(wildcards[:5])}"
                                        ),
                                        "remediation_steps": [
                                            "Identify all principals attached to this policy.",
                                            "Use IAM Access Analyzer to generate "
                                            "least-privilege replacement policies.",
                                            "Replace wildcard with explicit action list.",
                                            "Test in non-production before applying.",
                                            "Create a new policy version — do not delete "
                                            "the old one until the new one is verified.",
                                        ],
                                        "remediation_cli": (
                                            f"# View current policy document\n"
                                            f"aws iam get-policy-version \\\n"
                                            f"  --policy-arn {policy['Arn']} \\\n"
                                            f"  --version-id "
                                            f"{policy['DefaultVersionId']}\n\n"
                                            f"# Generate least-privilege policy\n"
                                            f"aws accessanalyzer "
                                            f"generate-policy --filter '{{}}'"
                                        ),
                                    }
                                ))
                                break  # One finding per policy is enough

                    except Exception as e:
                        log.warning(
                            "Could not check policy %s: %s",
                            policy.get("PolicyName"), e
                        )

        except Exception as e:
            log.error("Failed to list IAM policies: %s", e)

        return findings


class AccessKeyNotRotated(SecurityRule):
    """
    CS-IAM-004 — CIS 1.14
    Ensure access keys are rotated every 90 days or less.

    Why it matters
    --------------
    Long-lived access keys dramatically increase the exploitation window.
    Keys leaked in a git commit 6 months ago remain valid if never rotated.
    Historical secret scanning (TruffleHog, GitLeaks, GitHub secret scanning)
    specifically targets stale, unrotated credentials in commit history.
    """
    rule_id      = "CS-IAM-004"
    title        = "IAM access key has not been rotated in 90+ days"
    description  = (
        "An IAM user access key has not been rotated in over 90 days. "
        "Long-lived keys increase the window of opportunity for credential "
        "theft. Keys leaked in source code, logs, or config files remain "
        "valid indefinitely unless explicitly rotated or deleted."
    )
    severity     = "MEDIUM"
    service      = "IAM"
    cis_control  = "CIS 1.14"
    nist_control = "PR.AC-1"
    soc2_control = "CC6.1"

    ROTATION_DAYS = 90

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        iam = session.client("iam")
        now = datetime.now(timezone.utc)

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    try:
                        keys = iam.list_access_keys(
                            UserName=username
                        )["AccessKeyMetadata"]

                        for key in keys:
                            if key["Status"] != "Active":
                                continue

                            created = key["CreateDate"]
                            age_days = (now - created).days

                            if age_days > self.ROTATION_DAYS:
                                findings.append(self._finding(
                                    resource_id  = key["AccessKeyId"],
                                    resource_arn = user["Arn"],
                                    extra={
                                        "detail": (
                                            f"Key {key['AccessKeyId']} for user "
                                            f"{username} is {age_days} days old "
                                            f"(limit: {self.ROTATION_DAYS} days)"
                                        ),
                                        "remediation_steps": [
                                            f"Create a new access key for {username}.",
                                            "Update all applications/CI using the old key.",
                                            "Verify the new key works in all systems.",
                                            f"Deactivate old key {key['AccessKeyId']}.",
                                            "Monitor for failures for 24-48 hours.",
                                            "Delete the deactivated key.",
                                        ],
                                        "remediation_cli": (
                                            f"# Create new key\n"
                                            f"aws iam create-access-key \\\n"
                                            f"  --user-name {username}\n\n"
                                            f"# Deactivate old key after updating systems\n"
                                            f"aws iam update-access-key \\\n"
                                            f"  --user-name {username} \\\n"
                                            f"  --access-key-id "
                                            f"{key['AccessKeyId']} \\\n"
                                            f"  --status Inactive\n\n"
                                            f"# Delete after verification\n"
                                            f"aws iam delete-access-key \\\n"
                                            f"  --user-name {username} \\\n"
                                            f"  --access-key-id "
                                            f"{key['AccessKeyId']}"
                                        ),
                                    }
                                ))
                    except Exception as e:
                        log.warning(
                            "Could not check keys for user %s: %s",
                            username, e
                        )

        except Exception as e:
            log.error("Failed to list IAM users for key rotation check: %s", e)

        return findings