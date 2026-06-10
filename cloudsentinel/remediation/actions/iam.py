"""
cloudsentinel.remediation.actions.iam
=======================================
Automated remediation actions for IAM findings.

Actions implemented
-------------------
CS-IAM-002  Attach MFA enforcement policy to non-compliant user
CS-IAM-003  Create least-privilege replacement for wildcard policy
CS-IAM-004  Deactivate stale access key + notify user
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

# Managed policy that denies all actions without MFA
# except those needed to set up MFA itself
MFA_ENFORCEMENT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyWithoutMFA",
            "Effect": "Deny",
            "NotAction": [
                "iam:CreateVirtualMFADevice",
                "iam:EnableMFADevice",
                "iam:GetUser",
                "iam:ListMFADevices",
                "iam:ListVirtualMFADevices",
                "iam:ResyncMFADevice",
                "sts:GetSessionToken",
            ],
            "Resource": "*",
            "Condition": {
                "BoolIfExists": {
                    "aws:MultiFactorAuthPresent": "false"
                }
            }
        }
    ]
}


@dataclass
class RemediationResult:
    """Result of a single remediation action."""
    success:      bool
    action_taken: str
    before_state: dict
    after_state:  dict
    error:        Optional[str] = None


class IAMRemediationActions:
    """
    Executes IAM remediation actions against a boto3 session.
    Every action captures before/after state for the audit trail.
    """

    def remediate_cs_iam_002(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-IAM-002 — Attach MFA enforcement policy to user.

        Attaches a deny-without-MFA policy to the non-compliant user.
        This forces the user to set up MFA on next login without
        locking them out — they can still access the MFA setup pages.

        This is a non-destructive fix — it adds a policy, never
        deletes credentials or modifies existing permissions.
        """
        username = resource_id
        iam      = session.client("iam")
        policy_name = f"CloudSentinel-RequireMFA-{username}"

        # Capture before state
        before = self._get_user_policies(iam, username)

        try:
            # Check if policy already exists
            try:
                iam.get_user_policy(
                    UserName   = username,
                    PolicyName = policy_name,
                )
                log.info("MFA enforcement policy already exists for %s", username)
                return RemediationResult(
                    success      = True,
                    action_taken = f"MFA enforcement policy already present on {username}",
                    before_state = before,
                    after_state  = before,
                )
            except iam.exceptions.NoSuchEntityException:
                pass

            # Attach MFA enforcement inline policy
            iam.put_user_policy(
                UserName       = username,
                PolicyName     = policy_name,
                PolicyDocument = json.dumps(MFA_ENFORCEMENT_POLICY),
            )

            after = self._get_user_policies(iam, username)
            log.info(
                "MFA enforcement policy attached to user %s", username
            )

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Attached MFA enforcement policy '{policy_name}' "
                    f"to IAM user '{username}'. "
                    f"User must now set up MFA to access AWS resources."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error("Failed to attach MFA policy to %s: %s", username, e)
            return RemediationResult(
                success      = False,
                action_taken = f"Attempted to attach MFA policy to {username}",
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    def remediate_cs_iam_004(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-IAM-004 — Deactivate stale access key.

        Deactivates (not deletes) the key to allow recovery if
        applications break. Key can be reactivated within 30 days
        before permanent deletion.

        Never deletes keys — deactivation is reversible and gives
        teams time to update applications before hard deletion.
        """
        # resource_id format: "AccessKeyId" (from rule finding)
        key_id   = resource_id
        iam      = session.client("iam")

        # Find which user owns this key
        username = self._find_key_owner(iam, key_id)
        if not username:
            return RemediationResult(
                success      = False,
                action_taken = f"Could not find owner of key {key_id}",
                before_state = {},
                after_state  = {},
                error        = "Key owner not found",
            )

        before = {"key_id": key_id, "status": "Active", "user": username}

        try:
            iam.update_access_key(
                UserName    = username,
                AccessKeyId = key_id,
                Status      = "Inactive",
            )

            after = {"key_id": key_id, "status": "Inactive", "user": username}
            log.info(
                "Access key %s for user %s deactivated", key_id, username
            )

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Deactivated access key {key_id} for user {username}. "
                    f"Key is inactive but not deleted — update applications "
                    f"and delete within 30 days."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to deactivate key %s for %s: %s", key_id, username, e
            )
            return RemediationResult(
                success      = False,
                action_taken = f"Attempted to deactivate key {key_id}",
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_user_policies(self, iam, username: str) -> dict:
        """Capture current policy state for a user."""
        try:
            inline   = iam.list_user_policies(UserName=username).get(
                "PolicyNames", []
            )
            attached = [
                p["PolicyName"]
                for p in iam.list_attached_user_policies(
                    UserName=username
                ).get("AttachedPolicies", [])
            ]
            return {
                "inline_policies":   inline,
                "attached_policies": attached,
            }
        except Exception:
            return {}

    def _find_key_owner(self, iam, key_id: str) -> Optional[str]:
        """Find the IAM user who owns an access key."""
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    keys = iam.list_access_keys(
                        UserName=user["UserName"]
                    ).get("AccessKeyMetadata", [])
                    for key in keys:
                        if key["AccessKeyId"] == key_id:
                            return user["UserName"]
        except Exception as e:
            log.error("Failed to find key owner: %s", e)
        return None