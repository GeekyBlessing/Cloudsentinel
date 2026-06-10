"""
cloudsentinel.remediation.actions.encryption
=============================================
Automated remediation actions for encryption findings.

Actions implemented
-------------------
CS-ENC-001  Enable EBS encryption by default at account level
"""
from __future__ import annotations

import logging

from .iam import RemediationResult

log = logging.getLogger(__name__)


class EncryptionRemediationActions:
    """Executes encryption remediation actions."""

    def remediate_cs_enc_001(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-ENC-001 — Enable EBS encryption by default.

        Enables account-level EBS encryption by default for the region.
        This affects all NEW volumes created after this point —
        existing unencrypted volumes are not automatically re-encrypted.

        To re-encrypt existing volumes: snapshot → encrypted copy → restore.
        """
        ec2    = session.client("ec2")
        region = session.region_name or "eu-north-1"

        # Capture before state
        before = self._get_ebs_encryption_default(ec2)

        try:
            ec2.enable_ebs_encryption_by_default()
            after = self._get_ebs_encryption_default(ec2)

            log.info(
                "EBS encryption by default enabled in %s", region
            )

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enabled EBS encryption by default in region {region}. "
                    f"All new EBS volumes will now be encrypted automatically. "
                    f"Existing unencrypted volumes require manual re-encryption "
                    f"via snapshot copy."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enable EBS encryption by default: %s", e
            )
            return RemediationResult(
                success      = False,
                action_taken = "Attempted to enable EBS encryption by default",
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    def _get_ebs_encryption_default(self, ec2) -> dict:
        """Capture current EBS encryption default setting."""
        try:
            response = ec2.get_ebs_encryption_by_default()
            return {
                "ebs_encryption_by_default": response.get(
                    "EbsEncryptionByDefault", False
                )
            }
        except Exception:
            return {}