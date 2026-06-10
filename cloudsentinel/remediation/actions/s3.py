"""
cloudsentinel.remediation.actions.s3
======================================
Automated remediation actions for S3 findings.

Actions implemented
-------------------
CS-S3-001  Enable S3 Block Public Access on bucket
CS-S3-003  Enable S3 access logging to dedicated logging bucket
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .iam import RemediationResult

log = logging.getLogger(__name__)


class S3RemediationActions:
    """Executes S3 remediation actions with before/after state capture."""

    def remediate_cs_s3_001(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-S3-001 — Enable S3 Block Public Access.

        Enables all four Block Public Access settings on the bucket.
        This is a safe, non-destructive operation — it blocks future
        public access without removing existing objects.

        Note: If the bucket hosts a static website, this will break it.
        The rule should be suppressed for intentional public buckets
        with a documented business justification.
        """
        bucket = resource_id
        s3     = session.client("s3")

        # Capture before state
        before = self._get_public_access_config(s3, bucket)

        try:
            s3.put_public_access_block(
                Bucket = bucket,
                PublicAccessBlockConfiguration = {
                    "BlockPublicAcls":       True,
                    "IgnorePublicAcls":      True,
                    "BlockPublicPolicy":     True,
                    "RestrictPublicBuckets": True,
                }
            )

            after = self._get_public_access_config(s3, bucket)
            log.info("Block Public Access enabled on bucket %s", bucket)

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enabled all four Block Public Access settings on "
                    f"bucket '{bucket}'. "
                    f"BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, "
                    f"RestrictPublicBuckets all set to true."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enable Block Public Access on %s: %s", bucket, e
            )
            return RemediationResult(
                success      = False,
                action_taken = (
                    f"Attempted to enable Block Public Access on {bucket}"
                ),
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    def remediate_cs_s3_003(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-S3-003 — Enable S3 access logging.

        Creates a dedicated logging bucket if it doesn't exist,
        then enables access logging on the target bucket.
        Logging bucket name: {bucket}-cloudsentinel-logs
        """
        bucket      = resource_id
        log_bucket  = f"{bucket}-cs-logs"
        s3          = session.client("s3")

        before = {"logging_enabled": False, "bucket": bucket}

        try:
            # Get bucket region
            location = s3.get_bucket_location(Bucket=bucket)
            region   = location.get("LocationConstraint") or "us-east-1"

            # Create logging bucket if it doesn't exist
            self._ensure_logging_bucket(s3, log_bucket, region)

            # Enable logging on target bucket
            s3.put_bucket_logging(
                Bucket = bucket,
                BucketLoggingStatus = {
                    "LoggingEnabled": {
                        "TargetBucket": log_bucket,
                        "TargetPrefix": f"{bucket}/",
                    }
                }
            )

            after = {
                "logging_enabled": True,
                "log_bucket":      log_bucket,
                "log_prefix":      f"{bucket}/",
            }
            log.info(
                "Access logging enabled on %s → %s", bucket, log_bucket
            )

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enabled access logging on bucket '{bucket}'. "
                    f"Logs are written to '{log_bucket}/{bucket}/'. "
                    f"Logging bucket created if it did not exist."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enable logging on %s: %s", bucket, e
            )
            return RemediationResult(
                success      = False,
                action_taken = f"Attempted to enable logging on {bucket}",
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_public_access_config(self, s3, bucket: str) -> dict:
        """Capture current Block Public Access configuration."""
        try:
            response = s3.get_public_access_block(Bucket=bucket)
            return response.get("PublicAccessBlockConfiguration", {})
        except Exception:
            return {"configured": False}

    def _ensure_logging_bucket(
        self, s3, log_bucket: str, region: str
    ) -> None:
        """Create logging bucket if it doesn't exist."""
        try:
            s3.head_bucket(Bucket=log_bucket)
            log.debug("Logging bucket %s already exists", log_bucket)
        except Exception:
            try:
                if region == "us-east-1":
                    s3.create_bucket(Bucket=log_bucket)
                else:
                    s3.create_bucket(
                        Bucket = log_bucket,
                        CreateBucketConfiguration = {
                            "LocationConstraint": region
                        }
                    )
                # Block public access on logging bucket
                s3.put_public_access_block(
                    Bucket = log_bucket,
                    PublicAccessBlockConfiguration = {
                        "BlockPublicAcls":       True,
                        "IgnorePublicAcls":      True,
                        "BlockPublicPolicy":     True,
                        "RestrictPublicBuckets": True,
                    }
                )
                log.info("Created logging bucket %s", log_bucket)
            except Exception as e:
                log.error(
                    "Failed to create logging bucket %s: %s", log_bucket, e
                )
                raise