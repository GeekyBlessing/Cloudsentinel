"""
cloudsentinel.scanner.rules.aws_encryption
============================================
Encryption at rest rules — CIS AWS Foundations Benchmark v1.5 Section 2

Rules implemented
-----------------
CS-ENC-001  EBS volume encryption disabled
CS-ENC-002  RDS instance encryption disabled
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import SecurityRule

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class EBSEncryptionDisabled(SecurityRule):
    """
    CS-ENC-001 — CIS 2.2.1
    Ensure EBS volume encryption is enabled by default.

    Why it matters
    --------------
    Unencrypted EBS snapshots can be shared with external AWS accounts.
    An attacker with ec2:ModifySnapshotAttribute can make a snapshot
    public or copy it to their own account — exfiltrating the full disk
    image including application secrets, database files, SSH keys, and
    any data written to disk by the operating system or applications.
    """
    rule_id      = "CS-ENC-001"
    title        = "EBS volume encryption is disabled"
    description  = (
        "This EBS volume is not encrypted at rest. Unencrypted EBS snapshots "
        "can be shared externally via ec2:ModifySnapshotAttribute, exposing "
        "the full disk image including secrets, credentials, and application "
        "data to anyone with access to the snapshot."
    )
    severity     = "MEDIUM"
    service      = "EBS"
    cis_control  = "CIS 2.2.1"
    nist_control = "PR.DS-1"
    soc2_control = "CC9.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        ec2 = session.client("ec2")

        try:
            # Check account-level EBS encryption default first
            default_enc = ec2.get_ebs_encryption_by_default()
            account_default_enabled = default_enc.get(
                "EbsEncryptionByDefault", False
            )

            if not account_default_enabled:
                # Flag the account-level setting as a finding
                findings.append(self._finding(
                    resource_id  = f"ebs-default:{region}",
                    resource_arn = (
                        f"arn:aws:ec2:{region}:{account_id}:"
                        f"ebs-default-encryption"
                    ),
                    extra={
                        "detail": (
                            "EBS encryption by default is disabled at "
                            "the account level — new volumes are unencrypted"
                        ),
                        "remediation_steps": [
                            "Enable EBS encryption by default at account level.",
                            "This applies to all new volumes created in this region.",
                            "Existing volumes must be re-encrypted via snapshot copy.",
                            "Use a customer-managed KMS key for full key control.",
                        ],
                        "remediation_cli": (
                            f"# Enable EBS encryption by default\n"
                            f"aws ec2 enable-ebs-encryption-by-default \\\n"
                            f"  --region {region}\n\n"
                            f"# Verify\n"
                            f"aws ec2 get-ebs-encryption-by-default \\\n"
                            f"  --region {region}"
                        ),
                    }
                ))

            # Also check individual unencrypted volumes
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    if not volume.get("Encrypted", False):
                        vol_id = volume["VolumeId"]

                        # Get volume name from tags
                        vol_name = next(
                            (t["Value"] for t in volume.get("Tags", [])
                             if t["Key"] == "Name"),
                            vol_id
                        )

                        # Check if volume is attached to a running instance
                        attachments = volume.get("Attachments", [])
                        attached_to = [
                            a["InstanceId"] for a in attachments
                            if a.get("State") == "attached"
                        ]

                        findings.append(self._finding(
                            resource_id  = vol_id,
                            resource_arn = (
                                f"arn:aws:ec2:{region}:{account_id}:"
                                f"volume/{vol_id}"
                            ),
                            extra={
                                "has_sensitive_data": bool(attached_to),
                                "detail": (
                                    f"Volume {vol_name} is unencrypted"
                                    + (
                                        f" and attached to {attached_to}"
                                        if attached_to else " (unattached)"
                                    )
                                ),
                                "remediation_steps": [
                                    f"Create an encrypted snapshot of {vol_id}.",
                                    "Create a new encrypted volume from the snapshot.",
                                    "Stop the instance, detach old volume, attach new.",
                                    "Verify application functions correctly.",
                                    "Delete the unencrypted volume after verification.",
                                ],
                                "remediation_cli": (
                                    f"# Step 1: Create snapshot\n"
                                    f"aws ec2 create-snapshot \\\n"
                                    f"  --volume-id {vol_id} \\\n"
                                    f"  --description 'Pre-encryption snapshot'\n\n"
                                    f"# Step 2: Copy snapshot with encryption\n"
                                    f"aws ec2 copy-snapshot \\\n"
                                    f"  --source-region {region} \\\n"
                                    f"  --source-snapshot-id <snapshot-id> \\\n"
                                    f"  --encrypted \\\n"
                                    f"  --region {region}"
                                ),
                            }
                        ))

        except Exception as e:
            log.error(
                "Failed to check EBS encryption in %s: %s", region, e
            )

        return findings


class RDSEncryptionDisabled(SecurityRule):
    """
    CS-ENC-002 — CIS 2.3.1
    Ensure RDS instances have encryption at rest enabled.

    Why it matters
    --------------
    Unencrypted RDS snapshots expose the full database. An attacker with
    rds:RestoreDBInstanceFromDBSnapshot can restore the production database
    into their own account and query it freely — extracting all customer
    data, application secrets, and credentials stored in the database
    without triggering any alerts in the victim account.
    """
    rule_id      = "CS-ENC-002"
    title        = "RDS instance is not encrypted at rest"
    description  = (
        "This RDS instance does not have encryption at rest enabled. "
        "Unencrypted RDS snapshots can be shared externally and restored "
        "into an attacker-controlled account, exposing the full database "
        "contents without triggering alerts in the source account."
    )
    severity     = "HIGH"
    service      = "RDS"
    cis_control  = "CIS 2.3.1"
    nist_control = "PR.DS-1"
    soc2_control = "CC9.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        rds = session.client("rds")

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    if not db.get("StorageEncrypted", False):
                        db_id  = db["DBInstanceIdentifier"]
                        db_arn = db["DBInstanceArn"]
                        engine = db.get("Engine", "unknown")
                        size   = db.get("DBInstanceClass", "unknown")

                        findings.append(self._finding(
                            resource_id  = db_id,
                            resource_arn = db_arn,
                            extra={
                                "has_sensitive_data": True,
                                "detail": (
                                    f"RDS instance {db_id} "
                                    f"({engine}, {size}) is unencrypted"
                                ),
                                "remediation_steps": [
                                    f"RDS encryption cannot be enabled on a running instance.",
                                    f"Process: snapshot → encrypt → restore.",
                                    f"1. Create a snapshot of {db_id}.",
                                    f"2. Copy snapshot with encryption enabled.",
                                    f"3. Restore new encrypted instance from snapshot.",
                                    f"4. Update connection strings and test thoroughly.",
                                    f"5. Delete unencrypted instance after verification.",
                                    "Schedule this during a maintenance window.",
                                ],
                                "remediation_cli": (
                                    f"# Step 1: Create snapshot\n"
                                    f"aws rds create-db-snapshot \\\n"
                                    f"  --db-instance-identifier {db_id} \\\n"
                                    f"  --db-snapshot-identifier "
                                    f"{db_id}-pre-encryption\n\n"
                                    f"# Step 2: Copy with encryption\n"
                                    f"aws rds copy-db-snapshot \\\n"
                                    f"  --source-db-snapshot-identifier "
                                    f"{db_id}-pre-encryption \\\n"
                                    f"  --target-db-snapshot-identifier "
                                    f"{db_id}-encrypted \\\n"
                                    f"  --kms-key-id alias/aws/rds\n\n"
                                    f"# Step 3: Restore encrypted instance\n"
                                    f"aws rds restore-db-instance-from-db-snapshot \\\n"
                                    f"  --db-instance-identifier {db_id}-new \\\n"
                                    f"  --db-snapshot-identifier "
                                    f"{db_id}-encrypted"
                                ),
                            }
                        ))

        except Exception as e:
            log.error(
                "Failed to check RDS encryption in %s: %s", region, e
            )

        return findings