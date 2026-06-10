"""
cloudsentinel.remediation.actions.ec2
=======================================
Automated remediation actions for EC2 findings.

Actions implemented
-------------------
CS-EC2-001  Revoke unrestricted SSH (0.0.0.0/0) from security group
CS-EC2-002  Revoke unrestricted RDP (0.0.0.0/0) from security group
CS-EC2-003  Enforce IMDSv2 on EC2 instance
"""
from __future__ import annotations

import logging
from typing import Optional

from .iam import RemediationResult

log = logging.getLogger(__name__)


class EC2RemediationActions:
    """Executes EC2 remediation actions with before/after state capture."""

    def remediate_cs_ec2_001(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-EC2-001 — Revoke unrestricted SSH ingress rule.

        Removes 0.0.0.0/0 and ::/0 ingress rules on port 22.
        Does NOT add a replacement rule — that requires knowledge
        of the correct CIDR range for the environment.
        Operators should add a restricted rule after remediation.
        """
        return self._revoke_unrestricted_port(
            session, resource_id, port=22, protocol_name="SSH"
        )

    def remediate_cs_ec2_002(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-EC2-002 — Revoke unrestricted RDP ingress rule.

        Removes 0.0.0.0/0 and ::/0 ingress rules on port 3389.
        """
        return self._revoke_unrestricted_port(
            session, resource_id, port=3389, protocol_name="RDP"
        )

    def remediate_cs_ec2_003(
        self, session, resource_id: str, account_id: str
    ) -> RemediationResult:
        """
        CS-EC2-003 — Enforce IMDSv2 on EC2 instance.

        Sets HttpTokens=required on the instance metadata options.
        This blocks IMDSv1 requests — any application using the old
        SDK without session tokens will stop receiving credentials.

        Test in non-production first. AWS recommends checking
        CloudWatch metric MetadataNoToken before enforcing.
        """
        instance_id = resource_id
        ec2         = session.client("ec2")

        # Capture before state
        before = self._get_imds_config(ec2, instance_id)

        try:
            ec2.modify_instance_metadata_options(
                InstanceId  = instance_id,
                HttpTokens  = "required",
                HttpEndpoint = "enabled",
            )

            after = self._get_imds_config(ec2, instance_id)
            log.info("IMDSv2 enforced on instance %s", instance_id)

            return RemediationResult(
                success      = True,
                action_taken = (
                    f"Enforced IMDSv2 on instance {instance_id}. "
                    f"HttpTokens set to 'required'. "
                    f"IMDSv1 requests will now be rejected. "
                    f"Verify applications use AWS SDK v2+ before confirming."
                ),
                before_state = before,
                after_state  = after,
            )

        except Exception as e:
            log.error(
                "Failed to enforce IMDSv2 on %s: %s", instance_id, e
            )
            return RemediationResult(
                success      = False,
                action_taken = (
                    f"Attempted to enforce IMDSv2 on {instance_id}"
                ),
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _revoke_unrestricted_port(
        self,
        session,
        sg_id:         str,
        port:          int,
        protocol_name: str,
    ) -> RemediationResult:
        """Remove 0.0.0.0/0 and ::/0 ingress rules for a specific port."""
        ec2    = session.client("ec2")
        before = self._get_sg_rules(ec2, sg_id, port)
        revoked = []

        try:
            # Revoke IPv4
            try:
                ec2.revoke_security_group_ingress(
                    GroupId    = sg_id,
                    IpProtocol = "tcp",
                    FromPort   = port,
                    ToPort     = port,
                    CidrIp     = "0.0.0.0/0",
                )
                revoked.append("0.0.0.0/0")
                log.info(
                    "Revoked %s 0.0.0.0/0 from SG %s", protocol_name, sg_id
                )
            except Exception:
                pass   # Rule may not exist — not an error

            # Revoke IPv6
            try:
                ec2.revoke_security_group_ingress(
                    GroupId          = sg_id,
                    IpPermissions    = [{
                        "IpProtocol": "tcp",
                        "FromPort":   port,
                        "ToPort":     port,
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    }]
                )
                revoked.append("::/0")
                log.info(
                    "Revoked %s ::/0 from SG %s", protocol_name, sg_id
                )
            except Exception:
                pass

            after = self._get_sg_rules(ec2, sg_id, port)

            return RemediationResult(
                success      = len(revoked) > 0,
                action_taken = (
                    f"Revoked unrestricted {protocol_name} "
                    f"(port {port}) from security group {sg_id}. "
                    f"Removed CIDRs: {', '.join(revoked) or 'none found'}. "
                    f"Add a restricted rule with your VPN or bastion CIDR."
                ),
                before_state = before,
                after_state  = after,
                error        = None if revoked else "No matching rules found",
            )

        except Exception as e:
            log.error(
                "Failed to revoke %s from SG %s: %s",
                protocol_name, sg_id, e
            )
            return RemediationResult(
                success      = False,
                action_taken = (
                    f"Attempted to revoke {protocol_name} from {sg_id}"
                ),
                before_state = before,
                after_state  = {},
                error        = str(e),
            )

    def _get_sg_rules(self, ec2, sg_id: str, port: int) -> dict:
        """Capture ingress rules for a security group on a specific port."""
        try:
            sgs = ec2.describe_security_groups(
                GroupIds=[sg_id]
            ).get("SecurityGroups", [])
            if not sgs:
                return {}
            rules = [
                r for r in sgs[0].get("IpPermissions", [])
                if r.get("FromPort", 0) <= port <= r.get("ToPort", 0)
            ]
            return {"ingress_rules_on_port": rules}
        except Exception:
            return {}

    def _get_imds_config(self, ec2, instance_id: str) -> dict:
        """Capture IMDS configuration for an instance."""
        try:
            reservations = ec2.describe_instances(
                InstanceIds=[instance_id]
            ).get("Reservations", [])
            if not reservations:
                return {}
            instance = reservations[0]["Instances"][0]
            return instance.get("MetadataOptions", {})
        except Exception:
            return {}