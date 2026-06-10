"""
cloudsentinel.scanner.rules.aws_ec2
=====================================
EC2 and VPC security rules — CIS AWS Foundations Benchmark v1.5 Section 5

Rules implemented
-----------------
CS-EC2-001  Unrestricted SSH (0.0.0.0/0 on port 22)
CS-EC2-002  Unrestricted RDP (0.0.0.0/0 on port 3389)
CS-EC2-003  IMDSv1 enabled (SSRF to credential theft vector)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import SecurityRule

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class UnrestrictedSSH(SecurityRule):
    """
    CS-EC2-001 — CIS 5.2
    Ensure no security groups allow unrestricted ingress on port 22.

    Why it matters
    --------------
    Port 22 open to 0.0.0.0/0 is indexed by Shodan within minutes of
    instance launch. Every automated scanner and botnet on the internet
    will attempt to authenticate. Weak passwords, exposed keys, or SSH
    agent hijacking all become viable initial access vectors.
    """
    rule_id      = "CS-EC2-001"
    title        = "Security group allows unrestricted SSH from internet"
    description  = (
        "A security group allows inbound SSH (port 22) from 0.0.0.0/0 or ::/0. "
        "This exposes the instance to brute-force attacks, credential stuffing, "
        "and exploitation of SSH vulnerabilities from any IP on the internet."
    )
    severity     = "HIGH"
    service      = "EC2"
    cis_control  = "CIS 5.2"
    nist_control = "PR.AC-5"
    soc2_control = "CC6.6"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        return self._check_unrestricted_port(session, port=22, protocol="SSH")

    def _check_unrestricted_port(
        self, session, port: int, protocol: str
    ) -> list[dict]:
        findings = []
        ec2 = session.client("ec2")

        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    if self._has_unrestricted_ingress(sg, port):
                        findings.append(self._finding(
                            resource_id  = sg["GroupId"],
                            resource_arn = (
                                f"arn:aws:ec2:{session.region_name}:"
                                f"{sg.get('OwnerId','')}:"
                                f"security-group/{sg['GroupId']}"
                            ),
                            extra={
                                "is_public": True,
                                "detail": (
                                    f"SG {sg['GroupId']} ({sg.get('GroupName','')}) "
                                    f"allows {protocol} from 0.0.0.0/0 or ::/0"
                                ),
                                "remediation_steps": [
                                    f"Identify all EC2 instances using SG {sg['GroupId']}.",
                                    f"Replace 0.0.0.0/0 with specific IP ranges or "
                                    f"a bastion host security group.",
                                    "Consider using AWS Systems Manager Session Manager "
                                    "instead of direct SSH — eliminates port 22 entirely.",
                                    "If SSH is required, restrict to a VPN CIDR or bastion SG.",
                                ],
                                "remediation_cli": (
                                    f"# Remove unrestricted {protocol} rule\n"
                                    f"aws ec2 revoke-security-group-ingress \\\n"
                                    f"  --group-id {sg['GroupId']} \\\n"
                                    f"  --protocol tcp \\\n"
                                    f"  --port {port} \\\n"
                                    f"  --cidr 0.0.0.0/0\n\n"
                                    f"# Then add restricted rule (replace with your CIDR)\n"
                                    f"aws ec2 authorize-security-group-ingress \\\n"
                                    f"  --group-id {sg['GroupId']} \\\n"
                                    f"  --protocol tcp \\\n"
                                    f"  --port {port} \\\n"
                                    f"  --cidr 10.0.0.0/8"
                                ),
                            }
                        ))
        except Exception as e:
            log.error("Failed to describe security groups: %s", e)

        return findings

    @staticmethod
    def _has_unrestricted_ingress(sg: dict, port: int) -> bool:
        """Check if a security group has unrestricted ingress on a specific port."""
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort",   0)

            if from_port <= port <= to_port:
                # Check IPv4
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        return True
                # Check IPv6
                for ip_range in rule.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        return True
        return False


class UnrestrictedRDP(UnrestrictedSSH):
    """
    CS-EC2-002 — CIS 5.3
    Ensure no security groups allow unrestricted ingress on port 3389.

    Why it matters
    --------------
    RDP is the most exploited initial access vector in ransomware incidents.
    BlueKeep (CVE-2019-0708) and DejaBlue (CVE-2019-1181) are unauthenticated
    RCE vulnerabilities that target open RDP. Shodan shows millions of exposed
    RDP endpoints at any given time.
    """
    rule_id      = "CS-EC2-002"
    title        = "Security group allows unrestricted RDP from internet"
    description  = (
        "A security group allows inbound RDP (port 3389) from 0.0.0.0/0 or ::/0. "
        "RDP is the primary initial access vector in ransomware campaigns. "
        "BlueKeep (CVE-2019-0708) enables unauthenticated RCE on exposed RDP."
    )
    severity     = "HIGH"
    service      = "EC2"
    cis_control  = "CIS 5.3"
    nist_control = "PR.AC-5"
    soc2_control = "CC6.6"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        return self._check_unrestricted_port(session, port=3389, protocol="RDP")


class IMDSv1Enabled(SecurityRule):
    """
    CS-EC2-003 — CIS 5.6
    Ensure EC2 instances require IMDSv2 (disable IMDSv1).

    Why it matters
    --------------
    IMDSv1 requires no session token — any HTTP GET to 169.254.169.254
    returns instance role credentials. SSRF vulnerabilities in web
    applications running on EC2 can exploit this to steal IAM credentials
    without any authentication. This is exactly how the Capital One breach
    (2019) worked — a WAF misconfiguration led to SSRF, which hit the IMDS
    and returned credentials for a role with excessive S3 permissions.
    """
    rule_id      = "CS-EC2-003"
    title        = "EC2 instance allows IMDSv1 (SSRF credential theft risk)"
    description  = (
        "The EC2 instance does not enforce IMDSv2. IMDSv1 allows any process "
        "on the instance — including SSRF-exploitable web applications — to "
        "retrieve IAM role credentials with a simple unauthenticated HTTP GET "
        "to the instance metadata endpoint."
    )
    severity     = "HIGH"
    service      = "EC2"
    cis_control  = "CIS 5.6"
    nist_control = "PR.AC-3"
    soc2_control = "CC6.1"

    def check(self, session, account_id: str, region: str) -> list[dict]:
        findings = []
        ec2 = session.client("ec2")

        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        # Only check running instances
                        if instance.get("State", {}).get("Name") != "running":
                            continue

                        imds_options = instance.get(
                            "MetadataOptions", {}
                        )
                        http_tokens = imds_options.get(
                            "HttpTokens", "optional"
                        )

                        # "optional" means IMDSv1 is allowed
                        if http_tokens != "required":
                            instance_id = instance["InstanceId"]
                            findings.append(self._finding(
                                resource_id  = instance_id,
                                resource_arn = (
                                    f"arn:aws:ec2:{region}:{account_id}:"
                                    f"instance/{instance_id}"
                                ),
                                extra={
                                    "detail": (
                                        f"HttpTokens={http_tokens} — "
                                        f"IMDSv1 requests are accepted"
                                    ),
                                    "remediation_steps": [
                                        f"Enforce IMDSv2 on instance {instance_id}.",
                                        "Test that your application doesn't use IMDSv1 first.",
                                        "Update any SDKs/agents that use instance metadata.",
                                        "Enforce IMDSv2 account-wide via SCP after testing.",
                                    ],
                                    "remediation_cli": (
                                        f"aws ec2 modify-instance-metadata-options \\\n"
                                        f"  --instance-id {instance_id} \\\n"
                                        f"  --http-tokens required \\\n"
                                        f"  --http-endpoint enabled"
                                    ),
                                }
                            ))
        except Exception as e:
            log.error("Failed to describe EC2 instances: %s", e)

        return findings