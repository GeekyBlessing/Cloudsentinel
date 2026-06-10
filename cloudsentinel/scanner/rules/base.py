"""
cloudsentinel.scanner.rules.base
=================================
Base class for all CloudSentinel security rules.

Every rule inherits from SecurityRule and implements check().
The engine calls check() and then enriches the raw findings with
MITRE mappings, risk scores, and compliance controls.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import boto3

log = logging.getLogger(__name__)


class SecurityRule(ABC):
    """
    Abstract base for all CloudSentinel rules.

    Subclasses must define class-level attributes and implement check().
    The _finding() helper builds a consistent raw finding dict that the
    scan engine enriches before persisting.
    """

    # ── Required class attributes ─────────────────────────────────────────────
    rule_id:      str
    title:        str
    description:  str
    severity:     str    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    service:      str    # AWS service e.g. IAM, S3, EC2

    # ── Optional compliance mappings ──────────────────────────────────────────
    cis_control:  str = ""
    nist_control: str = ""
    soc2_control: str = ""
    pci_control:  str = ""

    @abstractmethod
    def check(self, session, account_id: str, region: str) -> list[dict]:
        """
        Run this rule against the provided boto3 session.

        Parameters
        ----------
        session:    boto3.Session configured for the target account/region
        account_id: AWS account ID being scanned
        region:     AWS region being scanned

        Returns
        -------
        List of raw finding dicts — one per violated resource.
        Empty list means the rule passed (no violations found).
        """
        ...

    def _finding(
        self,
        resource_id:  str,
        resource_arn: str = "",
        extra:        dict | None = None,
    ) -> dict:
        """
        Build a raw finding dict stub.

        The scan engine will enrich this with MITRE mappings,
        risk score, blast radius, and compliance controls.
        """
        finding = {
            "rule_id":      self.rule_id,
            "title":        self.title,
            "description":  self.description,
            "severity":     self.severity,
            "service":      self.service,
            "resource_id":  resource_id,
            "resource_arn": resource_arn,
            "cis_control":  self.cis_control,
            "nist_control": self.nist_control,
            "soc2_control": self.soc2_control,
            "pci_control":  self.pci_control,
            "is_public":          False,
            "has_sensitive_data": False,
            "remediation_steps":  [],
            "remediation_cli":    "",
        }
        if extra:
            finding.update(extra)

        log.debug(
            "Rule %s flagged resource %s (%s)",
            self.rule_id, resource_id, self.severity
        )
        return finding

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} rule_id={self.rule_id} severity={self.severity}>"