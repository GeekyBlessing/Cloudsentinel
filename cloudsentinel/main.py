"""
cloudsentinel.main
==================
CloudSentinel CSPM — FastAPI application entrypoint.

Endpoints
---------
GET  /health                     → Service health check
GET  /api/v1/posture             → Executive risk summary
POST /api/v1/scans               → Trigger async account scan
GET  /api/v1/scans/{scan_id}     → Get scan result by ID
GET  /api/v1/findings            → List findings with filters
GET  /api/v1/findings/{id}       → Get single finding detail
PATCH /api/v1/findings/{id}/status → Update finding status
GET  /api/v1/attack-path         → Kill chain from open findings
GET  /api/v1/compliance          → Compliance posture summary
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .enrichment.compliance import ComplianceMapper
from .enrichment.mitre      import MitreEnrichmentEngine
from .scanner.engine        import ScanEngine
from .storage.dynamodb      import FindingStore

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
log = logging.getLogger("cloudsentinel.api")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "CloudSentinel CSPM API",
    description = (
        "Multi-cloud security posture management with MITRE ATT&CK "
        "threat enrichment, blast radius scoring, and compliance mapping."
    ),
    version     = "2.1.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── Singletons ────────────────────────────────────────────────────────────────
store  = FindingStore()
mitre  = MitreEnrichmentEngine()
comp   = ComplianceMapper()

# In-memory scan job tracker
# Production: replace with DynamoDB or ElastiCache
_scan_jobs: dict[str, dict] = {}


# ── Request / Response models ─────────────────────────────────────────────────

class ScanRequest(BaseModel):
    account_id: str
    role_arn:   Optional[str] = None
    regions:    Optional[list[str]] = None


class StatusUpdateRequest(BaseModel):
    status: str                      # OPEN | REMEDIATED | SUPPRESSED
    reason: Optional[str] = None     # Required for SUPPRESSED


class ScanJobResponse(BaseModel):
    scan_id:    str
    account_id: str
    status:     str
    triggered:  str


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health():
    """Service liveness check."""
    return {
        "status":    "ok",
        "service":   "cloudsentinel",
        "version":   "2.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Posture summary ───────────────────────────────────────────────────────────

@app.get("/api/v1/posture", tags=["Posture"])
def get_posture():
    """
    Executive risk summary.

    Returns overall risk score, severity breakdown, cloud coverage,
    active ATT&CK tactics, and compliance posture across all frameworks.
    Used to populate the Overview dashboard tab.
    """
    try:
        all_findings = store.list(limit=1000)
        open_findings = [f for f in all_findings if f.get("status") == "OPEN"]

        # Severity counts
        severity_counts = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for f in open_findings:
            sev = f.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Average risk score
        avg_risk = (
            sum(float(f.get("risk_score", 0)) for f in open_findings)
            / len(open_findings)
            if open_findings else 0.0
        )

        # Cloud breakdown
        cloud_breakdown: dict[str, dict] = {}
        for f in open_findings:
            cloud = f.get("cloud", "UNKNOWN")
            cloud_breakdown.setdefault(
                cloud, {"total": 0, "critical": 0, "high": 0}
            )
            cloud_breakdown[cloud]["total"] += 1
            if f.get("severity") == "CRITICAL":
                cloud_breakdown[cloud]["critical"] += 1
            elif f.get("severity") == "HIGH":
                cloud_breakdown[cloud]["high"] += 1

        # Active ATT&CK tactics from open findings
        active_tactics: dict[str, int] = {}
        for f in open_findings:
            for m in f.get("mitre", []):
                tid = m.get("tactic_id", "")
                if tid:
                    active_tactics[tid] = active_tactics.get(tid, 0) + 1

        # Kill chain
        kill_chain = mitre.build_kill_chain(open_findings)

        # Compliance posture
        compliance = comp.posture_summary(all_findings)

        return {
            "total_open":       len(open_findings),
            "total_findings":   len(all_findings),
            "avg_risk_score":   round(avg_risk, 1),
            "severity_counts":  severity_counts,
            "cloud_breakdown":  cloud_breakdown,
            "active_tactics":   active_tactics,
            "kill_chain": {
                "total_tactics":  kill_chain.total_tactics,
                "highest_impact": kill_chain.highest_impact,
                "narrative":      kill_chain.narrative,
                "steps": [
                    {
                        "tactic_id":   s.tactic_id,
                        "tactic_name": s.tactic_name,
                        "order":       s.order,
                        "finding_count": len(s.findings),
                    }
                    for s in kill_chain.steps
                ],
            },
            "compliance":       compliance,
            "generated_at":     datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        log.error("Failed to generate posture summary: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.post("/api/v1/scans", response_model=ScanJobResponse, tags=["Scans"])
async def trigger_scan(
    request:            ScanRequest,
    background_tasks:   BackgroundTasks,
):
    """
    Trigger an async AWS account scan.

    Runs in the background — returns scan_id immediately.
    Poll /api/v1/scans/{scan_id} for status.
    """
    scan_id = str(uuid.uuid4())
    triggered = datetime.now(timezone.utc).isoformat()

    _scan_jobs[scan_id] = {
        "scan_id":    scan_id,
        "account_id": request.account_id,
        "status":     "RUNNING",
        "triggered":  triggered,
        "result":     None,
        "error":      None,
    }

    background_tasks.add_task(
        _run_scan,
        scan_id    = scan_id,
        account_id = request.account_id,
        role_arn   = request.role_arn,
        regions    = request.regions,
    )

    log.info("Scan %s triggered for account %s", scan_id, request.account_id)

    return ScanJobResponse(
        scan_id    = scan_id,
        account_id = request.account_id,
        status     = "RUNNING",
        triggered  = triggered,
    )


@app.get("/api/v1/scans/{scan_id}", tags=["Scans"])
def get_scan(scan_id: str):
    """Get scan job status and summary."""
    job = _scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


def _run_scan(
    scan_id:    str,
    account_id: str,
    role_arn:   Optional[str],
    regions:    Optional[list[str]],
) -> None:
    """Background scan task."""
    try:
        engine = ScanEngine(
            regions = regions,
            persist = True,
        )
        result = engine.scan_account(role_arn=role_arn)

        _scan_jobs[scan_id].update({
            "status": "COMPLETE",
            "result": result.summary(),
            "error":  None,
        })
        log.info(
            "Scan %s complete: %d findings", scan_id, result.total
        )

    except Exception as e:
        log.error("Scan %s failed: %s", scan_id, e)
        _scan_jobs[scan_id].update({
            "status": "FAILED",
            "error":  str(e),
        })


# ── Findings ──────────────────────────────────────────────────────────────────

@app.get("/api/v1/findings", tags=["Findings"])
def list_findings(
    cloud:    Optional[str] = Query(None, description="AWS | AZURE | GCP"),
    severity: Optional[str] = Query(None, description="CRITICAL | HIGH | MEDIUM | LOW"),
    service:  Optional[str] = Query(None, description="IAM | S3 | EC2 | RDS ..."),
    status:   Optional[str] = Query(None, description="OPEN | REMEDIATED | SUPPRESSED"),
    tactic:   Optional[str] = Query(None, description="ATT&CK tactic ID e.g. TA0001"),
    limit:    int            = Query(200, ge=1, le=1000),
):
    """
    List findings with optional filters.

    Supports filtering by cloud provider, severity, service, status,
    and ATT&CK tactic. Returns up to 1000 findings per request.
    """
    try:
        findings = store.list(
            cloud    = cloud,
            severity = severity,
            service  = service,
            status   = status,
            tactic   = tactic,
            limit    = limit,
        )
        return {
            "findings": findings,
            "total":    len(findings),
            "filters":  {
                "cloud": cloud, "severity": severity,
                "service": service, "status": status, "tactic": tactic,
            },
        }
    except Exception as e:
        log.error("Failed to list findings: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/findings/{finding_id}", tags=["Findings"])
def get_finding(finding_id: str):
    """Get a single finding by ID with full detail."""
    finding = store.get(finding_id)
    if not finding:
        raise HTTPException(
            status_code = 404,
            detail      = f"Finding {finding_id} not found",
        )
    return finding


@app.patch("/api/v1/findings/{finding_id}/status", tags=["Findings"])
def update_finding_status(finding_id: str, request: StatusUpdateRequest):
    """
    Update finding status.

    REMEDIATED: marks as fixed, sets 90-day TTL for auto-expiry
    SUPPRESSED: requires a reason (min 10 characters)
    OPEN:       re-opens a suppressed or remediated finding
    """
    allowed = {"OPEN", "REMEDIATED", "SUPPRESSED"}
    status  = request.status.upper()

    if status not in allowed:
        raise HTTPException(
            status_code = 400,
            detail      = f"Status must be one of: {', '.join(allowed)}",
        )

    if status == "SUPPRESSED" and (
        not request.reason or len(request.reason.strip()) < 10
    ):
        raise HTTPException(
            status_code = 400,
            detail      = "Suppression requires a reason of at least 10 characters",
        )

    success = store.update_status(finding_id, status, request.reason)
    if not success:
        raise HTTPException(
            status_code = 500,
            detail      = "Failed to update finding status",
        )

    return {
        "finding_id": finding_id,
        "status":     status,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Attack path ───────────────────────────────────────────────────────────────

@app.get("/api/v1/attack-path", tags=["Threat Intel"])
def get_attack_path(
    account_id: Optional[str] = Query(None),
    cloud:      Optional[str] = Query(None),
):
    """
    Construct adversary kill chain from open findings.

    Returns an ordered sequence of ATT&CK tactics an attacker could
    progress through given the current misconfiguration surface,
    plus a plain-English narrative for executive reporting.
    """
    try:
        findings = store.list(
            cloud   = cloud,
            status  = "OPEN",
            limit   = 1000,
        )
        chain = mitre.build_kill_chain(findings)

        return {
            "total_tactics":  chain.total_tactics,
            "highest_impact": chain.highest_impact,
            "narrative":      chain.narrative,
            "steps": [
                {
                    "tactic_id":     s.tactic_id,
                    "tactic_name":   s.tactic_name,
                    "order":         s.order,
                    "techniques":    s.techniques,
                    "enabled_by":    list(set(s.findings)),
                }
                for s in chain.steps
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        log.error("Failed to build attack path: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# ── Compliance ────────────────────────────────────────────────────────────────

@app.get("/api/v1/compliance", tags=["Compliance"])
def get_compliance(
    framework: Optional[str] = Query(
        None,
        description="CIS | NIST_CSF | SOC2 | PCI_DSS"
    ),
):
    """
    Compliance posture across all mapped frameworks.

    Returns pass/fail counts and failing control IDs per framework.
    Used to populate the Compliance dashboard tab.
    """
    try:
        findings = store.list(limit=1000)
        summary  = comp.posture_summary(findings)

        if framework:
            fw = framework.upper()
            if fw not in summary:
                raise HTTPException(
                    status_code = 400,
                    detail      = f"Unknown framework: {fw}. "
                                  f"Valid: {list(summary.keys())}",
                )
            return {fw: summary[fw]}

        return {
            "frameworks":   summary,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error("Failed to get compliance posture: %s", e)
        raise HTTPException(status_code=500, detail=str(e))