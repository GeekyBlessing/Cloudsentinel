"""
cloudsentinel.reporting.compliance_report
==========================================
Professional PDF compliance report generator.

Generates audit-ready reports mapping findings to:
- CIS AWS Foundations Benchmark v1.5
- NIST Cybersecurity Framework
- SOC 2 Type II
- PCI DSS v4.0

Report sections
---------------
1. Executive Summary — risk score, finding counts, posture trend
2. Compliance Posture — per-framework pass/fail with bar charts
3. Critical & High Findings — detailed finding cards
4. MITRE ATT&CK Coverage — active tactics and techniques
5. Remediation Status — what's fixed, what's pending
6. Appendix — full finding list with control mappings
"""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

log = logging.getLogger(__name__)

# ── Brand colors ──────────────────────────────────────────────────────────────
NAVY      = colors.HexColor("#0A0E1A")
STEEL     = colors.HexColor("#1E3A5F")
CYAN      = colors.HexColor("#00B4D8")
CRIMSON   = colors.HexColor("#E53E3E")
AMBER     = colors.HexColor("#D69E2E")
ORANGE    = colors.HexColor("#DD6B20")
GREEN     = colors.HexColor("#38A169")
LIGHT_BG  = colors.HexColor("#F7FAFC")
MID_GRAY  = colors.HexColor("#718096")
DARK_GRAY = colors.HexColor("#2D3748")

SEVERITY_COLORS = {
    "CRITICAL": CRIMSON,
    "HIGH":     ORANGE,
    "MEDIUM":   AMBER,
    "LOW":      GREEN,
    "INFO":     MID_GRAY,
}


class ComplianceReportGenerator:
    """
    Generates a professional PDF compliance report from scan results.

    Usage
    -----
    generator = ComplianceReportGenerator()
    path = generator.generate(
        findings       = findings,
        account_id     = "358487322954",
        scan_date      = datetime.now(timezone.utc),
        output_path    = "reports/compliance_report.pdf",
    )
    """

    def __init__(self) -> None:
        self.styles = getSampleStyleSheet()
        self._build_styles()

    def generate(
        self,
        findings:    list[dict],
        account_id:  str,
        scan_date:   Optional[datetime] = None,
        output_path: str = "compliance_report.pdf",
        org_name:    str = "CloudSentinel Security Assessment",
    ) -> str:
        """
        Generate PDF compliance report.
        Returns path to generated file.
        """
        scan_date = scan_date or datetime.now(timezone.utc)

        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        doc = SimpleDocTemplate(
            output_path,
            pagesize     = A4,
            rightMargin  = 20 * mm,
            leftMargin   = 20 * mm,
            topMargin    = 25 * mm,
            bottomMargin = 20 * mm,
        )

        story = []

        # ── Cover page ────────────────────────────────────────────────────────
        story += self._cover_page(org_name, account_id, scan_date)
        story.append(PageBreak())

        # ── Executive summary ─────────────────────────────────────────────────
        story += self._executive_summary(findings, scan_date)
        story.append(PageBreak())

        # ── Compliance posture ────────────────────────────────────────────────
        story += self._compliance_posture(findings)
        story.append(PageBreak())

        # ── Critical & High findings ──────────────────────────────────────────
        story += self._findings_section(findings)
        story.append(PageBreak())

        # ── MITRE ATT&CK coverage ─────────────────────────────────────────────
        story += self._mitre_section(findings)
        story.append(PageBreak())

        # ── Appendix — full finding table ─────────────────────────────────────
        story += self._appendix(findings)

        doc.build(story)
        log.info("Compliance report generated: %s", output_path)
        return output_path

    # ── Cover page ────────────────────────────────────────────────────────────

    def _cover_page(
        self, org_name: str, account_id: str, scan_date: datetime
    ) -> list:
        elements = []

        elements.append(Spacer(1, 40 * mm))

        elements.append(Paragraph(
            "CLOUD SECURITY POSTURE",
            self.st["cover_sub"]
        ))
        elements.append(Paragraph(
            "ASSESSMENT REPORT",
            self.st["cover_title"]
        ))
        elements.append(Spacer(1, 8 * mm))
        elements.append(HRFlowable(
            width="100%", thickness=2, color=CYAN
        ))
        elements.append(Spacer(1, 8 * mm))

        elements.append(Paragraph(org_name, self.st["cover_org"]))
        elements.append(Spacer(1, 4 * mm))

        meta = [
            ["AWS Account ID", account_id],
            ["Assessment Date", scan_date.strftime("%B %d, %Y")],
            ["Report Generated", datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"
            )],
            ["Frameworks", "CIS AWS v1.5 · NIST CSF · SOC 2 · PCI DSS v4.0"],
            ["Generated By", "CloudSentinel CSPM v2.1"],
        ]

        table = Table(meta, colWidths=[55 * mm, 110 * mm])
        table.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (0, -1), STEEL),
            ("TEXTCOLOR",   (0, 0), (0, -1), colors.white),
            ("BACKGROUND",  (1, 0), (1, -1), LIGHT_BG),
            ("TEXTCOLOR",   (1, 0), (1, -1), DARK_GRAY),
            ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
            ("PADDING",     (0, 0), (-1, -1), 8),
            ("GRID",        (0, 0), (-1, -1), 0.5, colors.white),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_BG, colors.white]),
        ]))
        elements.append(table)
        elements.append(Spacer(1, 10 * mm))

        elements.append(Paragraph(
            "CONFIDENTIAL — For internal use only. "
            "This report contains sensitive security findings.",
            self.st["disclaimer"]
        ))

        return elements

    # ── Executive summary ─────────────────────────────────────────────────────

    def _executive_summary(
        self, findings: list[dict], scan_date: datetime
    ) -> list:
        elements = []
        elements.append(Paragraph("Executive Summary", self.st["h1"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN))
        elements.append(Spacer(1, 4 * mm))

        open_f = [f for f in findings if f.get("status") == "OPEN"]
        counts = {s: 0 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        for f in open_f:
            sev = f.get("severity","INFO")
            counts[sev] = counts.get(sev, 0) + 1

        avg_risk = (
            sum(float(f.get("risk_score", 0)) for f in open_f) / len(open_f)
            if open_f else 0.0
        )

        # Risk summary text
        if counts["CRITICAL"] > 0:
            posture = "CRITICAL — Immediate action required"
            posture_color = CRIMSON
        elif counts["HIGH"] > 0:
            posture = "HIGH RISK — Remediation recommended within 24 hours"
            posture_color = ORANGE
        elif counts["MEDIUM"] > 0:
            posture = "MODERATE — Remediation recommended within 7 days"
            posture_color = AMBER
        else:
            posture = "ACCEPTABLE — Continue monitoring"
            posture_color = GREEN

        elements.append(Paragraph(
            f"Security Posture: <b>{posture}</b>",
            self.st["body"]
        ))
        elements.append(Spacer(1, 4 * mm))

        elements.append(Paragraph(
            f"CloudSentinel completed a security posture assessment of AWS account "
            f"on {scan_date.strftime('%B %d, %Y')}. The assessment evaluated "
            f"{len(findings)} security controls across IAM, S3, EC2, logging, "
            f"and encryption services. <b>{len(open_f)} finding(s)</b> require "
            f"attention, with an average risk score of "
            f"<b>{avg_risk:.1f}/10</b>.",
            self.st["body"]
        ))
        elements.append(Spacer(1, 6 * mm))

        # Finding counts table
        elements.append(Paragraph("Finding Summary", self.st["h2"]))
        elements.append(Spacer(1, 2 * mm))

        sev_data = [["Severity", "Count", "Risk Level", "SLA"]]
        sev_sla  = {
            "CRITICAL": "Immediate (< 4 hours)",
            "HIGH":     "Urgent (< 24 hours)",
            "MEDIUM":   "Standard (< 7 days)",
            "LOW":      "Planned (< 30 days)",
            "INFO":     "Informational",
        }
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
            if counts[sev] > 0:
                sev_data.append([
                    sev,
                    str(counts[sev]),
                    f"{sev.capitalize()} Risk",
                    sev_sla[sev],
                ])

        if len(sev_data) > 1:
            t = Table(
                sev_data,
                colWidths=[35*mm, 20*mm, 45*mm, 65*mm]
            )
            t.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,0), STEEL),
                ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 9),
                ("PADDING",     (0,0), (-1,-1), 6),
                ("GRID",        (0,0), (-1,-1), 0.3, MID_GRAY),
                ("ROWBACKGROUNDS",
                 (0,1), (-1,-1), [LIGHT_BG, colors.white]),
            ]))
            elements.append(t)

        return elements

    # ── Compliance posture ────────────────────────────────────────────────────

    def _compliance_posture(self, findings: list[dict]) -> list:
        from ..enrichment.compliance import ComplianceMapper, FRAMEWORK_TOTALS
        mapper  = ComplianceMapper()
        summary = mapper.posture_summary(findings)

        elements = []
        elements.append(Paragraph("Compliance Posture", self.st["h1"]))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN))
        elements.append(Spacer(1, 4 * mm))

        elements.append(Paragraph(
            "The following table shows compliance posture across all "
            "mapped frameworks based on open findings.",
            self.st["body"]
        ))
        elements.append(Spacer(1, 4 * mm))

        fw_descriptions = {
            "CIS":      "CIS AWS Foundations Benchmark v1.5",
            "NIST_CSF": "NIST Cybersecurity Framework",
            "SOC2":     "SOC 2 Type II (Trust Service Criteria)",
            "PCI_DSS":  "PCI DSS v4.0",
        }

        for fw, data in summary.items():
            pct     = data["pass_pct"]
            passing = data["passing"]
            total   = data["total"]
            failing = data["failing_controls"]

            if pct >= 90:
                status_color = GREEN
                status       = "COMPLIANT"
            elif pct >= 75:
                status_color = AMBER
                status       = "PARTIAL"
            else:
                status_color = CRIMSON
                status       = "NON-COMPLIANT"

            elements.append(Paragraph(
                fw_descriptions.get(fw, fw),
                self.st["h2"]
            ))

            fw_data = [
                ["Controls Passing", f"{passing}/{total}"],
                ["Pass Rate",        f"{pct:.1f}%"],
                ["Status",           status],
                ["Failing Controls", ", ".join(failing) if failing else "None"],
            ]

            t = Table(fw_data, colWidths=[50*mm, 115*mm])
            t.setStyle(TableStyle([
                ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 9),
                ("PADDING",     (0,0), (-1,-1), 6),
                ("BACKGROUND",  (0,0), (-1,-1), LIGHT_BG),
                ("GRID",        (0,0), (-1,-1), 0.3, colors.white),
                ("TEXTCOLOR",   (1,2), (1,2),   status_color),
                ("FONTNAME",    (1,2), (1,2),   "Helvetica-Bold"),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 4 * mm))

        return elements

    # ── Findings section ──────────────────────────────────────────────────────

    def _findings_section(self, findings: list[dict]) -> list:
        elements = []
        elements.append(Paragraph(
            "Critical & High Findings", self.st["h1"]
        ))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN))
        elements.append(Spacer(1, 4 * mm))

        priority = [
            f for f in findings
            if f.get("severity") in ("CRITICAL","HIGH")
            and f.get("status") == "OPEN"
        ]

        if not priority:
            elements.append(Paragraph(
                "No Critical or High severity findings. "
                "Continue monitoring for new issues.",
                self.st["body"]
            ))
            return elements

        for f in priority:
            sev   = f.get("severity","MEDIUM")
            color = SEVERITY_COLORS.get(sev, MID_GRAY)

            elements.append(Paragraph(f.get("title",""), self.st["h2"]))

            # TTPs
            ttps = [m.get("technique_id","") for m in f.get("mitre",[])]
            tactics = list(dict.fromkeys(
                m.get("tactic_name","") for m in f.get("mitre",[])
            ))

            detail_data = [
                ["Finding ID",   f.get("id","")],
                ["Rule",         f.get("rule_id","")],
                ["Severity",     sev],
                ["Risk Score",   f"{f.get('risk_score',0)}/10"],
                ["Resource",     f.get("resource_id","")],
                ["Account",      f.get("account_id","")],
                ["Region",       f.get("region","")],
                ["ATT&CK TTPs",  " · ".join(ttps) if ttps else "None"],
                ["Tactics",      " → ".join(tactics) if tactics else "None"],
                ["Description",  f.get("description","")],
            ]

            # Add remediation steps
            rem = f.get("remediation")
            if rem and isinstance(rem, dict):
                steps = rem.get("steps",[])
                if steps:
                    detail_data.append([
                        "Remediation",
                        steps[0] if steps else "See documentation"
                    ])

            t = Table(detail_data, colWidths=[40*mm, 125*mm])
            t.setStyle(TableStyle([
                ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("PADDING",    (0,0), (-1,-1), 5),
                ("BACKGROUND", (0,0), (-1,-1), LIGHT_BG),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.white),
                ("BACKGROUND", (0,2), (-1,2),  color),
                ("TEXTCOLOR",  (0,2), (-1,2),  colors.white),
                ("FONTNAME",   (0,2), (-1,2),  "Helvetica-Bold"),
                ("LEFTPADDING",(0,0), (-1,-1), 8),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 5 * mm))

        return elements

    # ── MITRE section ─────────────────────────────────────────────────────────

    def _mitre_section(self, findings: list[dict]) -> list:
        elements = []
        elements.append(Paragraph(
            "MITRE ATT&CK® Coverage", self.st["h1"]
        ))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN))
        elements.append(Spacer(1, 4 * mm))

        elements.append(Paragraph(
            "The following ATT&CK techniques are enabled by open findings. "
            "Each technique represents an adversary capability that exists "
            "due to the identified misconfigurations.",
            self.st["body"]
        ))
        elements.append(Spacer(1, 4 * mm))

        # Collect all techniques
        tech_map: dict[str, dict] = {}
        for f in findings:
            if f.get("status") != "OPEN":
                continue
            for m in f.get("mitre", []):
                tid = m.get("technique_id","")
                if tid not in tech_map:
                    tech_map[tid] = {
                        "technique_id":   tid,
                        "technique_name": m.get("technique_name",""),
                        "tactic_name":    m.get("tactic_name",""),
                        "findings":       [],
                    }
                tech_map[tid]["findings"].append(f.get("title",""))

        if not tech_map:
            elements.append(Paragraph(
                "No active ATT&CK techniques identified.", self.st["body"]
            ))
            return elements

        mitre_data = [["Technique ID", "Technique Name", "Tactic", "Findings"]]
        for tid, info in sorted(tech_map.items()):
            mitre_data.append([
                tid,
                info["technique_name"],
                info["tactic_name"],
                str(len(info["findings"])),
            ])

        t = Table(
            mitre_data,
            colWidths=[28*mm, 65*mm, 45*mm, 27*mm]
        )
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), STEEL),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("PADDING",       (0,0), (-1,-1), 5),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [LIGHT_BG, colors.white]),
            ("FONTNAME",      (0,1), (0,-1),  "Helvetica-Bold"),
            ("TEXTCOLOR",     (0,1), (0,-1),  STEEL),
        ]))
        elements.append(t)

        return elements

    # ── Appendix ──────────────────────────────────────────────────────────────

    def _appendix(self, findings: list[dict]) -> list:
        elements = []
        elements.append(Paragraph(
            "Appendix — Complete Finding List", self.st["h1"]
        ))
        elements.append(HRFlowable(width="100%", thickness=1, color=CYAN))
        elements.append(Spacer(1, 4 * mm))

        table_data = [[
            "ID", "Severity", "Service", "Title", "Risk", "Status"
        ]]
        for f in sorted(
            findings,
            key=lambda x: (
                ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(
                    x.get("severity","INFO")
                )
            )
        ):
            table_data.append([
                f.get("id","")[:14],
                f.get("severity",""),
                f.get("service",""),
                f.get("title","")[:45] + ("..." if len(f.get("title","")) > 45 else ""),
                str(f.get("risk_score",0)),
                f.get("status",""),
            ])

        t = Table(
            table_data,
            colWidths=[22*mm, 20*mm, 15*mm, 75*mm, 12*mm, 21*mm]
        )
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), STEEL),
            ("TEXTCOLOR",     (0,0), (-1,0), colors.white),
            ("FONTNAME",      (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7),
            ("PADDING",       (0,0), (-1,-1), 4),
            ("GRID",          (0,0), (-1,-1), 0.3, MID_GRAY),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [LIGHT_BG, colors.white]),
        ]))
        elements.append(t)

        elements.append(Spacer(1, 10 * mm))
        elements.append(Paragraph(
            f"Report generated by CloudSentinel CSPM v2.1 · "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} · "
            f"github.com/GeekyBlessing/Cloudsentinel",
            self.st["footer"]
        ))

        return elements

    # ── Style definitions ─────────────────────────────────────────────────────

    def _build_styles(self) -> None:
        self.st = {
            "cover_title": ParagraphStyle(
                "cover_title",
                fontSize=32, fontName="Helvetica-Bold",
                textColor=NAVY, alignment=TA_LEFT,
                spaceAfter=4,
            ),
            "cover_sub": ParagraphStyle(
                "cover_sub",
                fontSize=13, fontName="Helvetica",
                textColor=CYAN, alignment=TA_LEFT,
                spaceAfter=2,
            ),
            "cover_org": ParagraphStyle(
                "cover_org",
                fontSize=14, fontName="Helvetica-Bold",
                textColor=DARK_GRAY, alignment=TA_LEFT,
                spaceBefore=6,
            ),
            "disclaimer": ParagraphStyle(
                "disclaimer",
                fontSize=8, fontName="Helvetica",
                textColor=MID_GRAY, alignment=TA_CENTER,
            ),
            "h1": ParagraphStyle(
                "h1",
                fontSize=18, fontName="Helvetica-Bold",
                textColor=NAVY, spaceBefore=8, spaceAfter=3,
            ),
            "h2": ParagraphStyle(
                "h2",
                fontSize=12, fontName="Helvetica-Bold",
                textColor=STEEL, spaceBefore=6, spaceAfter=2,
            ),
            "body": ParagraphStyle(
                "body",
                fontSize=9, fontName="Helvetica",
                textColor=DARK_GRAY, leading=14,
                spaceAfter=4,
            ),
            "footer": ParagraphStyle(
                "footer",
                fontSize=7, fontName="Helvetica",
                textColor=MID_GRAY, alignment=TA_CENTER,
            ),
        }