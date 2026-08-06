"""
Report generation service.
Produces PDF and JSON reports using ReportLab.
"""
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from config import settings

logger = logging.getLogger(__name__)


def ensure_reports_dir() -> Path:
    path = Path(settings.REPORTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate_json_report(investigation_data: dict, investigation_id: str) -> str:
    """Write investigation JSON to disk and return the file path."""
    reports_dir = ensure_reports_dir()
    filename = f"CTDE_{investigation_id}_{_timestamp()}.json"
    filepath = reports_dir / filename

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(investigation_data, f, indent=2, default=str)

    logger.info("JSON report saved: %s", filepath)
    return str(filepath)


def generate_pdf_report(investigation_data: dict, investigation_id: str) -> str:
    """Generate a structured PDF forensic report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

        reports_dir = ensure_reports_dir()
        filename = f"CTDE_{investigation_id}_{_timestamp()}.pdf"
        filepath = reports_dir / filename

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=A4,
            rightMargin=20 * mm,
            leftMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        styles = getSampleStyleSheet()
        dark = colors.HexColor("#0a0e14")
        cyan = colors.HexColor("#00bcd4")
        gray = colors.HexColor("#6b7280")

        title_style = ParagraphStyle("Title", parent=styles["Title"], fontSize=18, textColor=cyan, spaceAfter=4)
        subtitle_style = ParagraphStyle("Sub", parent=styles["Normal"], fontSize=9, textColor=gray, spaceAfter=12)
        h2_style = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=12, textColor=cyan, spaceBefore=10, spaceAfter=4)
        body_style = ParagraphStyle("Body", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#374151"), leading=14)
        mono_style = ParagraphStyle("Mono", parent=styles["Normal"], fontSize=8, fontName="Courier", textColor=colors.HexColor("#374151"), leading=12)

        story = []

        # Header
        story.append(Paragraph("CyberTrust Decision Engine (CTDE)", title_style))
        story.append(Paragraph("Digital Forensics Investigation Report — AI-Assisted Analysis", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1, color=cyan))
        story.append(Spacer(1, 6 * mm))

        # Case summary table
        ev = investigation_data
        case_data = [
            ["Case ID", ev.get("caseId", "N/A"), "Risk Level", ev.get("riskLevel", "N/A")],
            ["Evidence Type", ev.get("evidenceType", "N/A").upper(), "Trust Score", f"{ev.get('trustScore', 0)}/100"],
            ["Evidence", ev.get("evidenceValue", "N/A"), "Confidence", f"{ev.get('confidence', 90)}%"],
            ["Timestamp", ev.get("timestamp", _timestamp()), "Investigator", ev.get("investigator", "CTDE System")],
        ]
        t = Table(case_data, colWidths=[40 * mm, 65 * mm, 35 * mm, 35 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5f3f6")),
            ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#e5f3f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
        story.append(Spacer(1, 6 * mm))

        # Analysis sections
        def add_section(title: str, content: str):
            story.append(Paragraph(title, h2_style))
            story.append(Paragraph(content.replace("\n", "<br/>"), body_style))
            story.append(Spacer(1, 3 * mm))

        add_section("Evidence Summary", ev.get("evidenceSummary", "N/A"))
        add_section("Identity Verification", ev.get("identityVerification", "N/A"))
        add_section("Domain Verification", ev.get("domainVerification", "N/A"))
        add_section("Certificate Validation", ev.get("certificateValidation", "N/A"))
        add_section("WHOIS Information", ev.get("whoisInfo", "N/A"))
        add_section("Brand Impersonation Analysis", ev.get("brandImpersonation", "N/A"))
        add_section("URL Analysis", ev.get("urlAnalysis", "N/A"))
        if ev.get("apkPermissionAnalysis"):
            add_section("APK Permission Analysis", ev["apkPermissionAnalysis"])
        if ev.get("senderVerification"):
            add_section("Sender Verification", ev["senderVerification"])
        if ev.get("qrVerification"):
            add_section("QR Destination Verification", ev["qrVerification"])
        add_section("Reputation Analysis", ev.get("reputationAnalysis", "N/A"))

        # MITRE ATT&CK
        story.append(Paragraph("MITRE ATT&CK Mapping", h2_style))
        mitre = ev.get("mitreMapping", [])
        if mitre:
            for m in mitre:
                story.append(Paragraph(f"• {m}", body_style))
        else:
            story.append(Paragraph("No MITRE techniques mapped.", body_style))
        story.append(Spacer(1, 3 * mm))

        add_section("AI Explanation", ev.get("aiExplanation", "N/A"))
        add_section("AI Summary", ev.get("aiSummary", "N/A"))

        # Recommendations
        story.append(Paragraph("Recommendations", h2_style))
        recs = ev.get("recommendations", [])
        for i, rec in enumerate(recs, 1):
            story.append(Paragraph(f"{i}. {rec}", body_style))
        story.append(Spacer(1, 3 * mm))

        # Evidence Panel
        story.append(Paragraph("Evidence Panel", h2_style))
        panel = ev.get("evidencePanel", {})
        panel_rows = [[k, str(v)] for k, v in panel.items()]
        if panel_rows:
            pt = Table(panel_rows, colWidths=[50 * mm, 115 * mm])
            pt.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(pt)

        doc.build(story)
        logger.info("PDF report saved: %s", filepath)
        return str(filepath)

    except ImportError:
        logger.error("ReportLab not installed — PDF generation unavailable")
        return generate_json_report(investigation_data, investigation_id)
    except Exception as exc:
        logger.error("PDF generation error: %s", exc)
        return generate_json_report(investigation_data, investigation_id)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
