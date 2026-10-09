"""
Report generation service.
Produces PDF and JSON reports using ReportLab.
"""
import json
import logging
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

    with open(filepath, "w", encoding="utf-8") as report_file:
        json.dump(investigation_data, report_file, indent=2, default=str)

    logger.info("JSON report saved: %s", filepath)
    return str(filepath)


def generate_pdf_report(investigation_data: dict, investigation_id: str) -> str:
    """Generate a structured PDF forensic report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
        from xml.sax.saxutils import escape

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
        cyan = colors.HexColor("#00bcd4")
        gray = colors.HexColor("#6b7280")

        title_style = ParagraphStyle(
            "CTDETitle",
            parent=styles["Title"],
            fontSize=18,
            textColor=cyan,
            spaceAfter=4,
        )
        subtitle_style = ParagraphStyle(
            "CTDESubtitle",
            parent=styles["Normal"],
            fontSize=9,
            textColor=gray,
            spaceAfter=12,
        )
        heading_style = ParagraphStyle(
            "CTDEHeading",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=cyan,
            spaceBefore=10,
            spaceAfter=4,
        )
        body_style = ParagraphStyle(
            "CTDEBody",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#374151"),
            leading=14,
        )

        story = [
            Paragraph("CyberTrust Decision Engine (CTDE)", title_style),
            Paragraph(
                "Digital Forensics Investigation Report — Automated Evidence Analysis",
                subtitle_style,
            ),
            HRFlowable(width="100%", thickness=1, color=cyan),
            Spacer(1, 6 * mm),
        ]

        ev = investigation_data
        case_data = [
            ["Case ID", ev.get("caseId", "N/A"), "Risk Level", ev.get("riskLevel", "N/A")],
            [
                "Evidence Type",
                str(ev.get("evidenceType", "N/A")).upper(),
                "Trust Score",
                f"{ev.get('trustScore', 0)}/100",
            ],
            ["Evidence", ev.get("evidenceValue", "N/A"), "Calibration", "Not benchmarked"],
            [
                "Timestamp",
                ev.get("timestamp", _timestamp()),
                "Investigator",
                ev.get("investigator", "CTDE System"),
            ],
        ]
        summary_table = Table(
            case_data,
            colWidths=[35 * mm, 60 * mm, 30 * mm, 45 * mm],
        )
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e5f3f6")),
                    ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#e5f3f6")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("PADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.extend([summary_table, Spacer(1, 6 * mm)])

        def add_section(title: str, content: object) -> None:
            """Add escaped text so evidence cannot be interpreted as PDF markup."""
            story.append(Paragraph(escape(str(title)), heading_style))
            safe_content = escape(str(content)).replace("\n", "<br/>")
            story.append(Paragraph(safe_content, body_style))
            story.append(Spacer(1, 3 * mm))

        add_section("Evidence Summary", ev.get("evidenceSummary", "N/A"))
        add_section(
            "Assessment Limitations",
            "The trust score is a heuristic score, not a probability or measured accuracy. "
            "Findings depend on the evidence and external checks available for this investigation. "
            "A risk label is not, by itself, confirmation of malicious activity.",
        )

        processing = ev.get("evidenceProcessing") or {}
        if processing:
            indicators = processing.get("indicators") or {}
            relationships = processing.get("relationships") or []
            processing_lines = [
                f"Status: {'Completed' if processing.get('processed') else 'Failed'}",
                f"Indicators: {(processing.get('summary') or {}).get('totalIndicators', 0)}",
                f"Relationships: {(processing.get('summary') or {}).get('totalRelationships', 0)}",
            ]

            if processing.get("error"):
                processing_lines.append(f"Error: {processing['error']}")

            for kind, values in indicators.items():
                processing_lines.append(
                    f"{kind}: {', '.join(map(str, values)) if values else 'None'}"
                )

            for item in relationships:
                processing_lines.append(
                    f"{item.get('source', 'Unknown')} -> "
                    f"{str(item.get('relationship', 'related')).replace('_', ' ')} -> "
                    f"{item.get('target', 'Unknown')}"
                )

            cross_correlation = processing.get("crossInvestigationCorrelation") or {}
            if cross_correlation:
                processing_lines.extend(
                    [
                        "Cross-investigation status: "
                        f"{cross_correlation.get('status', 'unknown')}",
                        "Prior investigations searched: "
                        f"{cross_correlation.get('searchedInvestigations', 0)}",
                        "Prior investigation matches: "
                        f"{cross_correlation.get('matchCount', 0)}",
                    ]
                )
                for match in cross_correlation.get("matches", []):
                    shared = ", ".join(
                        f"{item.get('type', 'indicator')}: {item.get('value', '')}"
                        for item in match.get("matchingIndicators", [])
                    )
                    processing_lines.append(
                        f"{match.get('caseId', 'Unknown case')} "
                        f"({match.get('evidenceType', 'unknown')}, "
                        f"{match.get('riskLevel', 'unknown')}) shared: {shared}"
                    )

            add_section(
                "Evidence Processing & Correlation",
                "\n".join(processing_lines),
            )

        for title, key in [
            ("Identity Verification", "identityVerification"),
            ("Domain Verification", "domainVerification"),
            ("Certificate Validation", "certificateValidation"),
            ("WHOIS Information", "whoisInfo"),
            ("Brand Impersonation Analysis", "brandImpersonation"),
            ("URL Analysis", "urlAnalysis"),
            ("Reputation Analysis", "reputationAnalysis"),
        ]:
            add_section(title, ev.get(key, "N/A"))

        for title, key in [
            ("APK Permission Analysis", "apkPermissionAnalysis"),
            ("Sender Verification", "senderVerification"),
            ("QR Destination Verification", "qrVerification"),
        ]:
            if ev.get(key):
                add_section(title, ev[key])

        story.append(Paragraph("MITRE ATT&amp;CK Mapping", heading_style))
        mitre = ev.get("mitreMapping", [])
        if mitre:
            for technique in mitre:
                story.append(Paragraph(f"• {escape(str(technique))}", body_style))
        else:
            story.append(Paragraph("No MITRE techniques mapped.", body_style))
        story.append(Spacer(1, 3 * mm))

        add_section("AI Explanation", ev.get("aiExplanation", "N/A"))
        add_section("AI Summary", ev.get("aiSummary", "N/A"))

        story.append(Paragraph("Recommendations", heading_style))
        for index, recommendation in enumerate(ev.get("recommendations", []), start=1):
            story.append(
                Paragraph(f"{index}. {escape(str(recommendation))}", body_style)
            )
        story.append(Spacer(1, 3 * mm))

        panel = ev.get("evidencePanel") or {}
        if panel:
            story.append(Paragraph("Evidence Panel", heading_style))
            panel_rows = [
                [escape(str(key)), escape(str(value))]
                for key, value in panel.items()
            ]
            panel_table = Table(panel_rows, colWidths=[50 * mm, 115 * mm])
            panel_table.setStyle(
                TableStyle(
                    [
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                        ("PADDING", (0, 0), (-1, -1), 4),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]
                )
            )
            story.append(panel_table)

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