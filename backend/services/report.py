"""Create downloadable JSON and PDF investigation reports."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import settings

logger = logging.getLogger(__name__)


def ensure_reports_dir() -> Path:
    path = Path(settings.REPORTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def generate_json_report(investigation_data: dict, investigation_id: str) -> str:
    """Write investigation JSON to disk and return its path."""
    filepath = ensure_reports_dir() / f"CTDE_{investigation_id}_{_timestamp()}.json"
    with filepath.open("w", encoding="utf-8") as report_file:
        json.dump(investigation_data, report_file, indent=2, default=str)
    logger.info("JSON report saved: %s", filepath)
    return str(filepath)


def generate_pdf_report(investigation_data: dict, investigation_id: str) -> str:
    """Create a wrapped, paginated PDF report. Fall back to JSON on PDF errors."""
    try:
        from xml.sax.saxutils import escape

        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            KeepTogether,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

        output = ensure_reports_dir() / f"CTDE_{investigation_id}_{_timestamp()}.pdf"
        page_width, page_height = A4
        left = right = 18 * mm
        top = 34 * mm
        bottom = 20 * mm

        def safe(value: Any, fallback: str = "Not available") -> str:
            if value is None or value == "":
                value = fallback
            return escape(str(value)).replace("\n", "<br/>")

        def draw_page(canvas: Any, doc: Any) -> None:
            """Repeat the branded header and page number on every page."""
            canvas.saveState()
            canvas.setFillColor(colors.HexColor("#0a0e14"))
            canvas.rect(0, page_height - 27 * mm, page_width, 27 * mm, fill=1, stroke=0)
            canvas.setFillColor(colors.HexColor("#00d7e8"))
            canvas.setFont("Helvetica-Bold", 14)
            canvas.drawString(left, page_height - 12 * mm, "CyberTrust Decision Engine (CTDE)")
            canvas.setFillColor(colors.HexColor("#d1d5db"))
            canvas.setFont("Helvetica", 8)
            canvas.drawString(left, page_height - 19 * mm, "Digital Forensics Investigation Report")
            canvas.drawRightString(
                page_width - right,
                page_height - 19 * mm,
                f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
            )
            canvas.setStrokeColor(colors.HexColor("#d1d5db"))
            canvas.line(left, 14 * mm, page_width - right, 14 * mm)
            canvas.setFillColor(colors.HexColor("#6b7280"))
            canvas.setFont("Helvetica", 8)
            canvas.drawString(left, 9 * mm, "Department of Cyber Security - College Project")
            canvas.drawRightString(page_width - right, 9 * mm, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(output),
            pagesize=A4,
            leftMargin=left,
            rightMargin=right,
            topMargin=top,
            bottomMargin=bottom,
            title=f"CTDE Investigation Report {investigation_id}",
            author="CyberTrust Decision Engine",
        )

        styles = getSampleStyleSheet()
        section_style = ParagraphStyle(
            "CTDESection",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#007c9b"),
            spaceBefore=7,
            spaceAfter=4,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "CTDEBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            alignment=TA_LEFT,
            splitLongWords=True,
            wordWrap="CJK",
            spaceAfter=1,
        )
        label_style = ParagraphStyle(
            "CTDELabel",
            parent=body_style,
            fontName="Helvetica-Bold",
            backColor=colors.HexColor("#e8f4f6"),
        )

        ev = investigation_data or {}
        story: list[Any] = []

        def add_section(title: str, content: Any) -> None:
            text = str(content if content not in (None, "") else "Not available")
            safe_lines = "<br/>".join(safe(line) for line in text.splitlines())
            story.append(KeepTogether([
                Paragraph(safe(title), section_style),
                Paragraph(safe_lines or "Not available", body_style),
                Spacer(1, 2 * mm),
            ]))

        # Paragraph objects ensure long email headers and evidence values wrap
        # within their cells instead of stretching the table beyond the page.
        case_rows = [
            [Paragraph("Case ID", label_style), Paragraph(safe(ev.get("caseId")), body_style),
             Paragraph("Risk level", label_style), Paragraph(safe(ev.get("riskLevel")), body_style)],
            [Paragraph("Evidence type", label_style), Paragraph(safe(ev.get("evidenceType", "N/A")).upper(), body_style),
             Paragraph("Trust score", label_style), Paragraph(f"{safe(ev.get('trustScore', 0))}/100", body_style)],
            [Paragraph("Evidence", label_style), Paragraph(safe(ev.get("evidenceValue")), body_style),
             Paragraph("Calibration", label_style), Paragraph("Not benchmarked", body_style)],
            [Paragraph("Timestamp", label_style), Paragraph(safe(ev.get("timestamp", _timestamp())), body_style),
             Paragraph("Investigator", label_style), Paragraph(safe(ev.get("investigator", "CTDE System")), body_style)],
        ]
        case_table = Table(
            case_rows,
            colWidths=[27 * mm, 65 * mm, 25 * mm, 37 * mm],
            repeatRows=0,
            hAlign="LEFT",
        )
        case_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([Paragraph("Case Details", section_style), case_table, Spacer(1, 4 * mm)])

        add_section("Evidence Summary", ev.get("evidenceSummary", "Not available"))
        add_section(
            "Assessment Limitations",
            "The trust score is a heuristic score, not a probability or measured accuracy. "
            "Findings depend on the evidence and external checks available for this investigation. "
            "A risk label alone does not confirm malicious activity.",
        )

        processing = ev.get("evidenceProcessing") or {}
        if processing:
            summary = processing.get("summary") or {}
            lines = [
                f"Status: {'Completed' if processing.get('processed') else 'Failed'}",
                f"Indicators: {summary.get('totalIndicators', 0)}",
                f"Relationships: {summary.get('totalRelationships', 0)}",
            ]
            if processing.get("error"):
                lines.append(f"Processing error: {processing['error']}")
            for kind, values in (processing.get("indicators") or {}).items():
                items = values if isinstance(values, list) else []
                lines.append(f"{kind}: {', '.join(map(str, items)) if items else 'None'}")
            for relation in processing.get("relationships") or []:
                lines.append(
                    f"{relation.get('source', 'Unknown')} -> "
                    f"{str(relation.get('relationship', 'related')).replace('_', ' ')} -> "
                    f"{relation.get('target', 'Unknown')}"
                )
            correlation = processing.get("crossInvestigationCorrelation") or {}
            if correlation:
                lines.extend([
                    f"Cross-investigation status: {correlation.get('status', 'unknown')}",
                    f"Prior investigations searched: {correlation.get('searchedInvestigations', 0)}",
                    f"Prior investigation matches: {correlation.get('matchCount', 0)}",
                ])
                for match in correlation.get("matches") or []:
                    shared = ", ".join(
                        f"{item.get('type', 'indicator')}: {item.get('value', '')}"
                        for item in (match.get("matchingIndicators") or [])
                    ) or "None"
                    lines.append(
                        f"{match.get('caseId', 'Unknown case')} "
                        f"({match.get('evidenceType', 'unknown')}, {match.get('riskLevel', 'unknown')}) "
                        f"shared: {shared}"
                    )
            add_section("Evidence Processing & Correlation", "\n".join(lines))

        for title, key in (
            ("Identity Verification", "identityVerification"),
            ("Domain Verification", "domainVerification"),
            ("Certificate Validation", "certificateValidation"),
            ("WHOIS Information", "whoisInfo"),
            ("Brand Impersonation Analysis", "brandImpersonation"),
            ("URL Analysis", "urlAnalysis"),
            ("Reputation Analysis", "reputationAnalysis"),
        ):
            add_section(title, ev.get(key, "Not available"))

        for title, key in (
            ("APK Permission Analysis", "apkPermissionAnalysis"),
            ("Sender Verification", "senderVerification"),
            ("QR Destination Verification", "qrVerification"),
        ):
            if ev.get(key):
                add_section(title, ev[key])

        mitre = ev.get("mitreMapping") or []
        add_section("MITRE ATT&CK Mapping", "\n".join(map(str, mitre)) if mitre else "No techniques mapped.")
        add_section("AI Explanation", ev.get("aiExplanation", "Not available"))
        add_section("AI Summary", ev.get("aiSummary", "Not available"))

        recommendations = ev.get("recommendations") or []
        add_section(
            "Recommendations",
            "\n".join(f"{index}. {item}" for index, item in enumerate(recommendations, 1))
            if recommendations else "No recommendations were generated.",
        )

        panel = ev.get("evidencePanel") or {}
        if panel:
            rows = [[Paragraph("Field", label_style), Paragraph("Value", label_style)]]
            rows.extend(
                [Paragraph(safe(key), body_style), Paragraph(safe(value), body_style)]
                for key, value in panel.items()
            )
            panel_table = Table(rows, colWidths=[42 * mm, 112 * mm], repeatRows=1)
            panel_table.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8f4f6")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.extend([Paragraph("Evidence Panel", section_style), panel_table, Spacer(1, 2 * mm)])

        timeline = ev.get("timeline") or []
        if timeline:
            add_section(
                "Investigation Timeline",
                "\n".join(
                    f"{item.get('timestamp', 'Time unavailable')} - {item.get('label', 'Event')}"
                    for item in timeline
                ),
            )

        doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
        logger.info("PDF report saved: %s", output)
        return str(output)
    except ImportError:
        logger.exception("ReportLab not installed; returning JSON report instead")
        return generate_json_report(investigation_data, investigation_id)
    except Exception as exc:
        logger.exception("PDF generation failed; returning JSON report: %s", exc)
        return generate_json_report(investigation_data, investigation_id)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
