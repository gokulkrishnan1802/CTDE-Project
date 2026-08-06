"""
Reports router.
GET /reports — list user reports.
GET /reports/{id} — get a specific report.
GET /reports/{id}/download — download PDF.
"""
import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import User, Investigation, Report
from schemas import ReportOut
from services.report import generate_pdf_report, generate_json_report

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("", response_model=list[dict])
def list_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    investigations = (
        db.query(Investigation)
        .filter(Investigation.user_id == current_user.id)
        .order_by(Investigation.created_at.desc())
        .all()
    )
    return [
        {
            "id": inv.id,
            "caseId": inv.case_id,
            "evidenceType": inv.evidence_type,
            "evidenceValue": inv.evidence_value,
            "trustScore": inv.trust_score,
            "riskLevel": inv.risk_level,
            "createdAt": inv.created_at.isoformat(),
        }
        for inv in investigations
    ]


@router.get("/{report_id}", response_model=dict)
def get_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    inv = db.query(Investigation).filter(
        Investigation.id == report_id,
        Investigation.user_id == current_user.id,
    ).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return inv.result_json or {}


@router.post("/{report_id}/pdf")
def download_pdf(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    inv = db.query(Investigation).filter(
        Investigation.id == report_id,
        Investigation.user_id == current_user.id,
    ).first()
    if not inv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    data = inv.result_json or {}
    data["caseId"] = inv.case_id
    data["investigator"] = current_user.full_name
    data["timestamp"] = inv.created_at.isoformat()

    pdf_path = generate_pdf_report(data, inv.case_id)
    path = Path(pdf_path)
    if not path.exists():
        raise HTTPException(status_code=500, detail="PDF generation failed")
    return FileResponse(path, media_type="application/pdf", filename=path.name)
