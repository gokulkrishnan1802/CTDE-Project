"""
Reports router.
GET /reports — list user reports.
GET /reports/{id} — get a specific report.
GET /reports/{id}/download — download PDF.
GET /reports/{id}/download.json — download JSON.
"""
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse

from auth import get_current_user
from database import get_db
from models import Investigation, User
from services.report import generate_json_report, generate_pdf_report

router = APIRouter(prefix="/reports", tags=["reports"])
Session = Any


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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    return inv.result_json or {}


def _owned_report_data(
    db: Session,
    report_id: str,
    current_user: User,
) -> tuple[Investigation, dict]:
    inv = db.query(Investigation).filter(
        Investigation.id == report_id,
        Investigation.user_id == current_user.id,
    ).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )

    data = dict(inv.result_json or {})
    data.update(
        {
            "caseId": inv.case_id,
            "investigator": current_user.full_name,
            "timestamp": inv.created_at.isoformat(),
        }
    )
    return inv, data


def _pdf_response(data: dict, inv: Investigation) -> FileResponse:
    pdf_path = generate_pdf_report(data, inv.case_id)
    path = Path(pdf_path)
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Report generation failed",
        )

    media_type = (
        "application/pdf"
        if path.suffix.lower() == ".pdf"
        else "application/json"
    )
    return FileResponse(path, media_type=media_type, filename=path.name)


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download the signed-in user's generated PDF report."""
    inv, data = _owned_report_data(db, report_id, current_user)
    return _pdf_response(data, inv)


@router.get("/{report_id}/download.json")
def download_json_report(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Download the signed-in user's investigation as JSON."""
    inv, data = _owned_report_data(db, report_id, current_user)
    json_path = generate_json_report(data, inv.case_id)
    path = Path(json_path)
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JSON report generation failed",
        )
    return FileResponse(
        path,
        media_type="application/json",
        filename=path.name,
    )


@router.post("/{report_id}/pdf")
def download_pdf(
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Keep the existing PDF-download endpoint working."""
    inv, data = _owned_report_data(db, report_id, current_user)
    return _pdf_response(data, inv)