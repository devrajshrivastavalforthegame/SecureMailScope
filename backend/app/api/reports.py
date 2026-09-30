from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.app.services.report_service import generate_pdf_report

router = APIRouter(
    prefix="/api/reports",
    tags=["reports"],
)


@router.get("/{case_id}/pdf")
def download_pdf_report(case_id: str):
    try:
        pdf_path = generate_pdf_report(case_id)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate PDF report: {exc}",
        ) from exc

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name,
    )
