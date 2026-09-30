from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from backend.app.services.report_service import generate_pdf_report


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/reports",
    tags=["reports"],
)

CASE_ID_PATTERN = re.compile(
    r"^CASE-\d{8}-[A-F0-9]{8}$"
)


def validate_case_id(case_id: str) -> str:
    if not CASE_ID_PATTERN.fullmatch(case_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid case ID.",
        )

    return case_id


@router.get("/{case_id}/pdf")
def download_pdf_report(case_id: str):
    case_id = validate_case_id(case_id)

    try:
        pdf_path = generate_pdf_report(case_id)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Analysis report not found.",
        )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Unable to generate the requested report.",
        )

    except Exception:
        logger.exception(
            "Unexpected PDF generation failure for case %s",
            case_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Report generation failed.",
        )

    return FileResponse(
        path=str(pdf_path),
        media_type="application/pdf",
        filename=pdf_path.name,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": (
                f'attachment; filename="{pdf_path.name}"'
            ),
        },
    )
