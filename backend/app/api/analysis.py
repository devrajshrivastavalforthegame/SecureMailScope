from __future__ import annotations

import logging
import re

from fastapi import APIRouter, HTTPException

from backend.app.services.analysis_service import analyze_case


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/analysis",
    tags=["Analysis"],
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


@router.post("/{case_id}")
def run_analysis(case_id: str):
    case_id = validate_case_id(case_id)

    try:
        return analyze_case(case_id)

    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail="Case or evidence not found.",
        )

    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Unable to analyze the supplied evidence.",
        )

    except Exception:
        logger.exception(
            "Unexpected analysis failure for case %s",
            case_id,
        )

        raise HTTPException(
            status_code=500,
            detail="Analysis service failed.",
        )
