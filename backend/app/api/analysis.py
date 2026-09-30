from fastapi import APIRouter, HTTPException

from backend.app.services.analysis_service import (
    analyze_case,
)


router = APIRouter(
    prefix="/api/analysis",
    tags=["Analysis"],
)


@router.post("/{case_id}")
def run_analysis(case_id: str):
    try:
        return analyze_case(case_id)

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {exc}",
        )
