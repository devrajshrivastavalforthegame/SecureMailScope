from __future__ import annotations

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.app.services.evidence_service import save_evidence


router = APIRouter(
    prefix="/api/evidence",
    tags=["Evidence"],
)


@router.post("/upload")
async def upload_evidence(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file supplied.",
        )

    try:
        case = await save_evidence(file)

        return {
            "success": True,
            "message": "PCAP evidence uploaded successfully.",
            "case": case,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Evidence processing failed.",
        )
