from fastapi import APIRouter, UploadFile, File, HTTPException

from backend.app.services.evidence_service import save_evidence


router = APIRouter(
    prefix="/api/evidence",
    tags=["Evidence"]
)


@router.post("/upload")
async def upload_evidence(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file supplied."
        )

    try:
        case = await save_evidence(file)

        return {
            "success": True,
            "message": "PCAP evidence uploaded successfully.",
            "case": case
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        )

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Evidence processing failed: {exc}"
        )
