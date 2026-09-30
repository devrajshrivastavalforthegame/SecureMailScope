from fastapi import FastAPI

from backend.app.api.evidence import router as evidence_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.reports import router as reports_router


app = FastAPI(
    title="SecureMailScope",
    description=(
        "AI-Assisted Cryptographic Security Posture Assessment "
        "for Secure Email Communications"
    ),
    version="0.1.0"
)


app.include_router(evidence_router)
app.include_router(analysis_router)
app.include_router(reports_router)


@app.get("/")
def root():
    return {
        "application": "SecureMailScope",
        "status": "running",
        "version": "0.1.0"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


