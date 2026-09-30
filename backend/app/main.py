from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from backend.app.api.evidence import router as evidence_router
from backend.app.api.analysis import router as analysis_router
from backend.app.api.reports import router as reports_router


app = FastAPI(
    title="SecureMailScope",
    description=(
        "AI-Assisted Cryptographic Security Posture Assessment "
        "for Secure Email Communications"
    ),
    version="0.1.0",
)


# Only allow the local React development server to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=[
        "GET",
        "POST",
        "OPTIONS",
    ],
    allow_headers=[
        "Accept",
        "Content-Type",
    ],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response: Response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

    return response


app.include_router(evidence_router)
app.include_router(analysis_router)
app.include_router(reports_router)


@app.get("/")
def root():
    return {
        "application": "SecureMailScope",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
    }
