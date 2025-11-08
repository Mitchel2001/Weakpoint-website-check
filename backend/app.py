from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

from .scanner import run_scan


class ScanRequest(BaseModel):
    url: HttpUrl


app = FastAPI(
    title="WeakPoint Security Scanner API",
    description="API-laag bovenop de Python scanner. Niet-intrusief bedoeld.",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz", tags=["meta"])
def healthcheck():
    return {"status": "ok"}


@app.post("/api/scan", tags=["scan"])
def scan(payload: ScanRequest):
    try:
        report = run_scan(str(payload.url))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return report
