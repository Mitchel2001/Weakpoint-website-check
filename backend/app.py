from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from queue import Queue
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
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


@app.get("/api/scan/stream", tags=["scan"])
def scan_stream(url: HttpUrl):
    event_queue: "Queue[Optional[dict]]" = Queue()

    def progress(event: dict) -> None:
        enriched = {
            **event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        event_queue.put(enriched)

    def worker() -> None:
        try:
            report = run_scan(str(url), progress_callback=progress)
            event_queue.put(
                {
                    "type": "report",
                    "report": report,
                    "progress": 100,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        except Exception as exc:
            event_queue.put(
                {
                    "type": "error",
                    "message": str(exc),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        finally:
            event_queue.put(None)

    threading.Thread(target=worker, daemon=True).start()

    def event_stream():
        while True:
            item = event_queue.get()
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")
