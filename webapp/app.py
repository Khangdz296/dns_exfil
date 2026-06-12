"""FastAPI application for the DNS exfiltration detector dashboard."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from webapp.job_manager import AGENT_ORDER, PROJECT_ROOT, manager


STATIC_DIR = Path(__file__).resolve().parent / "static"
AGENTS_DIR = PROJECT_ROOT / ".pi" / "agents"

app = FastAPI(
    title="Pi DNS Exfiltration Dashboard",
    version="1.0.0",
    description="Web monitor for the Pi multi-agent DNS detection pipeline.",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class CaptureRequest(BaseModel):
    interface: str | None = None
    timeout: int = Field(default=30, ge=5, le=300)
    max_packets: int = Field(default=1000, ge=1, le=10_000)


def read_agent_description(config_path: Path) -> str:
    """Read the folded description field from Pi agent front matter."""
    if not config_path.exists():
        return ""

    lines = config_path.read_text(encoding="utf-8").splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("description:"):
            continue
        inline = line.partition(":")[2].strip()
        if inline and inline != ">":
            return inline

        description_lines = []
        for candidate in lines[index + 1 :]:
            if candidate.startswith((" ", "\t")):
                description_lines.append(candidate.strip())
            else:
                break
        return " ".join(description_lines)
    return ""


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/agents")
def agents() -> list[dict[str, Any]]:
    result = []
    for order, agent_name in enumerate(AGENT_ORDER, 1):
        config_path = AGENTS_DIR / f"{agent_name}.md"
        result.append(
            {
                "name": agent_name,
                "order": order,
                "stage": 1 if order <= 2 else 2 if order <= 5 else 3,
                "parallel": 3 <= order <= 5,
                "description": read_agent_description(config_path),
                "configured": config_path.exists(),
            }
        )
    return result


@app.post("/api/jobs", status_code=202)
def create_job(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        return manager.save_upload(file.filename or "", file.file).public_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        file.file.close()


@app.get("/api/interfaces")
def interfaces() -> dict[str, Any]:
    return manager.list_interfaces()


@app.post("/api/captures", status_code=202)
def create_capture(request: CaptureRequest) -> dict[str, Any]:
    try:
        return manager.start_capture(
            request.interface,
            request.timeout,
            request.max_packets,
        ).public_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.delete("/api/captures/{job_id}", status_code=202)
def stop_capture(job_id: str) -> dict[str, Any]:
    try:
        return manager.stop_capture(job_id).public_dict()
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/jobs")
def list_jobs() -> list[dict[str, Any]]:
    return manager.list_jobs()


def require_job(job_id: str):
    job = manager.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    return require_job(job_id).public_dict()


@app.get("/api/jobs/{job_id}/scores")
def get_scores(job_id: str, limit: int = 100) -> dict[str, Any]:
    job = require_job(job_id)
    scores_path = job.job_dir / "output" / "scores.json"
    if not scores_path.exists():
        raise HTTPException(status_code=404, detail="Scores are not available yet.")
    try:
        scores = json.loads(scores_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail="Could not read scores.") from exc
    if not isinstance(scores, list):
        raise HTTPException(status_code=500, detail="Scores must be a JSON array.")

    try:
        ordered = sorted(
            scores,
            key=lambda item: float(item.get("combined_score", 0.0)),
            reverse=True,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=500, detail="Scores contain invalid records.") from exc
    safe_limit = max(1, min(limit, 1000))
    return {"total": len(ordered), "items": ordered[:safe_limit]}


@app.get("/api/jobs/{job_id}/report")
def get_report(job_id: str) -> dict[str, str]:
    job = require_job(job_id)
    report_path = job.job_dir / "output" / "exfil_report.md"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report is not available yet.")
    return {"markdown": report_path.read_text(encoding="utf-8")}


@app.get("/api/jobs/{job_id}/capture")
def download_capture(job_id: str) -> FileResponse:
    job = require_job(job_id)
    capture_path = job.input_path
    if job.mode != "live" or not capture_path.exists():
        raise HTTPException(status_code=404, detail="Captured PCAP is not available.")
    return FileResponse(
        capture_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"dns-capture-{job.id}.pcap",
    )


@app.websocket("/ws/jobs/{job_id}")
async def job_events(websocket: WebSocket, job_id: str) -> None:
    await websocket.accept()
    try:
        while True:
            job = manager.get(job_id)
            if job is None:
                await websocket.send_json({"error": "Job not found."})
                return
            await websocket.send_json(job.public_dict())
            if job.status in {"completed", "failed"}:
                return
            await asyncio.sleep(0.75)
    except WebSocketDisconnect:
        return
