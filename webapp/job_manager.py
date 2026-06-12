"""Background pipeline jobs used by the FastAPI dashboard."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO


PROJECT_ROOT = Path(__file__).resolve().parents[1]
JOBS_ROOT = PROJECT_ROOT / "data" / "web_jobs"
STAGE1_OUTPUT = PROJECT_ROOT / "data" / "output"
PIPELINE_OUTPUT = PROJECT_ROOT / "outputs"
ALLOWED_SUFFIXES = {".pcap", ".pcapng", ".csv"}
MAX_UPLOAD_BYTES = 512 * 1024 * 1024
MIN_CAPTURE_SECONDS = 5
MAX_CAPTURE_SECONDS = 300
MIN_CAPTURE_PACKETS = 1
MAX_CAPTURE_PACKETS = 10_000
LIVE_DNS_FILTER = "udp dst port 53 or tcp dst port 53"

AGENT_ORDER = (
    "pcap_reader_agent",
    "dns_extractor_agent",
    "entropy_agent",
    "dga_classifier_agent",
    "embedding_agent",
    "orchestrator_agent",
    "report_agent",
)

OUTPUT_FILES = (
    "raw_packets.json",
    "dns_queries.json",
    "entropy_scores.json",
    "dga_scores.json",
    "embed_scores.json",
    "scores.json",
    "exfil_report.md",
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def output_run_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S_%f")


def safe_upload_name(filename: str) -> str:
    """Return a basename suitable for a job input directory."""
    name = Path((filename or "").replace("\\", "/")).name
    if not name or name in {".", ".."}:
        raise ValueError("A valid input filename is required.")
    if Path(name).suffix.lower() not in ALLOWED_SUFFIXES:
        raise ValueError("Only .pcap, .pcapng, and .csv files are supported.")
    return name


def initial_agents(mode: str) -> dict[str, str]:
    agents = {agent: "pending" for agent in AGENT_ORDER}
    if mode == "csv":
        agents["pcap_reader_agent"] = "skipped"
    return agents


@dataclass
class PipelineJob:
    id: str
    filename: str
    mode: str
    input_path: Path
    job_dir: Path
    status: str = "queued"
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    logs: list[str] = field(default_factory=list)
    agents: dict[str, str] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    capture: dict[str, Any] = field(default_factory=dict)
    output_run_id: str | None = None

    def public_dict(self, include_logs: bool = True) -> dict[str, Any]:
        payload = {
            "id": self.id,
            "filename": self.filename,
            "mode": self.mode,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "agents": dict(self.agents),
            "summary": dict(self.summary),
            "capture": dict(self.capture),
            "output_run_id": self.output_run_id,
        }
        if include_logs:
            payload["logs"] = list(self.logs[-500:])
        return payload


def apply_log_event(job: PipelineJob, line: str) -> None:
    """Update agent state from the runner's structured lifecycle logs."""
    job.logs.append(line)
    if "SUBAGENT START | " in line:
        agent = line.split("SUBAGENT START | ", 1)[1].split(" |", 1)[0].strip()
        if agent in job.agents:
            job.agents[agent] = "running"
    elif "SUBAGENT END | " in line:
        agent = line.split("SUBAGENT END | ", 1)[1].split(" |", 1)[0].strip()
        if agent in job.agents:
            job.agents[agent] = "completed"
    elif "SUBAGENT FAILED | " in line:
        agent = line.split("SUBAGENT FAILED | ", 1)[1].split(" |", 1)[0].strip()
        if agent in job.agents:
            job.agents[agent] = "failed"


def summarize_scores(scores_path: Path) -> dict[str, Any]:
    if not scores_path.exists():
        return {}
    try:
        records = json.loads(scores_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(records, list):
        return {}

    suspected = [item for item in records if item.get("verdict") == "suspected"]
    highest = max(
        (float(item.get("combined_score", 0.0)) for item in records),
        default=0.0,
    )
    return {
        "total_queries": len(records),
        "suspected_count": len(suspected),
        "highest_risk_score": round(highest, 4),
    }


def parse_tcpdump_interfaces(output: str) -> list[dict[str, str]]:
    """Parse tcpdump -D output while using its stable numeric selector."""
    interfaces = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or "." not in stripped:
            continue
        identifier, label = stripped.split(".", 1)
        if not identifier.isdigit() or not label.strip():
            continue
        interfaces.append({"id": identifier, "label": label.strip()})
    return interfaces


def validate_capture_options(timeout: int, max_packets: int) -> None:
    if not MIN_CAPTURE_SECONDS <= timeout <= MAX_CAPTURE_SECONDS:
        raise ValueError(
            f"Capture duration must be from {MIN_CAPTURE_SECONDS} "
            f"to {MAX_CAPTURE_SECONDS} seconds."
        )
    if not MIN_CAPTURE_PACKETS <= max_packets <= MAX_CAPTURE_PACKETS:
        raise ValueError(
            f"Packet limit must be from {MIN_CAPTURE_PACKETS} "
            f"to {MAX_CAPTURE_PACKETS}."
        )


def validate_interface(interface: str | None) -> str | None:
    if interface is None:
        return None
    normalized = interface.strip()
    if not normalized or normalized == "default":
        return None
    if len(normalized) > 128 or any(char in normalized for char in "\r\n\0"):
        raise ValueError("The capture interface is invalid.")
    return normalized


class JobManager:
    """Own pipeline jobs and serialize access to shared Stage 1 output."""

    def __init__(self, jobs_root: Path = JOBS_ROOT) -> None:
        self.jobs_root = jobs_root
        self.jobs_root.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, PipelineJob] = {}
        self._lock = threading.RLock()
        self._pipeline_lock = threading.Lock()
        self._capture_processes: dict[str, subprocess.Popen[str]] = {}
        self._active_capture_id: str | None = None

    def list_interfaces(self) -> dict[str, Any]:
        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            return {
                "available": False,
                "detail": "tcpdump executable was not found.",
                "interfaces": [],
            }
        try:
            result = subprocess.run(
                [tcpdump, "-D"],
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"available": False, "detail": str(exc), "interfaces": []}

        interfaces = parse_tcpdump_interfaces(result.stdout)
        if result.returncode != 0 or not interfaces:
            detail = result.stderr.strip() or "No capture interfaces were found."
            return {"available": False, "detail": detail, "interfaces": []}
        return {"available": True, "detail": "", "interfaces": interfaces}

    def save_upload(self, filename: str, source: BinaryIO) -> PipelineJob:
        safe_name = safe_upload_name(filename)
        mode = "csv" if Path(safe_name).suffix.lower() == ".csv" else "pcap"
        job_id = uuid.uuid4().hex[:12]
        job_dir = self.jobs_root / job_id
        input_dir = job_dir / "input"
        input_dir.mkdir(parents=True)
        input_path = input_dir / safe_name

        total = 0
        with input_path.open("wb") as destination:
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    destination.close()
                    input_path.unlink(missing_ok=True)
                    shutil.rmtree(job_dir, ignore_errors=True)
                    raise ValueError("The upload exceeds the 512 MB limit.")
                destination.write(chunk)
        if total == 0:
            input_path.unlink(missing_ok=True)
            shutil.rmtree(job_dir, ignore_errors=True)
            raise ValueError("The uploaded file is empty.")

        job = PipelineJob(
            id=job_id,
            filename=safe_name,
            mode=mode,
            input_path=input_path,
            job_dir=job_dir,
            agents=initial_agents(mode),
        )
        with self._lock:
            self._jobs[job_id] = job

        threading.Thread(
            target=self._run_job,
            args=(job_id,),
            name=f"pipeline-job-{job_id}",
            daemon=True,
        ).start()
        return job

    def start_capture(
        self,
        interface: str | None,
        timeout: int,
        max_packets: int,
    ) -> PipelineJob:
        validate_capture_options(timeout, max_packets)
        interface = validate_interface(interface)
        tcpdump = shutil.which("tcpdump")
        if tcpdump is None:
            raise RuntimeError("tcpdump executable was not found.")

        with self._lock:
            if self._active_capture_id is not None:
                active = self._jobs.get(self._active_capture_id)
                if active and active.status in {"queued", "capturing", "stopping"}:
                    raise RuntimeError("Another live capture is already active.")
                self._active_capture_id = None

            job_id = uuid.uuid4().hex[:12]
            job_dir = self.jobs_root / job_id
            input_dir = job_dir / "input"
            input_dir.mkdir(parents=True)
            input_path = input_dir / "live_capture.pcap"
            job = PipelineJob(
                id=job_id,
                filename="live_capture.pcap",
                mode="live",
                input_path=input_path,
                job_dir=job_dir,
                agents=initial_agents("live"),
                capture={
                    "interface": interface or "default",
                    "timeout": timeout,
                    "max_packets": max_packets,
                    "stop_requested": False,
                },
            )
            self._jobs[job_id] = job
            self._active_capture_id = job_id

        threading.Thread(
            target=self._run_capture,
            args=(job_id, tcpdump),
            name=f"capture-job-{job_id}",
            daemon=True,
        ).start()
        return job

    def stop_capture(self, job_id: str) -> PipelineJob:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise LookupError("Capture job not found.")
            if job.mode != "live":
                raise ValueError("The requested job is not a live capture.")
            if job.status not in {"queued", "capturing", "stopping"}:
                raise ValueError("The capture is no longer active.")

            job.status = "stopping"
            job.capture["stop_requested"] = True
            job.logs.append("LIVE CAPTURE STOP REQUESTED")
            process = self._capture_processes.get(job_id)

        if process is not None and process.poll() is None:
            process.terminate()
        return job

    def get(self, job_id: str) -> PipelineJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = sorted(
                self._jobs.values(),
                key=lambda item: item.created_at,
                reverse=True,
            )
            return [job.public_dict(include_logs=False) for job in jobs]

    def _run_job(self, job_id: str) -> None:
        job = self.get(job_id)
        if job is None:
            return

        with self._pipeline_lock:
            job.status = "running"
            job.started_at = utc_now()
            try:
                self._execute_pipeline(job, job.mode)
            except Exception as exc:
                job.status = "failed"
                job.error = str(exc)
                job.logs.append(f"WEB JOB FAILED | {exc}")
            finally:
                job.finished_at = utc_now()

    def _run_capture(self, job_id: str, tcpdump: str) -> None:
        job = self.get(job_id)
        if job is None:
            return

        with self._pipeline_lock:
            job.started_at = utc_now()
            job.status = "capturing"
            job.agents["pcap_reader_agent"] = "running"
            command = [tcpdump]
            interface = job.capture.get("interface")
            if interface and interface != "default":
                command.extend(["-i", str(interface)])
            command.extend(
                [
                    "-n",
                    "-U",
                    "-s",
                    "0",
                    "-c",
                    str(job.capture["max_packets"]),
                    "-w",
                    str(job.input_path),
                    LIVE_DNS_FILTER,
                ]
            )
            job.logs.append(
                "LIVE CAPTURE START | "
                f"interface={interface} | timeout={job.capture['timeout']}s | "
                f"max_packets={job.capture['max_packets']}"
            )

            try:
                process = subprocess.Popen(
                    command,
                    cwd=PROJECT_ROOT,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                with self._lock:
                    self._capture_processes[job_id] = process

                deadline = time.monotonic() + int(job.capture["timeout"])
                timed_out = False
                while process.poll() is None:
                    if job.capture.get("stop_requested"):
                        process.terminate()
                        break
                    if time.monotonic() >= deadline:
                        timed_out = True
                        job.logs.append("LIVE CAPTURE TIMEOUT | stopping tcpdump")
                        process.terminate()
                        break
                    time.sleep(0.2)

                try:
                    _, stderr = process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, stderr = process.communicate()

                stderr = (stderr or "").strip()
                stopped = bool(job.capture.get("stop_requested")) or timed_out
                accepted_stop_code = stopped and process.returncode in {-15, 1}
                if process.returncode != 0 and not accepted_stop_code:
                    raise RuntimeError(stderr or f"tcpdump exited with {process.returncode}.")
                if not job.input_path.exists():
                    raise RuntimeError(stderr or "tcpdump did not create a PCAP file.")

                job.logs.append(f"LIVE CAPTURE END | output={job.input_path}")
                job.agents["pcap_reader_agent"] = "pending"
                job.status = "analyzing"
                self._execute_pipeline(job, "pcap")
            except Exception as exc:
                job.status = "failed"
                job.error = str(exc)
                job.agents["pcap_reader_agent"] = "failed"
                job.logs.append(f"LIVE CAPTURE FAILED | {exc}")
            finally:
                with self._lock:
                    self._capture_processes.pop(job_id, None)
                    if self._active_capture_id == job_id:
                        self._active_capture_id = None
                job.finished_at = utc_now()

    def _execute_pipeline(self, job: PipelineJob, pipeline_mode: str) -> None:
        job.output_run_id = output_run_id()
        command = [
            sys.executable,
            "-u",
            "-m",
            "tools.run_pipeline",
            "--mode",
            pipeline_mode,
            "--input",
            str(job.input_path),
            "--run-id",
            job.output_run_id,
        ]
        process = subprocess.Popen(
            command,
            cwd=PROJECT_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        if process.stdout is not None:
            for raw_line in process.stdout:
                line = raw_line.rstrip()
                if line:
                    with self._lock:
                        apply_log_event(job, line)
        return_code = process.wait()
        if return_code != 0:
            raise RuntimeError(f"Pipeline exited with code {return_code}.")

        self._snapshot_outputs(job)
        job.summary = summarize_scores(job.job_dir / "output" / "scores.json")
        job.status = "completed"

    def _snapshot_outputs(self, job: PipelineJob) -> None:
        output_dir = job.job_dir / "output"
        output_dir.mkdir(parents=True, exist_ok=True)
        pipeline_run_output = (
            PIPELINE_OUTPUT / job.output_run_id
            if job.output_run_id
            else PIPELINE_OUTPUT
        )
        for filename in OUTPUT_FILES:
            if job.mode == "csv" and filename == "raw_packets.json":
                continue
            source_root = (
                STAGE1_OUTPUT
                if filename in {"raw_packets.json", "dns_queries.json"}
                else pipeline_run_output
            )
            source = source_root / filename
            if source.exists():
                shutil.copy2(source, output_dir / filename)
        (output_dir / "pipeline.log").write_text(
            "\n".join(job.logs) + "\n",
            encoding="utf-8",
        )


manager = JobManager()
