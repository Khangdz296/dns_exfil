# Web Dashboard

The dashboard provides a browser interface for the Pi multi-agent DNS
exfiltration pipeline.

## Features

- Upload `.pcap`, `.pcapng`, or `.csv` evidence.
- Start a timed live DNS capture from a selected network interface.
- Stop an active capture early and analyze the packets already collected.
- Download the captured PCAP after analysis.
- Monitor all seven agents through WebSocket updates.
- Show the parallel Stage 2 execution.
- Review pipeline lifecycle logs.
- Browse prioritized DNS risk scores.
- Read the generated Markdown security report.
- Keep isolated result snapshots for each web job.

Stage 1 writes `raw_packets.json` and `dns_queries.json` to `data/output`.
Live captures are saved under `data/input`. Stage 2/3 JSON results and the
Markdown report are written to timestamped directories such as
`outputs/20260612_153045_123456/`. The web job manager intentionally runs one
pipeline at a time, with job snapshots under `data/web_jobs/<job-id>/`.

Each pipeline process writes a timestamped execution log under the root-level
`logs` directory.

Live capture requires `tcpdump` and permission to capture packets. It uses the
fixed filter `udp dst port 53 or tcp dst port 53`, allows durations from 5 to
300 seconds, and preserves the generated PCAP in the job input directory.

## Run

Create and activate a Python environment, then install dependencies:

```powershell
py -m pip install -r requirements.txt
py -m uvicorn webapp.app:app --reload
```

Open `http://127.0.0.1:8000`.

Interactive API documentation is available at
`http://127.0.0.1:8000/docs`.

Live capture endpoints:

```text
GET    /api/interfaces
POST   /api/captures
DELETE /api/captures/{job_id}
GET    /api/jobs/{job_id}/capture
```

## Test

```powershell
py -m pytest -v
```

## Pi Integration

Agent metadata is read from `.pi/agents`. Pipeline execution uses
`tools/run_pipeline.py`, which mirrors `.pi/prompts/dns_exfil.chain.md` and
provides deterministic lifecycle logs for the web UI. A Pi CLI binary is not
required to run the dashboard.
