# Project Plan - DNS Exfiltration Detector

**Course:** Network Programming with AI/ML for Cybersecurity  
**Topic:** 05 - DNS Exfiltration Detector  
**Framework:** Pi Coding Agent + subagent extension  
**Duration:** 3 weeks | **Group size:** 3

---

## 1. Project Overview

Build a multi-agent pipeline that analyzes DNS traffic from PCAP, live capture,
or CSV input, detects suspected DNS tunneling / data exfiltration, and generates
a structured security report.

The pipeline has 3 sequential stages. Stage 2 uses parallel execution because
entropy scoring, DGA scoring, and embedding scoring are independent.

```text
PCAP, live capture, or CSV input
      |
      v
Stage 1 - Data ingestion
  pcap_reader_agent -> raw_packets.json
  dns_extractor_agent -> dns_queries.json
      |
      v
Stage 2 - Parallel scoring
  /parallel
    entropy_agent -> entropy_scores.json
    dga_classifier_agent -> dga_scores.json
    embedding_agent -> embed_scores.json
  /end_parallel
      |
      v
Stage 3 - Aggregation and reporting
  orchestrator_agent -> scores.json
  report_agent -> exfil_report.md
```

---

## 2. Agents

| # | Agent | Stage | Parallel |
|---|-------|-------|----------|
| 1 | `pcap_reader_agent` | 1 | No |
| 2 | `dns_extractor_agent` | 1 | No |
| 3 | `entropy_agent` | 2 | Yes |
| 4 | `dga_classifier_agent` | 2 | Yes |
| 5 | `embedding_agent` | 2 | Yes |
| 6 | `orchestrator_agent` | 3 | No |
| 7 | `report_agent` | 3 | No |

---

## 3. File Structure

```text
dns-exfiltration-detector/
|-- .pi/
|   |-- agents/
|   |   |-- pcap_reader_agent.md
|   |   |-- dns_extractor_agent.md
|   |   |-- entropy_agent.md
|   |   |-- dga_classifier_agent.md
|   |   |-- embedding_agent.md
|   |   |-- orchestrator_agent.md
|   |   `-- report_agent.md
|   |-- skills/
|   |   |-- pcap_reader/SKILL.md
|   |   |-- dns_extractor/SKILL.md
|   |   |-- entropy_analysis/SKILL.md
|   |   |-- dga_classifier/SKILL.md
|   |   |-- embedding_scorer/SKILL.md
|   |   |-- aggregate_scores/SKILL.md
|   |   `-- report_generation/SKILL.md
|   `-- prompts/
|       |-- dns_exfil.chain.md
|       |-- test_dga_classifier.md
|       `-- test_entropy.chain.md
|-- data/
|   |-- input/
|   |   |-- demo.pcap
|   |   |-- demo_exfil_strong.pcap
|   |   |-- dnscat2_dns_tunneling_24hr.pcap
|   |   `-- dns_tunneling.csv
|   `-- output/
|       |-- raw_packets.json
|       |-- dns_queries.json
|       |-- entropy_scores.json
|       |-- dga_scores.json
|       |-- embed_scores.json
|       |-- scores.json
|       |-- exfil_report.md
|       `-- pipeline.log
|-- models/
|   |-- dga_model.pkl
|   `-- embed_model.pkl
|-- tools/
|   |-- pcap_reader.py
|   |-- dns_extractor.py
|   |-- generate_test_pcap.py
|   |-- shannon_entropy.py
|   |-- dga_model.py
|   |-- embed_score.py
|   |-- aggregate_scores.py
|   `-- generate_report.py
|-- tests/
|   |-- test_stage1.py
|   |-- test_stage2.py
|   `-- test_stage3.py
|-- PROJECT.md
|-- SYSTEM.md
|-- TASK.md
`-- requirements.txt
```

---

## 4. Stage Detail

### Stage 1 - Data Ingestion

**Goal:** Normalize PCAP, live capture, or CSV input into
`data/output/dns_queries.json`.

**Data flow:**
- PCAP path -> `pcap_reader_agent` -> `raw_packets.json`
- Live capture -> `pcap_reader_agent` -> saved PCAP -> `raw_packets.json`
- `raw_packets.json` -> `dns_extractor_agent` -> `dns_queries.json`
- CSV path -> `dns_extractor_agent` -> `dns_queries.json`

**Tool functions:**
- `read_pcap_file(filepath, max_packets=10000)`
- `capture_live_dns(interface=None, timeout=30, max_packets=1000,
  output_pcap="data/output/live_capture.pcap")`
- `extract_dns_queries(packets=None, csv_path=None)`

**Output schema: `dns_queries.json`**

```json
{
  "query_id": 1,
  "timestamp": 0.0,
  "src_ip": "10.0.0.5",
  "domain": "a3f9bc12.evil.com",
  "query_type": "A",
  "subdomain": "a3f9bc12",
  "tld": "com",
  "label_count": 3,
  "domain_length": 18,
  "digit_ratio": 0.625,
  "label": "malicious",
  "count": 1,
  "source": "pcap"
}
```

### Stage 2 - Parallel Scoring

**Goal:** Score each DNS query with 3 independent methods in parallel.

Each agent reads the same `dns_queries.json` and writes its own score file.
There is no dependency between these 3 scoring branches.

#### Entropy Agent

- Tool: `tools/shannon_entropy.py`
- Function: `calculate_entropy(input_path, output_path)`
- Output: `data/output/entropy_scores.json`
- Signal: high Shannon entropy in subdomain characters.

Output row:

```json
{
  "query_id": 1,
  "domain": "a3f9bc12.evil.com",
  "subdomain": "a3f9bc12",
  "label": "malicious",
  "entropy_score": 3.58,
  "source": "pcap"
}
```

#### DGA Classifier Agent

- Tool: `tools/dga_model.py`
- Function: `score_dga_file(input_path, output_path, model_path)`
- Model: `models/dga_model.pkl`
- Output: `data/output/dga_scores.json`
- Signal: RandomForest probability that a domain resembles malicious/DGA traffic.

Output row:

```json
{
  "query_id": 1,
  "domain": "a3f9bc12.evil.com",
  "label": "malicious",
  "dga_score": 0.91,
  "source": "pcap"
}
```

#### Embedding Agent

- Tool: `tools/embed_score.py`
- Function: `calculate_embed_scores(input_path, output_path, model_path)`
- Model: `models/embed_model.pkl`
- Output: `data/output/embed_scores.json`
- Signal: TF-IDF character n-gram distance from benign DNS references.

Output row:

```json
{
  "query_id": 1,
  "domain": "a3f9bc12.evil.com",
  "label": "malicious",
  "embed_score": 0.87,
  "source": "pcap"
}
```

### Stage 3 - Aggregation and Report

**Goal:** Merge Stage 2 outputs, classify final verdicts, and generate a
Markdown security report.

#### Orchestrator Agent

- Tool: `tools/aggregate_scores.py`
- Function: `aggregate_scores(entropy_path, dga_path, embed_path, output_path)`
- Inputs:
  - `entropy_scores.json`
  - `dga_scores.json`
  - `embed_scores.json`
- Output: `data/output/scores.json`

The orchestrator uses an inner join on `query_id`, so a query must have all
3 score types before it receives a final verdict.

Weighted score:

```text
entropy_norm = min(max(entropy_score / 5.17, 0.0), 1.0)
combined_score = 0.3*entropy_norm + 0.4*dga_score + 0.3*embed_score
```

Hybrid verdict rule:

```text
suspected if:
  combined_score >= 0.6
  OR dga_score >= 0.75
  OR (entropy_norm >= 0.65 AND embed_score >= 0.85)
```

This rule prevents the detector from depending too heavily on one model. If
DGA misses a short exfiltration-like domain but entropy and embedding agree,
the query can still be flagged.

Output row:

```json
{
  "query_id": 1,
  "domain": "a3f9bc12.evil.com",
  "label": "malicious",
  "source": "pcap",
  "entropy_score": 3.58,
  "entropy_norm": 0.692,
  "dga_score": 0.02,
  "embed_score": 1.0,
  "combined_score": 0.51,
  "verdict": "suspected",
  "risk_reasons": [
    "high_entropy",
    "far_from_benign_embedding",
    "entropy_embedding_agreement"
  ]
}
```

#### Report Agent

- Tool: `tools/generate_report.py`
- Function: `generate_report(input_path, output_path, top_n=10)`
- Input: `data/output/scores.json`
- Output: `data/output/exfil_report.md`

Report sections:
1. Executive Summary
2. Top Suspicious Domains
3. Score Breakdown
4. Hybrid Verdict Rule
5. Source Distribution
6. Recommendations

All pipeline tools also write execution logs to `data/output/pipeline.log`.

---

## 5. Chain Structure

The orchestration file is `.pi/prompts/dns_exfil.chain.md`.

```markdown
## Stage 1 - Data Ingestion
run: pcap_reader_agent
  mode: pcap
  input: data/input/demo.pcap
  output: data/output/raw_packets.json

<!-- Optional live capture mode:
run: pcap_reader_agent
  mode: live
  interface: default
  timeout: 30
  max_packets: 1000
  output: data/output/raw_packets.json
-->

run: dns_extractor_agent
  packets: data/output/raw_packets.json
  output: data/output/dns_queries.json

<!-- Optional CSV-only dataset mode:
run: dns_extractor_agent
  csv: data/input/dns_tunneling.csv
  output: data/output/dns_queries.json
-->

## Stage 2 - Parallel Analysis
/parallel

run: entropy_agent
  input: data/output/dns_queries.json
  output: data/output/entropy_scores.json

run: dga_classifier_agent
  input: data/output/dns_queries.json
  model: models/dga_model.pkl
  output: data/output/dga_scores.json

run: embedding_agent
  input: data/output/dns_queries.json
  model: models/embed_model.pkl
  output: data/output/embed_scores.json

/end_parallel

## Stage 3 - Orchestration and Report
run: orchestrator_agent
  entropy: data/output/entropy_scores.json
  dga: data/output/dga_scores.json
  embed: data/output/embed_scores.json
  output: data/output/scores.json

run: report_agent
  input: data/output/scores.json
  output: data/output/exfil_report.md
  top_n: 10
```

---

## 6. Dependencies

```text
scapy>=2.5.0
tldextract>=3.4.0
pandas>=2.0.0
scikit-learn>=1.3.0
joblib>=1.3.0
numpy>=1.24.0
pytest>=7.0.0
```

Install:

```bash
pip install -r requirements.txt
```

### Model Version Note

The local model files can emit scikit-learn persistence warnings if the runtime
version differs from the training version. The project still runs locally, but
for the cleanest demo either:

- run with the same scikit-learn version used to train the model files, or
- retrain `models/dga_model.pkl` and `models/embed_model.pkl` in the current
  Python environment.

---

## 7. Recommended Demo Inputs

Use one of these local inputs:

| Input | Purpose |
|-------|---------|
| `data/input/demo.pcap` | Small smoke test |
| `data/input/demo_exfil_strong.pcap` | Small demo with several suspected records |
| `data/input/dnscat2_dns_tunneling_24hr.pcap` | Strong real tunneling demo |
| `data/input/dns_tunneling.csv` | CSV dataset path |

The strongest oral-test demo is `dnscat2_dns_tunneling_24hr.pcap`, because it
produces many high-confidence suspected DNS tunneling records.

---

## 8. Demo Checklist

Before the oral test, verify:

- [ ] `python -m pytest tests/test_stage2.py tests/test_stage3.py -q` passes.
- [ ] `python -m tools.run_pipeline --mode pcap --input data/input/demo.pcap`
      runs end-to-end.
- [ ] Stage 1 offline mode works in the local environment with Scapy.
- [ ] Pipeline runs end-to-end on a PCAP input.
- [ ] Optional live capture mode works with tcpdump, libpcap/Npcap, and
  capture privileges.
- [ ] Pipeline runs end-to-end on a CSV input.
- [ ] `data/output/exfil_report.md` is generated.
- [ ] `data/output/pipeline.log` contains the execution trail.
- [ ] Report contains suspected domains, score breakdown, source distribution,
      and risk reasons.
- [ ] Stage 2 parallelism is visible in `.pi/prompts/dns_exfil.chain.md`.
- [ ] `pipeline.log` contains `STAGE 2 PARALLEL START` and subagent start/end
      lines.

---

## 9. Role Split

| Member | Layer | Primary files |
|--------|-------|---------------|
| A | Data ingestion | `pcap_reader_agent.md`, `dns_extractor_agent.md`, `tools/pcap_reader.py`, `tools/dns_extractor.py` |
| B | ML/AI analysis | `entropy_agent.md`, `dga_classifier_agent.md`, `embedding_agent.md`, Stage 2 tools and models |
| C | Orchestration and output | `orchestrator_agent.md`, `report_agent.md`, `.pi/prompts/dns_exfil.chain.md`, Stage 3 tools |
