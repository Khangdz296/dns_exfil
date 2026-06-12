# dns_exfil.chain.md

Full pipeline for DNS exfiltration detection with parallel Stage 2 analysis.
Use one `run_timestamp` value in `YYYYMMDD_HHMMSS_microseconds` format for
every path under `outputs/` in the same run. Replace `<run_timestamp>` with
the local start time before invoking any Stage 2 agent.

## Stage 1 - Data Ingestion (Sequential)

run: pcap_reader_agent
  mode: pcap
  input: data/input/demo.pcap
  output: data/output/raw_packets.json

# Optional live capture mode for local runs:
# run: pcap_reader_agent
#   mode: live
#   interface: default
#   timeout: 30
#   max_packets: 1000
#   output_pcap: data/input/live_capture.pcap
#   output: data/output/raw_packets.json

run: dns_extractor_agent
  packets: data/output/raw_packets.json
  output: data/output/dns_queries.json

# Optional CSV-only dataset mode:
# run: dns_extractor_agent
#   csv: data/input/dns_tunneling.csv
#   output: data/output/dns_queries.json

## Stage 2 - Parallel Analysis

/parallel

run: entropy_agent
  input: data/output/dns_queries.json
  output: outputs/<run_timestamp>/entropy_scores.json

run: dga_classifier_agent
  input: data/output/dns_queries.json
  model: models/dga_model.pkl
  output: outputs/<run_timestamp>/dga_scores.json

run: embedding_agent
  input: data/output/dns_queries.json
  model: models/embed_model.pkl
  output: outputs/<run_timestamp>/embed_scores.json

/end_parallel

## Stage 3 - Orchestration & Report (Sequential)

run: orchestrator_agent
  entropy: outputs/<run_timestamp>/entropy_scores.json
  dga: outputs/<run_timestamp>/dga_scores.json
  embed: outputs/<run_timestamp>/embed_scores.json
  output: outputs/<run_timestamp>/scores.json

run: report_agent
  input: outputs/<run_timestamp>/scores.json
  output: outputs/<run_timestamp>/exfil_report.md
  top_n: 10
