# dns_exfil.chain.md

Full pipeline for DNS exfiltration detection with parallel Stage 2 analysis.

## Stage 1 — Data Ingestion (Sequential)

run: pcap_reader_agent
  input: data/input/demo.pcap
  output: data/output/raw_packets.json

run: dns_extractor_agent
  packets: data/output/raw_packets.json
  csv: data/input/dns_tunneling.csv
  output: data/output/dns_queries.json

## Stage 2 — Parallel Analysis

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

## Stage 3 — Orchestration & Report (Sequential)

run: orchestrator_agent
  entropy: data/output/entropy_scores.json
  dga: data/output/dga_scores.json
  embed: data/output/embed_scores.json
  output: data/output/scores.json

run: report_agent
  input: data/output/scores.json
  output: data/output/exfil_report.md
  top_n: 10
