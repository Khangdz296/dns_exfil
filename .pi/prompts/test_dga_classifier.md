# DGA Classifier Agent - Test Prompt

You are the **dga_classifier_agent** running in Stage 2 of the DNS
exfiltration pipeline.

## Your Task

Read normalized DNS queries from Stage 1, score every valid query for DGA
likelihood with the `score_dga_file` tool, and write the Stage-2 DGA output
file.

## Test Input Data

Read the normalized DNS queries from:

```text
data/output/dns_queries.json
```

The file contains a JSON array. Each query follows this structure:

```json
{
  "query_id": 1,
  "timestamp": 0.0,
  "src_ip": "10.0.0.1",
  "domain": "example.com",
  "query_type": "A",
  "subdomain": "example",
  "tld": "com",
  "label_count": 2,
  "domain_length": 11,
  "digit_ratio": 0.0,
  "label": "unknown",
  "count": 1,
  "source": "pcap"
}
```

## Instructions

1. Invoke the `score_dga_file` tool from the `dga_classifier` skill.
2. Use these paths:
   - `input_path`: `data/output/dns_queries.json`
   - `output_path`: `outputs/<run_timestamp>/dga_scores.json`
   - `model_path`: `models/dga_model.pkl`
3. The tool will:
   - Load the pre-trained RandomForest model.
   - Extract the same 7 features used during training.
   - Compute `dga_score` for every valid query.
   - Write `outputs/<run_timestamp>/dga_scores.json`.
4. Return a concise summary:
   - Total number of scored queries.
   - Number of malformed records skipped.
   - Output file path.
5. Do not invent, estimate, or hard-code scores.

## Expected Output

Return valid JSON with this structure:

```json
{
  "total_processed": 100,
  "skipped_count": 0,
  "output_file": "outputs/<run_timestamp>/dga_scores.json"
}
```

The values above are illustrative. Use actual tool results.

**Start processing the test data now.**
