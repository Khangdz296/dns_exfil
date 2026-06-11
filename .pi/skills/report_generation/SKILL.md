# SKILL: report_generation

## Purpose
Generate a Markdown security report from aggregated DNS exfiltration scores.
Used by `report_agent` in Stage 3 after `orchestrator_agent` writes
`data/output/scores.json`.

## Tool function
`generate_report(input_path: str, output_path: str, top_n: int = 10) -> dict`

## When to use
Use this skill after Stage 2 scores have been aggregated into `scores.json`.
The input must be a JSON array where each record contains the final combined
score and verdict for one DNS query.

## Inputs
| Parameter     | Type | Required | Description                         |
|---------------|------|----------|-------------------------------------|
| `input_path`  | str  | yes      | Path to aggregated `scores.json`    |
| `output_path` | str  | yes      | Path to write the Markdown report   |
| `top_n`       | int  | no       | Number of top records to list       |

## Expected input fields
Each score record should contain:

| Field            | Type   | Description                              |
|------------------|--------|------------------------------------------|
| `query_id`       | int    | Query identifier from Stage 1            |
| `domain`         | str    | Full DNS domain                          |
| `label`          | str    | Ground-truth label if available          |
| `source`         | str    | Data source, such as `pcap` or `csv`     |
| `entropy_score`  | float  | Raw entropy score                        |
| `dga_score`      | float  | DGA probability                          |
| `embed_score`    | float  | Embedding anomaly score                  |
| `combined_score` | float  | Final weighted score                     |
| `verdict`        | str    | `benign` or `suspected`                  |

## Outputs
Returns a dict with processing summary:

| Field             | Type    | Description                         |
|-------------------|---------|-------------------------------------|
| `total_queries`   | integer | Number of records in `scores.json`  |
| `suspected_count` | integer | Count where verdict is `suspected`  |
| `report_file`     | string  | Path where the report was written   |

Also writes a Markdown file to `output_path`.

## Report sections
The generated report includes:

1. Executive Summary
2. Top N Suspicious Domains
3. Score Breakdown
4. Source Distribution
5. Recommendations

## Error handling
- Missing input file -> `{"error": "file_not_found", ...}`
- Invalid JSON -> `{"error": "invalid_json", ...}`
- Non-array JSON -> `{"error": "invalid_format", ...}`
- Empty score array -> generate a report with a warning section

## Example call
```python
from tools.generate_report import generate_report

result = generate_report(
    input_path="data/output/scores.json",
    output_path="data/output/exfil_report.md",
    top_n=10,
)

print(f"Report written to {result['report_file']}")
```

## Notes
- This skill does not calculate scores. It only formats Stage 3 output.
- Source distribution depends on `orchestrator_agent` preserving the `source`
  field from Stage 2 score records.
- The report is deterministic except for the generation timestamp.
