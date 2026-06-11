# SKILL: aggregate_scores

## Purpose
Merge the three parallel Stage-2 score outputs and calculate the final DNS
exfiltration verdict for each query. Used by `orchestrator_agent` in Stage 3.

## Tool function
`aggregate_scores(entropy_path: str, dga_path: str, embed_path: str, output_path: str) -> dict`

## When to use
Use this skill after all three Stage-2 agents have finished:

- `entropy_agent` writes `entropy_scores.json`
- `dga_classifier_agent` writes `dga_scores.json`
- `embedding_agent` writes `embed_scores.json`

## Inputs
| Parameter      | Type | Required | Description                         |
|----------------|------|----------|-------------------------------------|
| `entropy_path` | str  | yes      | Path to entropy scores JSON         |
| `dga_path`     | str  | yes      | Path to DGA scores JSON             |
| `embed_path`   | str  | yes      | Path to embedding scores JSON       |
| `output_path`  | str  | yes      | Path to write aggregated scores     |

## Expected Stage-2 fields
Each input record must contain `query_id` and its branch-specific score:

| File                  | Required score field |
|-----------------------|----------------------|
| `entropy_scores.json` | `entropy_score`      |
| `dga_scores.json`     | `dga_score`          |
| `embed_scores.json`   | `embed_score`        |

Records should also include `domain`, `label`, and `source` when available.

## Outputs
Returns a dict with processing summary:

| Field             | Type    | Description                           |
|-------------------|---------|---------------------------------------|
| `total_processed` | integer | Number of merged queries              |
| `suspected_count` | integer | Count where verdict is `suspected`    |
| `output_file`     | string  | Path where `scores.json` was written  |

Also writes a JSON array to `output_path`.

## Output fields
| Field            | Type   | Description                              |
|------------------|--------|------------------------------------------|
| `query_id`       | int    | Query identifier from Stage 1            |
| `domain`         | str    | Full DNS domain                          |
| `label`          | str    | Ground-truth label if available          |
| `source`         | str    | Data source, such as `pcap` or `csv`     |
| `entropy_score`  | float  | Raw entropy score                        |
| `entropy_norm`   | float  | Normalized entropy score                 |
| `dga_score`      | float  | DGA probability                          |
| `embed_score`    | float  | Embedding anomaly score                  |
| `combined_score` | float  | Final weighted score                     |
| `verdict`        | str    | `benign` or `suspected`                  |
| `risk_reasons`   | list   | Detection signals that triggered risk    |

## Algorithm
1. Load all three Stage-2 JSON arrays.
2. Index each file by `query_id`.
3. Use an inner join so only query IDs present in all three files are scored.
4. Normalize entropy with `min(max(entropy_score / 5.17, 0.0), 1.0)`.
5. Compute:
   `combined_score = 0.3*entropy_norm + 0.4*dga_score + 0.3*embed_score`
6. Set `verdict = "suspected"` when any hybrid rule is true:
   - `combined_score >= 0.6`
   - `dga_score >= 0.75`
   - `entropy_norm >= 0.65 and embed_score >= 0.85`
7. Add `risk_reasons` for the matched signals.
8. Sort output by `combined_score` descending.

## Error handling
- Missing input file -> structured error
- Invalid JSON -> structured error
- Non-array JSON -> structured error
- Malformed records -> skip and log warning
- Mismatched query IDs -> skip incomplete records
- Empty inputs -> write an empty output array

## Example call
```python
from tools.aggregate_scores import aggregate_scores

result = aggregate_scores(
    entropy_path="data/output/entropy_scores.json",
    dga_path="data/output/dga_scores.json",
    embed_path="data/output/embed_scores.json",
    output_path="data/output/scores.json",
)

print(f"Processed {result['total_processed']} records")
```
