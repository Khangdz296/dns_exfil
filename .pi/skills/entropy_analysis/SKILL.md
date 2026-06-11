# SKILL: entropy_analysis

## Purpose
Calculate Shannon entropy for DNS subdomains to detect high-randomness
strings characteristic of DGA domains and DNS exfiltration. Used by
`entropy_agent` in Stage 2 parallel analysis.

## Tool function
`calculate_entropy(input_path: str, output_path: str) -> dict`

## When to use
Input is a JSON file containing DNS queries with `subdomain` fields.

## Inputs
| Parameter     | Type | Required | Description                              |
|---------------|------|----------|------------------------------------------|
| `input_path`  | str  | yes      | Path to `dns_queries.json` (Stage 1 out) |
| `output_path` | str  | yes      | Path to write entropy scores JSON        |

## Outputs
Returns a dict with processing summary:

| Field                | Type    | Description                               |
|----------------------|---------|-------------------------------------------|
| `total_processed`    | integer | Number of queries processed               |
| `high_entropy_count` | integer | Count where entropy_score > 3.5           |
| `output_file`        | string  | Path where results were written           |

Also writes a JSON array to `output_path`. Each entry contains:

| Field           | Type    | Description                                    |
|-----------------|---------|------------------------------------------------|
| `query_id`      | integer | Matching the input query_id                    |
| `domain`        | string  | Full domain from input                         |
| `subdomain`     | string  | Subdomain extracted from input                 |
| `label`         | string  | Ground truth label (benign/malicious) if known |
| `entropy_score` | float   | Shannon entropy H = -Σ p(x) log₂ p(x)          |

## Algorithm
- **Shannon Entropy:** H = -Σ [p(c) × log₂(p(c))] for each unique character c
- Character-level probability distribution on subdomain string
- Range: 0.0 (no randomness) to ~5.17 (max for alphanumeric)
- **Threshold:** entropy > 3.5 → suspicious (high randomness)

## Edge cases
- Empty subdomain → `entropy_score = 0.0`
- Single character → `entropy_score = 0.0`
- Missing subdomain field → `entropy_score = 0.0`
- Very short subdomains (< 3 chars) → typically low entropy

## Dependencies
```
# No external dependencies required — uses Python stdlib only
# math.log2 for logarithm calculation
```

## Example call
```python
from tools.shannon_entropy import calculate_entropy

result = calculate_entropy(
    input_path="data/output/dns_queries.json",
    output_path="data/output/entropy_scores.json"
)

print(f"Processed {result['total_processed']} queries")
print(f"Found {result['high_entropy_count']} high-entropy domains")
```

## Notes
- This tool is stateless and requires no training or model files.
- Typical benign domains (e.g., "google", "cdn") → entropy 2.5–3.2
- Random hex/base64 strings → entropy > 3.5
- Runs independently in parallel with `dga_classifier` and `embedding_agent`.
- Output is merged by `orchestrator_agent` in Stage 3.
