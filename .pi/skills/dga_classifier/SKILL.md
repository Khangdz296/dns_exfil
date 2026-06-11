---
name: dga-classifier
description: Compute DGA probabilities using a pre-trained RandomForest model.
---

# SKILL: dga_classifier

## Purpose
Compute a DGA probability for every normalized DNS query using the model
trained by `tools/train_dga_model.py`. This skill is used by
`dga_classifier_agent` in parallel Stage 2.

## Tool function
Primary file-based tool for Pi chain execution:

```python
score_dga_file(
    input_path: str,
    output_path: str,
    model_path: str | Path = MODEL_PATH,
) -> dict
```

Low-level in-memory helper:

```python
score_dga(
    queries: list[dict],
    model_path: str | Path = MODEL_PATH,
) -> list[dict]
```

Implementation: `tools/dga_model.py`

## Inputs
| Parameter     | Type | Required | Description                              |
|---------------|------|----------|------------------------------------------|
| `input_path`  | str  | yes      | Path to `data/output/dns_queries.json`   |
| `output_path` | str  | yes      | Path to write `data/output/dga_scores.json` |
| `model_path`  | str  | no       | Path to `models/dga_model.pkl`           |

Each input query should contain:

| Field           | Type    | Missing value used by features |
|-----------------|---------|--------------------------------|
| `query_id`      | integer | required for output            |
| `domain`        | string  | required for output            |
| `domain_length` | integer | `0`                            |
| `digit_ratio`   | float   | `0.0`                          |
| `label_count`   | integer | `0`                            |
| `subdomain`     | string  | `""`                           |
| `label`         | string  | `unknown`                      |
| `source`        | string  | `unknown`                      |

## Feature engineering
Features are generated in this exact order:

1. `domain_length`
2. `digit_ratio`
3. `label_count`
4. `subdomain_length`
5. `vowel_ratio`
6. `consonant_ratio`
7. `unique_char_ratio`

Subdomain-derived features match the training logic in
`tools/train_dga_model.py`.

## Model inference
- Model type: `RandomForestClassifier`
- Default model: `models/dga_model.pkl`
- Inference method: batch `predict_proba`
- DGA probability: `predict_proba(feature_matrix)[:, 1]`
- Score precision: rounded to 6 decimal places
- Model instances are cached by model path

## Outputs
Returns a dict with processing summary:

| Field             | Type    | Description                           |
|-------------------|---------|---------------------------------------|
| `total_processed` | integer | Number of valid queries scored        |
| `skipped_count`   | integer | Malformed query records skipped       |
| `output_file`     | string  | Path where DGA scores were written    |

Also writes a JSON array to `output_path`. Each output row contains:

| Field       | Type  | Description                          |
|-------------|-------|--------------------------------------|
| `query_id`  | int   | Query identifier from Stage 1        |
| `domain`    | str   | Full DNS domain                      |
| `label`     | str   | Ground-truth label if available      |
| `dga_score` | float | Malicious-class probability, 0.0-1.0 |
| `source`    | str   | Data source, such as `pcap` or `csv` |

## Error handling
- Missing input file -> `{"error": "file_not_found", ...}`
- Missing model file -> `{"error": "model_not_found", ...}`
- Invalid JSON -> `{"error": "invalid_json", ...}`
- Non-array JSON -> `{"error": "invalid_format", ...}`
- Empty valid input -> write an empty output array
- Malformed records -> skip and increment `skipped_count`

## Dependencies
```text
joblib
numpy
scikit-learn
```

## Example call
```python
from tools.dga_model import score_dga_file

result = score_dga_file(
    input_path="data/output/dns_queries.json",
    output_path="data/output/dga_scores.json",
    model_path="models/dga_model.pkl",
)

print(f"Processed {result['total_processed']} queries")
```

## Notes
- This tool performs inference only; it does not train the model.
- It runs independently in parallel with `entropy_agent` and `embedding_agent`.
- `dga_scores.json` is merged with entropy and embedding outputs downstream.
