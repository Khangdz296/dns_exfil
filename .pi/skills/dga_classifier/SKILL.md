---
name: dga-classifier
description: Compute DGA probabilities using a pre-trained Random Forest model.
---

# SKILL: dga_classifier

## Purpose

Compute a DGA probability for every normalized DNS query using the model
trained by `tools/train_dga_model.py`.

## Tool function

```python
score_dga(
    queries: list[dict],
    model_path: Path = MODEL_PATH,
) -> list[dict]
```

Implementation: `tools/dga_model.py`

## Inputs

| Parameter    | Type       | Required | Description                    |
| ------------ | ---------- | -------- | ------------------------------ |
| `queries`    | list[dict] | yes      | Normalized DNS query records   |
| `model_path` | Path       | no       | Path to the trained model file |

The feature extractor uses:

| Field           | Type    | Missing value |
| --------------- | ------- | ------------- |
| `domain_length` | integer | `0`           |
| `digit_ratio`   | float   | `0.0`         |
| `label_count`   | integer | `0`           |
| `subdomain`     | string  | `""`          |

## Feature engineering

Features are generated in this exact order:

1. `domain_length`
2. `digit_ratio`
3. `label_count`
4. `subdomain_length`
5. `vowel_ratio`
6. `consonant_ratio`
7. `unique_char_ratio`

Subdomain-derived features use the same preprocessing implemented in
`tools/train_dga_model.py`.

## Model inference

- Model type: `RandomForestClassifier`
- Default model: `models/dga_model.pkl`
- Inference method: batch `predict_proba`
- DGA probability: `predict_proba(feature_matrix)[:, 1]`
- Score precision: rounded to 6 decimal places
- Model instances are cached by model path

## Outputs

Returns a deep copy of `queries`. Every output record contains all original
fields plus:

| Field       | Type  | Range     | Description                 |
| ----------- | ----- | --------- | --------------------------- |
| `dga_score` | float | `0.0-1.0` | Malicious-class probability |

The input list and its dictionaries are not modified.

## Exceptions

| Exception           | Condition                 |
| ------------------- | ------------------------- |
| `ValueError`        | `queries` is empty        |
| `FileNotFoundError` | Model file does not exist |

Other model or feature conversion errors propagate to the caller.

## Dependencies

```text
joblib
numpy
scikit-learn
```

## Example

```python
from tools.dga_model import score_dga

results = score_dga(queries)

for record in results:
    print(record["domain"], record["dga_score"])
```

## Notes

- The tool performs inference only; it does not train the model.
- Processing is completed in memory.
- No JSON file is read or written.
