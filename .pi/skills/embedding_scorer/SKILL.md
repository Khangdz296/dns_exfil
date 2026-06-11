# SKILL: embedding_scorer

## Purpose
Calculate embedding-based anomaly scores for DNS queries using a hybrid TF-IDF
character n-gram model. The scorer uses subdomain similarity by default and
falls back to full-domain similarity when the subdomain is missing or too
short. Used by `embedding_agent` in Stage 2 parallel analysis.

## Tool function
`calculate_embed_scores(input_path: str, output_path: str, model_path: str) -> dict`

## When to use
Input is a JSON file containing DNS queries. The scorer reads the full `domain`
for every query and uses the `subdomain` field when it is available and
informative. A trained hybrid model must exist at `model_path`.

## Inputs
| Parameter     | Type | Required | Description                              |
|---------------|------|----------|------------------------------------------|
| `input_path`  | str  | yes      | Path to `dns_queries.json` (Stage 1 out) |
| `output_path` | str  | yes      | Path to write embedding scores JSON      |
| `model_path`  | str  | no       | Path to trained model (default: `models/embed_model.pkl`) |

## Outputs
Returns a dict with processing summary:

| Field                  | Type    | Description                               |
|------------------------|---------|-------------------------------------------|
| `total_processed`      | integer | Number of queries processed               |
| `subdomain_path_count` | integer | Queries scored via subdomain branch       |
| `domain_fallback_count`| integer | Queries scored via full-domain fallback   |
| `high_distance_count`  | integer | Count where `embed_score > 0.6`           |
| `output_file`          | string  | Path where results were written           |

Also writes a JSON array to `output_path`. Each entry contains:

| Field         | Type    | Description                                    |
|---------------|---------|------------------------------------------------|
| `query_id`    | integer | Matching the input query_id                    |
| `domain`      | string  | Full domain from input                         |
| `label`       | string  | Ground truth label (benign/malicious) if known |
| `embed_score` | float   | Distance from the nearest benign reference     |
| `source`      | string  | Data source: "pcap" or "csv"                   |

## Algorithm
- **Model:** hybrid TF-IDF character n-gram vectorizer
- **Analyzer:** `char`
- **n-gram range:** `(3, 5)`
- **Primary input unit:** `subdomain`
- **Fallback input unit:** `domain`
- **Short subdomain threshold:** `3`
- **Method:**
  1. Load the trained hybrid model from `model_path`
  2. Normalize the full domain and subdomain for each query
  3. If subdomain exists and has length ≥ 3, use the subdomain branch
  4. Otherwise, use the full-domain fallback branch
  5. Compute cosine similarity against benign reference vectors
  6. Let `best_similarity = max(similarities)` and `embed_score = 1 - best_similarity`
- **Threshold:** `embed_score > 0.6` → suspicious

## Training phase (prerequisite)

Before running inference, train the model ONCE:

```bash
python tools/embed_score.py train data/input/merged.csv models/embed_model.pkl
```

This generates `models/embed_model.pkl` containing:
- `subdomain_branch`: TF-IDF vectorizer + benign references for subdomain scoring
- `domain_branch`: TF-IDF vectorizer + benign references for full-domain fallback scoring
- `embedding_model`: `tfidf-char-ngram-hybrid-knn`
- `analyzer`: `char`
- `ngram_range`: `(3, 5)`
- `input_unit`: `hybrid`
- `scoring_method`: `max_benign_similarity_with_domain_fallback`
- `fallback_rule`: `use_domain_when_subdomain_missing_or_short`
- `short_subdomain_threshold`: `3`

## Why hybrid is useful
- Detects exfil-like random subdomains well
- Adds coverage for random-looking apex domains with no subdomain
- Reduces false positives caused by very short subdomains
- Preserves the same Stage 2 output contract used by downstream aggregation

## Edge cases
- Model file not found → error with instructions to run training
- Missing required fields → skip query, log warning
- Empty normalized domain → skip query
- Invalid JSON or unsupported JSON shape → structured error return
- Vectorizer transform failure in either branch → structured error return

## Dependencies
```bash
pip install numpy pandas scikit-learn tldextract
```

Includes:
- `numpy`
- `pandas`
- `scikit-learn`
- `tldextract`

## Example call
```python
from tools.embed_score import calculate_embed_scores

result = calculate_embed_scores(
    input_path="data/output/dns_queries.json",
    output_path="data/output/embed_scores.json",
    model_path="models/embed_model.pkl"
)

print(f"Processed {result['total_processed']} queries")
print(f"Subdomain path: {result['subdomain_path_count']}")
print(f"Domain fallback: {result['domain_fallback_count']}")
print(f"Found {result['high_distance_count']} high-distance domains")
```

## Example training call
```python
from tools.embed_score import train_embedding_model

result = train_embedding_model(
    csv_path="data/input/merged.csv",
    model_output_path="models/embed_model.pkl"
)

print(f"Trained on {result['benign_count']} benign domains")
print(f"Benign subdomains: {result['subdomain_count']}")
print(f"Model saved to {result['model_file']}")
```

## Performance
- **Training (offline):** slower than the old scorer because it fits two branches
- **Inference (runtime):** still CPU-friendly and suitable for large PCAP-derived query sets
- **Memory usage:** higher than the old scorer because the model stores both branches

## Interpretation
- **Low score (0.0–0.4):** Query looks similar to benign references → likely benign
- **Medium score (0.4–0.6):** Moderate distance → uncertain
- **High score (> 0.6):** Query is far from benign references → suspicious

## Notes
- This tool requires a trained model file.
- Training uses only benign DNS data to establish a normal lexical baseline.
- Runs independently in parallel with `entropy_agent` and `dga_classifier_agent`.
- Output is merged by `orchestrator_agent` in Stage 3.
- This implementation is now hybrid: subdomain-first with full-domain fallback.
