"""
tools/embed_score.py
Stage 2 — embedding_agent tool

Uses TF-IDF character n-grams over DNS strings to detect anomalous queries
by measuring their cosine distance from the most similar benign reference.

Hybrid design:
    - Primary path: score lexical anomaly on DNS subdomains
    - Fallback path: if the subdomain is missing or too short, score the full domain

Training Phase:
    - Extract benign full domains and benign subdomains from CSV domains
    - Fit separate TF-IDF vectorizers for subdomain and full-domain branches
    - Transform benign strings into sparse lexical vectors
    - Keep curated benign reference sets for both branches
    - Save both branches in a single pickle file

Inference Phase:
    - Load trained TF-IDF vectorizers and benign references
    - Read queries from dns_queries.json
    - Use subdomain scoring when the subdomain is informative
    - Fall back to full-domain scoring when subdomain is missing or too short
    - Output embed_score (0.0 = most similar to benign reference, 1.0 = far away)

Requirements:
    - pip install numpy pandas scikit-learn tldextract
"""

import json
import logging
import pickle
from collections import Counter
from pathlib import Path
from typing import Any, Dict

import numpy as np
import pandas as pd
import tldextract
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

from tools.logging_utils import setup_pipeline_logger

log = setup_pipeline_logger(__name__)

# TF-IDF configuration (matches PLAN.md design)
ANALYZER = "char"
NGRAM_RANGE = (3, 5)
SUSPICIOUS_THRESHOLD = 0.6
MAX_REFERENCE_VALUES = 20000
MAX_REFERENCE_PER_VALUE = 5
SHORT_SUBDOMAIN_THRESHOLD = 3
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)


def normalize_domain(domain: str) -> str:
    """Normalize full domain strings consistently across training and scoring."""
    return str(domain).strip().lower().rstrip(".")


def normalize_subdomain(subdomain: str) -> str:
    """Normalize subdomain strings consistently across training and scoring."""
    return str(subdomain).strip().lower().rstrip(".")


def detect_domain_column(df: pd.DataFrame) -> str | None:
    """Return the first supported domain column name from the dataset."""
    for column in ("domain", "domain_name", "dns_domain_name"):
        if column in df.columns:
            return column
    return None


def extract_subdomain(domain: str) -> str:
    """Extract subdomain from a full domain using cached PSL data only."""
    normalized = normalize_domain(domain)
    if not normalized:
        return ""
    return normalize_subdomain(EXTRACTOR(normalized).subdomain or "")


def build_reference_values(values: list[str]) -> list[str]:
    """
    Build a bounded benign reference set for nearest-similarity scoring.

    Strategy:
        - count normalized values
        - keep frequent values first
        - cap duplicates so generic tokens do not dominate
        - bound total reference size for practical runtime/memory
    """
    counts = Counter(values)
    references: list[str] = []

    for value, count in counts.most_common():
        repeats = min(count, MAX_REFERENCE_PER_VALUE)
        references.extend([value] * repeats)
        if len(references) >= MAX_REFERENCE_VALUES:
            break

    return references[:MAX_REFERENCE_VALUES]


def fit_branch(values: list[str], branch_name: str) -> Dict[str, Any]:
    """Fit one TF-IDF + nearest-neighbor branch on normalized benign values."""
    if len(values) == 0:
        return {"error": f"no_{branch_name}_found"}

    log.info(
        f"Fitting {branch_name} TF-IDF vectorizer "
        f"(analyzer={ANALYZER}, ngram_range={NGRAM_RANGE})"
    )

    vectorizer = TfidfVectorizer(analyzer=ANALYZER, ngram_range=NGRAM_RANGE)

    try:
        value_vectors = vectorizer.fit_transform(values)
    except Exception as e:
        log.error(f"Failed to fit {branch_name} TF-IDF vectorizer: {e}")
        return {"error": "vectorizer_fit_failed", "detail": str(e), "branch": branch_name}

    embedding_dim = int(value_vectors.shape[1])
    log.info(f"{branch_name} TF-IDF matrix shape: {value_vectors.shape}")

    reference_values = build_reference_values(values)
    if not reference_values:
        return {"error": f"no_{branch_name}_references"}

    log.info(f"Built {len(reference_values)} benign {branch_name} references")

    try:
        reference_vectors = vectorizer.transform(reference_values)
    except Exception as e:
        log.error(f"Failed to transform benign {branch_name} references: {e}")
        return {
            "error": "reference_transform_failed",
            "detail": str(e),
            "branch": branch_name,
        }

    try:
        nearest_neighbors = NearestNeighbors(metric="cosine", algorithm="brute")
        nearest_neighbors.fit(reference_vectors)
    except Exception as e:
        log.error(f"Failed to fit {branch_name} nearest-neighbor index: {e}")
        return {
            "error": "neighbor_index_failed",
            "detail": str(e),
            "branch": branch_name,
        }

    return {
        "vectorizer": vectorizer,
        "reference_values": reference_values,
        "reference_vectors": reference_vectors,
        "nearest_neighbors": nearest_neighbors,
        "input_count": len(values),
        "reference_count": len(reference_values),
        "embedding_dim": embedding_dim,
    }


def train_embedding_model(csv_path: str, model_output_path: str) -> Dict[str, Any]:
    """
    Train a hybrid TF-IDF lexical embedding model.

    Process:
        1. Load CSV dataset
        2. Filter rows where label == "benign"
        3. Detect supported domain column
        4. Extract and normalize benign full domains and subdomains
        5. Fit TF-IDF + nearest-neighbor branches for both representations
        6. Save hybrid model metadata as pickle
    """
    csv_file = Path(csv_path)
    if not csv_file.exists():
        log.error(f"CSV file not found: {csv_path}")
        return {"error": "file_not_found", "path": str(csv_path)}

    log.info(f"Loading dataset: {csv_path}")
    try:
        df = pd.read_csv(csv_file)
    except Exception as e:
        log.error(f"Failed to read CSV: {e}")
        return {"error": "invalid_csv", "detail": str(e)}

    domain_col = detect_domain_column(df)
    if domain_col is None:
        log.error("CSV must contain 'domain', 'domain_name', or 'dns_domain_name' column")
        return {
            "error": "missing_columns",
            "required": ["domain or domain_name or dns_domain_name", "label"],
        }

    if "label" not in df.columns:
        log.error("CSV must contain 'label' column")
        return {"error": "missing_columns", "required": ["label"]}

    benign_df = df[df["label"].astype(str).str.lower() == "benign"]
    benign_domains = [
        normalize_domain(domain)
        for domain in benign_df[domain_col].dropna().astype(str).tolist()
    ]
    benign_domains = [domain for domain in benign_domains if domain]

    benign_subdomains = [extract_subdomain(domain) for domain in benign_domains]
    benign_subdomains = [subdomain for subdomain in benign_subdomains if subdomain]

    if len(benign_domains) == 0:
        log.error("No benign domains found in dataset")
        return {"error": "no_benign_domains"}

    if len(benign_subdomains) == 0:
        log.error("No benign subdomains found in dataset")
        return {"error": "no_benign_subdomains"}

    log.info(f"Found {len(benign_domains)} benign domains")
    log.info(f"Found {len(benign_subdomains)} benign subdomains")

    domain_branch = fit_branch(benign_domains, "domain")
    if "error" in domain_branch:
        return domain_branch

    subdomain_branch = fit_branch(benign_subdomains, "subdomain")
    if "error" in subdomain_branch:
        return subdomain_branch

    model_data = {
        "subdomain_branch": subdomain_branch,
        "domain_branch": domain_branch,
        "embedding_model": "tfidf-char-ngram-hybrid-knn",
        "analyzer": ANALYZER,
        "ngram_range": NGRAM_RANGE,
        "input_unit": "hybrid",
        "scoring_method": "max_benign_similarity_with_domain_fallback",
        "fallback_rule": "use_domain_when_subdomain_missing_or_short",
        "short_subdomain_threshold": SHORT_SUBDOMAIN_THRESHOLD,
        "benign_count": len(benign_domains),
        "subdomain_count": len(benign_subdomains),
        "domain_count": len(benign_domains),
    }

    model_file = Path(model_output_path)
    model_file.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(model_file, "wb") as f:
            pickle.dump(model_data, f)
        log.info(f"Model saved → {model_file}")
    except Exception as e:
        log.error(f"Failed to save model: {e}")
        return {"error": "save_failed", "detail": str(e)}

    return {
        "benign_count": len(benign_domains),
        "subdomain_count": len(benign_subdomains),
        "domain_count": len(benign_domains),
        "embedding_dim": {
            "subdomain": subdomain_branch["embedding_dim"],
            "domain": domain_branch["embedding_dim"],
        },
        "model_name": model_data["embedding_model"],
        "model_file": str(model_file),
    }


def ensure_neighbors(branch: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild nearest-neighbor index if it is missing from a loaded branch."""
    nearest_neighbors = branch.get("nearest_neighbors")
    if nearest_neighbors is None:
        nearest_neighbors = NearestNeighbors(metric="cosine", algorithm="brute")
        nearest_neighbors.fit(branch["reference_vectors"])
        branch["nearest_neighbors"] = nearest_neighbors
    return branch


def score_branch(values: list[str], branch: Dict[str, Any], branch_name: str) -> list[float]:
    """Score a batch of normalized strings with one fitted branch."""
    if not values:
        return []

    branch = ensure_neighbors(branch)

    try:
        vectors = branch["vectorizer"].transform(values)
    except Exception as e:
        log.error(f"Failed to transform {branch_name} values with TF-IDF vectorizer: {e}")
        raise RuntimeError(f"vectorizer_transform_failed:{branch_name}:{e}") from e

    log.info(f"Computing distances from nearest benign {branch_name} references...")
    try:
        distances, _ = branch["nearest_neighbors"].kneighbors(vectors, n_neighbors=1)
    except Exception as e:
        log.error(f"Failed during {branch_name} nearest-neighbor scoring: {e}")
        raise RuntimeError(f"nearest_neighbor_failed:{branch_name}:{e}") from e

    return np.clip(distances.ravel(), 0.0, 1.0).tolist()


def load_branches(model_data: Dict[str, Any]) -> tuple[Dict[str, Any], Dict[str, Any] | None, int, bool]:
    """Load hybrid branches, with legacy subdomain-only compatibility."""
    if "subdomain_branch" in model_data and "domain_branch" in model_data:
        return (
            model_data["subdomain_branch"],
            model_data["domain_branch"],
            int(model_data.get("short_subdomain_threshold", SHORT_SUBDOMAIN_THRESHOLD)),
            True,
        )

    legacy_branch = {
        "vectorizer": model_data["vectorizer"],
        "reference_values": model_data.get("reference_subdomains", []),
        "reference_vectors": model_data["reference_vectors"],
        "nearest_neighbors": model_data.get("nearest_neighbors"),
        "input_count": model_data.get("benign_count", 0),
        "reference_count": model_data.get("reference_count", 0),
        "embedding_dim": model_data.get("embedding_dim", 0),
    }
    return legacy_branch, None, SHORT_SUBDOMAIN_THRESHOLD, False


def calculate_embed_scores(
    input_path: str,
    output_path: str,
    model_path: str = "models/embed_model.pkl",
) -> Dict[str, Any]:
    """
    Calculate embedding similarity scores for DNS queries.

    Hybrid process:
        1. Load trained TF-IDF model branches
        2. Load dns_queries.json
        3. Extract and normalize subdomain and full domain strings
        4. Use subdomain branch when subdomain is present and long enough
        5. Use full-domain fallback when subdomain is missing or too short
        6. Write results to embed_scores.json
    """
    model_file = Path(model_path)
    if not model_file.exists():
        log.error(f"Model file not found: {model_path}")
        log.error("Run training first: python embed_score.py train <csv_path> <model_path>")
        return {"error": "model_not_found", "path": str(model_path)}

    log.info(f"Loading model: {model_path}")
    try:
        with open(model_file, "rb") as f:
            model_data = pickle.load(f)
        subdomain_branch, domain_branch, short_threshold, hybrid_enabled = load_branches(model_data)
        log.info(
            "Model loaded "
            f"(type={model_data.get('embedding_model', 'unknown')}, "
            f"benign_count={model_data.get('benign_count', 0)}, "
            f"hybrid={hybrid_enabled})"
        )
    except Exception as e:
        log.error(f"Failed to load model: {e}")
        return {"error": "model_load_failed", "detail": str(e)}

    input_file = Path(input_path)
    if not input_file.exists():
        log.error(f"File not found: {input_path}")
        return {"error": "file_not_found", "path": str(input_path)}

    log.info(f"Reading DNS queries: {input_path}")
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.error(f"Failed to parse JSON: {e}")
        return {"error": "invalid_json", "detail": str(e)}

    if isinstance(data, dict) and "queries" in data:
        queries = data["queries"]
    elif isinstance(data, list):
        queries = data
    else:
        log.error("Unexpected JSON format (expected array or {queries: [...]})")
        return {"error": "invalid_format", "detail": "No queries found"}

    valid_queries = []
    routed_subdomains = []
    routed_domains = []
    skipped = 0

    for query in queries:
        if "query_id" not in query or "domain" not in query:
            log.warning(f"Skipping query missing required fields: {query}")
            skipped += 1
            continue

        domain = normalize_domain(query["domain"])
        if not domain:
            log.warning(f"Skipping query with empty normalized domain: {query}")
            skipped += 1
            continue

        subdomain = normalize_subdomain(query.get("subdomain", ""))
        if not subdomain:
            subdomain = extract_subdomain(domain)

        route_to_domain = hybrid_enabled and (
            not subdomain or len(subdomain) < short_threshold
        )

        query_record = {
            "query": query,
            "domain": domain,
            "subdomain": subdomain,
        }
        valid_queries.append(query_record)

        if route_to_domain:
            routed_domains.append(domain)
        else:
            routed_subdomains.append(subdomain)

    if not valid_queries:
        log.error("No valid queries found")
        return {"error": "no_valid_queries"}

    log.info(f"Found {len(valid_queries)} valid queries")
    if skipped:
        log.info(f"Skipped {skipped} invalid queries")

    try:
        subdomain_distances = iter(score_branch(routed_subdomains, subdomain_branch, "subdomain"))
        domain_distances = iter(score_branch(routed_domains, domain_branch, "domain")) if routed_domains else iter([])
    except RuntimeError as e:
        error_text = str(e)
        if error_text.startswith("vectorizer_transform_failed"):
            return {"error": "vectorizer_transform_failed", "detail": error_text}
        if error_text.startswith("nearest_neighbor_failed"):
            return {"error": "nearest_neighbor_failed", "detail": error_text}
        return {"error": "scoring_failed", "detail": error_text}

    results = []
    high_distance_count = 0
    subdomain_path_count = 0
    domain_fallback_count = 0

    for item in valid_queries:
        query = item["query"]
        subdomain = item["subdomain"]
        route_to_domain = hybrid_enabled and (
            not subdomain or len(subdomain) < short_threshold
        )

        if route_to_domain:
            embed_score = round(float(next(domain_distances)), 4)
            domain_fallback_count += 1
        else:
            embed_score = round(float(next(subdomain_distances)), 4)
            subdomain_path_count += 1

        if embed_score > SUSPICIOUS_THRESHOLD:
            high_distance_count += 1

        results.append({
            "query_id": query["query_id"],
            "domain": query["domain"],
            "label": query.get("label", "unknown"),
            "embed_score": embed_score,
            "source": query.get("source", "unknown")
        })

    total_processed = len(results)
    log.info(f"Processed {total_processed} queries")
    log.info(f"Subdomain path count: {subdomain_path_count}")
    log.info(f"Domain fallback count: {domain_fallback_count}")
    log.info(
        f"High-distance domains (> {SUSPICIOUS_THRESHOLD}): {high_distance_count}"
    )

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    log.info(f"Saved → {output_file}")

    return {
        "total_processed": total_processed,
        "subdomain_path_count": subdomain_path_count,
        "domain_fallback_count": domain_fallback_count,
        "high_distance_count": high_distance_count,
        "output_file": str(output_file),
    }


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  Train:     python embed_score.py train <csv_path> <model_output_path>")
        print("  Inference: python embed_score.py score <input_json> <output_json> [model_path]")
        print()
        print("Requirements:")
        print("  pip install numpy pandas scikit-learn tldextract")
        print()
        print("Examples:")
        print("  python embed_score.py train data/input/merged.csv models/embed_model.pkl")
        print("  python embed_score.py score data/output/dns_queries.json data/output/embed_scores.json")
        sys.exit(1)

    mode = sys.argv[1]

    if mode == "train":
        if len(sys.argv) < 4:
            print("[ERROR] Train mode requires: csv_path model_output_path")
            sys.exit(1)

        csv_path = sys.argv[2]
        model_output_path = sys.argv[3]

        result = train_embedding_model(csv_path, model_output_path)

        if "error" not in result:
            print(f"[OK] Trained on {result['benign_count']} benign domains")
            print(f"[OK] Benign subdomains: {result['subdomain_count']}")
            print(f"[OK] Embedding model: {result['model_name']}")
            print(f"[OK] Embedding dimension: {result['embedding_dim']}")
            print(f"[OK] Model saved: {result['model_file']}")
        else:
            print(f"[ERROR] {result}")
            sys.exit(1)

    elif mode == "score":
        if len(sys.argv) < 4:
            print("[ERROR] Score mode requires: input_json output_json [model_path]")
            sys.exit(1)

        input_path = sys.argv[2]
        output_path = sys.argv[3]
        model_path = sys.argv[4] if len(sys.argv) > 4 else "models/embed_model.pkl"

        result = calculate_embed_scores(input_path, output_path, model_path)

        if "error" not in result:
            print(f"[OK] Processed {result['total_processed']} queries")
            print(f"[OK] Subdomain path: {result['subdomain_path_count']}")
            print(f"[OK] Domain fallback: {result['domain_fallback_count']}")
            print(f"[OK] Found {result['high_distance_count']} high-distance domains")
            print(f"[OK] Output: {result['output_file']}")
        else:
            print(f"[ERROR] {result}")
            sys.exit(1)

    else:
        print(f"[ERROR] Unknown mode: {mode}")
        print("Valid modes: train, score")
        sys.exit(1)
