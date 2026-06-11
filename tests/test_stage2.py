"""
tests/test_stage2.py
Unit tests for Stage 2 DGA and embedding tools.

Run:
    python -m pytest tests/test_stage2.py -v
"""

import json
import pickle
from pathlib import Path

import pytest


@pytest.fixture
def sample_training_csv(tmp_path):
    """Create a minimal CSV for TF-IDF embedding training."""
    csv_path = tmp_path / "dns_tunneling.csv"
    csv_path.write_text(
        "domain_name,label\n"
        "google.com,benign\n"
        "cdn.shopify.com,benign\n"
        "connectivity-check.ubuntu.com,benign\n"
        "a3f9bc12.evil.com,malicious\n"
        "xk29ab.tunnel.net,malicious\n",
        encoding="utf-8",
    )
    return csv_path


@pytest.fixture
def sample_queries_json(tmp_path):
    """Create a small dns_queries.json fixture."""
    queries = [
        {
            "query_id": 1,
            "domain": "google.com",
            "subdomain": "",
            "label": "benign",
        },
        {
            "query_id": 2,
            "domain": "connectivity-check.ubuntu.com",
            "subdomain": "connectivity-check",
            "label": "benign",
        },
        {
            "query_id": 3,
            "domain": "a3f9bc12.evil.com",
            "subdomain": "a3f9bc12",
            "label": "malicious",
        },
    ]
    json_path = tmp_path / "dns_queries.json"
    json_path.write_text(json.dumps(queries), encoding="utf-8")
    return json_path


class TestDgaClassifier:

    def test_score_dga_file_writes_output(self, sample_queries_json, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        import numpy as np
        import tools.dga_model as dga_model

        class FakeModel:
            def predict_proba(self, feature_matrix):
                scores = np.array([0.1, 0.2, 0.9], dtype=float)
                return np.column_stack([1.0 - scores, scores])

        monkeypatch.setattr(dga_model, "_load_model", lambda model_path: FakeModel())

        output_path = "data/output/dga_scores.json"
        result = dga_model.score_dga_file(
            str(sample_queries_json),
            output_path,
            "models/fake_dga_model.pkl",
        )

        assert "error" not in result
        assert result["total_processed"] == 3
        assert Path(output_path).exists()

        rows = json.loads(Path(output_path).read_text(encoding="utf-8"))
        assert len(rows) == 3
        assert {"query_id", "domain", "label", "dga_score", "source"} <= set(rows[0].keys())
        assert rows[0]["dga_score"] == 0.1
        assert rows[2]["dga_score"] == 0.9

    def test_score_dga_file_skips_malformed_queries(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        import numpy as np
        import tools.dga_model as dga_model

        class FakeModel:
            def predict_proba(self, feature_matrix):
                scores = np.array([0.7], dtype=float)
                return np.column_stack([1.0 - scores, scores])

        monkeypatch.setattr(dga_model, "_load_model", lambda model_path: FakeModel())

        queries = [
            {"query_id": 1, "domain": "xk29ab.tunnel.net", "label": "malicious"},
            {"query_id": 2, "label": "missing-domain"},
            {"domain": "missing-id.test"},
        ]
        input_path = Path("dns_queries.json")
        input_path.write_text(json.dumps(queries), encoding="utf-8")

        result = dga_model.score_dga_file(
            str(input_path),
            "data/output/dga_scores.json",
            "models/fake_dga_model.pkl",
        )
        rows = json.loads(Path("data/output/dga_scores.json").read_text(encoding="utf-8"))

        assert result["total_processed"] == 1
        assert result["skipped_count"] == 2
        assert rows[0]["domain"] == "xk29ab.tunnel.net"
        assert rows[0]["dga_score"] == 0.7

    def test_score_dga_file_missing_model_returns_error(self, sample_queries_json, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        from tools.dga_model import score_dga_file

        result = score_dga_file(
            str(sample_queries_json),
            "data/output/dga_scores.json",
            "models/missing_dga_model.pkl",
        )

        assert result["error"] == "model_not_found"


class TestEmbeddingScorer:

    def test_train_embedding_model_creates_model_file(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import train_embedding_model

        model_path = "models/embed_model.pkl"
        result = train_embedding_model(str(sample_training_csv), model_path)

        assert "error" not in result
        assert result["benign_count"] == 3
        assert result["model_name"] == "tfidf-char-ngram-hybrid-knn"
        assert Path(model_path).exists()

    def test_trained_model_contains_expected_keys(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import train_embedding_model

        model_path = Path("models/embed_model.pkl")
        train_embedding_model(str(sample_training_csv), str(model_path))

        with model_path.open("rb") as f:
            model_data = pickle.load(f)

        required_keys = {
            "subdomain_branch",
            "domain_branch",
            "embedding_model",
            "analyzer",
            "ngram_range",
            "input_unit",
            "scoring_method",
            "fallback_rule",
            "short_subdomain_threshold",
            "benign_count",
            "subdomain_count",
            "domain_count",
        }
        assert required_keys <= set(model_data.keys())
        assert model_data["embedding_model"] == "tfidf-char-ngram-hybrid-knn"
        assert model_data["input_unit"] == "hybrid"
        assert model_data["scoring_method"] == "max_benign_similarity_with_domain_fallback"

    def test_calculate_embed_scores_writes_output(self, sample_training_csv, sample_queries_json, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import calculate_embed_scores, train_embedding_model

        model_path = "models/embed_model.pkl"
        output_path = "data/output/embed_scores.json"
        train_embedding_model(str(sample_training_csv), model_path)

        result = calculate_embed_scores(str(sample_queries_json), output_path, model_path)

        assert "error" not in result
        assert result["total_processed"] == 3
        assert Path(output_path).exists()

        rows = json.loads(Path(output_path).read_text(encoding="utf-8"))
        assert len(rows) == 3
        assert {"query_id", "domain", "label", "embed_score"} <= set(rows[0].keys())
        assert isinstance(rows[0]["embed_score"], float)

    def test_missing_model_returns_error(self, sample_queries_json, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)

        from tools.embed_score import calculate_embed_scores

        result = calculate_embed_scores(
            str(sample_queries_json),
            "data/output/embed_scores.json",
            "models/missing.pkl",
        )

        assert result["error"] == "model_not_found"

    def test_missing_required_fields_are_skipped(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import calculate_embed_scores, train_embedding_model

        bad_queries = [
            {"query_id": 1, "domain": "google.com", "subdomain": "", "label": "benign"},
            {"query_id": 2, "label": "malicious"},
            {"domain": "missing-id.com", "label": "unknown"},
        ]
        json_path = Path("dns_queries.json")
        json_path.write_text(json.dumps(bad_queries), encoding="utf-8")

        model_path = "models/embed_model.pkl"
        output_path = "data/output/embed_scores.json"
        train_embedding_model(str(sample_training_csv), model_path)

        result = calculate_embed_scores(str(json_path), output_path, model_path)

        assert "error" not in result
        assert result["total_processed"] == 1

        rows = json.loads(Path(output_path).read_text(encoding="utf-8"))
        assert len(rows) == 1
        assert rows[0]["domain"] == "google.com"
        assert isinstance(rows[0]["embed_score"], float)

    def test_empty_subdomain_uses_domain_fallback(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import calculate_embed_scores, train_embedding_model

        queries = [
            {"query_id": 1, "domain": "google.com", "subdomain": "", "label": "benign"},
        ]
        json_path = Path("dns_queries.json")
        json_path.write_text(json.dumps(queries), encoding="utf-8")

        model_path = "models/embed_model.pkl"
        output_path = "data/output/embed_scores.json"
        train_embedding_model(str(sample_training_csv), model_path)

        result = calculate_embed_scores(str(json_path), output_path, model_path)

        assert "error" not in result
        assert result["domain_fallback_count"] == 1
        rows = json.loads(Path(output_path).read_text(encoding="utf-8"))
        assert rows[0]["embed_score"] == 0.0

    def test_short_subdomain_uses_domain_fallback(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import calculate_embed_scores, train_embedding_model

        queries = [
            {"query_id": 1, "domain": "en.wikipedia.org", "subdomain": "en", "label": "benign"},
        ]
        json_path = Path("dns_queries.json")
        json_path.write_text(json.dumps(queries), encoding="utf-8")

        model_path = "models/embed_model.pkl"
        output_path = "data/output/embed_scores.json"
        train_embedding_model(str(sample_training_csv), model_path)

        result = calculate_embed_scores(str(json_path), output_path, model_path)

        assert "error" not in result
        assert result["domain_fallback_count"] == 1
        assert result["subdomain_path_count"] == 0

    def test_known_benign_subdomain_scores_lower_than_random_subdomain(self, sample_training_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("models").mkdir(parents=True, exist_ok=True)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.embed_score import calculate_embed_scores, train_embedding_model

        queries = [
            {
                "query_id": 1,
                "domain": "connectivity-check.ubuntu.com",
                "subdomain": "connectivity-check",
                "label": "benign",
            },
            {
                "query_id": 2,
                "domain": "a3f9bc12.evil.com",
                "subdomain": "a3f9bc12",
                "label": "malicious",
            },
        ]
        json_path = Path("dns_queries.json")
        json_path.write_text(json.dumps(queries), encoding="utf-8")

        model_path = "models/embed_model.pkl"
        output_path = "data/output/embed_scores.json"
        train_embedding_model(str(sample_training_csv), model_path)
        calculate_embed_scores(str(json_path), output_path, model_path)

        rows = json.loads(Path(output_path).read_text(encoding="utf-8"))
        benign_score = rows[0]["embed_score"]
        malicious_score = rows[1]["embed_score"]

        assert benign_score < malicious_score
