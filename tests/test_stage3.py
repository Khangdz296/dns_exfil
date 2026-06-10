"""
tests/test_stage3.py
Unit tests for Stage 3: aggregator and report tools.

Run:
    python -m pytest tests/test_stage3.py -v
"""

import json
from pathlib import Path

import pytest


@pytest.fixture
def sample_stage2_scores(tmp_path):
    """Create mock Stage 2 output files."""
    entropy = [
        {"query_id": 1, "domain": "google.com", "label": "benign", "entropy_score": 1.92},
        {"query_id": 2, "domain": "a3f9bc12.evil.com", "label": "malicious", "entropy_score": 3.0},
    ]
    dga = [
        {"query_id": 1, "domain": "google.com", "label": "benign", "dga_score": 0.1},
        {"query_id": 2, "domain": "a3f9bc12.evil.com", "label": "malicious", "dga_score": 0.91},
    ]
    embed = [
        {"query_id": 1, "domain": "google.com", "label": "benign", "embed_score": 0.0},
        {"query_id": 2, "domain": "a3f9bc12.evil.com", "label": "malicious", "embed_score": 0.87},
    ]

    Path("data/output").mkdir(parents=True, exist_ok=True)
    Path("data/output/entropy_scores.json").write_text(json.dumps(entropy))
    Path("data/output/dga_scores.json").write_text(json.dumps(dga))
    Path("data/output/embed_scores.json").write_text(json.dumps(embed))

    return tmp_path


class TestAggregateScores:

    def test_aggregate_creates_output(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json"
        )

        assert "error" not in result
        assert result["total_processed"] == 2
        assert Path("data/output/scores.json").exists()

    def test_combined_score_calculation(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores

        aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json"
        )

        scores = json.loads(Path("data/output/scores.json").read_text())

        # Malicious domain should have high combined score
        malicious = [s for s in scores if s["domain"] == "a3f9bc12.evil.com"][0]
        assert malicious["combined_score"] > 0.6
        assert malicious["verdict"] == "suspected"

        # Benign domain should have low combined score
        benign = [s for s in scores if s["domain"] == "google.com"][0]
        assert benign["combined_score"] < 0.6
        assert benign["verdict"] == "benign"


class TestGenerateReport:

    def test_report_creates_markdown(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores
        from tools.generate_report import generate_report

        aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json"
        )

        result = generate_report(
            "data/output/scores.json",
            "data/output/exfil_report.md"
        )

        assert "error" not in result
        assert result["total_queries"] == 2
        assert Path("data/output/exfil_report.md").exists()

    def test_report_contains_expected_sections(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores
        from tools.generate_report import generate_report

        aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json"
        )

        generate_report("data/output/scores.json", "data/output/exfil_report.md")

        report = Path("data/output/exfil_report.md").read_text()

        assert "# DNS Exfiltration Detection Report" in report
        assert "Executive Summary" in report
        assert "Top" in report and "Suspicious Domains" in report
        assert "Recommendations" in report
