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
    """Create mock Stage 2 output files inside the test workspace."""
    entropy = [
        {
            "query_id": 1,
            "domain": "google.com",
            "label": "benign",
            "source": "csv",
            "entropy_score": 1.92,
        },
        {
            "query_id": 2,
            "domain": "a3f9bc12.evil.com",
            "label": "malicious",
            "source": "pcap",
            "entropy_score": 3.0,
        },
    ]
    dga = [
        {
            "query_id": 1,
            "domain": "google.com",
            "label": "benign",
            "source": "csv",
            "dga_score": 0.1,
        },
        {
            "query_id": 2,
            "domain": "a3f9bc12.evil.com",
            "label": "malicious",
            "source": "pcap",
            "dga_score": 0.91,
        },
    ]
    embed = [
        {
            "query_id": 1,
            "domain": "google.com",
            "label": "benign",
            "source": "csv",
            "embed_score": 0.0,
        },
        {
            "query_id": 2,
            "domain": "a3f9bc12.evil.com",
            "label": "malicious",
            "source": "pcap",
            "embed_score": 0.87,
        },
    ]

    output_dir = tmp_path / "data/output"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "entropy_scores.json").write_text(json.dumps(entropy), encoding="utf-8")
    (output_dir / "dga_scores.json").write_text(json.dumps(dga), encoding="utf-8")
    (output_dir / "embed_scores.json").write_text(json.dumps(embed), encoding="utf-8")

    return tmp_path


class TestAggregateScores:

    def test_aggregate_creates_output(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
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
            "data/output/scores.json",
        )

        scores = json.loads(Path("data/output/scores.json").read_text(encoding="utf-8"))

        malicious = [s for s in scores if s["domain"] == "a3f9bc12.evil.com"][0]
        assert malicious["combined_score"] > 0.6
        assert malicious["verdict"] == "suspected"

        benign = [s for s in scores if s["domain"] == "google.com"][0]
        assert benign["combined_score"] < 0.6
        assert benign["verdict"] == "benign"

    def test_preserves_source_for_report(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores

        aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )

        scores = json.loads(Path("data/output/scores.json").read_text(encoding="utf-8"))
        sources = {score["domain"]: score["source"] for score in scores}

        assert sources["google.com"] == "csv"
        assert sources["a3f9bc12.evil.com"] == "pcap"

    def test_entropy_embedding_agreement_flags_suspected(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output_dir = Path("data/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        entropy = [
            {
                "query_id": 1,
                "domain": "hexchunk.exfil.test",
                "label": "malicious",
                "source": "pcap",
                "entropy_score": 3.6,
            },
        ]
        dga = [
            {
                "query_id": 1,
                "domain": "hexchunk.exfil.test",
                "label": "malicious",
                "source": "pcap",
                "dga_score": 0.02,
            },
        ]
        embed = [
            {
                "query_id": 1,
                "domain": "hexchunk.exfil.test",
                "label": "malicious",
                "source": "pcap",
                "embed_score": 0.95,
            },
        ]
        Path("data/output/entropy_scores.json").write_text(json.dumps(entropy), encoding="utf-8")
        Path("data/output/dga_scores.json").write_text(json.dumps(dga), encoding="utf-8")
        Path("data/output/embed_scores.json").write_text(json.dumps(embed), encoding="utf-8")

        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )
        scores = json.loads(Path("data/output/scores.json").read_text(encoding="utf-8"))

        assert result["suspected_count"] == 1
        assert scores[0]["combined_score"] < 0.6
        assert scores[0]["verdict"] == "suspected"
        assert "entropy_embedding_agreement" in scores[0]["risk_reasons"]

    def test_mismatched_query_ids_are_skipped(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output_dir = Path("data/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        entropy = [
            {"query_id": 1, "domain": "google.com", "entropy_score": 1.0},
            {"query_id": 2, "domain": "missing-branch.test", "entropy_score": 4.0},
        ]
        dga = [
            {"query_id": 1, "domain": "google.com", "dga_score": 0.1},
        ]
        embed = [
            {"query_id": 1, "domain": "google.com", "embed_score": 0.1},
        ]
        Path("data/output/entropy_scores.json").write_text(json.dumps(entropy), encoding="utf-8")
        Path("data/output/dga_scores.json").write_text(json.dumps(dga), encoding="utf-8")
        Path("data/output/embed_scores.json").write_text(json.dumps(embed), encoding="utf-8")

        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )
        scores = json.loads(Path("data/output/scores.json").read_text(encoding="utf-8"))

        assert result["total_processed"] == 1
        assert [score["query_id"] for score in scores] == [1]

    def test_empty_stage2_scores_write_empty_output(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output_dir = Path("data/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        for name in ("entropy_scores.json", "dga_scores.json", "embed_scores.json"):
            (output_dir / name).write_text("[]", encoding="utf-8")

        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )

        assert result["total_processed"] == 0
        assert result["suspected_count"] == 0
        assert json.loads(Path("data/output/scores.json").read_text(encoding="utf-8")) == []

    def test_malformed_score_records_are_skipped(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        output_dir = Path("data/output")
        output_dir.mkdir(parents=True, exist_ok=True)

        entropy = [
            {"query_id": 1, "domain": "google.com", "entropy_score": "bad"},
            {"query_id": 2, "domain": "ok.test", "entropy_score": 2.0},
        ]
        dga = [
            {"query_id": 1, "domain": "google.com", "dga_score": 0.1},
            {"query_id": 2, "domain": "ok.test", "dga_score": 0.2},
        ]
        embed = [
            {"query_id": 1, "domain": "google.com", "embed_score": 0.1},
            {"query_id": 2, "domain": "ok.test", "embed_score": 0.2},
        ]
        Path("data/output/entropy_scores.json").write_text(json.dumps(entropy), encoding="utf-8")
        Path("data/output/dga_scores.json").write_text(json.dumps(dga), encoding="utf-8")
        Path("data/output/embed_scores.json").write_text(json.dumps(embed), encoding="utf-8")

        from tools.aggregate_scores import aggregate_scores

        result = aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )
        scores = json.loads(Path("data/output/scores.json").read_text(encoding="utf-8"))

        assert result["total_processed"] == 1
        assert scores[0]["domain"] == "ok.test"


class TestGenerateReport:

    def test_report_creates_markdown(self, sample_stage2_scores, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools.aggregate_scores import aggregate_scores
        from tools.generate_report import generate_report

        aggregate_scores(
            "data/output/entropy_scores.json",
            "data/output/dga_scores.json",
            "data/output/embed_scores.json",
            "data/output/scores.json",
        )

        result = generate_report(
            "data/output/scores.json",
            "data/output/exfil_report.md",
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
            "data/output/scores.json",
        )

        generate_report("data/output/scores.json", "data/output/exfil_report.md")

        report = Path("data/output/exfil_report.md").read_text(encoding="utf-8")

        assert "# DNS Exfiltration Detection Report" in report
        assert "Executive Summary" in report
        assert "Top" in report and "Suspicious Domains" in report
        assert "Reasons" in report
        assert "Hybrid Verdict Rule" in report
        assert "Source Distribution" in report
        assert "**csv:** 1 queries" in report
        assert "**pcap:** 1 queries" in report
        assert "Recommendations" in report

    def test_empty_scores_report_contains_warning(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)
        Path("data/output/scores.json").write_text("[]", encoding="utf-8")

        from tools.generate_report import generate_report

        result = generate_report("data/output/scores.json", "data/output/exfil_report.md")
        report = Path("data/output/exfil_report.md").read_text(encoding="utf-8")

        assert result["total_queries"] == 0
        assert "No score records were available" in report
        assert "No source data available" in report

    def test_invalid_json_returns_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)
        Path("data/output/scores.json").write_text("{bad json", encoding="utf-8")

        from tools.generate_report import generate_report

        result = generate_report("data/output/scores.json", "data/output/exfil_report.md")

        assert result["error"] == "invalid_json"
        assert not Path("data/output/exfil_report.md").exists()
