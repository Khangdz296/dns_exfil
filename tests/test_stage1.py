"""
tests/test_stage1.py
Unit tests for Stage 1: pcap_reader and dns_extractor tools.

Run:
    python -m pytest tests/test_stage1.py -v
"""

import os
import json
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault("WINDIR", r"C:\Windows")

from scapy.all import IP, UDP, DNS, DNSQR, wrpcap


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def sample_pcap(tmp_path):
    """Create a small PCAP with 3 DNS queries and 1 non-DNS packet."""
    domains = ["google.com", "a3f9bc12.evil.com", "github.com"]
    packets = []
    for domain in domains:
        pkt = (
            IP(src="192.168.1.1", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=domain))
        )
        packets.append(pkt)

    # Add 1 non-DNS packet (port 80) — should be filtered out
    non_dns = IP(src="192.168.1.1", dst="1.1.1.1") / UDP(sport=9999, dport=80)
    packets.append(non_dns)

    pcap_path = tmp_path / "test.pcap"
    wrpcap(str(pcap_path), packets)
    return pcap_path


@pytest.fixture
def sample_csv(tmp_path):
    """Create a minimal Kaggle-style CSV."""
    csv_path = tmp_path / "dns_tunneling.csv"
    csv_path.write_text(
        "domain_name,label\n"
        "google.com,benign\n"
        "a3f9bc12.evil.com,malicious\n"
        "xk29ab.tunnel.net,malicious\n"
    )
    return csv_path


# ── pcap_reader tests ─────────────────────────────────────────────────────────

class TestPcapReader:

    def test_returns_only_dns_packets(self, sample_pcap, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.pcap_reader import read_pcap_file
        result = read_pcap_file(str(sample_pcap))

        assert isinstance(result, list)
        assert len(result) == 3  # non-DNS packet filtered out

    def test_output_fields(self, sample_pcap, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.pcap_reader import read_pcap_file
        result = read_pcap_file(str(sample_pcap))

        required = {
            "packet_id", "timestamp", "src_ip", "dst_ip",
            "src_port", "dst_port", "protocol",
            "dns_payload_length", "raw_payload",
        }
        for record in result:
            assert required <= set(record.keys()), f"Missing fields in: {record}"

    def test_file_not_found(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.pcap_reader import read_pcap_file
        result = read_pcap_file("nonexistent.pcap")

        assert isinstance(result, dict)
        assert result["error"] == "file_not_found"

    def test_writes_json_output(self, sample_pcap, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.pcap_reader import read_pcap_file
        read_pcap_file(str(sample_pcap))

        output = tmp_path / "data/output/raw_packets.json"
        assert output.exists()
        data = json.loads(output.read_text())
        assert len(data) == 3

    def test_max_packets_limit(self, sample_pcap, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.pcap_reader import read_pcap_file
        result = read_pcap_file(str(sample_pcap), max_packets=1)

        assert len(result) == 1

    def test_capture_live_dns_uses_sniff(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools import pcap_reader

        pkt = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=49152, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="live.example.com"))
        )
        calls = {}

        def fake_sniff(**kwargs):
            calls.update(kwargs)
            return [pkt]

        monkeypatch.setattr(pcap_reader, "sniff", fake_sniff)

        result = pcap_reader.capture_live_dns(
            interface="test0",
            timeout=1,
            max_packets=5,
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["src_ip"] == "192.168.1.10"
        assert result[0]["dst_port"] == 53
        assert result[0]["protocol"] == "UDP"
        assert calls["iface"] == "test0"
        assert calls["timeout"] == 1
        assert calls["count"] == 5
        assert calls["filter"] == "udp port 53 or tcp port 53"

        output = tmp_path / "data/output/raw_packets.json"
        assert output.exists()
        data = json.loads(output.read_text())
        assert len(data) == 1

    def test_capture_live_dns_failure(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools import pcap_reader

        def fake_sniff(**kwargs):
            raise RuntimeError("no capture permission")

        monkeypatch.setattr(pcap_reader, "sniff", fake_sniff)

        result = pcap_reader.capture_live_dns(timeout=1)

        assert isinstance(result, dict)
        assert result["error"] == "capture_failed"
        assert "no capture permission" in result["detail"]


# ── dns_extractor tests ───────────────────────────────────────────────────────

class TestDnsExtractor:

    def test_csv_mode_basic(self, sample_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(sample_csv))

        assert isinstance(result, list)
        assert len(result) == 3

    def test_csv_output_fields(self, sample_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(sample_csv))

        required = {
            "query_id", "timestamp", "src_ip", "domain", "query_type",
            "subdomain", "tld", "label_count", "domain_length",
            "digit_ratio", "label", "count", "source",
        }
        for record in result:
            assert required <= set(record.keys())

    def test_csv_labels_preserved(self, sample_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(sample_csv))

        labels = {r["domain"]: r["label"] for r in result}
        assert labels["google.com"] == "benign"
        assert labels["a3f9bc12.evil.com"] == "malicious"

    def test_csv_defaults_for_missing_fields(self, sample_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(sample_csv))

        for r in result:
            assert r["timestamp"] == 0.0
            assert r["src_ip"] == "0.0.0.0"
            assert r["source"] == "csv"

    def test_domain_normalization(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        csv_path = tmp_path / "test.csv"
        csv_path.write_text("domain_name,label\nGOOGLE.COM,benign\n")

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(csv_path))

        assert result[0]["domain"] == "google.com"

    def test_no_input_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries()

        assert isinstance(result, dict)
        assert result["error"] == "no_input_found"

    def test_missing_columns_error(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        bad_csv = tmp_path / "bad.csv"
        bad_csv.write_text("wrong_col,other_col\nfoo,bar\n")

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(bad_csv))

        assert isinstance(result, dict)
        assert result["error"] == "missing_columns"

    def test_count_field_for_repeats(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        csv_path = tmp_path / "repeat.csv"
        csv_path.write_text(
            "domain_name,label\n"
            "evil.com,malicious\n"
            "evil.com,malicious\n"
            "google.com,benign\n"
        )

        from tools.dns_extractor import extract_dns_queries
        result = extract_dns_queries(csv_path=str(csv_path))

        evil = [r for r in result if r["domain"] == "evil.com"]
        assert all(r["count"] == 2 for r in evil)

        good = [r for r in result if r["domain"] == "google.com"]
        assert good[0]["count"] == 1

    def test_writes_json_output(self, sample_csv, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools.dns_extractor import extract_dns_queries
        extract_dns_queries(csv_path=str(sample_csv))

        output = tmp_path / "data/output/dns_queries.json"
        assert output.exists()
        data = json.loads(output.read_text())
        assert len(data) == 3
