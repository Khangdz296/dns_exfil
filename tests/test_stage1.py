"""
tests/test_stage1.py
Unit tests for Stage 1: pcap_reader and dns_extractor tools.

Run:
    python -m pytest tests/test_stage1.py -v
"""

import os
import json
import subprocess
from pathlib import Path

import pytest

os.environ.setdefault("WINDIR", r"C:\Windows")

from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, wrpcap


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

    def test_capture_live_dns_uses_tcpdump_and_reads_pcap(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools import pcap_reader

        pkt = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=49152, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="live.example.com"))
        )
        calls = {}

        class FakeProcess:
            returncode = 0

            def communicate(self, timeout=None):
                calls["timeout"] = timeout
                return "", ""

        def fake_popen(command, **kwargs):
            calls["command"] = command
            calls["popen_kwargs"] = kwargs
            output_path = Path(command[command.index("-w") + 1])
            wrpcap(str(output_path), [pkt])
            return FakeProcess()

        monkeypatch.setattr(
            pcap_reader.shutil,
            "which",
            lambda name: "/usr/sbin/tcpdump",
        )
        monkeypatch.setattr(pcap_reader.subprocess, "Popen", fake_popen)

        result = pcap_reader.capture_live_dns(
            interface="test0",
            timeout=1,
            max_packets=5,
            output_pcap="data/output/test-live.pcap",
        )

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["src_ip"] == "192.168.1.10"
        assert result[0]["dst_port"] == 53
        assert result[0]["protocol"] == "UDP"
        command = calls["command"]
        assert command[:3] == ["/usr/sbin/tcpdump", "-i", "test0"]
        assert command[command.index("-c") + 1] == "5"
        assert command[-1] == "udp dst port 53 or tcp dst port 53"
        assert calls["timeout"] == 1
        assert calls["popen_kwargs"]["text"] is True
        assert (tmp_path / "data/output/test-live.pcap").exists()

        output = tmp_path / "data/output/raw_packets.json"
        assert output.exists()
        data = json.loads(output.read_text())
        assert len(data) == 1

    def test_capture_live_dns_stops_after_timeout(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        Path("data/output").mkdir(parents=True, exist_ok=True)

        from tools import pcap_reader

        pkt = (
            IP(src="192.168.1.10", dst="8.8.8.8")
            / UDP(sport=49152, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="timed.example.com"))
        )
        calls = {"communicate": 0, "terminated": False}

        class FakeProcess:
            returncode = -15

            def communicate(self, timeout=None):
                calls["communicate"] += 1
                if calls["communicate"] == 1:
                    raise subprocess.TimeoutExpired("tcpdump", timeout)
                return "", ""

            def terminate(self):
                calls["terminated"] = True

            def kill(self):
                pytest.fail("kill should not be needed")

        def fake_popen(command, **kwargs):
            output_path = Path(command[command.index("-w") + 1])
            wrpcap(str(output_path), [pkt])
            return FakeProcess()

        monkeypatch.setattr(
            pcap_reader.shutil,
            "which",
            lambda name: "/usr/sbin/tcpdump",
        )
        monkeypatch.setattr(pcap_reader.subprocess, "Popen", fake_popen)

        result = pcap_reader.capture_live_dns(timeout=1)

        assert isinstance(result, list)
        assert len(result) == 1
        assert calls["terminated"] is True

    def test_max_packets_stops_streaming_reader_early(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        pcap_path = tmp_path / "streaming.pcap"
        pcap_path.touch()

        from tools import pcap_reader

        pkt = (
            IP(src="192.168.1.1", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="first.example.com"))
        )
        calls = {"next": 0, "closed": False}

        class FakeReader:
            def __iter__(self):
                return self

            def __next__(self):
                calls["next"] += 1
                if calls["next"] == 1:
                    return pkt
                pytest.fail("reader consumed packets after reaching max_packets")

            def close(self):
                calls["closed"] = True

        monkeypatch.setattr(pcap_reader, "PcapReader", lambda path: FakeReader())

        result = pcap_reader.read_pcap_file(str(pcap_path), max_packets=1)

        assert len(result) == 1
        assert calls["next"] == 1
        assert calls["closed"] is True

    def test_reads_ipv6_dns_packet(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        packet = (
            IPv6(src="2001:db8::10", dst="2001:4860:4860::8888")
            / UDP(sport=53000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="ipv6.example.com"))
        )
        pcap_path = tmp_path / "ipv6.pcap"
        wrpcap(str(pcap_path), [packet])

        from tools.pcap_reader import read_pcap_file

        result = read_pcap_file(str(pcap_path))

        assert len(result) == 1
        assert result[0]["src_ip"] == "2001:db8::10"
        assert result[0]["dst_ip"] == "2001:4860:4860::8888"

    def test_reassembles_tcp_dns_and_removes_length_prefix(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        dns_payload = bytes(
            DNS(rd=1, qd=DNSQR(qname="tcp.example.com"))
        )
        framed_payload = len(dns_payload).to_bytes(2, "big") + dns_payload
        split_at = 9
        packets = [
            (
                IP(src="192.168.1.20", dst="8.8.8.8")
                / TCP(sport=50000, dport=53, seq=1000)
                / Raw(framed_payload[:split_at])
            ),
            (
                IP(src="192.168.1.20", dst="8.8.8.8")
                / TCP(sport=50000, dport=53, seq=1000 + split_at)
                / Raw(framed_payload[split_at:])
            ),
        ]
        pcap_path = tmp_path / "tcp-dns.pcap"
        wrpcap(str(pcap_path), packets)

        from tools.pcap_reader import read_pcap_file

        result = read_pcap_file(str(pcap_path))

        assert len(result) == 1
        assert result[0]["protocol"] == "TCP"
        assert result[0]["raw_payload"] == dns_payload.hex()
        assert result[0]["dns_payload_length"] == len(dns_payload)

    def test_capture_live_dns_requires_tcpdump(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from tools import pcap_reader

        monkeypatch.setattr(pcap_reader.shutil, "which", lambda name: None)
        result = pcap_reader.capture_live_dns(timeout=1)

        assert result == {"error": "tcpdump_not_found"}

    def test_capture_live_dns_validates_arguments(self):
        from tools.pcap_reader import capture_live_dns

        result = capture_live_dns(timeout=0)
        assert isinstance(result, dict)
        assert result["error"] == "invalid_capture_argument"


# ── dns_extractor tests ───────────────────────────────────────────────────────

class TestDnsExtractor:

    def test_extracts_normalized_tcp_dns_payload(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        dns_payload = bytes(
            DNS(rd=1, qd=DNSQR(qname="tcp-query.example.com"))
        )
        packets = [
            {
                "packet_id": 1,
                "timestamp": 1.0,
                "src_ip": "192.168.1.20",
                "dst_ip": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 53,
                "protocol": "TCP",
                "dns_payload_length": len(dns_payload),
                "raw_payload": dns_payload.hex(),
            }
        ]

        from tools.dns_extractor import extract_dns_queries

        result = extract_dns_queries(packets=packets)

        assert len(result) == 1
        assert result[0]["domain"] == "tcp-query.example.com"

    def test_domain_parser_uses_offline_suffix_extractor(self, monkeypatch):
        from tools import dns_extractor

        calls = []

        class Extracted:
            subdomain = "api"
            suffix = "com"

        def fake_extractor(domain):
            calls.append(domain)
            return Extracted()

        monkeypatch.setattr(dns_extractor, "TLD_EXTRACTOR", fake_extractor)

        parsed = dns_extractor._parse_domain("API.Example.COM.")

        assert calls == ["api.example.com"]
        assert parsed["subdomain"] == "api"
        assert parsed["tld"] == "com"

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
