"""Unit tests for web pipeline job state helpers."""

import json
from types import SimpleNamespace

import pytest

from webapp.job_manager import (
    JobManager,
    PipelineJob,
    apply_log_event,
    initial_agents,
    output_run_id,
    parse_tcpdump_interfaces,
    safe_upload_name,
    summarize_scores,
    validate_capture_options,
    validate_interface,
)


def make_job(tmp_path, mode="pcap"):
    return PipelineJob(
        id="test-job",
        filename=f"sample.{mode}",
        mode=mode,
        input_path=tmp_path / f"sample.{mode}",
        job_dir=tmp_path,
        agents=initial_agents(mode),
    )


def test_safe_upload_name_removes_parent_path():
    assert safe_upload_name("../../capture.pcap") == "capture.pcap"
    assert safe_upload_name(r"..\..\capture.pcap") == "capture.pcap"


def test_output_run_id_uses_timestamp_format():
    run_id = output_run_id()
    assert len(run_id) == 22
    assert run_id[8] == "_"
    assert run_id[15] == "_"
    assert run_id.replace("_", "").isdigit()


def test_safe_upload_name_rejects_unsupported_extension():
    with pytest.raises(ValueError):
        safe_upload_name("payload.exe")


def test_csv_job_skips_pcap_reader():
    assert initial_agents("csv")["pcap_reader_agent"] == "skipped"


def test_parse_tcpdump_interfaces():
    output = (
        "1.eth0 [Up, Running]\n"
        "2.any (Pseudo-device that captures on all interfaces) [Up, Running]\n"
        "invalid line\n"
    )

    assert parse_tcpdump_interfaces(output) == [
        {"id": "1", "label": "eth0 [Up, Running]"},
        {
            "id": "2",
            "label": "any (Pseudo-device that captures on all interfaces) [Up, Running]",
        },
    ]


@pytest.mark.parametrize(
    ("timeout", "max_packets"),
    [(4, 100), (301, 100), (30, 0), (30, 10_001)],
)
def test_capture_options_reject_out_of_range_values(timeout, max_packets):
    with pytest.raises(ValueError):
        validate_capture_options(timeout, max_packets)


def test_validate_interface_normalizes_default_and_rejects_control_characters():
    assert validate_interface(" default ") is None
    assert validate_interface(" 2 ") == "2"
    with pytest.raises(ValueError):
        validate_interface("eth0\nmalformed")


def test_list_interfaces_uses_tcpdump_numeric_selectors(tmp_path, monkeypatch):
    manager = JobManager(tmp_path / "jobs")
    monkeypatch.setattr("webapp.job_manager.shutil.which", lambda name: "/usr/bin/tcpdump")
    monkeypatch.setattr(
        "webapp.job_manager.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="1.eth0 [Up]\n2.any [Up]\n",
            stderr="",
        ),
    )

    assert manager.list_interfaces() == {
        "available": True,
        "detail": "",
        "interfaces": [
            {"id": "1", "label": "eth0 [Up]"},
            {"id": "2", "label": "any [Up]"},
        ],
    }


def test_log_events_update_agent_state(tmp_path):
    job = make_job(tmp_path)

    apply_log_event(job, "SUBAGENT START | entropy_agent")
    assert job.agents["entropy_agent"] == "running"

    apply_log_event(job, "SUBAGENT END | entropy_agent | elapsed=0.10s")
    assert job.agents["entropy_agent"] == "completed"

    apply_log_event(job, "SUBAGENT FAILED | report_agent | elapsed=0.20s")
    assert job.agents["report_agent"] == "failed"


def test_summarize_scores(tmp_path):
    scores_path = tmp_path / "scores.json"
    scores_path.write_text(
        json.dumps(
            [
                {"verdict": "benign", "combined_score": 0.1},
                {"verdict": "suspected", "combined_score": 0.92},
            ]
        ),
        encoding="utf-8",
    )

    assert summarize_scores(scores_path) == {
        "total_queries": 2,
        "suspected_count": 1,
        "highest_risk_score": 0.92,
    }


def test_snapshot_reads_stage_outputs_from_timestamped_directory(
    tmp_path,
    monkeypatch,
):
    stage1_dir = tmp_path / "data" / "output"
    pipeline_output = tmp_path / "outputs"
    run_id = "20260612_153045_123456"
    run_dir = pipeline_output / run_id
    stage1_dir.mkdir(parents=True)
    run_dir.mkdir(parents=True)
    (stage1_dir / "raw_packets.json").write_text("[]", encoding="utf-8")
    (stage1_dir / "dns_queries.json").write_text("[]", encoding="utf-8")
    (run_dir / "scores.json").write_text("[]", encoding="utf-8")
    (run_dir / "exfil_report.md").write_text("# Report", encoding="utf-8")

    monkeypatch.setattr("webapp.job_manager.STAGE1_OUTPUT", stage1_dir)
    monkeypatch.setattr("webapp.job_manager.PIPELINE_OUTPUT", pipeline_output)

    manager = JobManager(tmp_path / "jobs")
    job = make_job(tmp_path / "job")
    job.output_run_id = run_id
    manager._snapshot_outputs(job)

    snapshot = job.job_dir / "output"
    assert (snapshot / "raw_packets.json").exists()
    assert (snapshot / "dns_queries.json").exists()
    assert (snapshot / "scores.json").exists()
    assert (snapshot / "exfil_report.md").exists()
