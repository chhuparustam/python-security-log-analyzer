"""Unit tests for analyzer.py (run with: pytest -v)."""

import json
from pathlib import Path

import pytest

from analyzer import (
    analyze_logs,
    classify_event,
    extract_ip,
    extract_username,
    format_summary,
    load_logs,
    main,
    parse_args,
    parse_log_line,
    save_csv_report,
    save_json_report,
)


# --- parse_log_line ---------------------------------------------------------

def test_parse_success_line():
    event = parse_log_line("2026-09-26 08:12:01 INFO Successful login for user alice from 192.168.1.10")
    assert event is not None
    assert event["event_type"] == "SUCCESS"
    assert event["username"] == "alice"
    assert event["ip"] == "192.168.1.10"
    assert event["timestamp_raw"] == "2026-09-26 08:12:01"


def test_parse_failed_ssh_style():
    event = parse_log_line(
        "2026-09-26 08:20:55 WARN Failed password for invalid user admin from 203.0.113.5 port 48231"
    )
    assert event is not None
    assert event["event_type"] == "FAILED"
    assert event["username"] == "admin"
    assert event["ip"] == "203.0.113.5"


def test_parse_blank_line_returns_none():
    assert parse_log_line("   \n") is None
    assert parse_log_line("") is None


def test_parse_garbage_line_has_no_signal():
    event = parse_log_line("THIS IS NOT A VALID LOG LINE")
    assert event is not None
    assert event["event_type"] == "OTHER"
    assert event["ip"] is None
    assert event["username"] is None
    assert event["timestamp_raw"] is None


# --- classify_event / extract_username --------------------------------------

@pytest.mark.parametrize(
    "line,expected",
    [
        ("Failed login for bob", "FAILED"),
        ("Invalid password attempt", "FAILED"),
        ("Access denied for eve", "FAILED"),
        ("Accepted password for bob", "SUCCESS"),
        ("Authentication succeeded", "SUCCESS"),
        ("System health check OK", "OTHER"),
    ],
)
def test_classify_event(line, expected):
    assert classify_event(line) == expected


@pytest.mark.parametrize(
    "line,expected",
    [
        ("Failed login for user alice from 1.1.1.1", "alice"),
        ("Failed password for invalid user root from 1.1.1.1", "root"),
        ("Accepted password for bob from 1.1.1.1", "bob"),
        ("login username=carol src_ip=1.1.1.1", "carol"),
        ("nothing here", None),
    ],
)
def test_extract_username(line, expected):
    assert extract_username(line) == expected


# --- analyze_logs ------------------------------------------------------------

def _make_event(event_type="FAILED", ip="1.2.3.4", username="alice"):
    return {
        "timestamp": None,
        "timestamp_raw": None,
        "event_type": event_type,
        "username": username,
        "ip": ip,
        "raw": "fake",
    }


def test_analyze_threshold_flags_suspicious_ip():
    events = [_make_event("FAILED", ip="9.9.9.9") for _ in range(4)]
    events += [_make_event("SUCCESS", ip="9.9.9.9")]
    report = analyze_logs(events, failed_threshold=3)
    assert report["failed_logins"] == 4
    assert report["successful_logins"] == 1
    assert report["suspicious_ips"] == {"9.9.9.9": 4}
    assert report["ip_summary"]["9.9.9.9"]["flagged_suspicious"] is True


def test_analyze_threshold_not_reached():
    events = [_make_event("FAILED", ip="5.5.5.5") for _ in range(2)]
    report = analyze_logs(events, failed_threshold=3)
    assert report["suspicious_ips"] == {}
    assert report["ip_summary"]["5.5.5.5"]["flagged_suspicious"] is False


def test_analyze_rejects_bad_threshold():
    with pytest.raises(ValueError):
        analyze_logs([], failed_threshold=0)


def test_parse_args_rejects_bad_threshold():
    with pytest.raises(ValueError):
        parse_args(["--threshold", "0"])


# --- load_logs / reports (tmp files) -----------------------------------------

def test_load_logs_missing_file(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_logs(tmp_path / "does-not-exist.log")


def test_load_logs_skips_garbage(tmp_path: Path):
    log = tmp_path / "t.log"
    log.write_text(
        "2026-09-26 08:12:01 INFO Successful login for user alice from 192.168.1.10\n"
        "GARBAGE LINE WITH NO SIGNAL\n"
        "\n",
        encoding="utf-8",
    )
    events = load_logs(log)
    assert len(events) == 1
    assert events[0]["username"] == "alice"


def test_save_json_and_csv_reports(tmp_path: Path):
    events = [_make_event("FAILED", ip="9.9.9.9", username="admin") for _ in range(3)]
    report = analyze_logs(events, failed_threshold=3)
    jp, cp = tmp_path / "r.json", tmp_path / "r.csv"
    save_json_report(report, jp)
    save_csv_report(report, cp)
    assert jp.exists() and cp.exists()
    text = cp.read_text(encoding="utf-8")
    assert "ip,successful_logins,failed_logins,total,flagged_suspicious" in text
    assert "9.9.9.9" in text


def test_format_summary_contains_key_sections():
    report = analyze_logs([_make_event("FAILED", ip="9.9.9.9") for _ in range(3)])
    summary = format_summary(report)
    assert "SECURITY LOG ANALYSIS SUMMARY" in summary
    assert "9.9.9.9" in summary


# --- IPv4 validation ---------------------------------------------------------

def test_extract_ip_rejects_invalid_octets():
    assert extract_ip("Failed login from 999.999.999.999") is None
    assert extract_ip("Failed login from 256.1.1.1") is None


def test_parse_log_line_rejects_invalid_ip():
    event = parse_log_line(
        "2026-09-26 08:12:01 WARN Failed login for user alice from 999.999.999.999"
    )
    assert event is not None
    assert event["ip"] is None
    assert event["event_type"] == "FAILED"


def test_extract_ip_skips_invalid_then_takes_valid():
    # First candidate is invalid, second is valid — valid one wins.
    assert extract_ip("Failed from 999.999.999.999 then from 1.2.3.4") == "1.2.3.4"


# --- empty events / empty log ------------------------------------------------

def test_analyze_empty_events():
    report = analyze_logs([], failed_threshold=3)
    assert report["total_events"] == 0
    assert report["successful_logins"] == 0
    assert report["failed_logins"] == 0
    assert report["other_events"] == 0
    assert report["suspicious_ips"] == {}
    assert report["ip_summary"] == {}
    assert report["time_range"] == {"start": None, "end": None}


def test_load_logs_empty_file(tmp_path: Path):
    log = tmp_path / "empty.log"
    log.write_text("", encoding="utf-8")
    assert load_logs(log) == []


# --- OTHER events excluded from failure summaries ----------------------------

def test_other_events_excluded_from_failed_summaries():
    events = [
        _make_event("OTHER", ip="7.7.7.7", username="bob"),
        _make_event("FAILED", ip="9.9.9.9", username="alice"),
    ]
    report = analyze_logs(events, failed_threshold=1)
    assert "7.7.7.7" not in report["failed_by_ip"]
    assert "7.7.7.7" not in report["suspicious_ips"]
    assert "7.7.7.7" not in report["ip_summary"]
    assert report["failed_by_ip"] == {"9.9.9.9": 1}


# --- report serialization / parent dirs --------------------------------------

def test_report_is_json_serializable():
    events = [_make_event("FAILED", ip="9.9.9.9", username="admin") for _ in range(3)]
    events += [_make_event("SUCCESS", ip="10.0.0.5", username="bob")]
    report = analyze_logs(events, failed_threshold=3)
    # Must not raise TypeError — timestamps are stored as ISO strings.
    text = json.dumps(report)
    assert "9.9.9.9" in text


def test_save_reports_create_parent_dirs(tmp_path: Path):
    events = [_make_event("FAILED", ip="9.9.9.9", username="admin") for _ in range(3)]
    report = analyze_logs(events, failed_threshold=3)
    jp = tmp_path / "nested" / "deep" / "r.json"
    cp = tmp_path / "nested" / "deep" / "r.csv"
    save_json_report(report, jp)
    save_csv_report(report, cp)
    assert jp.exists()
    assert cp.exists()


# --- main() entry point ------------------------------------------------------

def test_main_missing_file_returns_1(tmp_path: Path):
    code = main(["--log-file", str(tmp_path / "nope.log"), "--no-reports"])
    assert code == 1


def test_main_no_reports_returns_0(tmp_path: Path):
    log = tmp_path / "t.log"
    log.write_text(
        "2026-09-26 08:12:01 INFO Successful login for user alice from 192.168.1.10\n",
        encoding="utf-8",
    )
    code = main(["--log-file", str(log), "--no-reports"])
    assert code == 0
