"""Python Security Log Analyzer (defensive, educational).

Reads a local authentication/server log file, parses each line into
(timestamp, event type, username, source IP), and reports:

- successful logins
- failed logins
- repeated failed login attempts (brute-force signal)
- suspicious IP addresses (>= --threshold failures)

Standard library only: re, argparse, collections, datetime, json,
csv, pathlib, logging, ipaddress, typing.

Example:
    python analyzer.py --log-file sample.log --threshold 3
    python analyzer.py --log-file sample.log --json-out reports/out.json --csv-out reports/out.csv
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import re
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Literal

from config import (
    DEFAULT_CSV_REPORT,
    DEFAULT_FAILED_THRESHOLD,
    DEFAULT_JSON_REPORT,
    DEFAULT_LOG_FILE,
    TIMESTAMP_FORMAT,
)

logger = logging.getLogger("log_analyzer")

# ---------------------------------------------------------------------------
# Regex patterns (compiled once, reused for every line)
# ---------------------------------------------------------------------------

# Timestamp pattern "YYYY-MM-DD HH:MM:SS" searched anywhere in the line
# (by convention log lines start with the timestamp).
TIMESTAMP_RE = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")

# IPv4 candidate anywhere in the line. Candidates are validated with
# ipaddress.IPv4Address (see extract_ip), so invalid octets such as
# 999.999.999.999 are rejected.
IP_RE = re.compile(r"\b(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")

# Username heuristics — tried in order, first match wins.
# Covers: "user=alice", "username: bob", "Failed login for user alice",
# "Failed password for invalid user admin", "Accepted password for carol".
USER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"user(?:name)?\s*[=:]\s*(?P<u>[A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"for invalid user\s+(?P<u>[A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"for user\s+(?P<u>[A-Za-z0-9_.-]+)", re.IGNORECASE),
    re.compile(r"for\s+(?P<u>[A-Za-z0-9_.-]+)\s+from\s+\d", re.IGNORECASE),
    re.compile(r"User\s+(?P<u>[A-Za-z0-9_.-]+)\s+(?:logged|login)", re.IGNORECASE),
]

# Event-type keywords (checked case-insensitively).
FAILED_KEYWORDS = ("failed", "failure", "invalid", "denied", "unauthorized")
SUCCESS_KEYWORDS = ("success", "succeed", "accepted", "authenticated", "granted", "logged in")

# Valid event labels used throughout the report.
EventType = Literal["SUCCESS", "FAILED", "OTHER"]


# ---------------------------------------------------------------------------
# CLI / logging setup
# ---------------------------------------------------------------------------

def setup_logging(verbose: bool) -> None:
    """Configure the root logger for terminal output.

    Args:
        verbose: If True use DEBUG level, otherwise INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s: %(message)s",
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments.

    Args:
        argv: Optional argument list (defaults to sys.argv). Exposed as a
            parameter so unit tests can inject fake argv.

    Returns:
        Parsed argparse namespace with log_file, threshold,
        json_out, csv_out, no_reports, verbose.

    Raises:
        SystemExit: If argparse encounters invalid arguments.
        ValueError: If threshold is not a positive integer.
    """
    parser = argparse.ArgumentParser(
        description="Defensive security log analyzer: detect suspicious login activity."
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=DEFAULT_LOG_FILE,
        help=f"Path to log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_FAILED_THRESHOLD,
        help=f"Failed attempts from one IP to flag as suspicious (default: {DEFAULT_FAILED_THRESHOLD})",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_JSON_REPORT,
        help=f"Where to write the JSON report (default: {DEFAULT_JSON_REPORT})",
    )
    parser.add_argument(
        "--csv-out",
        type=Path,
        default=DEFAULT_CSV_REPORT,
        help=f"Where to write the CSV report (default: {DEFAULT_CSV_REPORT})",
    )
    parser.add_argument(
        "--no-reports",
        action="store_true",
        help="Print summary only, do not write JSON/CSV files.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args(argv)

    if args.threshold < 1:
        raise ValueError("--threshold must be a positive integer (>= 1).")

    return args


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def classify_event(line: str) -> EventType:
    """Classify a raw log line as SUCCESS, FAILED, or OTHER.

    Args:
        line: Raw log line text.

    Returns:
        One of "SUCCESS", "FAILED", "OTHER". FAILED is checked first
        so a line containing both (rare) is treated as a failure.
    """
    lowered = line.lower()
    if any(k in lowered for k in FAILED_KEYWORDS):
        return "FAILED"
    if any(k in lowered for k in SUCCESS_KEYWORDS):
        return "SUCCESS"
    return "OTHER"


def extract_username(line: str) -> str | None:
    """Extract a username from a log line, if present.

    Args:
        line: Raw log line text.

    Returns:
        Username string or None when no known pattern matches.
    """
    for pattern in USER_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group("u").strip(".,:;\"'")
    return None


def extract_ip(line: str) -> str | None:
    """Extract the first valid IPv4 address from a log line, if present.

    Args:
        line: Raw log line text.

    Returns:
        Dotted-quad IPv4 string or None. Regex candidates with out-of-range
        octets (for example "999.999.999.999") are rejected via
        ipaddress.IPv4Address.
    """
    for match in IP_RE.finditer(line):
        candidate = match.group("ip")
        try:
            ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        return candidate
    return None


def parse_log_line(line: str) -> dict | None:
    """Parse a single log line into a structured event dict.

    Args:
        line: One raw line from the log file (newline stripped or not).

    Returns:
        Dict with keys: timestamp (datetime | None), timestamp_raw (str | None),
        event_type ("SUCCESS"|"FAILED"|"OTHER"), username (str | None),
        ip (str | None), raw (str). Returns None for blank lines.
    """
    stripped = line.strip()
    if not stripped:
        return None  # skip empty lines silently

    timestamp: datetime | None = None
    timestamp_raw: str | None = None
    ts_match = TIMESTAMP_RE.search(stripped)
    if ts_match:
        timestamp_raw = ts_match.group("ts")
        try:
            timestamp = datetime.strptime(timestamp_raw, TIMESTAMP_FORMAT)
        except ValueError:
            logger.debug("Unparseable timestamp %r in line: %s", timestamp_raw, stripped)
            timestamp = None

    event: dict = {
        "timestamp": timestamp,
        "timestamp_raw": timestamp_raw,
        "event_type": classify_event(stripped),
        "username": extract_username(stripped),
        "ip": extract_ip(stripped),
        "raw": stripped,
    }
    return event


def validate_log_path(log_path: Path) -> Path:
    """Validate that a log file exists and is a file.

    Args:
        log_path: Candidate path to the log file.

    Returns:
        The same path, for chaining.

    Raises:
        FileNotFoundError: If the path does not exist or is not a file.
    """
    if not log_path.exists() or not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")
    return log_path


def load_logs(log_path: Path) -> list[dict]:
    """Read and parse every line of a log file.

    Malformed/blank lines are skipped with a warning (never crash the run).

    Args:
        log_path: Path to the log file.

    Returns:
        List of parsed event dicts (see parse_log_line).

    Raises:
        FileNotFoundError: If the log file does not exist.
        PermissionError: If the log file cannot be read.
        UnicodeDecodeError: If the file is not decodable as UTF-8.
    """
    validate_log_path(log_path)
    events: list[dict] = []
    skipped = 0
    try:
        with log_path.open("r", encoding="utf-8", errors="strict") as fh:
            for lineno, line in enumerate(fh, start=1):
                if not line.strip():
                    continue
                event = parse_log_line(line)
                if event is None:
                    continue
                # A line with no timestamp, no IP, no username and OTHER
                # type carries no signal — count it as unparseable.
                if (
                    event["timestamp_raw"] is None
                    and event["ip"] is None
                    and event["username"] is None
                    and event["event_type"] == "OTHER"
                ):
                    skipped += 1
                    logger.warning("Line %d: unparseable, skipped: %r", lineno, line.strip())
                    continue
                events.append(event)
    except PermissionError:
        logger.error("Permission denied reading log file: %s", log_path)
        raise
    if skipped:
        logger.info("Skipped %d unparseable line(s).", skipped)
    logger.info("Loaded %d event(s) from %s.", len(events), log_path)
    return events


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def analyze_logs(events: list[dict], failed_threshold: int = DEFAULT_FAILED_THRESHOLD) -> dict:
    """Aggregate parsed events into a security report dict.

    Args:
        events: Parsed events from load_logs().
        failed_threshold: IPs with >= this many failures are flagged.

    Returns:
        JSON-serializable report dict with totals, per-IP / per-user
        counters, suspicious IPs, and observed time range.

    Raises:
        ValueError: If failed_threshold < 1.
    """
    if failed_threshold < 1:
        raise ValueError("failed_threshold must be >= 1.")

    failed_by_ip: Counter = Counter()
    success_by_ip: Counter = Counter()
    failed_by_user: Counter = Counter()
    success_by_user: Counter = Counter()
    success_count = 0
    failed_count = 0

    timestamps = [e["timestamp"] for e in events if e.get("timestamp") is not None]

    for event in events:
        etype = event.get("event_type")
        ip = event.get("ip")
        user = event.get("username")
        if etype == "FAILED":
            failed_count += 1
            if ip:
                failed_by_ip[ip] += 1
            if user:
                failed_by_user[user] += 1
        elif etype == "SUCCESS":
            success_count += 1
            if ip:
                success_by_ip[ip] += 1
            if user:
                success_by_user[user] += 1

    suspicious_ips = {
        ip: count for ip, count in failed_by_ip.items() if count >= failed_threshold
    }
    # Most active attackers first.
    suspicious_ips = dict(
        sorted(suspicious_ips.items(), key=lambda kv: kv[1], reverse=True)
    )

    all_ips = set(failed_by_ip) | set(success_by_ip)
    ip_summary = {
        ip: {
            "successful_logins": success_by_ip.get(ip, 0),
            "failed_logins": failed_by_ip.get(ip, 0),
            "total": success_by_ip.get(ip, 0) + failed_by_ip.get(ip, 0),
            "flagged_suspicious": ip in suspicious_ips,
        }
        for ip in sorted(all_ips)
    }

    report: dict = {
        "total_events": len(events),
        "successful_logins": success_count,
        "failed_logins": failed_count,
        "other_events": len(events) - success_count - failed_count,
        "failed_threshold": failed_threshold,
        "suspicious_ips": suspicious_ips,
        "failed_by_ip": dict(failed_by_ip.most_common()),
        "success_by_ip": dict(success_by_ip.most_common()),
        "failed_by_user": dict(failed_by_user.most_common()),
        "success_by_user": dict(success_by_user.most_common()),
        "ip_summary": ip_summary,
        "time_range": {
            "start": min(timestamps).isoformat(sep=" ") if timestamps else None,
            "end": max(timestamps).isoformat(sep=" ") if timestamps else None,
        },
    }
    return report


# ---------------------------------------------------------------------------
# Output: terminal summary + JSON + CSV
# ---------------------------------------------------------------------------

def format_summary(report: dict) -> str:
    """Render the report as a human-readable terminal summary.

    Args:
        report: Dict returned by analyze_logs().

    Returns:
        Multi-line string ready to print.
    """
    lines = [
        "=" * 52,
        " SECURITY LOG ANALYSIS SUMMARY",
        "=" * 52,
        f"Total events       : {report['total_events']}",
        f"Successful logins  : {report['successful_logins']}",
        f"Failed logins      : {report['failed_logins']}",
        f"Other events       : {report['other_events']}",
        f"Failed threshold   : >= {report['failed_threshold']} fails from one IP",
        f"Time range         : {report['time_range']['start']} .. {report['time_range']['end']}",
        "-" * 52,
    ]
    if report["suspicious_ips"]:
        lines.append("SUSPICIOUS IPs (repeated failures):")
        for ip, count in report["suspicious_ips"].items():
            lines.append(f"  ! {ip:<15} {count} failed attempt(s)")
    else:
        lines.append("SUSPICIOUS IPs     : none detected")

    lines.append("-" * 52)
    lines.append("Top failed usernames targeted:")
    if report["failed_by_user"]:
        for user, count in list(report["failed_by_user"].items())[:5]:
            lines.append(f"    {user:<15} {count} failure(s)")
    else:
        lines.append("    (none)")

    lines.append("Top failed source IPs:")
    if report["failed_by_ip"]:
        for ip, count in list(report["failed_by_ip"].items())[:5]:
            lines.append(f"    {ip:<15} {count} failure(s)")
    else:
        lines.append("    (none)")
    lines.append("=" * 52)
    return "\n".join(lines)


def save_json_report(report: dict, output_path: Path) -> None:
    """Write the report dict to a pretty-printed JSON file.

    Args:
        report: Dict returned by analyze_logs().
        output_path: Destination .json file (parents created as needed).

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    logger.info("JSON report written to %s", output_path)


def save_csv_report(report: dict, output_path: Path) -> None:
    """Write the per-IP summary table to CSV.

    Columns: ip, successful_logins, failed_logins, total, flagged_suspicious.

    Args:
        report: Dict returned by analyze_logs().
        output_path: Destination .csv file (parents created as needed).

    Raises:
        OSError: If the file cannot be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["ip", "successful_logins", "failed_logins", "total", "flagged_suspicious"],
        )
        writer.writeheader()
        for ip, stats in report.get("ip_summary", {}).items():
            writer.writerow({"ip": ip, **stats})
    logger.info("CSV report written to %s", output_path)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    """CLI entry point: parse args, load, analyze, print, optionally save.

    Args:
        argv: Optional arg list for testing (defaults to sys.argv).

    Returns:
        Process exit code (0 = success, 1 = expected error, 2 = unexpected).
    """
    try:
        args = parse_args(argv)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    setup_logging(args.verbose)

    try:
        events = load_logs(args.log_file)
        if not events:
            logger.warning("No parseable events found in %s.", args.log_file)
        report = analyze_logs(events, failed_threshold=args.threshold)
        print(format_summary(report))

        if not args.no_reports:
            try:
                save_json_report(report, args.json_out)
                save_csv_report(report, args.csv_out)
            except OSError as exc:
                logger.error("Could not write report files: %s", exc)
                return 1
        return 0
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1
    except (PermissionError, UnicodeDecodeError, ValueError) as exc:
        logger.error("Failed to analyze logs: %s", exc)
        return 1
    except Exception as exc:  # defensive: never traceback on a CLI tool
        logger.exception("Unexpected error: %s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
