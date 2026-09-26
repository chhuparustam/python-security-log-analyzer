# Python Security Log Analyzer

A beginner-to-intermediate **defensive** cybersecurity project in Python.
It reads a local authentication/server log file, parses each line, and
detects suspicious login activity such as brute-force attempts.

Strictly defensive and educational — no offensive / hacking functionality.

## Features

- Parses per line: **timestamp**, **event type** (`SUCCESS` / `FAILED` / `OTHER`),
  **username** (if present), **source IP**
- Counts successful logins, failed logins, other events
- Detects **repeated failed attempts** and flags **suspicious IPs**
  (failed count from one IP `>= --threshold`, default `3`)
- Configurable threshold via CLI or `config.py`
- Outputs:
  - terminal security summary
  - JSON report (`reports/security_report.json`)
  - CSV per-IP summary (`reports/security_report.csv`)
- Robust: skips malformed lines with warnings, validates inputs,
  handles missing files / permissions gracefully
- Runtime uses Python standard library only (`re`, `argparse`, `collections`,
  `datetime`, `json`, `csv`, `pathlib`, `logging`, `ipaddress`, `typing`);
  `pytest` is a development-only dependency for tests
- Type hints + docstrings throughout, unit-tested

## Architecture

```text
sample.log ──▶ parse_log_line() ──▶ load_logs() ──▶ analyze_logs() ──┬──▶ format_summary() → terminal
               (re, datetime)        (pathlib,            (collections.Counter)  ├──▶ save_json_report() → .json
                                      logging, validation)                      └──▶ save_csv_report()  → .csv

config.py ──▶ shared defaults (paths, threshold, timestamp format)
tests/test_analyzer.py ──▶ pytest coverage of parsing, analysis, reports
```

Data flow: raw line → structured event dict
`{timestamp, timestamp_raw, event_type, username, ip, raw}`
→ aggregated report dict
`{totals, suspicious_ips, failed/success_by_ip/user, ip_summary, time_range}`.

## Installation

Requirements: **Python 3.11+** (supported and tested on Python 3.11, 3.12, 3.13).

```bash
# 1. Clone / enter the project
cd Security_log_analyzer

# 2. (Recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate

# 3. Install test dependency (development only)
pip install -r requirements.txt
```

No runtime dependencies — the analyzer itself uses the Python standard
library only. `requirements.txt` contains `pytest` for running the test suite.

## Usage

```bash
# Basic run (uses sample.log, threshold 3)
python analyzer.py

# Custom log file + threshold
python analyzer.py --log-file sample.log --threshold 5

# Custom report locations
python analyzer.py --json-out reports/my.json --csv-out reports/my.csv

# Summary only, no files written
python analyzer.py --no-reports

# Debug logging
python analyzer.py -v

# Full help
python analyzer.py --help
```

Run the tests:

```bash
pytest -v
```

Expected: all tests pass (33 passed on Python 3.11+).

## Example Output

Terminal:

```text
====================================================
 SECURITY LOG ANALYSIS SUMMARY
====================================================
Total events       : 32
Successful logins  : 10
Failed logins      : 20
Other events       : 2
Failed threshold   : >= 3 fails from one IP
Time range         : 2026-09-26 08:12:01 .. 2026-09-26 10:30:09
----------------------------------------------------
SUSPICIOUS IPs (repeated failures):
  ! 203.0.113.5     7 failed attempt(s)
  ! 192.168.1.99    5 failed attempt(s)
  ! 198.51.100.23   4 failed attempt(s)
----------------------------------------------------
Top failed usernames targeted:
    admin           8 failure(s)
    alice           4 failure(s)
    ...
Top failed source IPs:
    203.0.113.5     7 failure(s)
    192.168.1.99    5 failure(s)
    198.51.100.23   4 failure(s)
====================================================
INFO: JSON report written to reports/security_report.json
INFO: CSV report written to reports/security_report.csv
```

JSON (`reports/security_report.json`, excerpt):

```json
{
  "total_events": 32,
  "successful_logins": 10,
  "failed_logins": 20,
  "failed_threshold": 3,
  "suspicious_ips": {
    "203.0.113.5": 7,
    "192.168.1.99": 5,
    "198.51.100.23": 4
  }
}
```

CSV (`reports/security_report.csv`, excerpt):

```csv
ip,successful_logins,failed_logins,total,flagged_suspicious
10.0.0.5,3,0,3,False
192.168.1.99,0,5,5,True
198.51.100.23,0,4,4,True
203.0.113.5,0,7,7,True
```

## Security Considerations

- **Local-only, read-only**: the tool only *reads* the log file you point it at;
  it never opens network connections or modifies the system.
- **No credentials parsed**: only username + IP + timestamp are extracted;
  never feed files containing passwords/secrets into reports you share.
- **Warning logs may echo raw lines**: unparseable lines are logged with a
  warning that includes the raw line content. Handle logs containing secrets
  carefully (avoid sharing terminal output, redact before posting).
- **Reports may contain PII** (usernames, IPs) — treat JSON/CSV outputs as
  sensitive, restrict permissions, and redact before sharing.
- **Log integrity**: this tool assumes the log file is trustworthy. In
  production, ship logs to append-only storage so attackers cannot tamper
  with the evidence you analyze.
- **Threshold ≠ verdict**: a flagged IP is a *signal* (possible brute force),
  not proof of malice — always correlate with firewall/IDS data.

## Limitations

- IPv4 only (no IPv6 pattern yet). IPv4 candidates with out-of-range octets
  (for example `999.999.999.999`) are rejected via the standard-library
  `ipaddress` module.
- Single timestamp format (`YYYY-MM-DD HH:MM:SS`); other syslog formats
  without that prefix are counted as unparseable for time-range purposes
  (IP/user/event are still extracted when present).
- Keyword-based classification (`failed`/`accepted`/…); unusual wording
  falls back to `OTHER`.
- Single-file, whole-file-in-memory analysis — fine for learning-size logs,
  not for multi-GB production logs.
- No real-time / streaming mode.

## Future Improvements

- IPv6 + broader syslog timestamp support
- Time-window detection (e.g. “N failures in M minutes”) instead of flat counts
- Allowlist for known-good IPs, blocklist export (firewall rules)
- HTML dashboard report
- Streaming mode for large files (`mmap` / generators)
- Config file (`analyzer.ini` / `pyproject.toml` section) for thresholds

## License

MIT — see [LICENSE](LICENSE).
