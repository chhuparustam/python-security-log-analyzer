"""Central configuration for the Python Security Log Analyzer.

Keeps all tunable defaults in one place so the CLI (analyzer.py)
and tests import from here instead of hard-coding values.
"""

from pathlib import Path

# Base directory = folder that contains this file (project root).
BASE_DIR: Path = Path(__file__).resolve().parent

# Default inputs / outputs (relative to project root).
DEFAULT_LOG_FILE: Path = BASE_DIR / "sample.log"
DEFAULT_JSON_REPORT: Path = BASE_DIR / "reports" / "security_report.json"
DEFAULT_CSV_REPORT: Path = BASE_DIR / "reports" / "security_report.csv"

# Detection tuning: how many failed logins from one IP count as suspicious.
DEFAULT_FAILED_THRESHOLD: int = 3

# Expected timestamp format at the start of each log line.
TIMESTAMP_FORMAT: str = "%Y-%m-%d %H:%M:%S"
