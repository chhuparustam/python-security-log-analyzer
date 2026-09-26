# 🔐 Python Security Log Analyzer

A beginner-to-intermediate **defensive cybersecurity project built with Python** that analyzes local authentication/server log files and identifies suspicious login activity such as repeated failed login attempts that may indicate brute-force behavior.

The project is designed for **cybersecurity learning, log analysis, security monitoring, and Python practice**. It does not perform exploitation, unauthorized access, password attacks, or network scanning.

---

## 📌 Project Overview

Security logs contain valuable information about authentication activity on a system.

For example, a log may contain:

```text
2026-09-26 08:12:01 LOGIN_SUCCESS user=alice ip=192.168.1.10
2026-09-26 08:15:22 LOGIN_FAILED user=admin ip=192.168.1.99
2026-09-26 08:15:25 LOGIN_FAILED user=admin ip=192.168.1.99
2026-09-26 08:15:27 LOGIN_FAILED user=admin ip=192.168.1.99
```

Manually checking hundreds or thousands of log entries can be difficult.

This project automates the process by:

1. Reading a local log file.
2. Parsing individual log entries.
3. Identifying successful and failed login attempts.
4. Grouping failed attempts by source IP address.
5. Comparing failure counts against a configurable threshold.
6. Flagging potentially suspicious IP addresses.
7. Generating security reports in JSON and CSV format.
8. Handling malformed log entries without crashing.

> **Important:** A flagged IP does not automatically mean that an attack occurred. It indicates a suspicious pattern that may require further investigation.

---

# 🎯 Objectives

The main objectives of this project are:

* Learn practical Python programming.
* Understand authentication and server logs.
* Practice regular expressions and text parsing.
* Use Python collections for log analysis.
* Detect repeated failed authentication attempts.
* Generate machine-readable security reports.
* Practice exception handling and input validation.
* Write unit tests using `pytest`.
* Follow basic defensive cybersecurity practices.

---

# ✨ Features

### 🔍 Log File Analysis

Reads a local authentication/server log file and processes each line.

### 🔐 Login Event Detection

Identifies:

* Successful logins
* Failed logins
* Other events

### 🚨 Suspicious Activity Detection

Groups failed login attempts by source IP address.

By default, an IP is considered suspicious when it has:

```text
3 or more failed login attempts
```

The threshold can be configured.

### 📊 Security Summary

Displays a terminal summary containing:

```text
Total events
Successful logins
Failed logins
Other events
Failed threshold
Time range
Suspicious IP addresses
```

### 📄 JSON Report

The analyzer can generate a structured JSON report suitable for further processing.

Example:

```json
{
  "total_events": 32,
  "successful_logins": 10,
  "failed_logins": 20,
  "other_events": 2,
  "suspicious_ips": {
    "203.0.113.5": 7,
    "192.168.1.99": 5,
    "198.51.100.23": 4
  }
}
```

### 📑 CSV Report

A CSV report is also generated for easy viewing in spreadsheet applications.

### 🛡️ Graceful Error Handling

Malformed or invalid log lines are skipped with a warning instead of crashing the entire program.

Example:

```text
WARNING: Line 26: unparseable, skipped:
'THIS IS NOT A VALID LOG LINE AND SHOULD BE SKIPPED GRACEFULLY'
```

### 🧪 Automated Testing

The project includes unit tests using `pytest`.

Current test status:

```text
33 passed
```

---

# 🏗️ Project Architecture

```text
                    ┌──────────────────┐
                    │    sample.log    │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    analyzer.py   │
                    │                  │
                    │  Parse Log Lines │
                    │       ↓          │
                    │  Classify Events │
                    │       ↓          │
                    │ Count IPs        │
                    │       ↓          │
                    │ Detect Patterns  │
                    └────────┬─────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌───────────┐
        │ Terminal │   │   JSON   │   │    CSV    │
        │ Summary  │   │  Report  │   │   Report  │
        └──────────┘   └──────────┘   └───────────┘
```

---

# 🛠️ Technology Stack

| Technology                | Purpose                           |
| ------------------------- | --------------------------------- |
| **Python 3.11+**          | Core programming language         |
| **Regular Expressions**   | Log parsing                       |
| **Pathlib**               | File and path handling            |
| **Collections / Counter** | Counting failed attempts          |
| **Argparse**              | Command-line interface            |
| **IPaddress**             | IPv4 validation                   |
| **JSON**                  | Structured report generation      |
| **CSV**                   | Tabular report generation         |
| **Logging**               | Warnings and application messages |
| **Pytest**                | Automated testing                 |

### Runtime Dependencies

The application itself uses only the **Python standard library**.

`pytest` is used only for development and testing.

---

# 📁 Project Structure

```text
python-security-log-analyzer/
│
├── analyzer.py              # Main log analysis logic
├── config.py                # Configuration and threshold
├── sample.log               # Sample authentication log
├── README.md                # Project documentation
├── LICENSE                  # MIT License
├── requirements.txt         # Development dependency
├── .gitignore               # Git ignored files
│
├── reports/
│   └── .gitkeep             # Keeps reports directory in Git
│
└── tests/
    ├── __init__.py
    └── test_analyzer.py     # Automated tests
```

Generated reports are intentionally ignored by Git.

---

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone git@github.com:chhuparustam/python-security-log-analyzer.git
```

Or using HTTPS:

```bash
git clone https://github.com/chhuparustam/python-security-log-analyzer.git
```

---

## 2. Enter the project directory

```bash
cd python-security-log-analyzer
```

---

## 3. Create a virtual environment

### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

### Linux/macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 4. Install development dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

Run the analyzer with the default sample log:

```bash
python analyzer.py
```

The application analyzes `sample.log` and displays a security summary.

Example:

```text
====================================================
 SECURITY LOG ANALYSIS SUMMARY
====================================================

Total events       : 32
Successful logins  : 10
Failed logins      : 20
Other events       : 2
Failed threshold   : >= 3 fails from one IP

Time range         :
2026-09-26 08:12:01 .. 2026-09-26 10:30:09

Suspicious IPs:
203.0.113.5        : 7 failed attempts
192.168.1.99       : 5 failed attempts
198.51.100.23      : 4 failed attempts
```

---

# 🚫 Running Without Reports

If you only want the terminal analysis and do not want JSON/CSV reports generated:

```bash
python analyzer.py --no-reports
```

---

# 📝 Sample Log Format

The project uses authentication-style log entries such as:

```text
2026-09-26 08:12:01 LOGIN_SUCCESS user=alice ip=192.168.1.10
2026-09-26 08:13:45 LOGIN_FAILED user=admin ip=203.0.113.5
2026-09-26 08:14:03 LOGIN_FAILED user=admin ip=203.0.113.5
2026-09-26 08:14:22 LOGIN_FAILED user=admin ip=203.0.113.5
```

The analyzer extracts:

* Timestamp
* Event type
* Username
* Source IP address

---

# 🚨 How Suspicious IP Detection Works

Suppose the configuration threshold is:

```text
3 failed attempts
```

And the log contains:

```text
192.168.1.99 → 1 failed attempt
203.0.113.5  → 7 failed attempts
198.51.100.23 → 4 failed attempts
```

The analyzer identifies:

```text
203.0.113.5
198.51.100.23
```

as suspicious because their failed-login count is greater than or equal to the configured threshold.

### Important Security Interpretation

The application does **not** claim that these IP addresses are attackers.

It only detects a pattern that may be consistent with:

* Brute-force attempts
* Repeated authentication failures
* Misconfigured applications
* Forgotten passwords
* Automated login attempts
* Other abnormal authentication behavior

Further investigation would be required before concluding that an attack occurred.

---

# 🧠 Key Python Concepts Demonstrated

This project demonstrates practical use of:

### File Handling

```python
with open(log_file, "r", encoding="utf-8") as file:
    ...
```

### Regular Expressions

Used to extract structured information from log lines.

### `Counter`

Used to count failed attempts per IP address.

### `argparse`

Used to provide command-line options.

### `pathlib`

Used for portable file and directory handling.

### Exception Handling

Used to handle:

* Missing files
* Invalid input
* Malformed log entries
* Invalid IP addresses
* Report-writing errors

### Type Hints

Functions use type annotations to improve readability and maintainability.

### Unit Testing

The analyzer is tested using `pytest`.

---

# 🧪 Testing

Run all tests:

```bash
pytest -q
```

Current result:

```text
33 passed
```

The tests cover areas including:

* Valid log parsing
* Invalid log lines
* Empty logs
* Failed-login detection
* Suspicious IP detection
* Invalid IP addresses
* Event classification
* JSON serialization
* CSV/report generation
* Missing input files
* Command-line behavior
* Parent directory creation

---

# 🔒 Security Design

This project is intentionally **defensive**.

It:

* Reads local files only.
* Does not connect to external systems.
* Does not scan networks.
* Does not exploit vulnerabilities.
* Does not perform password attacks.
* Does not attempt unauthorized access.
* Does not collect credentials.
* Does not execute commands from log content.

Its purpose is to demonstrate basic **security monitoring and log analysis**.

---

# ⚠️ Limitations

This is an educational project and should not be considered a production SIEM or intrusion detection system.

Current limitations include:

* Supports the project's defined log format.
* Detection is based primarily on failed-login counts.
* Does not perform real-time log monitoring.
* Does not correlate events across multiple servers.
* Does not perform geolocation or reputation checks.
* Does not automatically block suspicious IP addresses.
* Does not confirm whether suspicious activity is malicious.
* Does not integrate with external SIEM platforms.

---

# 🚀 Future Improvements

Possible future improvements include:

* Real-time log monitoring
* Support for Apache/Nginx logs
* Support for Windows Event Logs
* Configurable detection rules
* Time-window based detection
* Email security alerts
* Dashboard visualization
* SQLite/PostgreSQL storage
* SIEM integration
* IP reputation integration
* Authentication anomaly detection
* Docker deployment
* Web-based security dashboard

---

# 📚 Learning Outcomes

Through this project, I practiced:

* Python programming
* File processing
* Regular expressions
* Data structures
* Exception handling
* CLI application development
* Unit testing
* JSON and CSV processing
* IP validation
* Defensive cybersecurity
* Security log analysis
* Git and GitHub workflow
* Writing technical documentation

---

# 🎓 Project Purpose

This project was developed as part of my practical learning journey in **Python and Cybersecurity**.

It demonstrates how Python can be used to automate a basic security monitoring task and identify potentially suspicious authentication patterns from log data.

---

# 👨‍💻 Author

**Chhuparustam Kumar Kushwaha**

BCA Student | Python Developer | Cybersecurity Enthusiast

GitHub:
https://github.com/chhuparustam

Portfolio:
https://chhuparustam.com.np

---

# 📄 License

This project is licensed under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

## ⭐ If You Find This Project Useful

Feel free to explore the repository, study the implementation, and use the project for educational purposes.

**Built with Python 🐍 and a focus on Defensive Cybersecurity 🔐**
