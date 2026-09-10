# Security Log Analyzer

A Python-based security log analyzer for detecting suspicious authentication activity and generating security reports.

## Features

The analyzer processes authentication logs and detects several types of suspicious activity:

- Failed login attempts
- Possible brute-force attacks
- Successful logins after multiple failed attempts
- Possible password spraying
- Risk scores
- Severity levels
- Security report generation
- Basic error handling
- Unit tests

## Detection Rules

### Brute-force Detection

The analyzer counts failed login attempts from each IP address.

| Failed attempts | Risk score | Severity |
|---|---:|---|
| 5–7 | 60 | HIGH |
| 8–9 | 70 | HIGH |
| 10+ | 80 | CRITICAL |

### Successful Login After Failed Attempts

A successful login after previous failed attempts is flagged for investigation.

This detection currently assigns a risk score of 80 (CRITICAL).

### Password Spraying

The analyzer checks whether one IP address has failed login attempts against multiple usernames.

| Targeted users | Risk score | Severity |
|---|---:|---|
| 3–4 | 40 | MEDIUM |
| 5–6 | 50 | MEDIUM |
| 7+ | 60 | HIGH |

## Severity Levels

Risk scores are converted into severity levels:

- **LOW:** 0–29
- **MEDIUM:** 30–59
- **HIGH:** 60–79
- **CRITICAL:** 80+

## Project Structure

```text
security-log-analyzer/
├── reports/
│   └── security_report.txt
├── src/
│   └── security_analyzer.py
├── tests/
│   └── test_analyzer.py
├── .gitignore
├── README.md
└── sample.log

## How to Run

Make sure Python is installed, then run:

```powershell
python src/security_analyzer.py

The analyzer reads `sample.log` and generates:

```text
reports/security_report.txt