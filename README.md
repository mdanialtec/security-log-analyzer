# Security Log Analyzer

A Python-based security log analyzer for detecting suspicious authentication activity and generating security reports and structured security alerts.

This project was created as a learning project to practice security monitoring, log analysis, detection rules, risk scoring, alert generation, and security reporting.

## Features

The analyzer supports both traditional text logs and JSON Lines (JSONL) logs.

It can detect:

- Failed login attempts
- Possible brute-force attacks
- Successful logins after failed attempts
- Possible password spraying
- Malformed log entries
- Risk scores
- Severity levels
- Structured JSON security alerts
- Timestamped alerts
- Security report generation
- Unit tests

## Supported Log Formats

### Text Log

Example:

```text
2026-09-04 18:02:05 LOGIN_FAILED user=admin ip=10.0.0.15