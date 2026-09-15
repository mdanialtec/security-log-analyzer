import unittest
import json
from pathlib import Path
from datetime import datetime, timedelta

from src.security_analyzer import (
    parse_log_line,
    parse_json_log_line,
    parse_any_log_line,
    create_alert,
    save_alerts,
    get_severity,
    detect_bruteforce,
    detect_bruteforce_window,
    detect_success_after_failure,
    detect_password_spraying
)


class TestSeverity(unittest.TestCase):

    def test_low_severity(self):
        self.assertEqual(get_severity(20), "LOW")

    def test_medium_severity(self):
        self.assertEqual(get_severity(40), "MEDIUM")

    def test_high_severity(self):
        self.assertEqual(get_severity(60), "HIGH")

    def test_critical_severity(self):
        self.assertEqual(get_severity(80), "CRITICAL")

    def test_bruteforce_detection(self):
        self.assertEqual(detect_bruteforce(5), 60)
        self.assertEqual(detect_bruteforce(10), 80)

    def test_bruteforce_within_time_window(self):
        start = datetime(2026, 9, 4, 18, 0, 0)

        timestamps = [
            start,
            start + timedelta(minutes=1),
            start + timedelta(minutes=2),
            start + timedelta(minutes=3),
            start + timedelta(minutes=4)
        ]

        self.assertEqual(detect_bruteforce_window(timestamps), 60)

    def test_bruteforce_outside_time_window(self):
        start = datetime(2026, 9, 4, 18, 0, 0)

        timestamps = [
            start,
            start + timedelta(minutes=6),
            start + timedelta(minutes=12),
            start + timedelta(minutes=18),
            start + timedelta(minutes=24)
        ]

        self.assertEqual(detect_bruteforce_window(timestamps), 0)

    def test_bruteforce_unsorted_timestamps(self):
        start = datetime(2026, 9, 4, 18, 0, 0)

        timestamps = [
            start + timedelta(minutes=4),
            start,
            start + timedelta(minutes=2),
            start + timedelta(minutes=1),
            start + timedelta(minutes=3)
        ]

        self.assertEqual(detect_bruteforce_window(timestamps), 60)

    def test_bruteforce_at_time_window_boundary(self):
        start = datetime(2026, 9, 4, 18, 0, 0)

        timestamps = [
            start,
            start + timedelta(minutes=1),
            start + timedelta(minutes=2),
            start + timedelta(minutes=3),
            start + timedelta(minutes=5)
        ]

        self.assertEqual(detect_bruteforce_window(timestamps), 60)

    def test_success_after_failure(self):
        self.assertEqual(detect_success_after_failure(2), 80)
        self.assertEqual(detect_success_after_failure(0), 0)

    def test_password_spraying(self):
        self.assertEqual(detect_password_spraying(3), 40)
        self.assertEqual(detect_password_spraying(7), 60)

    def test_malformed_log(self):
        line = "THIS IS A MALFORMED LOG ENTRY"

        self.assertIsNone(parse_log_line(line))

    def test_malformed_failed_login(self):
        line = "2026-09-04 18:02:05 LOGIN_FAILED user=admin"

        self.assertIsNone(parse_log_line(line))

    def test_invalid_timestamp(self):
        line = "NOT-A-DATE 18:02:05 LOGIN_FAILED user=admin ip=10.0.0.15"

        self.assertIsNone(parse_log_line(line))

    def test_empty_username(self):
        line = "2026-09-04 18:02:05 LOGIN_FAILED user= ip=10.0.0.15"

        self.assertIsNone(parse_log_line(line))

    def test_empty_ip(self):
        line = "2026-09-04 18:02:05 LOGIN_FAILED user=admin ip="

        self.assertIsNone(parse_log_line(line))

    def test_valid_json_log(self):
        line = '{"timestamp": "2026-09-04 18:02:05", "event": "LOGIN_FAILED", "username": "admin", "ip": "10.0.0.15"}'

        result = parse_json_log_line(line)

        self.assertEqual(
            result,
            (
                "2026-09-04 18:02:05",
                "LOGIN_FAILED",
                "admin",
                "10.0.0.15"
            )
        )

    def test_malformed_json_log(self):
        line = '{"timestamp": "2026-09-04 18:02:05", "event": "LOGIN_FAILED"'

        self.assertIsNone(parse_json_log_line(line))

    def test_json_missing_field(self):
        line = '{"timestamp": "2026-09-04 18:02:05", "event": "LOGIN_FAILED", "username": "admin"}'

        self.assertIsNone(parse_json_log_line(line))

    def test_parse_any_log_line_text(self):
        line = "2026-09-04 18:02:05 LOGIN_FAILED user=admin ip=10.0.0.15"

        result = parse_any_log_line(line)

        self.assertEqual(
            result,
            (
                "2026-09-04 18:02:05",
                "LOGIN_FAILED",
                "admin",
                "10.0.0.15"
            )
        )

    def test_parse_any_log_line_json(self):
        line = '{"timestamp": "2026-09-04 18:02:05", "event": "LOGIN_FAILED", "username": "admin", "ip": "10.0.0.15"}'

        result = parse_any_log_line(line)

        self.assertEqual(
            result,
            (
                "2026-09-04 18:02:05",
                "LOGIN_FAILED",
                "admin",
                "10.0.0.15"
            )
        )

    def test_create_alert(self):
        alert = create_alert(
            "brute_force",
            "10.0.0.15",
            "HIGH",
            60,
            "Possible brute-force attack"
        )

        self.assertIn("timestamp", alert)
        self.assertEqual(alert["alert_type"], "brute_force")
        self.assertEqual(alert["source_ip"], "10.0.0.15")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["risk_score"], 60)
        self.assertEqual(
            alert["description"],
            "Possible brute-force attack"
        )

    def test_create_alert_has_timestamp(self):
        alert = create_alert(
            "brute_force",
            "10.0.0.15",
            "HIGH",
            60,
            "Possible brute-force attack"
        )

        self.assertIn("timestamp", alert)

    def test_bruteforce_alert(self):
        alert = create_alert(
            "brute_force",
            "10.0.0.15",
            "HIGH",
            60,
            "Possible brute-force attack"
        )

        self.assertEqual(alert["alert_type"], "brute_force")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["risk_score"], 60)

    def test_successful_login_after_failures_alert(self):
        alert = create_alert(
            "successful_login_after_failures",
            "10.0.0.25",
            "CRITICAL",
            80,
            "2 failed attempts before a successful login"
        )

        self.assertEqual(
            alert["alert_type"],
            "successful_login_after_failures"
        )
        self.assertEqual(alert["severity"], "CRITICAL")
        self.assertEqual(alert["risk_score"], 80)

    def test_password_spraying_alert(self):
        alert = create_alert(
            "password_spraying",
            "10.0.0.30",
            "MEDIUM",
            40,
            "Possible password spraying targeting 3 users"
        )

        self.assertEqual(
            alert["alert_type"],
            "password_spraying"
        )
        self.assertEqual(alert["severity"], "MEDIUM")
        self.assertEqual(alert["risk_score"], 40)

    def test_save_alerts(self):
        alerts = [
            create_alert(
                "brute_force",
                "10.0.0.15",
                "HIGH",
                60,
                "Possible brute-force attack"
            )
        ]

        log_file = Path("sample.log")

        alerts_file = save_alerts(alerts, log_file)

        self.assertTrue(alerts_file.exists())

        with open(alerts_file, "r") as file:
            saved_alerts = json.load(file)

        self.assertEqual(saved_alerts, alerts)

        alerts_file.unlink()
    



if __name__ == "__main__":
    unittest.main()