import unittest
from datetime import datetime, timedelta

from src.security_analyzer import (
    parse_log_line,
    parse_json_log_line,
    parse_any_log_line,
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
    



if __name__ == "__main__":
    unittest.main()