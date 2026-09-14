import unittest
from datetime import datetime, timedelta

from src.security_analyzer import (
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


if __name__ == "__main__":
    unittest.main()