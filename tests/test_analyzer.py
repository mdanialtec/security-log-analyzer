import unittest
from src.security_analyzer import (
    get_severity,
    detect_bruteforce,
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

    def test_success_after_failure(self):
        self.assertEqual(detect_success_after_failure(2), 80)
        self.assertEqual(detect_success_after_failure(0), 0)

    def test_password_spraying(self):
        self.assertEqual(detect_password_spraying(3), 40)
        self.assertEqual(detect_password_spraying(7), 60)


if __name__ == "__main__":
    unittest.main()