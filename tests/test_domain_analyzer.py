import unittest
from osint_collector.core.domain_analyzer import normalize_domain

class DomainAnalyzerTests(unittest.TestCase):
    def test_normalizes_case_and_trailing_dot(self):
        self.assertEqual(normalize_domain("Example.COM."), "example.com")

    def test_rejects_invalid_value(self):
        with self.assertRaises(ValueError):
            normalize_domain("not a domain")

if __name__ == "__main__":
    unittest.main()
