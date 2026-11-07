import unittest
from unittest.mock import patch

from osint_collector.core.collection_service import collect_domain_intelligence


class CollectionServiceTests(unittest.TestCase):
    @patch("osint_collector.core.collection_service.collect_dns_records")
    def test_builds_evidence_entities_and_relationships(self, dns_mock):
        dns_mock.return_value = {
            "records": {
                "A": ["192.0.2.10"],
                "MX": ["mail.example.org (prioridad 10)"],
                "AAAA": [],
                "NS": [],
                "TXT": [],
                "CNAME": [],
            },
            "errors": {},
        }

        result = collect_domain_intelligence("Example.org.")

        self.assertEqual(result["target"], "example.org")
        self.assertEqual(result["summary"]["record_count"], 2)
        self.assertEqual(result["summary"]["relationship_count"], 2)
        self.assertEqual(result["summary"]["evidence_count"], 2)
        self.assertEqual(result["entities"][0]["type"], "domain")
        self.assertEqual(result["graph"].number_of_edges(), 2)

    def test_rejects_invalid_domain(self):
        with self.assertRaises(ValueError):
            collect_domain_intelligence("not a domain")


if __name__ == "__main__":
    unittest.main()
