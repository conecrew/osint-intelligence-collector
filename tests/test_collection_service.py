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

    @patch("osint_collector.core.collection_service.run_passive_connectors")
    @patch("osint_collector.core.collection_service.collect_dns_records")
    def test_external_results_are_correlated_into_graph(self, dns_mock, providers_mock):
        dns_mock.return_value = {"records": {"A": [], "AAAA": [], "MX": [],
                                             "NS": [], "TXT": [], "CNAME": []},
                                 "errors": {}}
        providers_mock.return_value = [{
            "provider": "SecurityTrails", "status": "ok", "data": {
                "subdomains": ["www"],
            }, "message": None,
        }, {
            "provider": "Shodan", "status": "ok", "data": {
                "matches": [{"ip_str": "192.0.2.25"}],
            }, "message": None,
        }]
        result = collect_domain_intelligence("example.org", include_external=True)
        node_ids = [entity["id"] for entity in result["entities"]]
        self.assertIn("subdomain:www.example.org", node_ids)
        self.assertIn("observed_ip:192.0.2.25", node_ids)
        self.assertEqual(result["summary"]["external_provider_count"], 2)
        self.assertEqual(result["graph"].number_of_edges(), 2)

    def test_rejects_invalid_domain(self):
        with self.assertRaises(ValueError):
            collect_domain_intelligence("not a domain")


if __name__ == "__main__":
    unittest.main()
