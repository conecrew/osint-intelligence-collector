import os
import unittest
from unittest.mock import patch, Mock

from osint_collector.modules import external_intelligence as ext


class ExternalConnectorTests(unittest.TestCase):
    def test_api_connectors_report_missing_credentials(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ext.query_securitytrails("example.org")["status"], "missing_credentials")
            self.assertEqual(ext.query_shodan("example.org")["status"], "missing_credentials")
            self.assertEqual(ext.query_censys("example.org")["status"], "missing_credentials")
            self.assertEqual(ext.query_virustotal("example.org")["status"], "missing_credentials")

    @patch("osint_collector.modules.external_intelligence._get")
    def test_rdap_parses_domain_and_nameservers(self, mocked_get):
        response = Mock()
        response.status_code = 200
        response.json.return_value = {
            "handle": "EXAMPLE",
            "ldhName": "example.org",
            "status": ["active"],
            "nameservers": [{"ldhName": "ns1.example.org"}],
            "events": [],
            "entities": [],
        }
        mocked_get.return_value = response
        result = ext.query_rdap("example.org")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["data"]["nameservers"], ["ns1.example.org"])

    @patch("osint_collector.modules.external_intelligence._get")
    def test_ct_returns_historical_certificates(self, mocked_get):
        response = Mock()
        response.json.return_value = [{
            "id": 123, "common_name": "example.org",
            "name_value": "example.org", "not_before": "2025-01-01",
            "not_after": "2026-01-01", "issuer_name": "Example CA",
        }]
        mocked_get.return_value = response
        result = ext.query_certificate_transparency("example.org")
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["data"]["historical"])
        self.assertEqual(len(result["data"]["certificates"]), 1)


if __name__ == "__main__":
    unittest.main()
