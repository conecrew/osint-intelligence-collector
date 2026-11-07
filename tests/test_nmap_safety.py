import unittest
from osint_collector.modules.nmap_scanner import run_ssl_cert_scan


class NmapSafetyTests(unittest.TestCase):
    def test_requires_explicit_authorization(self):
        with self.assertRaises(PermissionError):
            run_ssl_cert_scan("example.org", authorized=False, approved_targets=[])

    def test_requires_target_in_approved_scope(self):
        with self.assertRaises(PermissionError):
            run_ssl_cert_scan("example.org", authorized=True, approved_targets=["other.org"])


if __name__ == "__main__":
    unittest.main()
