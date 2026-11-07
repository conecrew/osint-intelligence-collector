import json
import unittest

from osint_collector.reporting.report_generator import build_json_report
from osint_collector.visualization.graph_engine import (
    build_relationship_graph,
    graph_to_dot,
)


class IntegrationComponentTests(unittest.TestCase):
    def test_graph_contains_expected_relationship(self):
        graph = build_relationship_graph(
            [
                {"id": "domain:example.org", "type": "domain", "label": "example.org"},
                {"id": "A:192.0.2.5", "type": "a", "label": "192.0.2.5"},
            ],
            [
                {
                    "source": "domain:example.org",
                    "target": "A:192.0.2.5",
                    "relation": "resolves_to",
                    "evidence_source": "DNS",
                }
            ],
        )
        dot = graph_to_dot(graph)
        self.assertEqual(graph.number_of_nodes(), 2)
        self.assertEqual(graph.number_of_edges(), 1)
        self.assertIn("resolves_to", dot)
        self.assertIn("example.org", dot)

    def test_json_report_is_valid_json(self):
        report = build_json_report({"target": "example.org", "records": {"A": ["192.0.2.5"]}})
        decoded = json.loads(report)
        self.assertEqual(decoded["data"]["target"], "example.org")
        self.assertEqual(decoded["project"], "OSINT Intelligence Collector")


if __name__ == "__main__":
    unittest.main()
