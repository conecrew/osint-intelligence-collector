"""Construcción básica de un grafo de relaciones OSINT."""
import networkx as nx

def build_relationship_graph(entities: list[dict], relationships: list[dict]) -> nx.DiGraph:
    graph = nx.DiGraph()
    for entity in entities:
        graph.add_node(entity["id"], **{k: v for k, v in entity.items() if k != "id"})
    for relation in relationships:
        graph.add_edge(relation["source"], relation["target"],
                       relation=relation.get("relation", "related_to"),
                       source=relation.get("evidence_source", "unknown"))
    return graph
