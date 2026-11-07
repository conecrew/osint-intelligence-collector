"""Construcción y representación de grafos de relaciones OSINT."""
import networkx as nx


def build_relationship_graph(entities, relationships):
    graph = nx.DiGraph()
    for entity in entities:
        graph.add_node(entity["id"], **{
            key: value for key, value in entity.items() if key != "id"
        })
    for relation in relationships:
        graph.add_edge(
            relation["source"],
            relation["target"],
            relation=relation.get("relation", "related_to"),
            source=relation.get("evidence_source", "unknown"),
        )
    return graph


def _dot_quote(value):
    """Escapa valores para utilizarlos como etiquetas DOT."""
    text = str(value).replace("\\", "\\\\").replace('"', '\\"')
    text = text.replace("\n", " ")
    return '"' + text + '"'


def graph_to_dot(graph):
    """Convierte el grafo en DOT sin depender de pygraphviz."""
    lines = ["digraph OSINT {", "  rankdir=LR;", '  graph [bgcolor="#050807"];',
             '  node [shape=box, style="rounded,filled", fillcolor="#10291b", '
             'fontcolor="#d8e5dc", color="#38a65d"];',
             '  edge [color="#7cff9b", fontcolor="#8ba394"];']
    for node_id, attributes in graph.nodes(data=True):
        label = attributes.get("label", node_id)
        lines.append("  %s [label=%s];" % (
            _dot_quote(node_id), _dot_quote(label)))
    for source, target, attributes in graph.edges(data=True):
        label = attributes.get("relation", "related_to")
        lines.append("  %s -> %s [label=%s];" % (
            _dot_quote(source), _dot_quote(target), _dot_quote(label)))
    lines.append("}")
    return "\n".join(lines)
