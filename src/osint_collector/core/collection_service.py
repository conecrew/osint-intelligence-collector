"""Orquestación de la primera fase de reconocimiento pasivo."""
from osint_collector.core.domain_analyzer import normalize_domain
from osint_collector.core.evidence_manager import Evidence
from osint_collector.modules.dns_intelligence import collect_dns_records
from osint_collector.visualization.graph_engine import build_relationship_graph


_RELATIONS = {
    "A": "resolves_to",
    "AAAA": "resolves_to",
    "MX": "mail_exchange",
    "NS": "name_server",
    "TXT": "has_txt_record",
    "CNAME": "alias_to",
}


def collect_domain_intelligence(raw_domain):
    """Valida un dominio y reúne DNS, evidencias y relaciones.

    Solo realiza consultas DNS pasivas. No ejecuta Nmap ni modifica el sistema.
    """
    domain = normalize_domain(raw_domain)
    dns_result = collect_dns_records(domain)
    records = dns_result["records"]
    errors = dns_result["errors"]

    entities = [{
        "id": "domain:" + domain,
        "type": "domain",
        "label": domain,
    }]
    relationships = []
    evidence = []
    seen_entities = set(["domain:" + domain])

    for record_type, values in records.items():
        for value in values:
            value = str(value)
            entity_id = record_type.lower() + ":" + value
            if entity_id not in seen_entities:
                entities.append({
                    "id": entity_id,
                    "type": record_type.lower(),
                    "label": value,
                })
                seen_entities.add(entity_id)

            relationships.append({
                "source": "domain:" + domain,
                "target": entity_id,
                "relation": _RELATIONS.get(record_type, "related_to"),
                "evidence_source": "DNS",
            })
            source = "system resolver" if record_type in ("A", "AAAA") else "dnspython"
            evidence.append(Evidence(
                subject=domain,
                attribute=record_type,
                value=value,
                source=source,
                classification="pending",
                confidence="medium",
            ).to_dict())

    graph = build_relationship_graph(entities, relationships)
    return {
        "target": domain,
        "records": records,
        "errors": errors,
        "entities": entities,
        "relationships": relationships,
        "evidence": evidence,
        "summary": {
            "record_count": sum(len(values) for values in records.values()),
            "entity_count": len(entities),
            "relationship_count": len(relationships),
            "evidence_count": len(evidence),
        },
        "graph": graph,
    }
