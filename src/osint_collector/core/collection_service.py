"""Orquestación de reconocimiento pasivo y conectores externos."""
from osint_collector.core.domain_analyzer import normalize_domain
from osint_collector.core.evidence_manager import Evidence
from osint_collector.modules.dns_intelligence import collect_dns_records
from osint_collector.modules.external_intelligence import run_passive_connectors
from osint_collector.visualization.graph_engine import build_relationship_graph

_RELATIONS = {
    "A": "resolves_to", "AAAA": "resolves_to", "MX": "mail_exchange",
    "NS": "name_server", "TXT": "has_txt_record", "CNAME": "alias_to",
}


def collect_domain_intelligence(raw_domain, include_external=False):
    """Valida y reúne DNS, evidencias, grafo y, opcionalmente, proveedores OSINT.

    include_external habilita RDAP, CT, SecurityTrails, Shodan, Censys,
    VirusTotal y detección HTTP. Nmap queda separado por ser activo.
    """
    domain = normalize_domain(raw_domain)
    dns_result = collect_dns_records(domain)
    records, errors = dns_result["records"], dns_result["errors"]
    entities = [{"id": "domain:" + domain, "type": "domain", "label": domain}]
    relationships, evidence = [], []
    seen_entities = set(["domain:" + domain])

    def add_entity(entity_id, entity_type, label):
        if entity_id not in seen_entities:
            entities.append({"id": entity_id, "type": entity_type, "label": str(label)})
            seen_entities.add(entity_id)

    for record_type, values in records.items():
        for value in values:
            value = str(value)
            entity_id = record_type.lower() + ":" + value
            add_entity(entity_id, record_type.lower(), value)
            relationships.append({
                "source": "domain:" + domain, "target": entity_id,
                "relation": _RELATIONS.get(record_type, "related_to"),
                "evidence_source": "DNS",
            })
            evidence.append(Evidence(
                subject=domain, attribute=record_type, value=value,
                source="system resolver" if record_type in ("A", "AAAA") else "dnspython",
                classification="pending", confidence="medium",
            ).to_dict())

    external_results = run_passive_connectors(domain) if include_external else []
    for provider_result in external_results:
        provider = provider_result["provider"]
        evidence.append(Evidence(
            subject=domain, attribute="provider_status",
            value={"status": provider_result["status"], "message": provider_result.get("message")},
            source=provider, classification="pending", confidence="unknown",
        ).to_dict())
        data = provider_result.get("data", {})
        for item in data.get("subdomains", []):
            subdomain = str(item).strip().lower()
            if subdomain and "." in subdomain:
                entity_id = "subdomain:" + subdomain
                add_entity(entity_id, "subdomain", subdomain)
                relationships.append({
                    "source": "domain:" + domain, "target": entity_id,
                    "relation": "has_observed_subdomain", "evidence_source": provider,
                })
        for cert in data.get("certificates", []):
            names = str(cert.get("name_value") or "").splitlines()
            for name in names:
                name = name.strip().lower().lstrip("*.")
                if name and "." in name:
                    entity_id = "certificate_name:" + name
                    add_entity(entity_id, "certificate_name", name)
                    relationships.append({
                        "source": "domain:" + domain, "target": entity_id,
                        "relation": "certificate_name_observed", "evidence_source": provider,
                    })

    graph = build_relationship_graph(entities, relationships)
    return {
        "target": domain, "records": records, "errors": errors,
        "external_results": external_results,
        "entities": entities, "relationships": relationships, "evidence": evidence,
        "summary": {
            "record_count": sum(len(values) for values in records.values()),
            "entity_count": len(entities), "relationship_count": len(relationships),
            "evidence_count": len(evidence),
            "external_provider_count": len(external_results),
        },
        "graph": graph,
    }
