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
    """Valida y reúne DNS, evidencias, grafo y, opcionalmente, proveedores externos.

    Los conectores HTTP/APIs son independientes. Nmap queda fuera de este flujo
    y se ejecuta únicamente mediante la acción activa con alcance confirmado.
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

    def add_relationship(source, target, relation, provider):
        relationships.append({
            "source": source, "target": target,
            "relation": relation, "evidence_source": provider,
        })

    for record_type, values in records.items():
        for value in values:
            value = str(value)
            entity_id = record_type.lower() + ":" + value
            add_entity(entity_id, record_type.lower(), value)
            add_relationship("domain:" + domain, entity_id,
                             _RELATIONS.get(record_type, "related_to"), "DNS")
            evidence.append(Evidence(
                subject=domain, attribute=record_type, value=value,
                source="system resolver" if record_type in ("A", "AAAA") else "dnspython",
                classification="pending", confidence="medium",
            ).to_dict())

    external_results = run_passive_connectors(domain) if include_external else []
    for provider_result in external_results:
        provider = provider_result["provider"]
        status = provider_result["status"]
        data = provider_result.get("data", {})
        evidence.append(Evidence(
            subject=domain, attribute="provider_status",
            value={"status": status, "message": provider_result.get("message")},
            source=provider, classification="pending", confidence="unknown",
        ).to_dict())

        if data:
            evidence.append(Evidence(
                subject=domain, attribute="provider_observation",
                value=data, source=provider,
                classification="historical" if provider == "Certificate Transparency" else "associated",
                confidence="low",
            ).to_dict())

        # SecurityTrails entrega etiquetas relativas, no FQDN completos.
        for item in data.get("subdomains", []):
            label = str(item).strip().lower().rstrip(".")
            subdomain = label if label.endswith("." + domain) else label + "." + domain
            if subdomain and "." in subdomain:
                entity_id = "subdomain:" + subdomain
                add_entity(entity_id, "subdomain", subdomain)
                add_relationship("domain:" + domain, entity_id,
                                 "has_observed_subdomain", provider)

        for cert in data.get("certificates", []):
            for name in str(cert.get("name_value") or "").splitlines():
                name = name.strip().lower().lstrip("*.")
                if name and (name == domain or name.endswith("." + domain)):
                    entity_id = "certificate_name:" + name
                    add_entity(entity_id, "certificate_name", name)
                    add_relationship("domain:" + domain, entity_id,
                                     "certificate_name_observed", provider)

        # Direcciones observadas por motores externos: se marcan como asociadas,
        # no como prueba de titularidad ni de exposición actual.
        observed_ips = []
        observed_ips.extend(
            item.get("ip_str") for item in data.get("matches", []) if item.get("ip_str")
        )
        observed_ips.extend(
            item.get("ip") for item in data.get("hosts", []) if item.get("ip")
        )
        for ip in sorted(set(observed_ips)):
            entity_id = "observed_ip:" + str(ip)
            add_entity(entity_id, "observed_ip", ip)
            add_relationship("domain:" + domain, entity_id,
                             "infrastructure_observed_by", provider)

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
