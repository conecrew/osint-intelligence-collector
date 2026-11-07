"""Conectores OSINT externos con claves opcionales y fallos aislados.

Las consultas usan APIs públicas/oficiales y límites de tiempo. No ejecutan
escaneos de puertos. Las claves se leen exclusivamente desde variables de entorno.
"""
import os
from datetime import datetime, timezone
from urllib.parse import quote

import requests

TIMEOUT = 12
USER_AGENT = "OSINT-Intelligence-Collector/0.2 (authorized research)"


def _result(provider, status, data=None, message=None, source_type="passive"):
    return {
        "provider": provider,
        "status": status,
        "source_type": source_type,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "data": data or {},
        "message": message,
    }


def _get(url, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", USER_AGENT)
    return requests.get(url, headers=headers, timeout=TIMEOUT, **kwargs)



def query_whois(domain):
    """Consulta WHOIS clásico si python-whois está instalado."""
    try:
        import whois
    except ImportError:
        return _result("WHOIS", "dependency_missing",
                       message="Instalar python-whois para habilitar WHOIS clásico.")
    try:
        record = whois.whois(domain)
        data = {}
        for field in ("domain_name", "registrar", "whois_server", "creation_date",
                      "expiration_date", "updated_date", "name_servers", "status",
                      "emails", "org", "country"):
            value = getattr(record, field, None)
            if value is not None:
                if hasattr(value, "isoformat"):
                    value = value.isoformat()
                elif isinstance(value, (list, tuple)):
                    value = [item.isoformat() if hasattr(item, "isoformat") else str(item)
                             for item in value]
                else:
                    value = str(value)
                data[field] = value
        return _result("WHOIS", "ok" if data else "no_data", data)
    except Exception as exc:
        return _result("WHOIS", "error", message=str(exc))

def query_rdap(domain):
    """Consulta RDAP público a través del bootstrap rdap.org."""
    try:
        response = _get("https://rdap.org/domain/" + quote(domain, safe=""))
        if response.status_code == 404:
            return _result("RDAP", "no_data", message="El registro RDAP no devolvió el dominio.")
        response.raise_for_status()
        payload = response.json()
        events = payload.get("events", [])
        nameservers = [x.get("ldhName") for x in payload.get("nameservers", []) if x.get("ldhName")]
        return _result("RDAP", "ok", {
            "handle": payload.get("handle"),
            "ldh_name": payload.get("ldhName"),
            "status": payload.get("status", []),
            "nameservers": nameservers,
            "events": events,
            "entities": [{"handle": x.get("handle"), "roles": x.get("roles", [])}
                         for x in payload.get("entities", [])],
        })
    except requests.RequestException as exc:
        return _result("RDAP", "error", message=str(exc))
    except (ValueError, TypeError) as exc:
        return _result("RDAP", "error", message="Respuesta RDAP no válida: %s" % exc)


def query_certificate_transparency(domain):
    """Busca certificados públicos en crt.sh; los resultados son históricos."""
    try:
        response = _get("https://crt.sh/", params={"q": "%." + domain, "output": "json"})
        response.raise_for_status()
        rows = response.json()
        certificates = []
        seen = set()
        for row in rows[:500]:
            key = (row.get("id"), row.get("name_value"))
            if key in seen:
                continue
            seen.add(key)
            certificates.append({
                "id": row.get("id"),
                "common_name": row.get("common_name"),
                "name_value": row.get("name_value"),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "issuer_name": row.get("issuer_name"),
            })
        return _result("Certificate Transparency", "ok" if certificates else "no_data",
                       {"certificates": certificates, "historical": True})
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _result("Certificate Transparency", "error", message=str(exc))


def query_securitytrails(domain):
    key = os.getenv("SECURITYTRAILS_API_KEY")
    if not key:
        return _result("SecurityTrails", "missing_credentials",
                       message="Configurar SECURITYTRAILS_API_KEY.")
    try:
        response = _get(
            "https://api.securitytrails.com/v1/domain/%s/subdomains" % quote(domain, safe=""),
            headers={"APIKEY": key},
        )
        response.raise_for_status()
        payload = response.json()
        return _result("SecurityTrails", "ok", {
            "subdomains": payload.get("subdomains", []),
            "total": payload.get("subdomain_count", len(payload.get("subdomains", []))),
        })
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _result("SecurityTrails", "error", message=str(exc))


def query_shodan(domain):
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return _result("Shodan", "missing_credentials", message="Configurar SHODAN_API_KEY.")
    try:
        response = _get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": "hostname:" + domain},
        )
        response.raise_for_status()
        payload = response.json()
        matches = [{
            "ip_str": item.get("ip_str"),
            "port": item.get("port"),
            "transport": item.get("transport"),
            "hostnames": item.get("hostnames", []),
            "org": item.get("org"),
            "product": item.get("product"),
            "timestamp": item.get("timestamp"),
        } for item in payload.get("matches", [])[:100]]
        return _result("Shodan", "ok" if matches else "no_data",
                       {"matches": matches, "total": payload.get("total", len(matches)),
                        "historical_or_observed": True})
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _result("Shodan", "error", message=str(exc))


def query_censys(domain):
    api_id = os.getenv("CENSYS_API_ID")
    api_secret = os.getenv("CENSYS_API_SECRET")
    if not api_id or not api_secret:
        return _result("Censys", "missing_credentials",
                       message="Configurar CENSYS_API_ID y CENSYS_API_SECRET.")
    try:
        response = _get(
            "https://search.censys.io/api/v2/hosts/search",
            params={"q": "services.tls.certificates.leaf.names: " + domain, "per_page": 25},
            auth=(api_id, api_secret),
        )
        response.raise_for_status()
        payload = response.json()
        hits = payload.get("result", {}).get("hits", [])
        hosts = [{
            "ip": item.get("ip"),
            "last_updated_at": item.get("last_updated_at"),
            "services": [{"port": service.get("port"), "service_name": service.get("service_name")}
                         for service in item.get("services", [])],
        } for item in hits]
        return _result("Censys", "ok" if hosts else "no_data",
                       {"hosts": hosts, "historical_or_observed": True})
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _result("Censys", "error", message=str(exc))


def query_virustotal(domain):
    key = os.getenv("VIRUSTOTAL_API_KEY")
    if not key:
        return _result("VirusTotal", "missing_credentials",
                       message="Configurar VIRUSTOTAL_API_KEY.")
    try:
        response = _get(
            "https://www.virustotal.com/api/v3/domains/" + quote(domain, safe=""),
            headers={"x-apikey": key},
        )
        response.raise_for_status()
        payload = response.json().get("data", {}).get("attributes", {})
        stats = payload.get("last_analysis_stats", {})
        return _result("VirusTotal", "ok", {
            "reputation": payload.get("reputation"),
            "last_analysis_stats": stats,
            "categories": payload.get("categories", {}),
            "last_analysis_date": payload.get("last_analysis_date"),
            "creation_date": payload.get("creation_date"),
        })
    except (requests.RequestException, ValueError, TypeError) as exc:
        return _result("VirusTotal", "error", message=str(exc))


def detect_web_technologies(domain):
    """Inspección HTTP(S) ligera de cabeceras y firmas; no explota servicios."""
    url = "https://" + domain
    try:
        response = _get(url, allow_redirects=True)
    except requests.RequestException as first_error:
        try:
            url = "http://" + domain
            response = _get(url, allow_redirects=True)
        except requests.RequestException as exc:
            return _result("Technology Detection", "error",
                           message="HTTPS: %s; HTTP: %s" % (first_error, exc),
                           source_type="direct_http")
    headers = response.headers
    technologies = []
    signatures = {
        "server": headers.get("Server"),
        "x-powered-by": headers.get("X-Powered-By"),
        "x-generator": headers.get("X-Generator"),
    }
    for name, value in signatures.items():
        if value:
            technologies.append({"source": name, "value": value})
    html = response.text[:250000].lower()
    for marker, label in [
        ("wp-content", "WordPress"), ("/sites/default/", "Drupal"),
        ("__next", "Next.js"), ("_nuxt", "Nuxt"),
        ("cdn.shopify.com", "Shopify"), ("jquery", "jQuery"),
    ]:
        if marker in html:
            technologies.append({"source": "html_signature", "value": label})
    return _result("Technology Detection", "ok", {
        "url": response.url,
        "status_code": response.status_code,
        "technologies": technologies,
        "server_headers": signatures,
    }, source_type="direct_http")


def run_passive_connectors(domain):
    """Ejecuta cada conector de forma aislada; un proveedor no bloquea a los demás."""
    connectors = [
        query_rdap,
        query_whois,
        query_certificate_transparency,
        query_securitytrails,
        query_shodan,
        query_censys,
        query_virustotal,
        detect_web_technologies,
    ]
    results = []
    for connector in connectors:
        try:
            results.append(connector(domain))
        except Exception as exc:
            results.append(_result(connector.__name__, "error", message=str(exc)))
    return results
