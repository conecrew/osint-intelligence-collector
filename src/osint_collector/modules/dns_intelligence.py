"""Consultas DNS pasivas. No realiza escaneo de puertos."""
import socket

try:
    import dns.resolver
except ImportError:
    dns = None


DEFAULT_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")


def resolve_a_records(domain):
    """Devuelve direcciones IPv4 observadas por el resolver del sistema."""
    return _resolve_addresses(domain, socket.AF_INET)


def _resolve_addresses(domain, family):
    results = set()
    for item in socket.getaddrinfo(domain, None, family=family):
        results.add(item[4][0])
    return sorted(results)


def collect_dns_records(domain, record_types=None, timeout=4):
    """Recopila registros DNS y devuelve datos y errores por tipo.

    A y AAAA se consultan mediante el resolver del sistema. Los demás tipos
    utilizan dnspython cuando está instalado. La función nunca escanea puertos.
    """
    requested = record_types or DEFAULT_RECORD_TYPES
    records = {}
    errors = {}

    for record_type in requested:
        record_type = record_type.upper()
        records[record_type] = []

        if record_type == "A":
            try:
                records[record_type] = _resolve_addresses(domain, socket.AF_INET)
            except socket.gaierror as exc:
                errors[record_type] = str(exc)
            continue

        if record_type == "AAAA":
            try:
                records[record_type] = _resolve_addresses(domain, socket.AF_INET6)
            except socket.gaierror as exc:
                errors[record_type] = str(exc)
            continue

        if dns is None:
            errors[record_type] = "Instalá dnspython para consultar este tipo de registro."
            continue

        try:
            answer = dns.resolver.resolve(domain, record_type, lifetime=timeout)
            values = []
            for item in answer:
                if record_type == "MX":
                    values.append("%s (prioridad %s)" % (
                        str(item.exchange).rstrip("."), item.preference))
                elif record_type == "TXT":
                    values.append(item.to_text())
                else:
                    values.append(str(item).rstrip("."))
            records[record_type] = sorted(set(values))
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except Exception as exc:
            errors[record_type] = str(exc)

    return {"records": records, "errors": errors}
