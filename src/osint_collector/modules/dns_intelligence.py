"""Consultas DNS básicas. No realiza escaneo de puertos."""
import socket

def resolve_a_records(domain: str) -> list[str]:
    """Devuelve direcciones IPv4 observadas por el resolver del sistema."""
    results = set()
    for item in socket.getaddrinfo(domain, None, family=socket.AF_INET):
        results.add(item[4][0])
    return sorted(results)
