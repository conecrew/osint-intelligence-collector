"""Punto de entrada mínimo."""
from osint_collector.core.domain_analyzer import normalize_domain
from osint_collector.modules.dns_intelligence import resolve_a_records

def main():
    raw = input("Dominio para consulta DNS básica: ")
    try:
        domain = normalize_domain(raw)
        print(f"Dominio normalizado: {domain}")
        print("IPv4 observadas:", resolve_a_records(domain))
    except (ValueError, OSError) as exc:
        print(f"No se pudo completar la consulta: {exc}")

if __name__ == "__main__":
    main()
