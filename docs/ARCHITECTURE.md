# Arquitectura

## Capas

- **GUI:** dashboard Streamlit con estética oscura.
- **Core:** validación de objetivos, normalización, evidencias y correlación.
- **Modules:** adaptadores de fuentes OSINT y analizadores técnicos.
- **Visualization:** grafo de entidades y relaciones.
- **Reporting:** exportaciones JSON, TXT y PDF.

## Entidades previstas

Domain, Subdomain, IPAddress, ASN, Certificate, Service, Technology, Organization y Evidence.

## Evidencias

Cada observación deberá poder expresar: identificador, entidad, atributo, valor, fuente, timestamp, estado de vigencia, confianza, notas y referencia a la consulta que la produjo.

## Relaciones

Ejemplos: resolves_to, has_subdomain, presents_certificate, hosted_on, announces_prefix, uses_technology y observed_service. Las relaciones deben conservar fuente y fecha.

## Clasificación

confirmed, associated, historical, third_party y pending. No inferir que un rango IP completo pertenece a una organización solo porque aparezca asociado a un dominio.
