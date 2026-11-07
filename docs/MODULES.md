# Catálogo de módulos

Estado correspondiente a la rama `feature/integrated-dashboard`.

| Módulo | Función | Estado |
|---|---|---|
| Domain Analyzer | Validación y normalización | Integrado |
| DNS Intelligence | A, AAAA, MX, NS, TXT y CNAME | Integración inicial |
| Evidence Manager | Registro de fuente, fecha, confianza y clasificación | Integrado |
| Intelligence / Collection Service | Orquestación de DNS, entidades y relaciones | Integración inicial |
| Graph Engine | Grafo NetworkX y salida Graphviz/DOT | Integrado |
| Report Generator | Serialización y exportación JSON | Integrado |
| Local DNS & Hosts Manager | Lectura de /etc/hosts y propuesta | Solo lectura / propuesta |
| Nmap NSE | Inspección activa con confirmación y lista de alcance | Módulo separado; no conectado al dashboard |
| WHOIS/RDAP | Registro y asignación | Pendiente |
| SecurityTrails | Subdominios e historial DNS | Pendiente |
| Certificate Intelligence | CT logs, SAN, emisor, validez y huellas | Pendiente |
| Shodan/Censys | Servicios e infraestructura observada | Pendiente |
| VirusTotal | Reputación e indicadores | Pendiente |
| Technology Detection | CMS y tecnologías web | Pendiente |
| GUI | Dashboard Streamlit dark / hacker | Integración inicial |

Los nombres de servicios externos identifican integraciones previstas; no implican que estén conectadas ni que exista una clave API configurada.

## Contrato inicial de resultados

El servicio de recopilación devuelve:

- `target`: dominio normalizado.
- `records`: registros DNS agrupados por tipo.
- `errors`: errores o limitaciones de consulta por tipo.
- `entities`: dominio y entidades observadas.
- `relationships`: vínculos entre dominio y registros.
- `evidence`: observaciones con fuente, timestamp, clasificación y confianza.
- `summary`: contadores.
- `graph`: grafo NetworkX para visualización.

La consulta DNS es pasiva. No realiza escaneo de puertos ni modifica archivos del sistema.
