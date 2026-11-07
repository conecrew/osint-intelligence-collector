# Metodología OSINT

## Fuentes previstas

- DNS público y consultas RDAP/WHOIS.
- SecurityTrails para datos DNS e históricos, según acceso disponible.
- Certificate Transparency, por ejemplo crt.sh.
- Shodan y Censys para observaciones de servicios e infraestructura.
- VirusTotal para reputación y relaciones observadas.
- DNSDumpster como fuente complementaria.

## Reglas de interpretación

- Un registro DNS es una observación, no prueba de propiedad.
- Una IP puede ser de hosting compartido, CDN, WAF o proveedor externo.
- Distinguir datos actuales de históricos.
- Conservar la fuente y el instante de consulta.
- Registrar contradicciones y datos no verificados.
- Respetar términos de servicio, límites y condiciones de cada API.
