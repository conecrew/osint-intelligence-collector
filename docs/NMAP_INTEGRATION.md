# Integración prevista de Nmap

Nmap será un componente de reconocimiento activo separado de las consultas OSINT pasivas.

## Alcance inicial

- Ejecutar Nmap solo contra objetivos expresamente autorizados.
- Usar parámetros acotados y documentar el alcance.
- Preferir salida XML mediante -oX para procesamiento reproducible.
- Incorporar el NSE ssl-cert para recopilar datos del certificado TLS presentado por el servicio.
- Normalizar los resultados para el Evidence Manager.

## Interpretación de ssl-cert

El script ssl-cert recupera información del certificado que presenta el servicio, como sujeto, emisor, fechas y nombres alternativos cuando están disponibles. No equivale a una auditoría completa de TLS ni demuestra que la infraestructura pertenezca al dominio.

ssl-enum-ciphers queda como ampliación posterior y también requiere autorización explícita.

## Controles

La interfaz deberá exigir confirmación de autorización antes de ejecutar un escaneo. Los resultados incluirán fecha, objetivo, parámetros y estado de ejecución. No se implementarán funciones para evadir WAF/CDN ni para descubrir o acceder a orígenes de terceros.
