# Hoja de ruta

## Fase 0 — Fundaciones
- [x] Repositorio independiente.
- [x] README, arquitectura, metodología y hoja de ruta.
- [x] Estructura modular inicial.
- [x] Prototipo visual oscuro.

## Fase 1 — Reconocimiento pasivo básico
- [x] Domain Analyzer inicial.
- [x] DNS Intelligence A, AAAA, MX, NS, TXT y CNAME.
- [x] Modelo de evidencias trazables.
- [x] Servicio de orquestación y normalización de resultados.
- [x] Primeras relaciones dominio-registro.
- [x] Dashboard conectado a los módulos básicos.
- [x] Exportación JSON.
- [ ] Robustecer validación, errores DNS y pruebas con dominios de laboratorio.
- [ ] WHOIS/RDAP.

## Fase 2 — Certificados e infraestructura
- [ ] Certificate Transparency / crt.sh.
- [ ] Nmap NSE ssl-cert con XML y alcance autorizado.
- [ ] Adaptadores Shodan/Censys.
- [ ] Historial, deduplicación y normalización.

## Fase 3 — Correlación y visualización
- [x] Grafo inicial NetworkX y salida DOT.
- [ ] Motor de correlación y confianza.
- [ ] Grafo interactivo PyVis.
- [ ] Filtros por fuente, fecha y clasificación.

## Fase 4 — Sistema e informes
- [x] Exportación JSON inicial.
- [x] Lectura de /etc/hosts en modo solo lectura.
- [ ] Exportación TXT/PDF.
- [ ] Local DNS & Hosts Manager con confirmación previa, backup y rollback.
- [ ] Registro de actividad y auditoría.

## Fase 5 — Calidad
- [x] Pruebas unitarias iniciales.
- [x] Flujo CI para Python 3.10 y 3.11.
- [ ] Pruebas con laboratorios propios.
- [ ] Documentación completa de instalación y ejemplos.
- [ ] Revisión de seguridad y publicación de versión inicial.

## Compatibilidad

El entorno de desarrollo principal se orienta a Python 3.10 o superior. Se mantiene un archivo de dependencias mínimo para una vista previa en Ubuntu 18.04 / Python 3.6; no se garantiza que todos los conectores futuros sean compatibles con esa plataforma.
