# 🔒 KANEDA — Auditor de Seguridad y Funciones Inseguras en C

KANEDA es una herramienta pedagógica para la detección temprana de funciones C prohibidas o inseguras (`gets`, `strcpy`, `sprintf`, `scanf("%s")`, `system`), vulnerabilidades de tipo `Format String` y llamadas a sistema no autorizadas.

## Uso Rápido

```bash
# 1. Auditar archivos C o carpetas de código
kaneda audit src/ main.c

# 2. Salida estructurada JSON
kaneda audit src/ --json

# 3. Listar catálogo de reglas
kaneda rules
```
