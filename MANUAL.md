# Manual de Uso y Referencia Técnica: kaneda

> **KANEDA** — Auditor pedagógico de seguridad C, buffer overflows y llamadas a sistema restringidas
> **Versión:** `0.1.0` · **CLI principal:** `kaneda` · **Plugin Ripley:** `security`

---

## 1. Arquitectura y Propósito Pedagógico

`kaneda` forma parte del ecosistema de herramientas de la cátedra de Programación 1 (UNRN). Su objetivo central es resolver de forma modular, determinista y automatizada las tareas asociadas a su dominio específico dentro del ciclo de desarrollo, evaluación y aprendizaje de software en C.

### Alcance Funcional (Qué cubre)
- Auditoría pedagógica de seguridad estática en código C con su propio catálogo de 7 reglas (`KAN001`-`KAN007`). Sus códigos son `KANxxx`, no `0x30XXh`: esa numeración pertenece a `gaff` y no se emite desde acá.
- Detección estricta de funciones vulnerables a desbordamiento de búfer (`gets`, `strcpy`, `strcat`, `sprintf`, `scanf` con `%s` sin límite de ancho).
- Detección de vulnerabilidades de cadena de formato (`printf` o `fprintf` con variable como formato directo sin especificadores).
- Prohibición terminante de invocación de subprocesos y comandos del sistema (`system`, `popen`).
- Detección de llamadas al sistema restringidas o no autorizadas (red, sockets, bifurcación no controlada).

### Límites de Responsabilidad y Delegación (Qué no cubre)
- Propiedad de la detección de funciones inseguras (`gets`, `strcpy`, `sprintf`, `scanf("%s")`): es de `kaneda`. `gaff` (`0x5004h`, `0x5006h`, `0x5008h`) solo señala el uso desde el estilo y `spunkmeyer` lo hace como antipatrón didáctico; no son la fuente de verdad de seguridad.
- Confinamiento y sandbox en tiempo de ejecución (delegado a `nostromo`).
- Análisis dinámico de sanitizers en memoria (delegado a `tetsuo`).
- Depuración post-mortem de crashes (delegado a `hal`).

### Principios de Diseño
- **Enfoque Pedagógico:** Diagnósticos y mensajes en español rioplatense orientados a facilitar la comprensión de errores conceptuales.
- **Salida Estructurada Dual:** Soporte nativo para visualización enriquecida en terminal (Rich) y salida parseable para orquestadores (`--json`).
- **Integración Contractual:** Capacidad de emitir secciones de reporte para `dredd` (`dredd-section`) y actuar como satélite orquestado por `ripley`.
- **Idempotencia y Robustez:** Validación de precondiciones y comandos de autodiagnóstico (`doctor`) para verificación del entorno.

---

## 2. Instalación y Requisitos

### Requisitos del Sistema
- **Python:** `>= 3.10` (recomendado Python 3.11 o 3.12).
- **Gestor de paquetes:** [`uv`](https://github.com/astral-sh/uv) (entorno estándar de cátedra).
- **Toolchain C (si aplica):** GCC / Clang, Make, GDB y bibliotecas estándar de desarrollo.

### Instalación en el Entorno de Usuario
Para instalar la herramienta de forma global y aislada en el sistema mediante `uv tool`:
```bash
uv tool install --editable /home/mrtin/dev/tools/kaneda
```

### Verificación de Instalación
Ejecutá el comando `doctor` para constatar que todas las dependencias y binarios requeridos estén presentes y operativos:
```bash
kaneda doctor
```

---

## 3. Guía Integral de Comandos (CLI)

| Comando | Descripción Breve |
| :--- | :--- |
| [`kaneda audit`](#audit) | Audita código C en busca de funciones vulnerables a buffer overflow y llamadas restringidas. |
| [`kaneda report`](#report) | Genera directamente la sección de reporte Markdown de KANEDA para Dredd. |
| [`kaneda rules`](#rules) | Lista las reglas de seguridad auditadas por KANEDA. |
| [`kaneda doctor`](#doctor) | Verifica el estado del entorno de auditoría de seguridad KANEDA (Tree-Sitter C, Python, GCC). |

### `kaneda audit`

Audita código C en busca de funciones vulnerables a buffer overflow y llamadas restringidas.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `rutas` | `List[Path]` | Archivos C/H o directorios a auditar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Salida estructurada en JSON. |
| `--md`, `--output-md`, `-o` | `Optional[Path]` | `None` | Generar sección de reporte en formato Markdown para fusión en Dredd. |
| `--strict` | `bool` | `False` | Sin efecto: cualquier hallazgo ya hace fallar la auditoría (se acepta por compatibilidad). |

#### Ejemplo de Invocación
```bash
kaneda audit <rutas>
```

### `kaneda report`

Genera directamente la sección de reporte Markdown de KANEDA para Dredd.

#### Argumentos
| Argumento | Tipo | Descripción |
| :--- | :--- | :--- |
| `rutas` | `List[Path]` | Archivos C/H o directorios a auditar. |

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--output`, `-o` | `Optional[Path]` | `None` | Ruta de destino del archivo Markdown. |

#### Ejemplo de Invocación
```bash
kaneda report <rutas>
```

### `kaneda rules`

Lista las reglas de seguridad auditadas por KANEDA.

#### Ejemplo de Invocación
```bash
kaneda rules
```

### `kaneda doctor`

Verifica el estado del entorno de auditoría de seguridad KANEDA (Tree-Sitter C, Python, GCC).

#### Opciones y Banderas
| Opción / Banderas | Tipo | Por Defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `--json` | `bool` | `False` | Emitir diagnóstico en formato JSON estructurado. |

#### Ejemplo de Invocación
```bash
kaneda doctor
```

---

## 4. Formatos de Salida e Integración con el Ecosistema

### Modo Interactivo / Terminal (Rich)
Por defecto, la herramienta renderiza paneles, árboles y tablas estilizadas para facilitar la lectura del estudiante y docente en terminales modernas con soporte ANSI.

### Modo Estructurado JSON (`--json`)
Para integración con pipelines de CI/CD, scripts de automatización u orquestadores externos, la opción `--json` emite un documento JSON estricto por la salida estándar (`stdout`), dirigiendo cualquier mensaje de logging a `stderr`:
```bash
kaneda audit --json
```

### Integración con Dredd (`dredd-section`)
Cuando la herramienta genera reportes de evaluación para entregas de alumnos, produce una sección Markdown estandarizada conforme al contrato de integración de Dredd (v1.0.0):
```markdown
<!-- dredd-section: kaneda, tool=kaneda, version=0.1.0, status=ok -->
```
Este encabezado garantiza la agregación determinista de los hallazgos en la rúbrica docente.

### Integración con Ripley
`kaneda` está registrada en el catálogo de plugins satélites de Ripley (`SATELLITE_CATALOG`). Puede invocarse directamente a través del motor de evaluación de Ripley configurando el análisis en `ripley.toml`.

---

## 5. Diagnóstico y Códigos de Salida

### Códigos de Retorno (`exit code`)
| Código | Significado |
| :---: | :--- |
| `0` | Ejecución exitosa sin hallazgos críticos ni errores de sintaxis. |
| `1` | Hallazgos pedagógicos detectados, infracción de reglas o advertencias activas. |
| `2` | Error de sintaxis en argumentos CLI o archivo fuente no encontrado. |
| `>2` | Error no recuperable del sistema, fallo de memoria o excepción interna. |

### Diagnóstico del Entorno (`doctor`)
Ante comportamientos inesperados, verificá el estado operativo con:
```bash
kaneda doctor
```
Comprueba la presencia de las dependencias requeridas y la integridad de los componentes del paquete.