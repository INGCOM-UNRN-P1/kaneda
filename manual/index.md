---
title: "Manual de Referencia: kaneda"
subtitle: "Kaneda — Auditor Estático de Seguridad en C y Detección de Funciones Inseguras Prohibidas"
author: "Cátedra de Algoritmos y Programación"
date: "2026-08-31"
---

(manual-kaneda)=
# Kaneda — Auditor Estático de Seguridad en C y Detección de Funciones Inseguras Prohibidas

````{abstract}
**Rol en el ecosistema:** Auditoría de vulnerabilidades en C: prohibición de `gets()`, `strcpy()`, `sprintf()`, detección de desbordes de buffer estáticos y vulnerabilidades de Format String.
````

---

(manual-kaneda-proposito)=
## 1. Propósito y Filosofía Pedagógica

La herramienta **`kaneda`** forma parte del ecosistema oficial de software de la cátedra. Su diseño sigue principios pedagógicos rigurosos:

1. **Evidencia Técnica Directa**: Todo diagnóstico se fundamenta en la norma ISO C (C11/C23), en el modelo de memoria del sistema o en convenciones arquitectónicas formales.
2. **Acción Correctiva Concreta**: Cada advertencia incluye la prescripción técnica inmediata para resolver el defecto sin recurrir a conjeturas.
3. **Autonomía del Estudiante**: Facilita la autoevaluación local antes de la entrega final del trabajo práctico.
4. **Objetividad Docente**: Estandariza la corrección automática eliminando discrepancias subjetivas en la evaluación.

---

(manual-kaneda-instalacion)=
## 2. Instalación y Diagnóstico del Entorno

````{important}
Asegurate de contar con el compilador GCC/Clang y las librerías del sistema instaladas antes de ejecutar `kaneda`.
````

Para comprobar el estado de salud de tu entorno de trabajo y las dependencias auxiliares:

````{code-block} bash
# Comprobación de dependencias del sistema
kaneda doctor
````

Si se detecta la falta de alguna utilidad (como `gdb`, `valgrind`, `clang-format` o `typst`), el comando indicará el paquete exacto a instalar según tu distribución GNU/Linux o entorno MSYS2.

---

(manual-kaneda-comandos)=
## 3. Referencia Completa de Comandos CLI

A continuación se detallan los subcomandos principales disponibles en `kaneda`:

| Sintaxis del Comando | Descripción y Efecto |
| :--- | :--- |
| `kaneda audit src/ include/` | Audita todos los archivos C buscando llamadas inseguras y vulnerabilidades. |
| `kaneda scan <archivo.c>` | Analiza un archivo individual y sugiere alternativas seguras (`fgets`, `snprintf`). |
| `kaneda rules` | Muestra el catálogo de funciones prohibidas y buenas prácticas de seguridad. |
| `kaneda doctor` | Verifica analizadores estáticos y reglas de seguridad. |

````{tip}
Podés agregar el flag `--json` a la mayoría de los comandos para exportar resultados en formato estructurado o `--md` para generar reportes Markdown para el informe de entrega.
````

---

(manual-kaneda-tutorial)=
## 4. Tutorial Paso a Paso con Ejemplos Reales

### Caso de Estudio

Considerá el siguiente fragmento de código representativo:

````{code-block} c
:linenos:
#include <stdio.h>
#include <string.h>

void vulnerabilidad_seguridad(void) {
    char buffer[16];
    gets(buffer);                     // Prohibido: Buffer Overflow crítico
    char destino[10];
    strcpy(destino, "Texto muy largo"); // Prohibido: Desborde
    printf(buffer);                   // Prohibido: Format String Vulnerability
}
````

### Ejecución de la Herramienta

Ejecutá el análisis desde tu terminal:

````{code-block} bash
kaneda audit src/ include/
````

### Salida Obtenida en Consola

````{code-block} text
🚨 KANEDA SECURITY AUDIT REPORT: 3 vulnerabilidades críticas detectadas:
┌──────────────────┬──────────┬────────────────────────────────────────────────────────┐
│ Ubicación        │ Gravedad │ Vulnerabilidad y Acción Requerida                      │
├──────────────────┼──────────┼────────────────────────────────────────────────────────┤
│ auth.c:5:5       │ CRÍTICA  │ Uso de 'gets()'. Reemplazá obligatoriamente por fgets()│
│ auth.c:7:5       │ ALTA     │ 'strcpy()' sin límite. Usá strncpy() o snprintf()      │
│ auth.c:8:5       │ ALTA     │ Format string sin formato fijo. Usá printf("%s", buf)  │
└──────────────────┴──────────┴────────────────────────────────────────────────────────┘
````

````{note}
Prestá atención a la explicación pedagógica generada: la herramienta no solo señala la línea del problema, sino que explica la causa raíz y el impacto en memoria o arquitectura.
````

---

(manual-kaneda-ejercicios)=
## 5. Ejercicios Prácticos y Desafíos

Practicá el uso avanzado de **`kaneda`** resolviendo los siguientes ejercicios:

````{exercise} Desafío 1: Auditoría de Seguridad de Pre-Entrega
Escanear todo el proyecto para garantizar 0 funciones inseguras.

**Instrucción de ejecución:**
```bash
kaneda audit src/ include/
```
````

````{solution} Desafío 1
```bash
kaneda audit src/ include/
# Verificá que la operación concluya exitosamente con código de salida 0.
```
````

````{exercise} Desafío 2: Reemplazo de `gets` por `fgets`
Corregir lectura de teclado asegurando el tamaño del buffer.

**Instrucción de ejecución:**
```bash
kaneda scan src/login.c
```
````

````{solution} Desafío 2
```bash
kaneda scan src/login.c
# Revisá el archivo generado o el informe en terminal para confirmar la resolución del problema.
```
````

````{exercise} Desafío 3: Protección contra Format Strings
Revisar llamadas a `printf` y `syslog` que reciben buffers de usuario.

**Instrucción de ejecución:**
```bash
kaneda audit src/ --strict
```
````

````{solution} Desafío 3
```bash
kaneda audit src/ --strict
# Comprobá que la salida confirme la ausencia de advertencias o errores pendientes.
```
````

---

(manual-kaneda-makefile)=
## 6. Integración en el Flujo de Trabajo y Makefile

Para incorporar `kaneda` de forma automática a tu flujo de desarrollo, agregá la siguiente regla en el `Makefile` de tu proyecto:

````{code-block} makefile
check-kaneda:
	@echo "=== Ejecutando verificación con kaneda ==="
	kaneda check src/ include/

.PHONY: check-kaneda
````

Ejecutá `make check-kaneda` antes de cada commit para asegurar que tu código conserve el estado de aprobación.
