"""Catálogo de reglas de seguridad e higiene de memoria en KANEDA."""

from __future__ import annotations

from typing import Dict, Optional

# kaneda es el dueño del catálogo de funciones inseguras (revisión 07 §3): cada regla lleva su CWE
# (el material de seguridad lo usa) y, si existe, la regla del apunte que la cubre. `kaneda rules
# --json` lo exporta versionado para spunkmeyer, gaff y la devolución de dredd.
CATALOGO_VERSION = "1.1.0"

CATALOGO_SEGURIDAD: Dict[str, Dict[str, Optional[str]]] = {
    "KAN001": {
        "titulo": "Uso de la función prohibida 'gets()'",
        "severidad": "CRITICO",
        "descripcion": "'gets()' no verifica los límites del búfer destino y es intrínsecamente vulnerable a desbordamientos de búfer (Buffer Overflow).",
        "sugerencia": "Reemplazá 'gets(buf)' por 'fgets(buf, sizeof(buf), stdin)'.",
        "cwe": "CWE-242",
        "regla_catedra": "0x5008h",
        "ejemplo_incorrecto": 'char nombre[50];\ngets(nombre);',
        "ejemplo_correcto": 'char nombre[50];\nfgets(nombre, sizeof(nombre), stdin);',
    },
    "KAN002": {
        "titulo": "Copia insegura de cadenas con 'strcpy()' o 'strcat()'",
        "severidad": "ALTO",
        "descripcion": "'strcpy' y 'strcat' no limitan la cantidad de bytes copiados, provocando corrupción de memoria si la cadena origen excede el búfer.",
        "sugerencia": "Usá 'strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = '\\0';' o 'snprintf()'.",
        "cwe": "CWE-120",
        "regla_catedra": "0x5004h",
        "ejemplo_incorrecto": 'char destino[8];\nstrcpy(destino, origen);',
        "ejemplo_correcto": 'char destino[8];\nsnprintf(destino, sizeof(destino), "%s", origen);',
    },
    "KAN003": {
        "titulo": "Formateo inseguro con 'sprintf()'",
        "severidad": "ALTO",
        "descripcion": "'sprintf' no verifica el tamaño del búfer destino.",
        "sugerencia": "Reemplazá 'sprintf(buf, ...)' por 'snprintf(buf, sizeof(buf), ...)'.",
        "cwe": "CWE-787",
        "regla_catedra": "0x5004h",
        "ejemplo_incorrecto": 'char linea[16];\nsprintf(linea, "%s: %d", nombre, edad);',
        "ejemplo_correcto": 'char linea[16];\nsnprintf(linea, sizeof(linea), "%s: %d", nombre, edad);',
    },
    "KAN004": {
        "titulo": "Lectura sin límite en 'scanf(\"%s\")'",
        "severidad": "ALTO",
        "descripcion": "El especificador '%s' sin ancho máximo en scanf permite escribir más bytes de los reservados.",
        "sugerencia": "Especificá el ancho máximo, por ejemplo: 'scanf(\"%99s\", buf)' para un arreglo de 100 chars.",
        "cwe": "CWE-120",
        "regla_catedra": "0x5006h",
        "ejemplo_incorrecto": 'char palabra[100];\nscanf("%s", palabra);',
        "ejemplo_correcto": 'char palabra[100];\nscanf("%99s", palabra);',
    },
    "KAN005": {
        "titulo": "Vulnerabilidad de cadena de formato (Format String)",
        "severidad": "CRITICO",
        "descripcion": "Pasar una variable directamente como primer argumento a 'printf(str)' permite leer y escribir memoria arbitraria de la pila mediante especificadores maliciosos.",
        "sugerencia": "Usá siempre una cadena de formato literal constante: 'printf(\"%s\", str);'.",
        "cwe": "CWE-134",
        "regla_catedra": None,
        "ejemplo_incorrecto": 'printf(mensaje);',
        "ejemplo_correcto": 'printf("%s", mensaje);',
    },
    "KAN006": {
        "titulo": "Invocación al intérprete de comandos con 'system()' o 'popen()'",
        "severidad": "CRITICO",
        "descripcion": "Ejecutar comandos del shell mediante 'system()' es vulnerable a inyección de comandos y está prohibido en la cátedra.",
        "sugerencia": "Utilizá funciones nativas de la biblioteca estándar de C o APIs del sistema en lugar de llamar al shell.",
        "cwe": "CWE-78",
        "regla_catedra": None,
        "ejemplo_incorrecto": 'system("clear");',
        "ejemplo_correcto": '/* Sin limpiar la pantalla: el programa solo escribe su salida. */',
    },
    "KAN007": {
        "titulo": "Llamada a sistema restringida fuera de consigna",
        "severidad": "ALTO",
        "descripcion": "Se detectó el uso de syscalls de control de procesos o red (fork, exec, kill, ptrace, socket) en una práctica donde no están autorizadas.",
        "sugerencia": "Resolvé el ejercicio utilizando únicamente las primitivas de E/S y algoritmos solicitados.",
        "cwe": "CWE-676",
        "regla_catedra": None,
        "ejemplo_incorrecto": 'pid_t hijo = fork();',
        "ejemplo_correcto": '/* Resolvé el ejercicio en un solo proceso, con las funciones pedidas. */',
    },
}
