"""Catálogo de reglas de seguridad e higiene de memoria en KANEDA."""

from __future__ import annotations

from typing import Dict

CATALOGO_SEGURIDAD: Dict[str, Dict[str, str]] = {
    "KAN001": {
        "titulo": "Uso de la función prohibida 'gets()'",
        "severidad": "CRITICO",
        "descripcion": "'gets()' no verifica los límites del búfer destino y es intrínsecamente vulnerable a desbordamientos de búfer (Buffer Overflow).",
        "sugerencia": "Reemplazá 'gets(buf)' por 'fgets(buf, sizeof(buf), stdin)'.",
    },
    "KAN002": {
        "titulo": "Copia insegura de cadenas con 'strcpy()' o 'strcat()'",
        "severidad": "ALTO",
        "descripcion": "'strcpy' y 'strcat' no limitan la cantidad de bytes copiados, provocando corrupción de memoria si la cadena origen excede el búfer.",
        "sugerencia": "Usá 'strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst)-1] = '\\0';' o 'snprintf()'.",
    },
    "KAN003": {
        "titulo": "Formateo inseguro con 'sprintf()'",
        "severidad": "ALTO",
        "descripcion": "'sprintf' no verifica el tamaño del búfer destino.",
        "sugerencia": "Reemplazá 'sprintf(buf, ...)' por 'snprintf(buf, sizeof(buf), ...)'.",
    },
    "KAN004": {
        "titulo": "Lectura sin límite en 'scanf(\"%s\")'",
        "severidad": "ALTO",
        "descripcion": "El especificador '%s' sin ancho máximo en scanf permite escribir más bytes de los reservados.",
        "sugerencia": "Especificá el ancho máximo, por ejemplo: 'scanf(\"%99s\", buf)' para un arreglo de 100 chars.",
    },
    "KAN005": {
        "titulo": "Vulnerabilidad de cadena de formato (Format String)",
        "severidad": "CRITICO",
        "descripcion": "Pasar una variable directamente como primer argumento a 'printf(str)' permite leer y escribir memoria arbitraria de la pila mediante especificadores maliciosos.",
        "sugerencia": "Usá siempre una cadena de formato literal constante: 'printf(\"%s\", str);'.",
    },
    "KAN006": {
        "titulo": "Invocación al intérprete de comandos con 'system()' o 'popen()'",
        "severidad": "CRITICO",
        "descripcion": "Ejecutar comandos del shell mediante 'system()' es vulnerable a inyección de comandos y está prohibido en la cátedra.",
        "sugerencia": "Utilizá funciones nativas de la biblioteca estándar de C o APIs del sistema en lugar de llamar al shell.",
    },
    "KAN007": {
        "titulo": "Llamada a sistema restringida fuera de consigna",
        "severidad": "ALTO",
        "descripcion": "Se detectó el uso de syscalls de control de procesos o red (fork, exec, kill, ptrace, socket) en una práctica donde no están autorizadas.",
        "sugerencia": "Resolvé el ejercicio utilizando únicamente las primitivas de E/S y algoritmos solicitados.",
    },
}
