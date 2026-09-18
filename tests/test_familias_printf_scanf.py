"""Regresión de KANEDA-D0302: las familias de scanf y printf, no solo las dos funciones exactas.

El motor comparaba `func_name == "scanf"` / `"printf"`, así que `fscanf(f, "%s", b)`,
`sscanf(s, "%s", b)` y `fprintf(f, variable)` —el mismo defecto que el README
promete detectar— pasaban sin hallazgo.
"""

from pathlib import Path

import pytest

from kaneda.core.security import auditar_archivo


def _codigos_por_linea(tmp_path: Path, cuerpo: str):
    archivo = tmp_path / "caso.c"
    archivo.write_text(
        "#include <stdio.h>\nint main(void) {\n    char b[8]; char *msg = \"x\"; FILE *f = stdin;\n"
        + cuerpo
        + "\n    return 0;\n}\n",
        encoding="utf-8",
    )
    return {(v.linea, v.codigo) for v in auditar_archivo(archivo)}


@pytest.mark.parametrize(
    "llamada",
    ['scanf("%s", b);', 'fscanf(f, "%s", b);', 'sscanf(msg, "%s", b);'],
)
def test_lectura_de_cadena_sin_limite_se_detecta_en_toda_la_familia(tmp_path, llamada):
    assert (4, "KAN004") in _codigos_por_linea(tmp_path, "    " + llamada)


@pytest.mark.parametrize("llamada", ['fscanf(f, "%7s", b);', 'sscanf(msg, "%d", &n);', 'scanf("%99s", b);'])
def test_la_lectura_con_ancho_o_de_otro_tipo_no_se_marca(tmp_path, llamada):
    assert not any(c == "KAN004" for _, c in _codigos_por_linea(tmp_path, "    int n; " + llamada))


@pytest.mark.parametrize("llamada", ["printf(msg);", "fprintf(stderr, msg);"])
def test_formato_por_variable_se_detecta_en_printf_y_fprintf(tmp_path, llamada):
    assert (4, "KAN005") in _codigos_por_linea(tmp_path, "    " + llamada)


@pytest.mark.parametrize(
    "llamada",
    ['printf("%s\\n", msg);', 'fprintf(stderr, "%s\\n", msg);', 'fprintf(stderr, "fijo\\n");'],
)
def test_el_formato_literal_no_se_marca(tmp_path, llamada):
    assert not any(c == "KAN005" for _, c in _codigos_por_linea(tmp_path, "    " + llamada))
