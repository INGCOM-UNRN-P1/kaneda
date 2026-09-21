"""KANEDA-D0702: cada regla del motor con su caso positivo y sus límites (falsos positivos/negativos)."""

import pytest

from kaneda.core.rules import CATALOGO_SEGURIDAD
from kaneda.core.security import auditar_archivo


def _codigos(tmp_path, cuerpo: str):
    f = tmp_path / "t.c"
    f.write_text("#include <stdio.h>\n#include <string.h>\n" + cuerpo, encoding="utf-8")
    return [v.codigo for v in auditar_archivo(f)]


POSITIVOS = {
    "KAN001": "void f(char *b) { gets(b); }",
    "KAN002": "void f(char *d, char *s) { strcpy(d, s); }",
    "KAN003": 'void f(char *d, int n) { sprintf(d, "%d", n); }',
    "KAN004": 'void f(char *b) { scanf("%s", b); }',
    "KAN005": "void f(char *u) { printf(u); }",
    "KAN006": 'void f(void) { system("ls"); }',
    "KAN007": "void f(void) { fork(); }",
}


def test_el_catalogo_completo_tiene_caso_positivo():
    assert set(POSITIVOS) == set(CATALOGO_SEGURIDAD)


@pytest.mark.parametrize("codigo", sorted(POSITIVOS))
def test_cada_regla_dispara_con_su_caso(tmp_path, codigo):
    assert codigo in _codigos(tmp_path, POSITIVOS[codigo])


@pytest.mark.parametrize("cuerpo", [
    "#if 0\nvoid f(char *b) { gets(b); }\n#endif\n",
    "// gets(b);\nvoid f(void) {}\n",
    '/* strcpy(a, b); */\nvoid f(void) {}\n',
    'void f(void) { puts("no llames a gets() ni a system()"); }',
    "void my_gets(char *b); void f(char *b) { my_gets(b); }",
    "void f(char *b) { fgets(b, 8, stdin); }",
    'void f(char *b) { scanf("%99s", b); }',
    'void f(char *b) { printf("%s", b); }',
    'void f(char *b) { snprintf(b, 8, "x"); }',
])
def test_limites_sin_falsos_positivos(tmp_path, cuerpo):
    assert _codigos(tmp_path, cuerpo) == []


def test_variantes_sobre_archivo_y_cadena(tmp_path):
    assert "KAN004" in _codigos(tmp_path, 'void f(FILE *a, char *b) { fscanf(a, "%s", b); }')
    assert "KAN004" in _codigos(tmp_path, 'void f(char *s, char *b) { sscanf(s, "%s", b); }')
    assert "KAN005" in _codigos(tmp_path, "void f(FILE *o, char *u) { fprintf(o, u); }")
    assert _codigos(tmp_path, 'void f(FILE *o, char *u) { fprintf(o, "%s", u); }') == []


def test_strcat_popen_y_familia_exec_tambien_cuentan(tmp_path):
    assert "KAN002" in _codigos(tmp_path, "void f(char *d, char *s) { strcat(d, s); }")
    assert "KAN006" in _codigos(tmp_path, 'void f(void) { popen("ls", "r"); }')
    assert "KAN007" in _codigos(tmp_path, 'void f(void) { execvp("ls", 0); }')
