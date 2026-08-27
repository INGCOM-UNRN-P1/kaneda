"""Tests unitarios para el auditor de seguridad en KANEDA."""

from pathlib import Path
import pytest
from kaneda.core.security import auditar_archivo, auditar_archivos


def test_detectar_gets_y_strcpy(tmp_path):
    fuente = tmp_path / "inseguro.c"
    fuente.write_text("""
    #include <stdio.h>
    #include <string.h>

    int main(void) {
        char buf[10];
        gets(buf);
        strcpy(buf, "demasiado largo");
        return 0;
    }
    """)

    vulns = auditar_archivo(fuente)
    assert len(vulns) >= 2
    codigos = [v.codigo for v in vulns]
    assert "KAN001" in codigos
    assert "KAN002" in codigos


def test_detectar_format_string(tmp_path):
    fuente = tmp_path / "fmt.c"
    fuente.write_text("""
    #include <stdio.h>
    void imprimir(char* user_input) {
        printf(user_input);
    }
    """)

    vulns = auditar_archivo(fuente)
    assert any(v.codigo == "KAN005" for v in vulns)


def test_codigo_limpio_seguro(tmp_path):
    fuente = tmp_path / "seguro.c"
    fuente.write_text("""
    #include <stdio.h>
    int main(void) {
        char buf[64];
        if (fgets(buf, sizeof(buf), stdin) != NULL) {
            printf("%s", buf);
        }
        return 0;
    }
    """)

    rep = auditar_archivos([fuente])
    assert rep.ok is True
    assert len(rep.vulnerabilidades) == 0
