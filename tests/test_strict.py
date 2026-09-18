"""Regresión de KANEDA-D0402: `--strict` estaba declarada y nadie la consultaba."""


import pytest
from typer.testing import CliRunner

from kaneda.cli import app

runner = CliRunner()


@pytest.fixture
def con_hallazgo(tmp_path):
    ruta = tmp_path / "a.c"
    ruta.write_text("#include <stdio.h>\nint main(void) { char b[8]; gets(b); return 0; }\n", encoding="utf-8")
    return ruta


@pytest.fixture
def limpio(tmp_path):
    ruta = tmp_path / "ok.c"
    ruta.write_text('#include <stdio.h>\nint main(void) { printf("hola\\n"); return 0; }\n', encoding="utf-8")
    return ruta


def test_strict_se_acepta_y_no_cambia_el_veredicto(con_hallazgo, limpio):
    """Todo hallazgo ya falla: `--strict` es redundante, pero un script que lo pase no debe romperse."""
    for ruta, esperado in ((con_hallazgo, 1), (limpio, 0)):
        sin = runner.invoke(app, ["audit", str(ruta)])
        con = runner.invoke(app, ["audit", str(ruta), "--strict"])
        assert sin.exit_code == con.exit_code == esperado


def test_strict_no_aparece_en_la_ayuda_como_si_hiciera_algo():
    ayuda = runner.invoke(app, ["audit", "--help"]).output
    assert "--strict" not in ayuda
