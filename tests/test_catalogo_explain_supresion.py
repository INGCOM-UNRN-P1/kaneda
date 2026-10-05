"""Catálogo exportable con CWE, `kaneda explain` (QoL #577) y supresión con motivo (QoL #583)."""

import json

from typer.testing import CliRunner

from kaneda.cli import app
from kaneda.core.security import auditar_archivos
from kaneda.core.supresion import leer_supresiones

runner = CliRunner()

FUENTE = """#include <stdio.h>
#include <string.h>
int main(void)
{
    char a[8], b[8] = "hola";
    strcpy(a, b);  // kaneda:ignore KAN002 b tiene 5 bytes y a 8
    // kaneda:ignore KAN003
    sprintf(a, "%d", 1);
    strcat(a, b);
    gets(a);  // kaneda:ignore KAN002 este código no es el de esta línea
    return 0;
}
"""


def test_supresion_con_motivo(tmp_path):
    f = tmp_path / "p.c"
    f.write_text(FUENTE, encoding="utf-8")
    reporte = auditar_archivos([f])
    activas = sorted((v.codigo, v.linea) for v in reporte.vulnerabilidades)
    assert activas == [("KAN001", 10), ("KAN002", 9)]
    suprimidas = {(v.codigo, v.linea): v.motivo_supresion for v in reporte.suprimidas}
    assert suprimidas == {("KAN002", 6): "b tiene 5 bytes y a 8", ("KAN003", 8): ""}
    datos = reporte.to_dict()
    assert {s["motivo_supresion"] for s in datos["suprimidas"]} == {"b tiene 5 bytes y a 8", "(sin motivo)"}


def test_supresion_sin_codigo_cubre_toda_la_linea():
    sup = leer_supresiones(["gets(a); // kaneda:ignore lectura de prueba"])
    assert sup[1].codigos is None and sup[1].motivo == "lectura de prueba"


def test_hallazgos_con_cwe_y_regla_del_apunte(tmp_path):
    f = tmp_path / "p.c"
    f.write_text(FUENTE, encoding="utf-8")
    datos = auditar_archivos([f]).to_dict()
    gets = next(h for h in datos["hallazgos"] if h["codigo"] == "KAN001")
    assert gets["id"] == "kaneda:KAN001" and gets["cwe"] == "CWE-242" and gets["severidad"] == "error"
    assert gets["enlace"].endswith("/x5008h") and gets["categoria"] == "seguridad"
    assert next(v for v in datos["vulnerabilidades"] if v["codigo"] == "KAN001")["cwe"] == "CWE-242"


def test_catalogo_json():
    res = runner.invoke(app, ["rules", "--json"])
    datos = json.loads(res.stdout)
    assert datos["herramienta"] == "kaneda" and datos["version_catalogo"]
    reglas = {r["codigo"]: r for r in datos["reglas"]}
    assert reglas["KAN005"]["cwe"] == "CWE-134" and reglas["KAN002"]["regla_catedra"] == "0x5004h"
    assert all(r["ejemplo_incorrecto"] and r["ejemplo_correcto"] for r in datos["reglas"])


def test_explain():
    res = runner.invoke(app, ["explain", "kan002"])
    assert res.exit_code == 0
    assert "CWE-120" in res.stdout and "Antes" in res.stdout and "snprintf" in res.stdout and "x5004h" in res.stdout
    assert runner.invoke(app, ["explain", "KAN999"]).exit_code == 2
