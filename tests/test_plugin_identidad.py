"""Regresión de KANEDA-D0901: el plugin se publicaba con un nombre distinto del de su entry-point."""

import pytest

from kaneda.ripley_plugin import KanedaPlugin


@pytest.fixture
def con_hallazgo(tmp_path):
    ruta = tmp_path / "a.c"
    ruta.write_text("#include <stdio.h>\nint main(void) { char b[8]; gets(b); return 0; }\n", encoding="utf-8")
    return ruta


def test_el_plugin_se_publica_con_el_nombre_del_entry_point(tmp_path):
    from importlib.metadata import entry_points

    declarados = {ep.name: ep.value for ep in entry_points(group="ripley.plugins") if "kaneda" in ep.value}
    if declarados:
        assert KanedaPlugin.name in declarados
    assert KanedaPlugin.name == "security"


def test_el_plugin_devuelve_ubicacion_y_veredicto(con_hallazgo):
    res = KanedaPlugin().execute(con_hallazgo.parent, {})
    assert res["ok"] is False
    assert res["observaciones"][0]["codigo"] == "KAN001"
    assert res["observaciones"][0]["linea"] == 2
