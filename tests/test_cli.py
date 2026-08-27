"""Tests de integración de la CLI de KANEDA."""

import json
from pathlib import Path
from typer.testing import CliRunner
from kaneda.cli import app

runner = CliRunner()


def test_cli_version():
    res = runner.invoke(app, ["--version"])
    assert res.exit_code == 0
    assert "KANEDA" in res.stdout


def test_cli_rules():
    res = runner.invoke(app, ["rules"])
    assert res.exit_code == 0
    assert "KAN001" in res.stdout


def test_cli_audit_json(tmp_path):
    fuente = tmp_path / "system.c"
    fuente.write_text('#include <stdlib.h>\nint main(void) { system("ls"); return 0; }\n')

    res = runner.invoke(app, ["audit", str(fuente), "--json"])
    assert res.exit_code == 1
    data = json.loads(res.stdout)
    assert data["ok"] is False
    assert any(v["codigo"] == "KAN006" for v in data["vulnerabilidades"])
