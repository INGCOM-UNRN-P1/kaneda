"""Tests adicionales para maximizar la cobertura en KANEDA."""

import json
from pathlib import Path
from typer.testing import CliRunner
import kaneda.cli
from kaneda.cli import app
from kaneda.core.security import auditar_archivos, auditar_archivo
from kaneda.ripley_plugin import KanedaPlugin

runner = CliRunner()


def test_plugin_execution(tmp_path):
    p = KanedaPlugin()
    assert p.is_available() is True

    f = tmp_path / "inseguro.c"
    f.write_text("int main() { char b[10]; gets(b); return 0; }\n")
    res = p.execute(tmp_path, {})
    assert res["ok"] is False
    assert len(res["observaciones"]) >= 1


def test_cli_audit_rich_and_clean(tmp_path):
    # Vulnerable rich output
    f_vuln = tmp_path / "vuln.c"
    f_vuln.write_text('#include <stdio.h>\nint main() { char b[10]; sprintf(b, "hi"); return 0; }\n')
    res_v = runner.invoke(app, ["audit", str(f_vuln)])
    assert res_v.exit_code == 1
    assert "Vulnerabilidades de Seguridad" in res_v.stdout

    # Clean rich output
    f_ok = tmp_path / "ok.c"
    f_ok.write_text("int main() { return 0; }\n")
    res_ok = runner.invoke(app, ["audit", str(f_ok)])
    assert res_ok.exit_code == 0
    assert "KANEDA Security Check OK" in res_ok.stdout


def test_security_rules_all(tmp_path):
    # Test scanf %s without width, and syscalls
    f = tmp_path / "test_all.c"
    f.write_text("""
    #include <stdio.h>
    #include <unistd.h>
    int main(void) {
        char s[50];
        scanf("%s", s);
        fork();
        return 0;
    }
    """)
    rep = auditar_archivos([f])
    codigos = [v.codigo for v in rep.vulnerabilidades]
    assert "KAN004" in codigos
    assert "KAN007" in codigos


def test_cli_main_block(monkeypatch):
    monkeypatch.setattr("sys.argv", ["kaneda", "--version"])
    try:
        kaneda.cli.main()
    except SystemExit as e:
        assert e.code == 0
