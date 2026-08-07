"""
Pruebas unitarias para la interfaz CLI.
"""

from pathlib import Path
from sentinel.core.analyzer import analyze_file


def test_cli_scan_flow(tmp_path: Path) -> None:
    valid_code = """def funcion_correcta(a: int) -> int:
    return a + 1
"""
    code_file = tmp_path / "valid.py"
    code_file.write_text(valid_code, encoding="utf-8")

    issues = analyze_file(code_file)
    assert len(issues) == 0
