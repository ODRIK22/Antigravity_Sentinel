"""
Pruebas unitarias para el motor de análisis estático AST.
"""

from pathlib import Path
from sentinel.core.analyzer import analyze_file


def test_analyze_file_detects_missing_types_and_insecure_calls(tmp_path: Path) -> None:
    sample_code = """def funcion_sin_tipos(x):
    eval("1 + 1")
    f = open("datos.txt")
    return x
"""
    sample_file = tmp_path / "sample.py"
    sample_file.write_text(sample_code, encoding="utf-8")

    issues = analyze_file(sample_file)
    codes = [issue.code for issue in issues]

    assert "TYP001" in codes  # Retorno no tipado
    assert "TYP002" in codes  # Argumento x no tipado
    assert "SEC001" in codes  # Llamada a eval()
    assert "IO001" in codes   # open() sin encoding
