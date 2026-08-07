"""
Pruebas unitarias para el conector opcional de IA local Ollama.
"""

from pathlib import Path
from sentinel.core.analyzer import IssueItem
from sentinel.core.ollama import OllamaClient


def test_ollama_client_empty_issues() -> None:
    client = OllamaClient()
    result = client.explain_issues("test.py", [])

    assert result.success is True
    assert "No se encontraron incidencias" in result.explanation


def test_ollama_client_offline_fallback() -> None:
    # Probar conexión a host inalcanzable para validar el manejo de fallos sin crash
    client = OllamaClient(host="http://localhost:59999")
    issues = [
        IssueItem(
            file_path="test.py",
            line_number=1,
            severity="ALTA",
            code="SEC001",
            message="Error test",
        )
    ]
    result = client.explain_issues("test.py", issues)

    assert result.success is False
    assert "No se pudo conectar a la IA local Ollama" in result.explanation


def test_ollama_client_extracts_surrounding_context(tmp_path: Path) -> None:
    code_file = tmp_path / "sample.py"
    code_file.write_text("line1\nline2\nline3\nline4\nline5", encoding="utf-8")

    client = OllamaClient()
    snippet = client._extract_surrounding_context(str(code_file), line_number=3, context_lines=1)

    assert "line2" in snippet
    assert "->    3 | line3" in snippet
    assert "line4" in snippet
