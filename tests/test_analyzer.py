"""
Pruebas unitarias para el motor de análisis estático (Taint Analysis, AST, Regex e ignorado de comentarios).
"""

from pathlib import Path
from sentinel.core.analyzer import analyze_file


def test_analyze_python_taint_analysis(tmp_path: Path) -> None:
    taint_code = """def procesar_entrada(user_input: str) -> None:
    eval(user_input)
"""
    taint_file = tmp_path / "taint.py"
    taint_file.write_text(taint_code, encoding="utf-8")

    issues = analyze_file(taint_file)
    codes = [issue.code for issue in issues]

    assert "TAINT001" in codes  # Variable user_input fluye hacia eval()


def test_analyze_comment_stripping_prevents_false_positives(tmp_path: Path) -> None:
    commented_code = """# AKIAIOSFODNN7EXAMPLE - Este es un comentario
// eval("test"); - Comentario JS
/* ghp_123456789012345678901234567890123456 */
"""
    commented_file = tmp_path / "comments.py"
    commented_file.write_text(commented_code, encoding="utf-8")

    issues = analyze_file(commented_file)
    # Ninguna coincidencia regex debe ser disparada por líneas de comentarios puros
    assert len(issues) == 0


def test_analyze_env_and_credentials(tmp_path: Path) -> None:
    env_content = """AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_123456789012345678901234567890123456
"""
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")

    issues = analyze_file(env_file)
    codes = [issue.code for issue in issues]

    assert "SEC002" in codes  # AWS key / GitHub token
