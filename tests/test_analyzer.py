"""
Pruebas unitarias para el motor de análisis estático multilenguaje (AST + Regex + HTML SRI + NoSQL Injection).
"""

from pathlib import Path
from sentinel.core.analyzer import analyze_file


def test_analyze_python_file(tmp_path: Path) -> None:
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
    assert "SEC003" in codes  # Llamada a eval()
    assert "IO001" in codes   # open() sin encoding


def test_analyze_javascript_and_typescript_files(tmp_path: Path) -> None:
    js_code = """function renderData(input) {
    document.getElementById("output").innerHTML = input;
    eval("console.log(input)");
}
"""
    js_file = tmp_path / "app.js"
    js_file.write_text(js_code, encoding="utf-8")

    issues = analyze_file(js_file)
    codes = [issue.code for issue in issues]

    assert "SEC003" in codes  # innerHTML y eval


def test_analyze_env_and_credentials(tmp_path: Path) -> None:
    env_content = """AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GITHUB_TOKEN=ghp_123456789012345678901234567890123456
DATABASE_URL=postgres://admin:supersecret123@localhost:5432/mydb
"""
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")

    issues = analyze_file(env_file)
    codes = [issue.code for issue in issues]

    assert "SEC002" in codes  # AWS key / GitHub token
    assert "SEC004" in codes  # Database URL con credenciales


def test_analyze_html_sri_missing(tmp_path: Path) -> None:
    html_code = """<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
</body>
</html>
"""
    html_file = tmp_path / "index.html"
    html_file.write_text(html_code, encoding="utf-8")

    issues = analyze_file(html_file)
    codes = [issue.code for issue in issues]

    assert "SEC005" in codes  # Falta SRI en CDN externo


def test_analyze_nosql_injection(tmp_path: Path) -> None:
    js_nosql_code = """const user = db.users.find({
    $where: "this.username == '" + userInput + "'"
});
"""
    nosql_file = tmp_path / "query.js"
    nosql_file.write_text(js_nosql_code, encoding="utf-8")

    issues = analyze_file(nosql_file)
    codes = [issue.code for issue in issues]

    assert "SEC006" in codes  # NoSQL injection con operador $where
