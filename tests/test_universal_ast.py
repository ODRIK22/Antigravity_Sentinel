"""
Pruebas unitarias para el motor AST Universal (PHP, Go, JS/TS, Python).
"""

from pathlib import Path
from sentinel.core.universal_ast import UniversalASTAnalyzer


def test_universal_ast_php(tmp_path: Path) -> None:
    php_file = tmp_path / "index.php"
    php_file.write_text("<?php\n$input = $_GET['user'];\nshell_exec($input);\n", encoding="utf-8")

    analyzer = UniversalASTAnalyzer(php_file)
    issues = analyzer.analyze()

    codes = [i.code for i in issues]
    assert "TAINT003" in codes


def test_universal_ast_go(tmp_path: Path) -> None:
    go_file = tmp_path / "main.go"
    go_file.write_text("package main\nfunc main() {\n  query := r.URL.Query()\n  exec.Command(query)\n}\n", encoding="utf-8")

    analyzer = UniversalASTAnalyzer(go_file)
    issues = analyzer.analyze()

    codes = [i.code for i in issues]
    assert "TAINT003" in codes
