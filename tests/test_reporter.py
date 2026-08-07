"""
Pruebas unitarias para el módulo de reportes (Consola ANSI, JSON y SARIF v2.1.0).
"""

import json
from sentinel.core.analyzer import IssueItem
from sentinel.core.reporter import format_console_report, format_json_report, format_sarif_report


def test_format_console_report_includes_ansi_colors() -> None:
    issues = [
        IssueItem(
            file_path="src/index.py",
            line_number=10,
            severity="ALTA",
            code="SEC001",
            message="Uso inseguro detectado",
        ),
        IssueItem(
            file_path="src/index.html",
            line_number=5,
            severity="MEDIA",
            code="SEC005",
            message="Recurso CDN sin atributo integrity",
        ),
        IssueItem(
            file_path="src/utils.py",
            line_number=2,
            severity="BAJA",
            code="IO001",
            message="Falta parámetro encoding",
        ),
    ]

    report = format_console_report(issues)
    assert "\033[91m" in report  # Rojo para ALTA
    assert "\033[93m" in report  # Amarillo para MEDIA
    assert "\033[92m" in report  # Verde para BAJA


def test_format_json_report_is_clean_without_ansi() -> None:
    issues = [
        IssueItem(
            file_path="src/index.py",
            line_number=10,
            severity="ALTA",
            code="SEC001",
            message="Uso inseguro detectado",
        )
    ]

    raw_json = format_json_report(issues)
    data = json.loads(raw_json)

    assert data["resumen"]["total_incidencias"] == 1
    assert data["incidencias"][0]["gravedad"] == "ALTA"
    assert "\033" not in raw_json  # JSON sin códigos ANSI


def test_format_sarif_report_valid_schema() -> None:
    issues = [
        IssueItem(
            file_path="src/app.py",
            line_number=15,
            severity="ALTA",
            code="SEC001",
            message="Evaluación dinámica peligrosa",
        )
    ]

    sarif_str = format_sarif_report(issues)
    sarif_data = json.loads(sarif_str)

    assert sarif_data["version"] == "2.1.0"
    assert "runs" in sarif_data
    assert len(sarif_data["runs"]) == 1
    driver = sarif_data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Antigravity Sentinel"
    results = sarif_data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "SEC001"
    assert results[0]["level"] == "error"
