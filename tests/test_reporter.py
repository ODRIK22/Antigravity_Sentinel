"""
Pruebas unitarias para el módulo de reportes (Consola ANSI y JSON).
"""

import json
from sentinel.core.analyzer import IssueItem
from sentinel.core.reporter import format_console_report, format_json_report


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
