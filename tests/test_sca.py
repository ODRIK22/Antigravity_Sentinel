"""
Pruebas unitarias para el análisis SCA de dependencias multi-ecosistema.
"""

from pathlib import Path
from sentinel.core.sca import analyze_dependencies, analyze_requirements_txt, analyze_package_json, analyze_composer_json, analyze_go_mod


def test_sca_requirements_txt_vulnerable(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requests==2.25.1\nflask\npytest==7.0.0\n", encoding="utf-8")

    issues = analyze_requirements_txt(req_file)
    codes = [i.code for i in issues]

    assert "SCA001" in codes  # requests < 2.31.0
    assert "SCA002" in codes  # flask sin pinning de versión


def test_sca_package_json_vulnerable(tmp_path: Path) -> None:
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text("""{
        "dependencies": {
            "express": "4.18.1",
            "lodash": "4.17.15"
        }
    }""", encoding="utf-8")

    issues = analyze_package_json(pkg_file)
    codes = [i.code for i in issues]

    assert "SCA001" in codes  # express / lodash vulnerables


def test_sca_composer_json_vulnerable(tmp_path: Path) -> None:
    composer_file = tmp_path / "composer.json"
    composer_file.write_text("""{
        "require": {
            "laravel/framework": "9.2.0"
        }
    }""", encoding="utf-8")

    issues = analyze_composer_json(composer_file)
    codes = [i.code for i in issues]

    assert "SCA001" in codes  # laravel < 10.10.0


def test_sca_go_mod_vulnerable(tmp_path: Path) -> None:
    go_file = tmp_path / "go.mod"
    go_file.write_text("module myapp\n\ngo 1.20\n\nrequire github.com/gin-gonic/gin v1.8.0\n", encoding="utf-8")

    issues = analyze_go_mod(go_file)
    codes = [i.code for i in issues]

    assert "SCA001" in codes  # gin-gonic < v1.9.0
