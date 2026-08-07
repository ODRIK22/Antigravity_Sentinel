"""
Pruebas unitarias para la validación y sanitización de rutas.
"""

import pytest
from pathlib import Path
from sentinel.core.sanitizer import sanitize_path, sanitize_text_input, SentinelSanitizerError


def test_sanitize_path_valid(tmp_path: Path) -> None:
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')", encoding="utf-8")
    
    result = sanitize_path(str(test_file), base_directory=str(tmp_path))
    assert result == test_file.resolve()


def test_sanitize_path_traversal_prevention(tmp_path: Path) -> None:
    outside_file = tmp_path.parent / "outside.py"
    
    with pytest.raises(SentinelSanitizerError):
        sanitize_path(str(outside_file), base_directory=str(tmp_path))


def test_sanitize_text_input() -> None:
    dirty = "texto\x00 con nulos\x00  "
    clean = sanitize_text_input(dirty)
    assert clean == "texto con nulos"
