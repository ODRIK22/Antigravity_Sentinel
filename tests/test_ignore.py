"""
Pruebas unitarias para el gestor de exclusiones .sentinelignore.
"""

from pathlib import Path
from sentinel.core.ignore import SentinelIgnoreManager


def test_sentinelignore_custom_patterns(tmp_path: Path) -> None:
    ignore_file = tmp_path / ".sentinelignore"
    ignore_file.write_text("custom_folder/*\n*.log\nsecret.txt", encoding="utf-8")

    mgr = SentinelIgnoreManager(tmp_path)

    test_file_1 = tmp_path / "custom_folder" / "app.py"
    test_file_2 = tmp_path / "app.log"
    test_file_3 = tmp_path / "secret.txt"
    normal_file = tmp_path / "main.py"

    assert mgr.is_ignored(test_file_1) is True
    assert mgr.is_ignored(test_file_2) is True
    assert mgr.is_ignored(test_file_3) is True
    assert mgr.is_ignored(normal_file) is False
