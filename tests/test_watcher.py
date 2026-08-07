"""
Pruebas unitarias para el monitor de archivos en tiempo real (FileSystemWatcher).
"""

import time
from pathlib import Path
from sentinel.core.watcher import FileSystemWatcher


def test_file_system_watcher_detects_changes(tmp_path: Path) -> None:
    test_file = tmp_path / "app.py"
    test_file.write_text("print('v1')", encoding="utf-8")

    watcher = FileSystemWatcher(tmp_path)

    # Iniciar la medición mtime inicial
    initial_mtimes = watcher._scan_and_get_mtimes()
    watcher.file_mtimes = initial_mtimes

    changes_detected = []

    def on_change(file_path: Path, issues: list) -> None:
        changes_detected.append(file_path)

    # Pequeña pausa para asegurar diferencia de mtime en el sistema de archivos
    time.sleep(0.05)

    # Simular una modificación de mtime
    test_file.write_text("print('v2')", encoding="utf-8")

    # Ejecutar un ciclo del watcher
    watcher.start_watch(run_once=True, callback=on_change)

    assert len(changes_detected) == 1
    assert changes_detected[0].name == "app.py"
