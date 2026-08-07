"""
Módulo de monitorización en tiempo real del sistema de archivos (File System Watcher) para Antigravity Sentinel.
"""

import time
from pathlib import Path
from typing import Callable, Sequence
from sentinel.config import SUPPORTED_EXTENSIONS
from sentinel.core.ignore import SentinelIgnoreManager
from sentinel.core.analyzer import analyze_file, IssueItem
from sentinel.core.reporter import format_console_report


class FileSystemWatcher:
    """Escucha cambios en archivos de código en tiempo real realizando escaneos incrementales."""

    def __init__(self, target_path: Path) -> None:
        self.target_path = target_path.resolve()
        self.ignore_manager = SentinelIgnoreManager(
            self.target_path if self.target_path.is_dir() else self.target_path.parent
        )
        self.file_mtimes: dict[Path, float] = {}

    def _scan_and_get_mtimes(self) -> dict[Path, float]:
        """Recorre la ruta objetivo y registra los sellos mtime de archivos soportados."""
        current_mtimes: dict[Path, float] = {}
        if self.target_path.is_file():
            if not self.ignore_manager.is_ignored(self.target_path):
                current_mtimes[self.target_path] = self.target_path.stat().st_mtime
        elif self.target_path.is_dir():
            for item in self.target_path.rglob("*"):
                if self.ignore_manager.is_ignored(item):
                    continue
                if item.is_file() and (item.suffix in SUPPORTED_EXTENSIONS or item.name == ".env"):
                    try:
                        current_mtimes[item] = item.stat().st_mtime
                    except Exception:
                        pass
        return current_mtimes

    def start_watch(
        self,
        interval: float = 1.0,
        run_once: bool = False,
        callback: Callable[[Path, Sequence[IssueItem]], None] | None = None
    ) -> None:
        """
        Inicia el bucle de monitorización en tiempo real.

        Args:
            interval: Tiempo de espera en segundos entre ciclos de inspección.
            run_once: Si es True, realiza un ciclo único y termina (para pruebas unitarias).
            callback: Función opcional invocada al detectar un archivo modificado.
        """
        if not self.file_mtimes:
            self.file_mtimes = self._scan_and_get_mtimes()

        print(f"👀 Modo Watch activo en: {self.target_path}")
        print("Presiona Ctrl+C para detener la monitorización...\n")

        while True:
            try:
                latest_mtimes = self._scan_and_get_mtimes()

                for file_path, mtime in latest_mtimes.items():
                    prev_mtime = self.file_mtimes.get(file_path)
                    if prev_mtime is None or mtime > prev_mtime:
                        print(f"⚡ Cambio detectado en: {file_path.name}")
                        issues = analyze_file(file_path)

                        if callback:
                            callback(file_path, issues)
                        else:
                            print(format_console_report(issues))

                self.file_mtimes = latest_mtimes

                if run_once:
                    break

                time.sleep(interval)
            except KeyboardInterrupt:
                print("\n🛑 Modo Watch detenido por el usuario.")
                break
