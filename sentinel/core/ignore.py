"""
Módulo de filtrado y control de exclusiones basado en .sentinelignore (Zero Trust).
"""

import fnmatch
from pathlib import Path
from sentinel.config import IGNORE_DIRS


class SentinelIgnoreManager:
    """Maneja el filtrado de archivos y directorios basándose en IGNORE_DIRS y patrones .sentinelignore."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir.resolve()
        self.patterns: list[str] = list(IGNORE_DIRS)
        self._load_sentinelignore()

    def _load_sentinelignore(self) -> None:
        """Carga patrones de exclusión desde un archivo .sentinelignore si existe."""
        ignore_file = self.base_dir / ".sentinelignore"
        if ignore_file.exists() and ignore_file.is_file():
            try:
                lines = ignore_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.patterns.append(line)
            except Exception:
                pass

    def is_ignored(self, target_path: Path) -> bool:
        """
        Determina si una ruta dada debe ser ignorada según IGNORE_DIRS o .sentinelignore.

        Args:
            target_path: Ruta a evaluar.

        Returns:
            True si la ruta debe omitirse, False en caso contrario.
        """
        resolved = target_path.resolve()

        # 1. Comprobar si algún segmento de la ruta coincide con IGNORE_DIRS
        for part in resolved.parts:
            if part in IGNORE_DIRS:
                return True

        # 2. Comprobar ruta relativa contra patrones fnmatch de .sentinelignore
        try:
            rel_path = resolved.relative_to(self.base_dir)
            rel_str = str(rel_path).replace("\\", "/")
            name_str = resolved.name

            for pattern in self.patterns:
                pattern_clean = pattern.replace("\\", "/").rstrip("/")
                if fnmatch.fnmatch(rel_str, pattern_clean) or fnmatch.fnmatch(name_str, pattern_clean):
                    return True
                if fnmatch.fnmatch(rel_str, f"*/{pattern_clean}") or fnmatch.fnmatch(rel_str, f"{pattern_clean}/*"):
                    return True
        except ValueError:
            pass

        return False
