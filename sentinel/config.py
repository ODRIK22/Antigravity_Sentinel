"""
Configuración global y constantes de seguridad para Antigravity Sentinel.
"""

from pathlib import Path
from typing import Final

# Nombre de la aplicación
APP_NAME: Final[str] = "Antigravity Sentinel"
VERSION: Final[str] = "0.1.0"

# Archivos de código soportados para análisis estático
SUPPORTED_EXTENSIONS: Final[set[str]] = {".py", ".js", ".ts"}

# Codificación por defecto
DEFAULT_ENCODING: Final[str] = "utf-8"
