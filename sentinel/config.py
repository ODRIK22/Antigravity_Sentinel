"""
Configuración global y constantes de seguridad para Antigravity Sentinel.
"""

from typing import Final

# Nombre de la aplicación y versión
APP_NAME: Final[str] = "Antigravity Sentinel"
VERSION: Final[str] = "0.3.0"

# Extensiones de archivos de código soportadas para análisis
SUPPORTED_EXTENSIONS: Final[set[str]] = {
    ".py",
    ".js",
    ".ts",
    ".php",
    ".html",
    ".htm",
    ".json",
    ".env",
    ".yml",
    ".yaml",
}

# Carpetas ignoradas durante los escaneos recursivos
IGNORE_DIRS: Final[set[str]] = {
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    ".specify",
    ".mypy_cache",
    ".pytest_cache",
}

# Constantes de formato y colores ANSI para consola
COLOR_RED: Final[str] = "\033[91m"
COLOR_YELLOW: Final[str] = "\033[93m"
COLOR_GREEN: Final[str] = "\033[92m"
COLOR_BOLD: Final[str] = "\033[1m"
COLOR_RESET: Final[str] = "\033[0m"

# Codificación por defecto
DEFAULT_ENCODING: Final[str] = "utf-8"
