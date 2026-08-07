"""
Configuración global y constantes de seguridad para Antigravity Sentinel.
"""

from typing import Final

# Nombre de la aplicación y versión
APP_NAME: Final[str] = "Antigravity Sentinel"
VERSION: Final[str] = "0.2.0"

# Extensiones de archivos de código soportadas para análisis
SUPPORTED_EXTENSIONS: Final[set[str]] = {
    ".py",
    ".js",
    ".ts",
    ".php",
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

# Codificación por defecto
DEFAULT_ENCODING: Final[str] = "utf-8"
