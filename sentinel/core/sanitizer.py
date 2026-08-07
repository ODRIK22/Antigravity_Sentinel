"""
Módulo de sanitización de datos y validación de rutas para garantizar la arquitectura Zero Trust.
"""

from pathlib import Path
import os


class SentinelSanitizerError(Exception):
    """Excepción lanzada cuando falla una validación de seguridad o sanitización."""
    pass


def sanitize_path(target_path: str, base_directory: str | None = None) -> Path:
    """
    Valida y sanitiza una ruta para asegurar que se encuentre dentro de los límites permitidos.

    Args:
        target_path: La ruta recibida como argumento o entrada.
        base_directory: Directorio base permitido (por defecto el directorio actual).

    Returns:
        Path objeto validado y resuelto.

    Raises:
        SentinelSanitizerError: Si la ruta intenta salir del directorio base (Path Traversal).
    """
    if base_directory is None:
        base_dir = Path.cwd().resolve()
    else:
        base_dir = Path(base_directory).resolve()

    resolved_target = Path(target_path).resolve()

    try:
        # Verifica si resolved_target está dentro de base_dir
        resolved_target.relative_to(base_dir)
    except ValueError:
        raise SentinelSanitizerError(
            f"Acceso denegado: La ruta '{target_path}' se encuentra fuera del directorio base permitido."
        )

    return resolved_target


def sanitize_text_input(input_text: str) -> str:
    """
    Sanitiza entradas de texto eliminando caracteres nulos o no imprimibles de riesgo.

    Args:
        input_text: Cadena de texto de entrada.

    Returns:
        Cadena sanitizada.
    """
    return input_text.replace("\x00", "").strip()
