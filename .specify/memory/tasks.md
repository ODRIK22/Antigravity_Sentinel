# Tareas de Implementación Técnica: Antigravity Sentinel (`/speckit.tasks`)

**Proyecto**: Antigravity Sentinel  
**Estado**: Listo para Ejecución  

---

## Lista de Tareas Secuencial

### Fase 1: Configuración de Infraestructura y Proyecto Base
- [ ] **TAREA-001**: Crear archivo `pyproject.toml` con configuración de depuración, metadatos del paquete, `mypy` (modo estricto) y `pytest`.
- [ ] **TAREA-002**: Crear estructura de directorios del paquete Python `sentinel/` y `tests/` con sus respectivos archivos `__init__.py`.
- [ ] **TAREA-003**: Implementar módulo de configuración global y constantes en `sentinel/config.py`.

### Fase 2: Desarrollo del Core (Núcleo Funcional)
- [ ] **TAREA-004**: Crear `sentinel/core/sanitizer.py` con funciones de validación de rutas y sanitización de entradas para garantizar Zero Trust.
- [ ] **TAREA-005**: Crear `sentinel/core/analyzer.py` utilizando `ast` de la librería estándar para detectar falta de tipos, funciones inseguras y excepciones genéricas.
- [ ] **TAREA-006**: Crear `sentinel/core/reporter.py` para formatear y emitir reportes en consola (legible para humanos) y JSON estructurado.
- [ ] **TAREA-007**: Crear `sentinel/core/patcher.py` para generar Artifacts interactivas en formato Markdown con bloques `diff` sin tocar archivos fuente.

### Fase 3: Interfaz CLI y Puntos de Entrada
- [ ] **TAREA-008**: Implementar `sentinel/cli.py` con subcomandos `scan`, `audit` y `patch` usando `argparse`.

### Fase 4: Pruebas Unitarias y Verificación de Calidad (TDD / mypy)
- [ ] **TAREA-009**: Escribir suite de pruebas unitarias en `tests/test_sanitizer.py`.
- [ ] **TAREA-010**: Escribir suite de pruebas unitarias en `tests/test_analyzer.py`.
- [ ] **TAREA-011**: Escribir suite de pruebas unitarias en `tests/test_patcher.py`.
- [ ] **TAREA-012**: Escribir suite de pruebas unitarias en `tests/test_cli.py`.
- [ ] **TAREA-013**: Ejecutar `mypy --strict sentinel` y la suite `pytest` para verificar 100% de pasaje sin errores.
