# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-6%20passed-success.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust-orange.svg)

**Antigravity Sentinel** es una herramienta de análisis estático de código (SAST), auditoría de calidad de software y propuesta automatizada de parches bajo arquitectura **Zero Trust**.

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel garantiza que el código mantenga estándares estrictos de tipado, sanitización de entradas (OWASP) e inmutabilidad de archivos fuente durante las revisiones.

---

## 🚀 Características Principales

- **Analizador Estático Basado en AST (`ast`):** Inspecciona el Árbol Sintáctico Abstracto de Python sin ejecutar código no confiable.
- **Detección de Malas Prácticas y Riesgos de Seguridad:**
  - Identifica funciones sin anotación de tipos en firma o retornos (`TYP001`, `TYP002`).
  - Detecta llamadas inseguras a `eval()` o `exec()` (`SEC001`).
  - Advierte sobre la apertura de archivos sin parámetro explícito `encoding` (`IO001`).
- **Arquitectura Zero Trust:** Sentinel **nunca modifica directamente los archivos fuente originales**. Las sugerencias de corrección se generan como Artifacts en formato Markdown con diffs interactivos para revisión previa.
- **Sanitización Estricta de Rutas:** Capa de seguridad que previene vulnerabilidades de Path Traversal.
- **Verificación Completa:** Cobertura de pruebas unitarias con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

---

## 🛠️ Estructura del Proyecto

```
Antigravity_Sentinel/
├── .specify/                   # Configuración y memoria del flujo Spec-Kit
│   ├── memory/
│   │   ├── constitution.md     # Constitución y reglas de arquitectura
│   │   ├── spec.md             # Especificación funcional
│   │   ├── analysis.md         # Informe de consistencia
│   │   ├── plan.md             # Plan técnico de arquitectura
│   │   ├── tasks.md            # Desglose de tareas
│   │   └── checklist.md        # Lista de verificación de calidad
│   └── artifacts/              # Repositorio de propuesta de parches (Diffs)
├── sentinel/                   # Paquete principal
│   ├── __init__.py
│   ├── cli.py                  # Interfaz CLI (subcomandos scan y patch)
│   ├── config.py               # Constantes globales
│   └── core/
│       ├── analyzer.py         # Motor de análisis estático AST
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador de consola y JSON
│       └── patcher.py          # Generador de Artifacts de parches
├── tests/                      # Suite de pruebas automáticas (pytest)
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_patcher.py
│   └── test_sanitizer.py
├── pyproject.toml              # Configuración de paquete, mypy y pytest
├── .gitignore                  # Exclusiones optimizadas para Python
├── LICENSE                     # Licencia MIT
└── README.md                   # Documentación principal
```

---

## ⚙️ Instalación y Configuración

### Requisitos Previos

- **Python 3.11** o superior.

### Pasos de Instalación

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/ODRIK22/Antigravity_Sentinel.git
   cd Antigravity_Sentinel
   ```

2. **Crear y activar un entorno virtual (opcional):**
   ```bash
   python -m venv venv
   # En Windows:
   venv\Scripts\activate
   # En Linux/macOS:
   source venv/bin/activate
   ```

3. **Instalar dependencias y el paquete en modo ejecutable:**
   ```bash
   pip install -e .
   ```

---

## 💻 Guía de Uso

### 1. Escaneo Estático de Código (`scan`)

Inspecciona un archivo o directorio completo e imprime las incidencias de calidad detectadas:

```bash
# Salida estándar legible en consola
python -m sentinel.cli scan --path ./sentinel

# Formato JSON estructurado
python -m sentinel.cli scan --path ./sentinel --format json
```

### 2. Generación de Parches Zero Trust (`patch`)

Genera una propuesta de parche en formato Artifact Markdown dentro de `.specify/artifacts/` sin sobreescribir el archivo fuente:

```bash
python -m sentinel.cli patch --file ./sentinel/cli.py
```

---

## 🧪 Pruebas y Control de Calidad

### Ejecutar Pruebas Unitarias (`pytest`)

```bash
python -m pytest
```

### Verificación de Tipos Estricta (`mypy`)

```bash
python -m mypy sentinel
```

---

## 📄 Licencia

Este proyecto está distribuido bajo la Licencia **MIT**. Consulta el archivo [LICENSE](file:///c:/Users/aidro/OneDrive/Documents/Antigravity%20Sentinel/LICENSE) para más información.
