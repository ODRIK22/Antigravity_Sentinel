# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-12%20passed-success.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust%20%7C%20100%25%20Offline-orange.svg)

**Antigravity Sentinel** es una herramienta avanzada de análisis estático de código (SAST), auditoría de calidad de software, **Taint Analysis** y propuesta automatizada de parches con plantillas de remediación semántica bajo arquitectura **Zero Trust** e integración con IA Local (Ollama).

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel garantiza que el código mantenga estándares estrictos de tipado, sanitización de entradas (OWASP), análisis de flujo sintáctico y privacidad 100% offline.

---

## 🚀 Características Principales

- **Taint Analysis Ligero (Rastreo Fuente a Sink):** Detecta variables no sanitizadas que fluyen desde fuentes de entrada de usuario (`req.body`, `req.query`, `sys.argv`, etc.) hasta funciones críticas (`eval`, `exec`, `subprocess`, `os.system`) (`TAINT001`).
- **Analizador Estático Basado en AST y Regex Híbrido:**
  - Omisión inteligente de líneas de comentarios para prevenir falsos positivos.
  - Identifica funciones sin anotación de tipos (`TYP001`, `TYP002`).
  - Detecta credenciales, tokens de API (AWS, GitHub, JWT) y claves privadas en texto plano (`SEC002`).
  - Detecta funciones de ejecución peligrosa (`eval`, `exec`, `innerHTML`, `shell_exec`) (`SEC003`).
  - Detecta cadenas de base de datos no encriptadas (`SEC004`).
  - Identifica enlaces CDN en HTML sin el atributo Subresource Integrity (`SEC005`).
  - Identifica patrones de Inyección NoSQL en MongoDB (`SEC006`).
- **Plantillas de Remediación Semántica (Zero Trust):** Sentinel **nunca modifica los archivos fuente originales**. Las sugerencias de corrección se generan como Artifacts en formato Markdown con diffs contextuales y sugerencias de remediación adaptativas (ej. `ast.literal_eval`, `textContent`, `integrity`, etc.).
- **Conector de IA Local Opcional (Ollama):** Permite consultar una instancia local de Ollama (`localhost:11434`, `deepseek-coder` / `codellama`) de forma 100% offline mediante la bandera `--explain-local`.
- **Verificación Completa:** Suite de pruebas con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

---

## 🛠️ Estructura del Proyecto

```
Antigravity_Sentinel/
├── .specify/                   # Configuración y memoria del flujo Spec-Kit
├── sentinel/                   # Paquete principal
│   ├── __init__.py
│   ├── cli.py                  # Interfaz CLI con subcomandos y --explain-local
│   ├── config.py               # Constantes globales y de formato ANSI
│   └── core/
│       ├── analyzer.py         # Motor híbrido AST (Taint Analysis) + Regex
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador de consola ANSI y JSON
│       ├── patcher.py          # Generador de Artifacts con remediación semántica
│       └── ollama.py           # Conector opcional para IA Local (Ollama)
├── tests/                      # Suite de pruebas automáticas (pytest)
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_ollama.py
│   ├── test_patcher.py
│   ├── test_reporter.py
│   └── test_sanitizer.py
├── pyproject.toml              # Configuración del paquete, mypy y pytest
├── LICENSE                     # Licencia MIT
└── README.md                   # Documentación principal
```

---

## ⚙️ Instalación y Configuración

```bash
# Clonar e instalar en modo ejecutable
git clone https://github.com/ODRIK22/Antigravity_Sentinel.git
cd Antigravity_Sentinel
pip install -e .
```

---

## 💻 Guía de Uso

### 1. Escaneo Estático y Taint Analysis (`scan`)

```bash
# Salida en consola con formato de colores ANSI
python -m sentinel.cli scan --path ./sentinel

# Salida estructurada JSON
python -m sentinel.cli scan --path ./sentinel --format json

# Escaneo con explicación contextual de IA Local (requiere Ollama ejecutándose en localhost:11434)
python -m sentinel.cli scan --path ./sentinel --explain-local
```

### 2. Generación de Parches Semánticos (`patch`)

```bash
python -m sentinel.cli patch --file ./sentinel/cli.py
```

---

## 🧪 Pruebas y Control de Calidad

```bash
# Pruebas unitarias
python -m pytest

# Verificación de tipos estricta
python -m mypy sentinel
```

---

## 📄 Licencia

Este proyecto está distribuido bajo la Licencia **MIT**. Consulta el archivo [LICENSE](file:///c:/Users/aidro/OneDrive/Documents/Antigravity%20Sentinel/LICENSE) para más información.
