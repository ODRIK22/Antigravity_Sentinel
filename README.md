# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-15%20passed-success.svg)
![SARIF Standard](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust%20%7C%20100%25%20Offline-orange.svg)

**Antigravity Sentinel** es una herramienta avanzada de análisis estático de código (SAST), auditoría de calidad de software, **Taint Analysis**, exportación estándar **SARIF v2.1.0** para CI/CD, parcheado interactivo y conector con IA Local (Ollama).

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel está preparado para integrarse en pipelines de integración continua (GitHub Security, CodeQL, GitLab CI) garantizando privacidad 100% offline y arquitectura Zero Trust.

---

## 🚀 Características Principales

- **Exportación en Estándar SARIF v2.1.0:** Genera reportes en formato OASIS SARIF (`--format sarif`) integrables de forma nativa con GitHub Code Scanning, GitLab Security Dashboard o CodeQL.
- **Modo Interactivo de Aplicación de Parches (`--apply-patch`):** Permite revisar visualmente el diff en consola y decidir interactivamente si se aplican los cambios al archivo fuente, creando automáticamente una copia de respaldo `.bak`.
- **Prompting Enriquecido con IA Local (Ollama):** Construye snippets de código circundantes (+/- 5 líneas) alrededor de cada falla para enviar a Ollama (`--explain-local`), obteniendo explicaciones y refactorizaciones precisas 100% offline.
- **Taint Analysis Ligero (Rastreo Fuente a Sink):** Detecta variables no sanitizadas que fluyen desde fuentes de entrada de usuario (`req.body`, `sys.argv`, etc.) hasta funciones críticas (`eval`, `exec`, `subprocess`) (`TAINT001`).
- **Analizador Estático Basado en AST y Regex Híbrido:**
  - Omisión inteligente de comentarios.
  - Tipado (`TYP001`, `TYP002`), credenciales expuestas (`SEC002`), funciones peligrosas (`SEC003`), URIs de BD (`SEC004`), SRI en HTML (`SEC005`), e Inyección NoSQL (`SEC006`).
- **Verificación Completa:** Suite de 15 pruebas unitarias con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

---

## 🛠️ Estructura del Proyecto

```
Antigravity_Sentinel/
├── .specify/                   # Configuración y memoria del flujo Spec-Kit
├── sentinel/                   # Paquete principal
│   ├── __init__.py
│   ├── cli.py                  # Interfaz CLI con subcomandos scan y patch
│   ├── config.py               # Constantes globales
│   └── core/
│       ├── analyzer.py         # Motor híbrido AST (Taint Analysis) + Regex
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador de consola ANSI, JSON y SARIF v2.1.0
│       ├── patcher.py          # Generador de Artifacts y aplicación interactiva (--apply-patch)
│       └── ollama.py           # Conector con IA Local (Ollama) y contexto enriquecido
├── tests/                      # Suite de 15 pruebas automáticas (pytest)
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

### 1. Escaneo Estático y Exportación SARIF (`scan`)

```bash
# Reporte en consola con colores ANSI
python -m sentinel.cli scan --path ./sentinel

# Exportación en formato SARIF v2.1.0 para GitHub Actions / CI/CD
python -m sentinel.cli scan --path ./sentinel --format sarif > results.sarif

# Escaneo con explicación enriquecida de IA Local (Ollama)
python -m sentinel.cli scan --path ./sentinel --explain-local
```

### 2. Generación y Aplicación Interactiva de Parches (`patch`)

```bash
# Generar propuesta de parche Zero Trust (Artifact Markdown)
python -m sentinel.cli patch --file ./sentinel/cli.py

# Revisar y aplicar cambios interactivamente en el archivo fuente (crea backup .bak)
python -m sentinel.cli patch --file ./sentinel/cli.py --apply-patch
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
