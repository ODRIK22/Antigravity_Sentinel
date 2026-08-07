# Antigravity Sentinel 🛡️

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Type Checking](https://img.shields.io/badge/mypy-strict-brightgreen.svg)
![Tests Pass](https://img.shields.io/badge/tests-19%20passed-success.svg)
![SARIF Standard](https://img.shields.io/badge/SARIF-v2.1.0-purple.svg)
![SCA Analysis](https://img.shields.io/badge/SCA-Dependencies-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Architecture](https://img.shields.io/badge/architecture-Zero%20Trust%20%7C%20100%25%20Offline-orange.svg)

**Antigravity Sentinel** es una herramienta avanzada de análisis estático de código (SAST), **Análisis de Componentes de Software (SCA)**, **Taint Analysis**, exportación **SARIF v2.1.0**, monitorización en tiempo real (`watch`) y conector con IA Local (Ollama).

Diseñado y desarrollado utilizando la metodología **Spec-Kit** dentro de la plataforma Antigravity, Sentinel está preparado para integrarse en pipelines de integración continua (GitHub Security, CodeQL, GitLab CI) garantizando privacidad 100% offline y arquitectura Zero Trust.

---

## 🚀 Características Principales

- **Análisis de Componentes de Software (SCA):** Audita manifiestos de dependencias (`requirements.txt` y `package.json`) buscando versiones obsoletas o vulnerabilidades conocidas (`SCA001`, `SCA002`).
- **Soporte para Exclusiones Personalizadas (`.sentinelignore`):** Lee patrones tipo `.gitignore` desde un archivo local `.sentinelignore` para omitir rutas específicas durante las inspecciones.
- **Modo Watch en Tiempo Real (`sentinel watch`):** Monitor de archivos en segundo plano que detecta cambios sintácticos y ejecuta escaneos incrementales automáticos al guardar.
- **Exportación en Estándar SARIF v2.1.0 (`--format sarif`):** Genera reportes en formato OASIS SARIF v2.1.0 integrables con GitHub Code Scanning o GitLab.
- **Modo Interactivo de Aplicación de Parches (`--apply-patch`):** Permite revisar visualmente el diff en consola y decidir interactivamente si se aplican los cambios al archivo fuente, creando de forma automática un respaldo `.bak`.
- **Prompting Enriquecido con IA Local (Ollama):** Construye snippets de código circundantes (+/- 5 líneas) alrededor de cada falla para enviar a Ollama (`--explain-local`), obteniendo explicaciones y refactorizaciones precisas 100% offline.
- **Taint Analysis Ligero (Rastreo Fuente a Sink):** Detecta variables no sanitizadas que fluyen desde fuentes de entrada de usuario (`req.body`, `sys.argv`, etc.) hasta funciones críticas (`eval`, `exec`, `subprocess`) (`TAINT001`).
- **Verificación Completa:** Suite de 19 pruebas unitarias con `pytest` y tipado 100% verificado con `mypy` en modo estricto.

---

## 🛠️ Estructura del Proyecto

```
Antigravity_Sentinel/
├── .specify/                   # Configuración y memoria del flujo Spec-Kit
├── sentinel/                   # Paquete principal
│   ├── __init__.py
│   ├── cli.py                  # Interfaz CLI (scan, sca, watch, patch)
│   ├── config.py               # Constantes globales
│   └── core/
│       ├── analyzer.py         # Motor híbrido AST (Taint Analysis) + Regex
│       ├── sanitizer.py        # Validación y sanitización de rutas/entradas
│       ├── reporter.py         # Formateador ANSI, JSON y SARIF v2.1.0
│       ├── patcher.py          # Generador de Artifacts e interactivo (--apply-patch)
│       ├── ollama.py           # Conector con IA Local (Ollama)
│       ├── ignore.py           # Gestor de patrones .sentinelignore
│       ├── sca.py              # Análisis de dependencias (requirements.txt / package.json)
│       └── watcher.py          # Monitor de archivos en tiempo real
├── tests/                      # Suite de 19 pruebas automáticas (pytest)
│   ├── test_analyzer.py
│   ├── test_cli.py
│   ├── test_ignore.py
│   ├── test_ollama.py
│   ├── test_patcher.py
│   ├── test_reporter.py
│   ├── test_sanitizer.py
│   ├── test_sca.py
│   └── test_watcher.py
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

# Exportación en formato SARIF v2.1.0
python -m sentinel.cli scan --path ./sentinel --format sarif > results.sarif
```

### 2. Análisis de Dependencias SCA (`sca`)

```bash
python -m sentinel.cli sca --path .
```

### 3. Modo Watch en Tiempo Real (`watch`)

```bash
python -m sentinel.cli watch --path ./sentinel
```

### 4. Generación y Aplicación Interactiva de Parches (`patch`)

```bash
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
