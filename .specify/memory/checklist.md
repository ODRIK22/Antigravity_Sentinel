# Lista de Verificación de Calidad y Criterios de Aceptación (`/speckit.checklist`)

**Proyecto**: Antigravity Sentinel  
**Fase de Validación**: Fase C - Control de Calidad  

---

## 1. Cumplimiento Constitucional (Zero Trust & OWASP)
- [ ] Ninguna función del paquete `sentinel` modifica directamente código fuente analizado (Zero Trust).
- [ ] Todas las excepciones lanzadas por el núcleo capturan fallos sin revelar trazas internas no controladas (Fail-Safe Defaults).
- [ ] No existen claves de API, tokens ni credenciales hardcodeadas en el código base.
- [ ] Toda la documentación, comentarios, docstrings y mensajes de la consola están redactados en español.

## 2. Calidad de Código e Integridad Estrucutral
- [ ] `mypy --strict sentinel` se ejecuta sin ningún error o advertencia de tipado.
- [ ] La suite completa de `pytest` se ejecuta correctamente superando el 85% de cobertura de código.
- [ ] Los subcomandos `sentinel scan`, `sentinel audit` y `sentinel patch` funcionan de forma transparente y determinista.

## 3. Generación de Artifacts
- [ ] Las sugerencias de parches generadas por `sentinel patch` se guardan exclusivamente en formato Markdown con diffs legibles dentro del directorio correspondiente.
