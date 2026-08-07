# Antigravity Sentinel Constitution

## Core Principles

### I. Aseguramiento de Calidad y Tipado Estricto
Todo el código producido dentro del proyecto debe contar con tipado estricto, arquitectura limpia y separación clara de responsabilidades. Cada módulo o función debe tener un propósito único y estar totalmente libre de efectos secundarios no documentados.

### II. Arquitectura Zero Trust y Principio de Menor Privilegio
El sistema opera bajo una política estricta de cero confianza (Zero Trust):
- Ningún módulo o script debe modificar directamente archivos del sistema o dependencias sin aprobación explícita o proceso de verificación.
- Todas las entradas externas o de usuario deben pasar por una capa de sanitización y validación estricta de tipos e esquemas antes de ser procesadas.

### III. Buenas Prácticas de Desarrollo Seguro (OWASP)
El código debe cumplir rigurosamente con las recomendaciones de seguridad según los estándares OWASP:
- Manejo seguro de errores sin revelar información sensible o trazas internas al usuario final (Fail-Safe Defaults).
- Almacenamiento y paso seguro de credenciales mediante variables de entorno o gestores de secretos, nunca mediante hardcoding.
- Prevención de inyecciones (SQL, comandos, scripts) mediante parámetros parametrizados e inmutabilidad de consultas.

### IV. Documentación e Idioma
- Configuración, código, comentarios de cabecera, docstrings y reportes estructurados estrictamente en **español**.
- Preservación de comentarios existentes y documentación detallada de las funciones públicas e interfaces.

### V. Pruebas Unitarias y Test-Driven Development (TDD)
- Las funcionalidades críticas y validaciones deben contar con pruebas unitarias automáticas de cobertura alta.
- Red-Green-Refactor: Las pruebas deben escribir y fallar antes de implementar soluciones a fallos o nuevas características.

## Estándares de Arquitectura y Negocio

1. **Modularidad Estricta:** Componentes desacoplados con interfaces claras (APIs/Contratos).
2. **Resiliencia y Registro Observable:** Registro de eventos (logging) estructurado sin exponer datos confidenciales.
3. **Manejo Centralizado de Excepciones:** Fallos controlados que retornen respuestas estándar estructuradas.

## Gobernanza

Esta constitución es la norma suprema del proyecto *Antigravity Sentinel*. Todas las especificaciones (`/speckit.specify`), planes (`/speckit.plan`), tareas (`/speckit.tasks`) y código producido (`/speckit.implement`) deben alinearse con estos principios.

**Versión**: 1.0.0 | **Ratificado**: 2026-08-07 | **Última Modificación**: 2026-08-07
