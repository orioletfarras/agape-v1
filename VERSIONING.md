# Versionado Automático - Agape V1

## Sistema de Versionado Semántico

Este proyecto usa **Semantic Versioning (SemVer)** gestionado automáticamente por Claude.

### Versión Actual: v1.0.0

## Reglas de Versionado

Claude decidirá automáticamente el tipo de versión basándose en los cambios:

### PATCH (v1.0.X)
**Incremento**: Bug fixes, correcciones menores, optimizaciones
**Ejemplos**:
- Corrección de errores
- Mejoras de rendimiento
- Ajustes en validaciones
- Actualizaciones de dependencias (patches)

### MINOR (v1.X.0)
**Incremento**: Nuevas funcionalidades compatibles hacia atrás
**Ejemplos**:
- Nuevos endpoints
- Nuevas funcionalidades en endpoints existentes
- Nuevas validaciones opcionales
- Actualizaciones de dependencias (minor)

### MAJOR (vX.0.0)
**Incremento**: Cambios que rompen compatibilidad
**Ejemplos**:
- Cambios en estructura de respuestas
- Eliminación de endpoints
- Cambios en autenticación/autorización
- Migraciones de base de datos que requieren cambios en el cliente
- Actualizaciones de dependencias (major)

## Proceso de Release

Cuando Claude hace cambios importantes:

1. **Analiza** los cambios realizados
2. **Determina** el tipo de versión (PATCH/MINOR/MAJOR)
3. **Actualiza** el archivo VERSION
4. **Crea** el tag de git correspondiente
5. **Pushea** el tag a GitHub
6. **GitHub Actions** automáticamente:
   - Construye la imagen Docker
   - Crea múltiples tags (v1.2.3, v1.2, v1, latest)
   - Despliega a producción
   - Crea un GitHub Release

## Historial de Versiones

### v1.0.0 (2025-11-16)
- Primera versión estable con versionado semántico
- Backend legacy Agape en producción
- Soporte para deployment automático con SemVer
