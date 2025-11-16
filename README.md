# Agape V1 - Legacy Backend

Backend legacy de Agape (anteriormente DeleJove), basado en Flask. Este repositorio contiene el código del sistema V1 que sirve los endpoints `/api/v1/*`.

## Arquitectura

- **Framework**: Flask + Gevent
- **Endpoints**: 226 rutas legacy
- **Deployment**: Docker en EC2
- **Base URL**: `https://agape.penwin.cloud/api/v1/`

## Tecnologías

- Python 3.11
- Flask 3.0
- SQLAlchemy 2.0
- Gevent para async
- Gunicorn como WSGI server

## Estructura

```
agape-v1/
├── login.py              # Aplicación principal (226 endpoints)
├── requirements.txt      # Dependencias Python
├── Dockerfile           # Containerización
├── .github/
│   └── workflows/
│       └── deploy.yml   # CI/CD automático
└── README.md
```

## Deployment Automático

Al hacer push a `main`:
1. GitHub Actions construye la imagen Docker
2. Push a Amazon ECR
3. Deploy automático a EC2
4. Nginx rutea `/api/v1/*` a este container

## Desarrollo Local

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env

# Ejecutar servidor
python login.py
```

## Variables de Entorno

Ver `.env.example` para la configuración necesaria.

## Migración a V2

Este es el sistema legacy. La nueva arquitectura hexagonal está en el repositorio `delejove-v3`. Eventualmente, todos estos endpoints serán migrados a V2.

## Monitoreo

- Health check: `https://agape.penwin.cloud/api/v1/health`
- El container tiene health checks automáticos cada 30s

## Notas

- Este código es legacy y está en modo mantenimiento
- Solo se hacen fixes críticos
- Nuevas features van a V2 (hexagonal architecture)
