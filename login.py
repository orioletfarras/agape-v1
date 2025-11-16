# Gevent monkey patching - debe estar ANTES de cualquier otro import
from gevent import monkey
monkey.patch_all()

import os
import random
import string
import json
import smtplib
import requests
import jwt
import time
import datetime
import base64
import re
import zipfile
import io
import stripe


from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import quote_plus
from email.mime.text import MIMEText
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy.orm.attributes import flag_modified
from openai import OpenAIError, OpenAI
from openai import OpenAI
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request

# ———————————————————————————————————————————————
#  Librería de Passbook
# ———————————————————————————————————————————————
# --- 3) Construcción del pase ---

# import passbook.models as _pb
import hashlib
# from M2Crypto import SMIME, X509
# from M2Crypto.X509 import X509_Stack

# Importaciones para generación de PDFs
# from reportlab.pdfgen import canvas
# from reportlab.lib.pagesizes import A4, letter
# from reportlab.lib.units import inch, cm
# from reportlab.lib import colors
# from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
# from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
# from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT



# from passbook.models import Pass, Barcode, BarcodeFormat, EventTicket
from functools import wraps


import openai


try:
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
except Exception as e:
    print(f"Warning: OpenAI client initialization failed: {e}")
    client = None

import boto3
from botocore.exceptions import NoCredentialsError
from PIL import Image

from flask import Flask, request, jsonify, g, redirect, session, url_for, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text as sa_text
from sqlalchemy import event
from flask_migrate import Migrate
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# # from youtube12 import YouTubeVideo  # Temporarily commented due to OpenAI client issue  # Temporarily commented due to OpenAI client issue

# -- Flask-Principal Imports --
from flask_principal import (
    Principal, Permission, RoleNeed, Identity, AnonymousIdentity,
    identity_changed, identity_loaded, Need
)

from dotenv import load_dotenv

# --------------------------------------------------------------------
#                     CONFIGURACIÓN Y VARIABLES
# --------------------------------------------------------------------

# Google Calendar

GCAL_SCOPES = ['https://www.googleapis.com/auth/calendar.readonly', 'https://www.googleapis.com/auth/youtube.force-ssl']
CREDENTIALS_FILE = 'client_secret.json'  # Ajusta si tu archivo está en otro sitio

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# SocketIO habilitado para notificaciones en tiempo real
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'RDS_DATABASE_URL',
    'mysql+pymysql://admin:Pwn20141130!@database-1.csf25ija4rhk.eu-south-2.rds.amazonaws.com/ChatApp'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '20141130')

# Configuración de pool de conexiones y timeouts para evitar deadlocks
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,              # Número máximo de conexiones en el pool
    'pool_recycle': 3600,         # Reciclar conexiones cada hora (3600 segundos)
    'pool_pre_ping': True,        # Verificar conexión antes de usar (detecta conexiones muertas)
    'pool_timeout': 30,           # Timeout para obtener conexión del pool (30 segundos)
    'max_overflow': 20,           # Conexiones adicionales permitidas sobre pool_size
    'connect_args': {
        'connect_timeout': 10,    # Timeout para conectar a la BD (10 segundos)
        'read_timeout': 30,       # Timeout para lecturas (30 segundos)
        'write_timeout': 30       # Timeout para escrituras (30 segundos)
    }
}

# Aquí puedes importar los modelos de otros módulos para que se registren.
# Por ejemplo, importa el modelo de YouTubeVideo desde youtube12.py:
# from youtube12 import YouTubeVideo  # Temporarily commented due to OpenAI client issue

# Importa la instancia compartida de la base de datos
from db import db
db.init_app(app)
migrate = Migrate(app, db)

# Importar modelo de push tokens
from create_push_tokens_table import PushToken

# Añadir teardown para cerrar sesiones automáticamente y prevenir fugas de conexiones
@app.teardown_appcontext
def shutdown_session(exception=None):
    """Cierra la sesión de SQLAlchemy al finalizar cada request para evitar conexiones colgadas"""
    try:
        db.session.remove()
    except Exception as e:
        app.logger.warning(f"Error al cerrar sesión de BD: {e}")

# Middleware para logging detallado de requests (ayuda a identificar bloqueos)
import time
from flask import g

@app.before_request
def log_request_start():
    """Registra el inicio de cada request con timestamp"""
    g.start_time = time.time()
    g.request_id = str(time.time())[-8:]  # ID único para tracking

    # Log detallado del request
    app.logger.info(
        f"🔵 [{g.request_id}] START {request.method} {request.path} "
        f"from {request.remote_addr} | UA: {request.user_agent.string[:50]}"
    )

    # Log de parámetros (útil para debugging, pero cuidado con datos sensibles)
    if request.args:
        app.logger.debug(f"📋 [{g.request_id}] Query params: {dict(request.args)}")

    # Log de headers importantes (excluyendo token completo por seguridad)
    headers_to_log = {
        'Content-Type': request.headers.get('Content-Type'),
        'Content-Length': request.headers.get('Content-Length'),
        'Has-Token': 'Yes' if request.headers.get('x-access-token') else 'No'
    }
    app.logger.debug(f"📨 [{g.request_id}] Headers: {headers_to_log}")

@app.after_request
def log_request_end(response):
    """Registra el final de cada request con duración y status code"""
    if hasattr(g, 'start_time'):
        duration = time.time() - g.start_time
        request_id = getattr(g, 'request_id', 'unknown')

        # Diferentes niveles de log según duración
        if duration > 5.0:
            # Request lento - WARNING
            app.logger.warning(
                f"🐌 [{request_id}] SLOW {request.method} {request.path} "
                f"| Status: {response.status_code} | Duration: {duration:.2f}s"
            )
        elif duration > 1.0:
            # Request moderado - INFO
            app.logger.info(
                f"⚠️  [{request_id}] END {request.method} {request.path} "
                f"| Status: {response.status_code} | Duration: {duration:.2f}s"
            )
        else:
            # Request rápido - DEBUG
            app.logger.debug(
                f"✅ [{request_id}] END {request.method} {request.path} "
                f"| Status: {response.status_code} | Duration: {duration:.3f}s"
            )

    return response

@app.errorhandler(Exception)
def handle_exception(e):
    """Captura todas las excepciones no manejadas y las registra detalladamente"""
    request_id = getattr(g, 'request_id', 'unknown')
    duration = time.time() - g.start_time if hasattr(g, 'start_time') else 0

    app.logger.error(
        f"❌ [{request_id}] ERROR {request.method} {request.path} "
        f"| Duration: {duration:.2f}s | Error: {type(e).__name__}: {str(e)}",
        exc_info=True  # Incluye stack trace completo
    )

    # Retornar error genérico al cliente (no exponer detalles internos)
    return jsonify({
        'error': 'Internal server error',
        'request_id': request_id
    }), 500

# Función para aplicar migraciones de columnas
def ensure_database_schema():
    """Asegura que las columnas requeridas existan en la base de datos"""
    try:
        with app.app_context():
            print("Iniciando verificación de esquema de base de datos...")

            # Verificar y añadir columna is_active a la tabla user
            with db.engine.connect() as connection:
                result = connection.execute(sa_text("SHOW COLUMNS FROM user LIKE 'is_active'"))
                if not result.fetchone():
                    print("Añadiendo columna is_active a la tabla user...")
                    connection.execute(sa_text("ALTER TABLE user ADD COLUMN is_active BOOLEAN DEFAULT TRUE NOT NULL"))
                    connection.commit()
                    print("Columna is_active añadida a la tabla user")
                else:
                    print("Columna is_active ya existe en la tabla user")

                # Verificar y añadir columna is_active a la tabla tutored_account
                result = connection.execute(sa_text("SHOW COLUMNS FROM tutored_account LIKE 'is_active'"))
                if not result.fetchone():
                    print("Añadiendo columna is_active a la tabla tutored_account...")
                    connection.execute(sa_text("ALTER TABLE tutored_account ADD COLUMN is_active BOOLEAN DEFAULT TRUE NOT NULL"))
                    connection.commit()
                    print("Columna is_active añadida a la tabla tutored_account")
                else:
                    print("Columna is_active ya existe en la tabla tutored_account")

                # Verificar y añadir columnas de pago a la tabla calendar_events
                payment_columns = [
                    ("max_attendees", "INTEGER NULL", "Añadiendo columna max_attendees a calendar_events..."),
                    ("event_price", "FLOAT NULL", "Añadiendo columna event_price a calendar_events..."),
                    ("payment_deadline", "VARCHAR(10) NULL", "Añadiendo columna payment_deadline a calendar_events..."),
                    ("allow_installments", "BOOLEAN DEFAULT FALSE", "Añadiendo columna allow_installments a calendar_events..."),
                    ("reservation_amount", "FLOAT NULL", "Añadiendo columna reservation_amount a calendar_events..."),
                    ("allow_help_requests", "BOOLEAN DEFAULT FALSE", "Añadiendo columna allow_help_requests a calendar_events..."),
                    ("custom_pricing_enabled", "BOOLEAN DEFAULT FALSE", "Añadiendo columna custom_pricing_enabled a calendar_events..."),
                    ("user_price", "FLOAT NULL", "Añadiendo columna user_price a calendar_events..."),
                    ("staff_price", "FLOAT NULL", "Añadiendo columna staff_price a calendar_events..."),
                    ("religious_price", "FLOAT NULL", "Añadiendo columna religious_price a calendar_events..."),
                    ("event_end_date", "DATETIME NULL", "Añadiendo columna event_end_date a calendar_events..."),
                    ("event_end_time", "VARCHAR(5) NULL", "Añadiendo columna event_end_time a calendar_events..."),
                    ("is_all_day", "BOOLEAN DEFAULT FALSE", "Añadiendo columna is_all_day a calendar_events..."),
                    ("is_multi_day", "BOOLEAN DEFAULT FALSE", "Añadiendo columna is_multi_day a calendar_events..."),
                    ("has_end_time", "BOOLEAN DEFAULT FALSE", "Añadiendo columna has_end_time a calendar_events..."),
                    ("is_public", "BOOLEAN DEFAULT TRUE", "Añadiendo columna is_public a calendar_events..."),
                    ("is_active", "BOOLEAN DEFAULT TRUE", "Añadiendo columna is_active a calendar_events...")
                ]

                for column_name, column_type, message in payment_columns:
                    try:
                        result = connection.execute(sa_text(f"SHOW COLUMNS FROM calendar_events LIKE '{column_name}'"))
                        if not result.fetchone():
                            print(message)
                            connection.execute(sa_text(f"ALTER TABLE calendar_events ADD COLUMN {column_name} {column_type}"))
                            connection.commit()
                            print(f"Columna {column_name} añadida a calendar_events")
                        else:
                            print(f"Columna {column_name} ya existe en calendar_events")
                    except Exception as e:
                        print(f"Error añadiendo columna {column_name}: {e}")

            print("Verificación de esquema completada.")

    except Exception as e:
        print(f"Error durante la migración de base de datos: {e}")

# Ejecutar migración al inicializar la app
ensure_database_schema()

# Credenciales OpenAI
  # lee la clave de tu .env

# Inicializa Flask-Principal
principals = Principal(app)

# Configuración AWS S3
S3_BUCKET = os.getenv('S3_BUCKET', 'delejove')
S3_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
S3_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
S3_REGION = os.getenv('AWS_DEFAULT_REGION', 'eu-west-3')

s3 = boto3.client(
    "s3",
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name=S3_REGION,
)

# Configuración de Instagram OAuth (actualiza las variables de entorno o reemplaza los valores)
# Actualiza los valores en tus variables de entorno o en la configuración:
INSTAGRAM_CLIENT_ID = os.getenv('INSTAGRAM_CLIENT_ID', '490767650748176')
INSTAGRAM_CLIENT_SECRET = os.getenv('INSTAGRAM_CLIENT_SECRET', 'c9c25c4bf57f711630bee4707e200dc4')
INSTAGRAM_REDIRECT_URI = os.getenv('INSTAGRAM_REDIRECT_URI', 'https://delejove.penwin.cloud:8443/insta_callback')
# Para cuentas corporativas, usa el endpoint de Facebook Graph
INSTAGRAM_OAUTH_AUTHORIZE_URL = "https://www.instagram.com/oauth/authorize"
INSTAGRAM_TOKEN_ENDPOINT = "https://api.instagram.com/oauth/access_token"
INSTAGRAM_REFRESH_ENDPOINT = "https://graph.instagram.com/refresh_access_token"
INSTAGRAM_ACCOUNT_ID = os.getenv('INSTAGRAM_ACCOUNT_ID', '766953857351017')

# --------------------------------------------------------------------
#                              MODELOS
# --------------------------------------------------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    nickname = db.Column(db.String(50), unique=True, nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_code = db.Column(db.String(6), nullable=True)
    id_code = db.Column(db.String(24), unique=True, nullable=True)
    role = db.Column(db.String(50), default='USER')
    is_active = db.Column(db.Boolean, default=True, nullable=False)  # Campo para activar/desactivar usuarios
    donating = db.Column(db.JSON, nullable=True)
    channels_admin = db.Column(db.JSON, nullable=True)
    user_settings = db.Column(db.JSON, nullable=True)
    post_like = db.Column(db.JSON, nullable=True)
    post_fav = db.Column(db.JSON, nullable=True)
    post_prays = db.Column(db.JSON, nullable=True)
    hide_posts = db.Column(db.JSON, nullable=True)
    stripe = db.Column(db.JSON, nullable=True)  # Información de pagos y Stripe
    login_activity = db.Column(db.JSON, nullable=True)  # Logs de actividad de login
    tutelados_json = db.Column(db.JSON, nullable=True)  # IDs de cuentas tuteladas (hijos)
    profile_image_url = db.Column(db.String(500), nullable=True)  # URL de imagen de perfil
    spouse_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # ID del cónyuge vinculado
    shares_children_with_spouse = db.Column(db.Boolean, default=False, nullable=False)  # Si comparte información de hijos con cónyuge
    primary_organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)  # Parroquia/organización principal del usuario
    parroquia_principal_id = db.Column(db.Integer, nullable=True)  # ID de parroquia principal para onboarding
    onboarding_completed = db.Column(db.Boolean, default=False, nullable=False)  # Si completó el onboarding
    auto_subscribe_enabled = db.Column(db.Boolean, default=False, nullable=False)  # Si acepta auto-subscribe a canales de parroquia/diócesis
    user_organizations = db.relationship('UserOrganization', back_populates='user')

class TutoredAccount(db.Model):
    __tablename__ = 'tutored_account'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellidos = db.Column(db.String(100), nullable=False)
    dni = db.Column(db.String(20), nullable=True)
    correo_electronico = db.Column(db.String(100), nullable=True)
    fecha_nacimiento = db.Column(db.Date, nullable=False)
    genero = db.Column(db.String(20), nullable=False)
    parroquia_principal = db.Column(db.String(100), nullable=False)
    tutor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Campo especial para marcar si la cuenta puede acceder (tiene email)
    can_access = db.Column(db.Boolean, default=False)
    # Campo para activar/desactivar la cuenta tutelada
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relación con el usuario tutor
    tutor = db.relationship('User', backref='tutored_accounts')

class Notification(db.Model):
    __tablename__ = 'notification'
    id = db.Column(db.Integer, primary_key=True)
    recipient_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Usuario que recibe la notificación
    sender_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Usuario que envía (opcional)
    type = db.Column(db.String(50), nullable=False)  # Tipo: 'spouse_request', 'channel_invite', etc.
    title = db.Column(db.String(200), nullable=False)  # Título de la notificación
    message = db.Column(db.Text, nullable=False)  # Mensaje descriptivo
    data = db.Column(db.JSON, nullable=True)  # Datos adicionales según el tipo
    status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'accepted', 'rejected', 'read'
    is_read = db.Column(db.Boolean, default=False, nullable=False)  # Si fue leída
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)  # Fecha de expiración (opcional)

    # Relaciones
    recipient = db.relationship('User', foreign_keys=[recipient_user_id], backref='received_notifications')
    sender = db.relationship('User', foreign_keys=[sender_user_id], backref='sent_notifications')


class ChannelPoll(db.Model):
    __tablename__ = 'channel_poll'
    id = db.Column(db.Integer, primary_key=True)
    channel_id = db.Column(db.String(100), nullable=False)
    creator_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.Column(db.String(500), nullable=False)
    options = db.Column(db.JSON, nullable=False)  # Lista de opciones: ["Opción 1", "Opción 2", ...]
    multiple_choice = db.Column(db.Boolean, default=False)  # Si permite múltiples respuestas
    anonymous = db.Column(db.Boolean, default=False)  # Si los votos son anónimos
    expires_at = db.Column(db.DateTime, nullable=True)  # Fecha de expiración
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    creator = db.relationship('User', backref='created_polls')
    votes = db.relationship('PollVote', backref='poll', cascade='all, delete-orphan')

class PollVote(db.Model):
    __tablename__ = 'poll_vote'
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('channel_poll.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    option_index = db.Column(db.Integer, nullable=False)  # Índice de la opción seleccionada
    voted_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relación con usuario
    user = db.relationship('User', backref='poll_votes')
    
    # Índice único para evitar votos duplicados (excepto si multiple_choice=True)
    __table_args__ = (db.Index('idx_poll_user_option', 'poll_id', 'user_id', 'option_index'),)

class Friendship(db.Model):
    __tablename__ = 'friendship'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relaciones
    user = db.relationship('User', foreign_keys=[user_id])
    friend = db.relationship('User', foreign_keys=[friend_id])

class ParroquiaCee(db.Model):
    __tablename__ = 'parroquias_cee'
    id = db.Column(db.Integer, primary_key=True)
    parroquia_id = db.Column(db.String(36), unique=True, nullable=True)
    diocesis = db.Column(db.String(255), nullable=False)
    nombre_parroquia = db.Column(db.String(500), nullable=False)
    municipio = db.Column(db.String(255), nullable=True)
    direccion = db.Column(db.Text, nullable=True)
    codigo_postal = db.Column(db.String(10), nullable=True)
    telefono = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    parroco = db.Column(db.String(255), nullable=True)
    url_diocesis = db.Column(db.String(500), nullable=True)
    provincia = db.Column(db.String(100), nullable=True)
    provincia_info = db.Column(db.String(255), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    fecha_scraping = db.Column(db.DateTime, nullable=True)

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Campos para parroquia/diócesis
    parish_type = db.Column(db.String(20), nullable=True)  # 'parish' o 'diocese'
    parish_id = db.Column(db.Integer, nullable=True)  # ID de la parroquia (si aplica)
    parish_name = db.Column(db.String(500), nullable=True)  # Nombre de la parroquia
    diocese_name = db.Column(db.String(255), nullable=True)  # Nombre de la diócesis

    # Campos de personalización
    logo_url = db.Column(db.String(500), nullable=True)  # URL del logotipo
    logo_color = db.Column(db.String(7), nullable=True, default='#007AFF')  # Color del logotipo (formato hexadecimal)
    custom_logo_url = db.Column(db.String(500), nullable=True)  # URL del logotipo personalizado subido
    description = db.Column(db.String(500), nullable=True)  # Descripción de la organización
    city = db.Column(db.String(100), nullable=True)  # Ciudad
    country = db.Column(db.String(100), nullable=True)  # País
    is_active = db.Column(db.Boolean, default=True)  # Si la organización está activa
    show_channel_navigation = db.Column(db.Boolean, default=False)  # Si se muestra el modal de navegación de canales

    # Canal principal de la organización
    main_channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=True)
    main_channel = db.relationship('Channel', foreign_keys=[main_channel_id])
    channels = db.relationship('Channel', foreign_keys='Channel.organization_id', back_populates='organization')
    organization_users = db.relationship('UserOrganization', back_populates='organization')

class UserOrganization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    user = db.relationship('User', back_populates='user_organizations')
    organization = db.relationship('Organization', back_populates='organization_users')

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    id_code = db.Column(db.String(24), unique=True, nullable=True)
    version = db.Column(db.Integer, default=1)  # <-- Nueva columna para la versión
    user_notifications = db.Column(db.JSON, nullable=True)
    subscribers_count = db.Column(db.Integer, default=0)
    organization = db.relationship('Organization', foreign_keys=[organization_id], back_populates='channels')
    user_settings = db.Column(db.JSON, nullable=True)
    suspect_comments = db.Column(db.JSON, nullable=True)  # <--- Campo donde guardarás comentarios sospechosos
    suspect_posts = db.Column(db.JSON, nullable=True)  # <--- Añadir esta línea
    subscribers_json = db.Column(db.JSON, nullable=True)
    story_json = db.Column(db.JSON, nullable=True)

class UserChannel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    user = db.relationship('User', backref='user_channels')
    channel = db.relationship('Channel', backref='channel_users')

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    id_code = db.Column(db.String(24), unique=True, nullable=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=False)
    channel = db.relationship('Channel', backref='posts')
    image_url = db.Column(db.String(255), nullable=True)
    text = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    epoch_created_at = db.Column(db.BigInteger, nullable=True, server_default=sa_text("(UNIX_TIMESTAMP())"))
    postimage_json = db.Column(db.JSON, nullable=True)
    reelsvideo_json = db.Column(db.JSON, nullable=True)
    like_count = db.Column(db.Integer, default=0)
    comment_count = db.Column(db.Integer, default=0)
    posttag = db.Column(db.String(255), nullable=True)
    has_story = db.Column(db.Boolean, default=False)
    is_published = db.Column(db.Boolean, default=True)
    post_prays = db.Column(db.JSON, nullable=True)
    post_comments = db.Column(db.JSON, nullable=True)
    post_likes = db.Column(db.JSON, nullable=True)


class UserSettingKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    placeholder = db.Column(db.String(255), nullable=True)
    id_category = db.Column(db.Integer, nullable=True)
    data_type = db.Column(db.String(50), nullable=False)

class ChannelSettingKeys(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key_name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    placeholder = db.Column(db.String(255), nullable=True)
    id_category = db.Column(db.Integer, nullable=True)
    data_type = db.Column(db.String(50), nullable=False)

class UserSettingCategories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(255), nullable=True)
    icon = db.Column(db.String(100), nullable=True)
    order = db.Column(db.Integer, nullable=True)
    permissions = db.Column(db.String(100), default='channel')


# -- Aquí añadimos la NUEVA tabla de categorías de configuración de CANAL --
class ChannelSettingCategories(db.Model):
    """
    Tabla análoga a UserSettingCategories, pero enfocada a configuraciones 
    de canal. Permite clasificar las 'ChannelSettingKeys'.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(255), nullable=True)
    icon = db.Column(db.String(100), nullable=True)
    order = db.Column(db.Integer, nullable=True)
    permissions = db.Column(db.String(100), default='channel')
    key_name = db.Column(db.String(100), nullable=False)
    placeholder = db.Column(db.String(255), nullable=True)
    data_type = db.Column(db.String(50), nullable=False)

class Translation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    language = db.Column(db.String(10), nullable=False)
    key = db.Column(db.String(500), nullable=False)
    translation = db.Column(db.Text, nullable=False)
    __table_args__ = (db.UniqueConstraint('language', 'key', name='unique_translation'),)

# Nuevo modelo para los posts de Instagram
class InstaPost(db.Model):
    __tablename__ = 'insta_posts'
    id = db.Column(db.String(50), primary_key=True)
    caption = db.Column(db.Text)
    media_url = db.Column(db.String(255))
    permalink = db.Column(db.String(255))
    media_type = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime)
    like_count = db.Column(db.Integer)
    comments_count = db.Column(db.Integer)
    s3_image_url = db.Column(db.String(255))

# Modelo para eventos del calendario de actividades
class CalendarEvent(db.Model):
    __tablename__ = 'calendar_events'
    id = db.Column(db.Integer, primary_key=True)
    id_code = db.Column(db.String(24), unique=True, nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    event_type = db.Column(db.String(50), nullable=False)  # 'like', 'comment', 'follow', 'event', 'prayer', etc.
    event_date = db.Column(db.DateTime, nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    profile_name = db.Column(db.String(100), nullable=True)
    profile_image = db.Column(db.String(255), nullable=True)
    post_image = db.Column(db.String(255), nullable=True)
    location = db.Column(db.String(200), nullable=True)
    # Campos de pago y configuración del evento
    max_attendees = db.Column(db.Integer, nullable=True)
    goal_attendees = db.Column(db.Integer, nullable=True)  # Objetivo personalizado de asistentes
    event_price = db.Column(db.Float, nullable=True)
    payment_deadline = db.Column(db.String(10), nullable=True)  # Formato DD/MM/AAAA
    allow_installments = db.Column(db.Boolean, default=False)
    reservation_amount = db.Column(db.Float, nullable=True)
    allow_help_requests = db.Column(db.Boolean, default=False)
    custom_pricing_enabled = db.Column(db.Boolean, default=False)
    user_price = db.Column(db.Float, nullable=True)
    staff_price = db.Column(db.Float, nullable=True)
    religious_price = db.Column(db.Float, nullable=True)
    # Campos adicionales del evento
    event_end_date = db.Column(db.DateTime, nullable=True)
    event_end_time = db.Column(db.String(5), nullable=True)  # Formato HH:MM
    is_all_day = db.Column(db.Boolean, default=False)
    is_multi_day = db.Column(db.Boolean, default=False)
    has_end_time = db.Column(db.Boolean, default=False)
    is_public = db.Column(db.Boolean, default=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Modelo para registros de eventos del calendario
class CalendarEventRegistration(db.Model):
    __tablename__ = 'calendar_event_registrations'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('calendar_events.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    installments = db.Column(db.Integer, default=1)
    total_price = db.Column(db.Float, nullable=True)
    installment_amount = db.Column(db.Float, nullable=True)
    amount_paid = db.Column(db.Float, default=0)  # Cantidad ya pagada
    amount_pending = db.Column(db.Float, nullable=True)  # Cantidad pendiente
    payment_status = db.Column(db.String(20), default='pending')  # pending, partial, completed, refunded
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True)  # ID del PaymentIntent de Stripe
    stripe_customer_id = db.Column(db.String(255), nullable=True)  # ID del Customer de Stripe
    purchase_date = db.Column(db.DateTime, nullable=True)  # Fecha de compra (primer pago)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    checked_in = db.Column(db.Boolean, default=False)
    check_in_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Tabla de transacciones de pago individuales (para plazos)
class PaymentTransaction(db.Model):
    __tablename__ = 'payment_transactions'
    id = db.Column(db.Integer, primary_key=True)
    registration_id = db.Column(db.Integer, db.ForeignKey('calendar_event_registrations.id'), nullable=False)
    installment_number = db.Column(db.Integer, nullable=False)  # Número de plazo (1, 2, 3, etc.)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, refunded
    stripe_payment_intent_id = db.Column(db.String(255), nullable=True)
    stripe_charge_id = db.Column(db.String(255), nullable=True)
    stripe_refund_id = db.Column(db.String(255), nullable=True)  # Si se hizo refund
    payment_date = db.Column(db.DateTime, nullable=True)
    refund_date = db.Column(db.DateTime, nullable=True)
    refund_amount = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DiscountCode(db.Model):
    __tablename__ = 'discount_codes'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('calendar_events.id'), nullable=False)
    code = db.Column(db.String(50), nullable=False)  # Código del descuento (ej: VERANO2025)
    discount_type = db.Column(db.String(20), nullable=False)  # 'percentage' o 'fixed'
    discount_value = db.Column(db.Float, nullable=False)  # Porcentaje (ej: 20) o valor fijo (ej: 10.00)
    start_date = db.Column(db.DateTime, nullable=True)  # Fecha de inicio (null = activo desde creación)
    end_date = db.Column(db.DateTime, nullable=True)  # Fecha de fin (null = nunca caduca)
    max_uses = db.Column(db.Integer, nullable=True)  # Número máximo de usos (null = ilimitado)
    times_used = db.Column(db.Integer, default=0)  # Contador de usos
    total_discount_amount = db.Column(db.Float, default=0)  # Total descontado en euros
    is_active = db.Column(db.Boolean, default=True)  # Permite activar/desactivar el código
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Índice único para evitar códigos duplicados en el mismo evento
    __table_args__ = (db.UniqueConstraint('event_id', 'code', name='unique_event_code'),)

class CalendarReaction(db.Model):
    __tablename__ = 'calendar_reactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.String(24), nullable=False)  # ID del evento del calendario
    reaction_type = db.Column(db.String(20), nullable=False)  # 'heart', 'pray', 'comment'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Índice único para evitar reacciones duplicadas del mismo usuario al mismo evento
    __table_args__ = (db.UniqueConstraint('user_id', 'event_id', name='unique_user_event_reaction'),)

class CalendarComment(db.Model):
    __tablename__ = 'calendar_comments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.String(24), nullable=False)  # ID del evento del calendario
    comment_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --------------------------------------------------------------------
#                       MODELOS DEL SISTEMA DE CHAT
# --------------------------------------------------------------------

class Conversation(db.Model):
    __tablename__ = 'conversations'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.Enum('private', 'group', 'channel', name='conversation_type'), default='private')
    title = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    avatar_url = db.Column(db.String(500), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    last_message_id = db.Column(db.Integer, nullable=True)
    last_message_at = db.Column(db.DateTime, nullable=True)

class ConversationParticipant(db.Model):
    __tablename__ = 'conversation_participants'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.Enum('admin', 'member', name='participant_role'), default='member')
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    left_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    last_read_message_id = db.Column(db.Integer, nullable=True)
    last_read_at = db.Column(db.DateTime, nullable=True)
    notifications_enabled = db.Column(db.Boolean, default=True)

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reply_to_message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=True)
    content = db.Column(db.Text, nullable=False)
    message_type = db.Column(db.Enum('text', 'image', 'video', 'audio', 'file', 'location', name='message_type'), default='text')
    file_url = db.Column(db.String(500), nullable=True)
    file_name = db.Column(db.String(255), nullable=True)
    file_size = db.Column(db.Integer, nullable=True)
    sent_as_channel = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    edited_at = db.Column(db.DateTime, nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    is_system_message = db.Column(db.Boolean, default=False)
    message_metadata = db.Column(db.JSON, nullable=True)

    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    conversation = db.relationship('Conversation', backref='messages')
    reply_to_message = db.relationship('Message', remote_side=[id])

class MessageReaction(db.Model):
    __tablename__ = 'message_reactions'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reaction_type = db.Column(db.String(50), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    user = db.relationship('User', backref='message_reactions')
    message = db.relationship('Message', backref='reactions')

class MessageReport(db.Model):
    __tablename__ = 'message_reports'
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('messages.id'), nullable=False)
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reason = db.Column(db.Enum('spam', 'harassment', 'inappropriate_content',
                               'violence', 'hate_speech', 'false_information', 'other',
                               name='report_reason'), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.Enum('pending', 'reviewed', 'resolved', 'dismissed', name='report_status'), default='pending')
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    resolution_note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UserChatSettings(db.Model):
    __tablename__ = 'user_chat_settings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notifications_enabled = db.Column(db.Boolean, default=True)
    sounds_enabled = db.Column(db.Boolean, default=True)
    read_receipts_enabled = db.Column(db.Boolean, default=True)
    last_seen_privacy = db.Column(db.Enum('everyone', 'contacts', 'nobody', name='privacy_setting'), default='everyone')
    profile_photo_privacy = db.Column(db.Enum('everyone', 'contacts', 'nobody', name='privacy_setting'), default='everyone')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class UserFollow(db.Model):
    __tablename__ = 'user_follows'
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.Enum('pending', 'accepted', 'rejected', name='follow_status'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relaciones
    follower = db.relationship('User', foreign_keys=[follower_id], backref='sent_follow_requests')
    following = db.relationship('User', foreign_keys=[following_id], backref='received_follow_requests')

    # Índice único para evitar solicitudes duplicadas
    __table_args__ = (db.UniqueConstraint('follower_id', 'following_id', name='unique_follow_request'),)

# ============================================================
# MODELOS PARA VIDA DE PIEDAD
# ============================================================

class LiturgicalPrayer(db.Model):
    __tablename__ = 'liturgical_prayers'
    id = db.Column(db.Integer, primary_key=True)
    prayer_type = db.Column(db.String(50), nullable=False)  # laudes, visperas, completas
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    audio_url = db.Column(db.String(500), nullable=True)  # URL del MP3
    liturgical_date = db.Column(db.Date, nullable=True)
    language = db.Column(db.String(10), default='es')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DailySaint(db.Model):
    __tablename__ = 'daily_saints'
    id = db.Column(db.Integer, primary_key=True)
    saint_date = db.Column(db.Date, nullable=False)
    saint_name = db.Column(db.String(255), nullable=False)
    biography = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500), nullable=True)
    language = db.Column(db.String(10), default='es')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class LiturgicalFeast(db.Model):
    __tablename__ = 'liturgical_feasts'
    id = db.Column(db.Integer, primary_key=True)
    feast_date = db.Column(db.Date, nullable=False)
    feast_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    liturgical_color = db.Column(db.String(50), nullable=True)  # verde, morado, blanco, rojo
    importance = db.Column(db.String(50), nullable=True)  # solemnidad, fiesta, memoria
    language = db.Column(db.String(10), default='es')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class DailyGospel(db.Model):
    __tablename__ = 'daily_gospel'
    id = db.Column(db.Integer, primary_key=True)
    gospel_date = db.Column(db.Date, nullable=False)
    gospel_reference = db.Column(db.String(100), nullable=False)
    gospel_text = db.Column(db.Text, nullable=False)
    reflection = db.Column(db.Text, nullable=True)
    language = db.Column(db.String(10), default='es')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class GeneralPrayer(db.Model):
    __tablename__ = 'general_prayers'
    id = db.Column(db.Integer, primary_key=True)
    prayer_category = db.Column(db.String(100), nullable=False)  # rosario, via_crucis, angelus, etc.
    prayer_name = db.Column(db.String(255), nullable=False)
    prayer_content = db.Column(db.Text, nullable=False)
    automatic_channel_id = db.Column(db.Integer, db.ForeignKey('channel.id'), nullable=True)  # Vinculación con canal automático
    display_order = db.Column(db.Integer, default=0)
    language = db.Column(db.String(10), default='es')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

with app.app_context():
    db.create_all()

# --------------------------------------------------------------------
#                    FLASK-PRINCIPAL: ROLES Y PERMISOS
# --------------------------------------------------------------------

superadmin_need = RoleNeed('SUPERADMIN')
superadmin_permission = Permission(superadmin_need)

class OrganizationNeed(Need):
    def __new__(cls, org_id):
        return super().__new__(cls, 'org_admin', str(org_id))

class OrganizationAdminPermission(Permission):
    def __init__(self, org_id):
        need = OrganizationNeed(org_id)
        super().__init__(need)

class ChannelNeed(Need):
    def __new__(cls, channel_id):
        return super().__new__(cls, 'channel_admin', str(channel_id))

class ChannelAdminPermission(Permission):
    def __init__(self, channel_id):
        super().__init__(ChannelNeed(channel_id))

# --------------------------------------------------------------------
#           DECORADOR PARA TOKEN & LÓGICA DE IDENTIDAD
# --------------------------------------------------------------------

# — Parche para el manifest (ya lo tienes) —
def _patched_createManifest(self, pass_json):
    pj = pass_json.encode('utf-8') if isinstance(pass_json, str) else pass_json
    self._hashes['pass.json'] = hashlib.sha1(pj).hexdigest()
    for filename, filedata in self._files.items():
        self._hashes[filename] = hashlib.sha1(filedata).hexdigest()
    return json.dumps(self._hashes)

# — Parche para la firma —
def _patched_createSignature(self, manifest, certificate, key,
                             wwdr_certificate, password):
    def passwordCallback(*args, **kwds):
        return password

    # prepará manifest como bytes
    manifest_bytes = manifest.encode('utf-8') if isinstance(manifest, str) else manifest

    smime = SMIME.SMIME()
    wwdrcert = X509.load_cert(wwdr_certificate)
    stack = X509_Stack()
    stack.push(wwdrcert)
    smime.set_x509_stack(stack)

    smime.load_key(str(key), certificate, callback=passwordCallback)
    # firmá sobre un buffer de bytes
    pk7 = smime.sign(
        SMIME.BIO.MemoryBuffer(manifest_bytes),
        flags=SMIME.PKCS7_DETACHED | SMIME.PKCS7_BINARY
    )

    out = SMIME.BIO.MemoryBuffer()
    pk7.write(out)
    pem = out.read()
    # extraé DER
    der = b"".join(
        line
        for line in pem.splitlines()
        if not line.startswith(b"-----")
    )
    return der

# _pb.Pass._createManifest  = _patched_createManifest
# _pb.Pass._createSignature = _patched_createSignature

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            identity_changed.send(app, identity=AnonymousIdentity())
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                identity_changed.send(app, identity=AnonymousIdentity())
                return jsonify({'message': 'User not found!'}), 404
            identity_changed.send(app, identity=Identity(current_user.id))
            g.current_user = current_user
        except jwt.ExpiredSignatureError:
            identity_changed.send(app, identity=AnonymousIdentity())
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            identity_changed.send(app, identity=AnonymousIdentity())
            return jsonify({'message': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Registrar endpoints de push notifications (después de definir token_required)
from push_notification_endpoints import register_push_endpoints
register_push_endpoints(app, db, token_required)

def safe_json_load(field_value, default=None):
    """Safely load JSON field that might be string JSON or already parsed dict/list"""
    if not field_value:
        return default if default is not None else []

    if isinstance(field_value, str):
        try:
            return json.loads(field_value)
        except json.JSONDecodeError:
            return default if default is not None else []
    else:
        # Already parsed dict/list
        return field_value

@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    user_id = identity.id
    if not user_id:
        return
    user_obj = User.query.get(user_id)
    if not user_obj:
        return
    if user_obj.role.upper() == "SUPERADMIN":
        identity.provides.add(superadmin_need)
    org_admin_links = UserOrganization.query.filter_by(user_id=user_obj.id, role='ORG_ADMIN').all()
    for link in org_admin_links:
        org_need = OrganizationNeed(link.organization_id)
        identity.provides.add(org_need)
    channel_admin_links = UserChannel.query.filter_by(user_id=user_obj.id, role='CHANNEL_ADMIN').all()
    for link in channel_admin_links:
        chan_need = ChannelNeed(link.channel_id)
        identity.provides.add(chan_need)

# --- Función para crear el servicio de Calendar desde el JSON almacenado ------
def get_calendar_service_from_channel(channel: Channel):
    """
    Reconstruye el servicio de Calendar usando 
    channel.user_settings["token_gcalendar"].
    """
    # 1) Extraer user_settings
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    creds_dict = channel_settings.get("token_gcalendar")
    if not creds_dict:
        raise ValueError("No se encontró 'token_gcalendar' en user_settings")

    # 2) Crear objeto Credentials
    creds = Credentials.from_authorized_user_info(creds_dict, GCAL_SCOPES)

    # 3) Verificar si está expirado y, si es posible, refrescar
    if not creds.valid and creds.refresh_token:
        # creds.refresh_token existe => podemos refrescar
        import requests
        try:
            creds.refresh(requests.Request())  # Actualiza tokens
            # Guardar de nuevo en la DB el token refrescado
            channel_settings["token_gcalendar"] = json.loads(creds.to_json())
            channel.user_settings = channel_settings
            flag_modified(channel, "user_settings")
            db.session.commit()
        except Exception as e:
            raise Exception(f"No se pudo refrescar el token: {e}")
    elif not creds.valid:
        # Sin refresh_token => se requerirá reautenticación
        raise Exception("Credenciales expiradas y sin refresh_token. Vuelve a vincular Google Calendar.")

    # 4) Crear service
    service = build('calendar', 'v3', credentials=creds)
    return service

# --- Función para crear el servicio de Youtube desde el JSON almacenado ------
def get_youtube_service_from_channel(channel: Channel):
    """
    Reconstruye el servicio de Calendar usando 
    channel.user_settings["token_youtube"].
    """
    # 1) Extraer user_settings
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    creds_dict = channel_settings.get("token_youtube")
    if not creds_dict:
        raise ValueError("No se encontró 'token_youtube' en user_settings")

    # 2) Crear objeto Credentials
    creds = Credentials.from_authorized_user_info(creds_dict, GCAL_SCOPES)

    # 3) Verificar si está expirado y, si es posible, refrescar
    if not creds.valid and creds.refresh_token:
        # creds.refresh_token existe => podemos refrescar
        import requests
        try:
            creds.refresh(requests.Request())  # Actualiza tokens
            # Guardar de nuevo en la DB el token refrescado
            channel_settings["token_youtube"] = json.loads(creds.to_json())
            channel.user_settings = channel_settings
            flag_modified(channel, "user_settings")
            db.session.commit()
        except Exception as e:
            raise Exception(f"No se pudo refrescar el token: {e}")
    elif not creds.valid:
        # Sin refresh_token => se requerirá reautenticación
        raise Exception("Credenciales expiradas y sin refresh_token. Vuelve a vincular Google Calendar.")

    # 4) Crear service
    service = build('youtube', 'v3', credentials=creds)
    return service

# ------------ Generador de Código Alfanumérico Único --------------------------

def generate_random_code(length=24):
    chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

@event.listens_for(Post, 'before_insert')
def assign_id_code(mapper, connection, target):
    if not target.id_code:
        target.id_code = generate_random_code(24)

@event.listens_for(Channel, 'before_insert')
def assign_id_code(mapper, connection, target):
    if not target.id_code:
        target.id_code = generate_random_code(24)

# ------------ Decorador para comentarios ---------------
def find_comment_by_id(comments_list, comment_id):
    """
    Busca recursivamente un comentario con 'id' == comment_id en la lista dada,
    incluyendo sus 'replies'. Devuelve el diccionario del comentario si lo encuentra.
    """
    for comment in comments_list:
        if comment.get("id") == comment_id:
            return comment
        if "replies" in comment and comment["replies"]:
            found = find_comment_by_id(comment["replies"], comment_id)
            if found:
                return found
    return None


# ------------ Decorador para moderación de comentarios ---------------
openai.api_key = os.getenv('OPENAI_API_KEY')

# 4. Función de moderación con la NUEVA API (≥1.0.0)
def check_offensive_content(comment_text):
    """
    Usa el endpoint 'openai.moderations.create' (API moderna)
    para evaluar si el texto es ofensivo.
    Retorna True si es ofensivo (flagged), False si no.
    """
    try:
        response = openai.moderations.create(
            input=comment_text,
            model="omni-moderation-latest"  # Cambia a tu modelo disponible
        )
        # 'response.results' es una lista
        result = response.results[0]
        flagged = result.flagged  # True/False
        # Opcional: categories = result.categories

        app.logger.info("Moderation response:")
        app.logger.info(response)

        return flagged
    except Exception as e:
        app.logger.error(f"Error en check_offensive_content: {e}")
        # Decide si quieres bloquear por defecto si falla la API
        return False

def validate_dni_nie(dni_nie):
    """
    Valida el formato de DNI/NIE español

    DNI: 8 dígitos seguidos de una letra (ej: 12345678A)
    NIE: Letra (X, Y, Z) seguida de 7 dígitos y una letra (ej: X1234567A)

    Args:
        dni_nie (str): El DNI/NIE a validar

    Returns:
        bool: True si es válido, False en caso contrario
    """
    if not dni_nie or not isinstance(dni_nie, str):
        return False

    dni_nie = dni_nie.upper().strip()

    # Tabla de letras para validación
    letters = 'TRWAGMYFPDXBNJZSQVHLCKE'

    # Validar DNI (8 dígitos + 1 letra)
    if len(dni_nie) == 9 and dni_nie[:8].isdigit():
        number = int(dni_nie[:8])
        expected_letter = letters[number % 23]
        return dni_nie[8] == expected_letter

    # Validar NIE (1 letra + 7 dígitos + 1 letra)
    elif len(dni_nie) == 9 and dni_nie[0] in 'XYZ' and dni_nie[1:8].isdigit():
        # Convertir primera letra a número
        first_char = dni_nie[0]
        if first_char == 'X':
            number = int('0' + dni_nie[1:8])
        elif first_char == 'Y':
            number = int('1' + dni_nie[1:8])
        elif first_char == 'Z':
            number = int('2' + dni_nie[1:8])

        expected_letter = letters[number % 23]
        return dni_nie[8] == expected_letter

    return False

# =========================================
# Helper para crear el servicio de Calendar
# =========================================
def get_youtube_service_from_channel(channel: Channel):
    """
    Reconstruye el servicio de YouTube usando el token OAuth
    que está en channel.user_settings["token_youtub"].
    Asume que ese token ya incluye el scope de YouTube 
    (p.ej. 'youtube.force-ssl').
    """
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    creds_dict = channel_settings.get("token_youtube")
    if not creds_dict:
        raise ValueError("No se encontró 'token_youtube' en user_settings para este canal")

    # Crear objeto Credentials
    creds = Credentials.from_authorized_user_info(creds_dict, GCAL_SCOPES)

    # Refrescar si es necesario
    if not creds.valid and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Guardar token refrescado
            channel_settings["token_youtube"] = json.loads(creds.to_json())
            channel.user_settings = channel_settings
            flag_modified(channel, "user_settings")
            db.session.commit()
        except Exception as e:
            raise Exception(f"No se pudo refrescar el token de YouTube: {e}")
    elif not creds.valid:
        raise Exception("Credenciales expiradas y sin refresh_token. Se requiere reautenticación con Google.")

    # Crear servicio de YouTube
    youtube_service = build('youtube', 'v3', credentials=creds)
    return youtube_service

# --------------------------------------------------------------------
#                              RUTAS
# --------------------------------------------------------------------

@app.route('/health', methods=['GET'])
def health_check():
    """
    Endpoint de health check para monitorear el estado del servidor.
    No requiere autenticación para permitir monitoreo externo.
    """
    try:
        # Verificar conexión a la base de datos
        db.session.execute(sa_text('SELECT 1'))
        db_status = 'healthy'
    except Exception as e:
        app.logger.error(f"❌ Health check - Database error: {e}")
        db_status = 'unhealthy'
        return jsonify({
            'status': 'unhealthy',
            'database': db_status,
            'error': str(e)
        }), 503

    return jsonify({
        'status': 'healthy',
        'database': db_status,
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/validate-token', methods=['GET'])
@token_required
def validate_token(current_user):
    return jsonify({'message': 'Token is valid', 'user_id': current_user.id}), 200

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        role = data.get('role', 'USER').upper()
        if not username or not email or not password:
            return jsonify({'message': 'All fields are required!'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already registered!'}), 400
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error during registration: {e}")
        return jsonify({'message': 'An error occurred during registration.'}), 500

def get_client_ip():
    """Obtener la IP real del cliente, considerando proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def get_device_info(user_agent):
    """Extraer información básica del dispositivo desde User-Agent"""
    if not user_agent:
        return "Unknown Device"

    user_agent = user_agent.lower()

    # Detectar sistema operativo
    if 'iphone' in user_agent or 'ipad' in user_agent:
        os_info = "iOS"
    elif 'android' in user_agent:
        os_info = "Android"
    elif 'windows' in user_agent:
        os_info = "Windows"
    elif 'macintosh' in user_agent or 'mac os x' in user_agent:
        os_info = "macOS"
    elif 'linux' in user_agent:
        os_info = "Linux"
    else:
        os_info = "Unknown OS"

    # Detectar navegador/app
    if 'chrome' in user_agent and 'safari' in user_agent:
        browser = "Chrome"
    elif 'safari' in user_agent and 'chrome' not in user_agent:
        browser = "Safari"
    elif 'firefox' in user_agent:
        browser = "Firefox"
    elif 'edge' in user_agent:
        browser = "Edge"
    else:
        browser = "Mobile App"

    return f"{os_info} - {browser}"

def add_login_log(user, ip_address, user_agent, device_info, success):
    """Agregar log de login al campo JSON del usuario"""
    try:
        # Obtener logs existentes o crear lista vacía
        login_activity = user.login_activity or []

        # Crear nuevo log
        new_log = {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'device_info': device_info,
            'login_time': datetime.utcnow().isoformat(),
            'success': success
        }

        # Agregar al inicio de la lista (más reciente primero)
        login_activity.insert(0, new_log)

        # Mantener solo los últimos 50 logs para no saturar la DB
        login_activity = login_activity[:50]

        # Guardar en el usuario y marcar como modificado
        user.login_activity = login_activity
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(user, "login_activity")
        db.session.commit()

    except Exception as e:
        app.logger.error(f"Error adding login log: {e}")

@app.route('/login', methods=['POST'])
def login():
    user = None
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        # Obtener información del cliente
        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', '')
        device_info = get_device_info(user_agent)

        if not email or not password:
            return jsonify({'message': 'Email and password are required!'}), 400

        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            # Registrar intento fallido si el usuario existe
            if user:
                add_login_log(user, client_ip, user_agent, device_info, False)
            return jsonify({'message': 'Invalid credentials!'}), 401

        # Registrar login exitoso
        add_login_log(user, client_ip, user_agent, device_info, True)

        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(weeks=300)
            },
            app.config['SECRET_KEY']
        )
        return jsonify({'token': token}), 200

    except Exception as e:
        app.logger.error(f"Error during login: {e}")
        # Registrar error en el log si tenemos usuario
        if user:
            try:
                client_ip = get_client_ip()
                user_agent = request.headers.get('User-Agent', '')
                device_info = get_device_info(user_agent)
                add_login_log(user, client_ip, user_agent, device_info, False)
            except:
                pass
        return jsonify({'message': 'An error occurred during login.'}), 500

@app.route('/validate-user-organization', methods=['POST'])
def validate_user_organization():
    """
    Valida que el usuario exista en la base de datos y que la contraseña sea correcta.
    Este endpoint se usa en el proceso de registro de organización para vincular un usuario existente.
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        organization_name = data.get('organizationName')

        if not email or not password or not organization_name:
            return jsonify({'message': 'Email, password y nombre de organización son obligatorios'}), 400

        # Buscar usuario por email
        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({'message': 'Usuario no encontrado'}), 404

        # Verificar contraseña
        if not check_password_hash(user.password, password):
            return jsonify({'message': 'Contraseña incorrecta'}), 401

        # Usuario validado correctamente
        return jsonify({
            'success': True,
            'message': 'Usuario validado correctamente',
            'userId': user.id,
            'userName': user.name
        }), 200

    except Exception as e:
        app.logger.error(f"Error validating user for organization: {e}")
        return jsonify({'message': 'Error al validar el usuario'}), 500

@app.route('/register-user-organization', methods=['POST'])
def register_user_organization():
    """
    Crea un nuevo usuario en la base de datos para el proceso de registro de organización.
    Verifica primero que el usuario no exista.
    """
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        organization_name = data.get('organizationName')

        if not email or not password or not organization_name:
            return jsonify({'message': 'Email, password y nombre de organización son obligatorios'}), 400

        # Verificar que el usuario no exista
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'message': 'Este usuario ya existe'}), 409

        # Crear nuevo usuario
        hashed_password = generate_password_hash(password)
        new_user = User(
            email=email,
            password=hashed_password,
            name=organization_name  # Usamos el nombre de la organización como nombre del usuario por ahora
        )

        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Usuario creado correctamente',
            'userId': new_user.id,
            'userName': new_user.name
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating user for organization: {e}")
        return jsonify({'message': 'Error al crear el usuario'}), 500

@app.route('/create-verification-session', methods=['POST'])
def create_verification_session():
    """
    Crea una sesión de verificación de identidad con Stripe Identity.
    """
    try:
        data = request.get_json()
        user_id = data.get('userId')

        if not user_id:
            return jsonify({'message': 'userId es obligatorio'}), 400

        # Configurar Stripe
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

        # Crear sesión de verificación
        verification_session = stripe.identity.VerificationSession.create(
            type='document',
            metadata={
                'user_id': str(user_id)
            },
            options={
                'document': {
                    'allowed_types': ['driving_license', 'id_card', 'passport'],
                    'require_matching_selfie': True,
                }
            }
        )

        return jsonify({
            'success': True,
            'sessionId': verification_session.id,
            'clientSecret': verification_session.client_secret,
            'url': verification_session.url
        }), 200

    except Exception as e:
        app.logger.error(f"Error creating verification session: {e}")
        return jsonify({'message': f'Error al crear la sesión de verificación: {str(e)}'}), 500

@app.route('/verify-identity-status/<session_id>', methods=['GET'])
def verify_identity_status(session_id):
    """
    Verifica el estado de una sesión de verificación de identidad.
    """
    try:
        # Configurar Stripe
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

        # Obtener sesión de verificación
        verification_session = stripe.identity.VerificationSession.retrieve(session_id)

        # Extraer datos verificados si están disponibles
        verified_data = None
        if verification_session.status == 'verified' and verification_session.verified_outputs:
            verified_data = {
                'dob': verification_session.verified_outputs.get('dob'),
                'id_number': verification_session.verified_outputs.get('id_number'),
                'first_name': verification_session.verified_outputs.get('first_name'),
                'last_name': verification_session.verified_outputs.get('last_name'),
                'address': verification_session.verified_outputs.get('address'),
            }

        return jsonify({
            'success': True,
            'status': verification_session.status,
            'verifiedData': verified_data,
            'lastError': verification_session.last_error.get('reason') if verification_session.last_error else None
        }), 200

    except Exception as e:
        app.logger.error(f"Error verifying identity status: {e}")
        return jsonify({'message': f'Error al verificar el estado: {str(e)}'}), 500

@app.route('/send-reset-code', methods=['POST'])
def send_reset_code():
    try:
        data = request.get_json()
        email = data.get('email')
        if not email:
            return jsonify({'message': 'Email is required!'}), 400
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'message': 'User not found!'}), 404
        reset_code = f"{random.randint(100000, 999999)}"
        user.reset_code = reset_code
        db.session.commit()
        sender_email = os.getenv('EMAIL_USER','colegios@penwin.org')
        sender_password = os.getenv('EMAIL_PASS','kqoq qsba bsoc srek')
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', 587))
        msg = MIMEText(f"Your password reset code is: {reset_code}")
        msg['Subject'] = 'Password Reset Code'
        msg['From'] = sender_email
        msg['To'] = email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        return jsonify({'message': 'Reset code sent to your email!'}), 200
    except Exception as e:
        app.logger.error(f"Error sending reset code: {e}")
        return jsonify({'message': 'An error occurred while sending the reset code.'}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email')
        otp = data.get('otp')
        if not email or not otp:
            return jsonify({'message': 'Email and OTP are required!'}), 400
        user = User.query.filter_by(email=email, reset_code=otp).first()
        if not user:
            return jsonify({'message': 'Invalid email or OTP!'}), 400
        token = jwt.encode(
            {
                'user_id': user.id,
                'exp': datetime.utcnow() + timedelta(hours=1)
            },
            app.config['SECRET_KEY'],
            algorithm="HS256"
        )
        user.reset_code = None
        db.session.commit()
        return jsonify({'message': 'OTP verified successfully!', 'token': token}), 200
    except Exception as e:
        app.logger.error(f"Error verifying OTP: {e}")
        return jsonify({'message': 'An error occurred during OTP verification.'}), 500

@app.route('/change-password', methods=['POST'])
def change_password():
    try:
        data = request.get_json()
        email = data.get('email')
        reset_code = data.get('reset_code')
        new_password = data.get('new_password')
        if not email or not reset_code or not new_password:
            return jsonify({'message': 'All fields are required!'}), 400
        user = User.query.filter_by(email=email, reset_code=reset_code).first()
        if not user:
            return jsonify({'message': 'Invalid email or reset code!'}), 400
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.password = hashed_password
        user.reset_code = None
        db.session.commit()
        return jsonify({'message': 'Password updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error during password change: {e}")
        return jsonify({'message': 'An error occurred while changing the password.'}), 500

@app.route('/update-password', methods=['POST'])
@token_required
def update_password(current_user):
    """Cambiar contraseña del usuario autenticado"""
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')

        if not current_password or not new_password:
            return jsonify({'message': 'Current password and new password are required!'}), 400

        # Verificar contraseña actual
        if not check_password_hash(current_user.password, current_password):
            return jsonify({'message': 'Current password is incorrect!'}), 400

        # Validar nueva contraseña (mínimo 6 caracteres)
        if len(new_password) < 6:
            return jsonify({'message': 'New password must be at least 6 characters long!'}), 400

        # Actualizar contraseña
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        current_user.password = hashed_password
        db.session.commit()

        return jsonify({'message': 'Password updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error updating password: {e}")
        return jsonify({'message': 'An error occurred while updating the password.'}), 500

@app.route('/get-personal-info', methods=['GET'])
@token_required
def get_personal_info(current_user):
    """Obtener información personal del usuario autenticado"""
    try:
        # Obtener configuraciones del usuario desde user_settings JSON
        user_settings = current_user.user_settings or {}
        if isinstance(user_settings, str):
            try:
                user_settings = json.loads(user_settings)
            except:
                user_settings = {}

        return jsonify({
            'username': current_user.username,
            'email': current_user.email,
            'phone': user_settings.get('phone', ''),
            'dni': user_settings.get('dni', '')
        }), 200
    except Exception as e:
        app.logger.error(f"Error getting personal info: {e}")
        return jsonify({'message': 'An error occurred while getting personal information.'}), 500

@app.route('/update-personal-info', methods=['POST'])
@token_required
def update_personal_info(current_user):
    """Actualizar información personal del usuario autenticado"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        dni = data.get('dni', '').strip()

        # Validaciones básicas
        if not username:
            return jsonify({'message': 'Username is required!'}), 400

        if len(username) < 2:
            return jsonify({'message': 'Username must be at least 2 characters long!'}), 400

        # Verificar si el username ya existe (excluyendo el usuario actual)
        existing_user = User.query.filter(User.username == username, User.id != current_user.id).first()
        if existing_user:
            return jsonify({'message': 'Username already exists!'}), 400

        # Obtener user_settings actual
        user_settings = current_user.user_settings or {}
        if isinstance(user_settings, str):
            try:
                user_settings = json.loads(user_settings)
            except:
                user_settings = {}

        # Actualizar solo información básica que se puede cambiar (username únicamente)
        current_user.username = username
        # El email NO se actualiza - se mantiene el actual

        # Actualizar phone y dni en user_settings
        user_settings['phone'] = phone if phone else ''
        user_settings['dni'] = dni if dni else ''

        current_user.user_settings = user_settings

        # Marcar el campo JSON como modificado para que SQLAlchemy lo actualice
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(current_user, "user_settings")

        db.session.commit()

        return jsonify({
            'message': 'Personal information updated successfully!',
            'username': current_user.username,
            'email': current_user.email,
            'phone': user_settings.get('phone', ''),
            'dni': user_settings.get('dni', '')
        }), 200
    except Exception as e:
        app.logger.error(f"Error updating personal info: {e}")
        return jsonify({'message': 'An error occurred while updating personal information.'}), 500

@app.route('/roles', methods=['GET'])
@token_required
def get_roles(current_user):
    try:
        is_superadmin = current_user.role.upper() == "SUPERADMIN"
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id, role='ORG_ADMIN').all()
        org_admin_ids = [uo.organization_id for uo in user_orgs]
        user_channels_admin = json.loads(current_user.channels_admin) if current_user.channels_admin else []
        org_channels = Channel.query.filter(Channel.organization_id.in_(org_admin_ids)).all()
        org_channels_ids = [channel.id_code for channel in org_channels]
        all_admin_channels = list(set(user_channels_admin + org_channels_ids))
        return jsonify({
            'superadmin': is_superadmin,
            'organizations_admin': org_admin_ids,
            'channels_admin': all_admin_channels
        }), 200
    except Exception as e:
        app.logger.error(f"Error retrieving user roles: {e}")
        return jsonify({'message': 'An error occurred while retrieving user roles.'}), 500

@app.route('/create-organization', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def create_organization(current_user):
    try:
        data = request.get_json()
        org_name = data.get('name')
        parish_type = data.get('parish_type')  # 'parish' o 'diocese'
        parish_id = data.get('parish_id')
        parish_name = data.get('parish_name')
        diocese_name = data.get('diocese_name')

        if not org_name:
            return jsonify({'message': 'Organization name is required!'}), 400
        if not parish_type:
            return jsonify({'message': 'Parish type is required!'}), 400
        if parish_type not in ['parish', 'diocese']:
            return jsonify({'message': 'Parish type must be "parish" or "diocese"!'}), 400

        if Organization.query.filter_by(name=org_name).first():
            return jsonify({'message': 'Organization already exists!'}), 400

        # Si es una parroquia, validar que existe
        if parish_type == 'parish' and parish_id:
            selected_parish = ParroquiaCee.query.filter_by(id=parish_id).first()
            if not selected_parish:
                return jsonify({'message': 'Selected parish does not exist!'}), 400
            parish_name = selected_parish.nombre_parroquia
            diocese_name = selected_parish.diocesis

        new_org = Organization(
            name=org_name,
            parish_type=parish_type,
            parish_id=parish_id,
            parish_name=parish_name,
            diocese_name=diocese_name
        )
        db.session.add(new_org)
        db.session.flush()  # Flush para obtener el ID de la organización

        # Crear canal principal con el mismo nombre de la organización
        main_channel = Channel(
            name=org_name,  # Mismo nombre que la organización
            organization_id=new_org.id
        )
        db.session.add(main_channel)
        db.session.flush()  # Flush para obtener el ID del canal

        # Asignar el canal como canal principal de la organización
        new_org.main_channel_id = main_channel.id

        db.session.commit()

        app.logger.info(f"✅ Organization '{org_name}' created with main channel '{main_channel.name}' (ID: {main_channel.id})")

        return jsonify({
            'message': 'Organization and main channel created successfully!',
            'organization_id': new_org.id,
            'main_channel_id': main_channel.id
        }), 201
    except Exception as e:
        app.logger.error(f"Error creating organization: {e}")
        return jsonify({'message': 'An error occurred while creating the organization.'}), 500

@app.route('/update-organization-main-channel', methods=['POST'])
@token_required
def update_organization_main_channel(current_user):
    """
    Actualiza el canal principal de una organización
    Body JSON:
    {
        "organization_id": 1,
        "main_channel_id": 5
    }
    """
    try:
        data = request.get_json()
        organization_id = data.get('organization_id')
        main_channel_id = data.get('main_channel_id')

        if not organization_id or not main_channel_id:
            return jsonify({'message': 'organization_id and main_channel_id are required!'}), 400

        # Buscar la organización
        organization = Organization.query.get(organization_id)
        if not organization:
            return jsonify({'message': 'Organization not found!'}), 404

        # Verificar que el canal existe y pertenece a esta organización
        channel = Channel.query.get(main_channel_id)
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        if channel.organization_id != organization_id:
            return jsonify({'message': 'Channel does not belong to this organization!'}), 400

        # Verificar permisos (SUPERADMIN o ORG_ADMIN)
        org_admin_perm = OrganizationAdminPermission(organization_id)
        if not (superadmin_permission.can() or org_admin_perm.can()):
            return jsonify({'message': 'No permission to update organization main channel!'}), 403

        # Actualizar el canal principal
        organization.main_channel_id = main_channel_id
        db.session.commit()

        app.logger.info(f"✅ Organization '{organization.name}' main channel updated to '{channel.name}' (ID: {channel.id})")

        return jsonify({
            'message': 'Main channel updated successfully!',
            'organization_id': organization.id,
            'main_channel_id': channel.id,
            'main_channel_name': channel.name
        }), 200

    except Exception as e:
        app.logger.error(f"Error updating organization main channel: {e}")
        return jsonify({'message': 'An error occurred while updating the main channel.'}), 500

@app.route('/update-organization', methods=['POST'])
@token_required
def update_organization(current_user):
    """
    Actualiza la información de una organización
    Soporta JSON o FormData (para subir logotipo personalizado)
    """
    try:
        # Detectar si es FormData o JSON
        is_form_data = request.content_type and 'multipart/form-data' in request.content_type

        if is_form_data:
            # Obtener datos del FormData
            organization_id = request.form.get('organization_id')
            logo_color = request.form.get('logo_color')
            custom_logo = request.files.get('custom_logo')
        else:
            # Obtener datos del JSON
            data = request.get_json()
            organization_id = data.get('organization_id')
            logo_color = data.get('logo_color')
            custom_logo = None

        if not organization_id:
            return jsonify({'message': 'organization_id is required!'}), 400

        # Buscar la organización
        organization = Organization.query.get(int(organization_id))
        if not organization:
            return jsonify({'message': 'Organization not found!'}), 404

        # Verificar permisos (SUPERADMIN o ORG_ADMIN)
        org_admin_perm = OrganizationAdminPermission(int(organization_id))
        if not (superadmin_permission.can() or org_admin_perm.can()):
            return jsonify({'message': 'No permission to update organization!'}), 403

        # Actualizar logo_color si se proporciona
        if logo_color:
            # Validar formato hexadecimal
            if not (logo_color.startswith('#') and len(logo_color) == 7):
                return jsonify({'message': 'logo_color must be in hexadecimal format (#RRGGBB)'}), 400
            organization.logo_color = logo_color

        # Si hay logotipo personalizado, subirlo a S3
        if custom_logo:
            try:
                # Validar que sea PNG
                if not custom_logo.filename.lower().endswith('.png'):
                    return jsonify({'message': 'Custom logo must be a PNG file'}), 400

                # Generar nombre único para el archivo
                import uuid
                filename = f"logo_{uuid.uuid4().hex}.png"
                s3_key = f"app/organizations/{organization.id}/{filename}"

                # Subir a S3
                s3.upload_fileobj(
                    custom_logo,
                    S3_BUCKET,
                    s3_key,
                    ExtraArgs={"ACL": "public-read", "ContentType": "image/png"}
                )

                # Construir URL del logotipo
                custom_logo_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
                organization.custom_logo_url = custom_logo_url

                app.logger.info(f"✅ Custom logo uploaded to S3: {custom_logo_url}")

            except Exception as upload_error:
                app.logger.error(f"Error uploading custom logo to S3: {upload_error}")
                return jsonify({'message': 'Error uploading custom logo'}), 500

        # Si no es FormData, actualizar otros campos del JSON
        if not is_form_data:
            data = request.get_json()

            if 'logo_url' in data:
                organization.logo_url = data['logo_url']

            if 'description' in data:
                organization.description = data['description']

            if 'city' in data:
                organization.city = data['city']

            if 'country' in data:
                organization.country = data['country']

            if 'show_channel_navigation' in data:
                organization.show_channel_navigation = bool(data['show_channel_navigation'])

        db.session.commit()

        app.logger.info(f"✅ Organization '{organization.name}' (ID: {organization.id}) updated successfully")

        return jsonify({
            'message': 'Organization updated successfully!',
            'organization': {
                'id': organization.id,
                'name': organization.name,
                'logo_color': organization.logo_color,
                'logo_url': organization.logo_url,
                'custom_logo_url': organization.custom_logo_url,
                'description': organization.description,
                'city': organization.city,
                'country': organization.country,
                'show_channel_navigation': organization.show_channel_navigation or False
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error updating organization: {e}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'message': 'An error occurred while updating the organization.'}), 500

@app.route('/assign-org-admin', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def assign_org_admin(current_user):
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        organization_id = data.get('organization_id')
        if not user_id or not organization_id:
            return jsonify({'message': 'user_id and organization_id are required!'}), 400
        user_obj = User.query.get(user_id)
        org_obj = Organization.query.get(organization_id)
        if not user_obj or not org_obj:
            return jsonify({'message': 'User or Organization not found!'}), 404
        existing = UserOrganization.query.filter_by(user_id=user_id, organization_id=organization_id).first()
        if existing:
            existing.role = 'ORG_ADMIN'
        else:
            new_uo = UserOrganization(user_id=user_id, organization_id=organization_id, role='ORG_ADMIN')
            db.session.add(new_uo)
        db.session.commit()
        return jsonify({'message': 'User assigned as ORG_ADMIN successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error assigning org admin: {e}")
        return jsonify({'message': 'An error occurred while assigning org admin.'}), 500

@app.route('/remove-org-admin', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def remove_org_admin(current_user):
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        organization_id = data.get('organization_id')

        if not user_id or not organization_id:
            return jsonify({'message': 'user_id and organization_id are required!'}), 400

        # Verificar que el usuario y la organización existen
        user_obj = User.query.get(user_id)
        org_obj = Organization.query.get(organization_id)

        if not user_obj or not org_obj:
            return jsonify({'message': 'User or Organization not found!'}), 404

        # Buscar la relación UserOrganization
        user_org = UserOrganization.query.filter_by(
            user_id=user_id,
            organization_id=organization_id,
            role='ORG_ADMIN'
        ).first()

        if not user_org:
            return jsonify({'message': 'User is not an admin of this organization!'}), 404

        # Remover la relación (o cambiar el rol si hay otros roles)
        db.session.delete(user_org)
        db.session.commit()

        return jsonify({'message': 'User removed from ORG_ADMIN successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error removing org admin: {e}")
        return jsonify({'message': 'An error occurred while removing org admin.'}), 500

@app.route('/organizations', methods=['GET'])
@token_required
def get_organizations(current_user):
    try:
        organizations = Organization.query.all()
        org_list = []
        for org in organizations:
            # Contar usuarios en la organización
            user_count = UserOrganization.query.filter_by(organization_id=org.id).count()

            org_list.append({
                'id': org.id,
                'name': org.name,
                'user_count': user_count,
                'parish_type': org.parish_type,
                'parish_name': org.parish_name,
                'diocese_name': org.diocese_name,
                'logo_color': org.logo_color,
                'logo_url': org.logo_url,
                'custom_logo_url': org.custom_logo_url,
                'description': org.description
            })
        return jsonify({'organizations': org_list}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving organizations: {e}")
        return jsonify({'message': 'An error occurred while retrieving organizations.'}), 500

@app.route('/organization/<int:org_id>/admins', methods=['GET'])
@token_required
def get_organization_admins(current_user, org_id):
    try:
        app.logger.info(f"Getting admins for organization {org_id}")

        # Verificar que la organización existe
        organization = Organization.query.get(org_id)
        app.logger.info(f"Organization found: {organization.name if organization else 'None'}")
        if not organization:
            return jsonify({'message': 'Organization not found!'}), 404

        # Obtener administradores de la organización
        admin_relationships = UserOrganization.query.filter_by(
            organization_id=org_id,
            role='ORG_ADMIN'
        ).all()
        app.logger.info(f"Found {len(admin_relationships)} admin relationships")

        admins = []
        for rel in admin_relationships:
            user = User.query.get(rel.user_id)
            app.logger.info(f"Processing user {rel.user_id}: {user.username if user else 'None'}")
            if user:
                admins.append({
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                })

        app.logger.info(f"Returning {len(admins)} admins")
        return jsonify({
            'organization': {
                'id': organization.id,
                'name': organization.name
            },
            'admins': admins
        }), 200
    except Exception as e:
        app.logger.error(f"Error retrieving organization admins: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'message': 'An error occurred while retrieving organization admins.'}), 500

@app.route('/users', methods=['GET'])
@token_required
@superadmin_permission.require(http_exception=403)
def get_users(current_user):
    try:
        # Obtener todos los usuarios excepto superadmins
        users = User.query.filter(User.role != 'SUPERADMIN').all()
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'username': user.username,
                'email': user.email
            })
        return jsonify({'users': user_list}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving users: {e}")
        return jsonify({'message': 'An error occurred while retrieving users.'}), 500

@app.route('/create-channel-db', methods=['POST'])
@token_required
def create_channel_db(current_user):
    """
    Primero, crea el canal en la base de datos para que MySQL genere el `id_code` automáticamente.
    Luego, devuelve el `id_code` generado para usarlo en la subida a S3.
    """
    try:
        data = request.get_json()
        name = data.get('name')
        organization_id = data.get('organization_id')

        if not name or not organization_id:
            return jsonify({'message': 'Channel name and organization_id are required!'}), 400

        if Channel.query.filter_by(name=name).first():
            return jsonify({'message': 'Channel already exists!'}), 400

        # Validar permisos
        org_admin_perm = OrganizationAdminPermission(organization_id)
        if not (superadmin_permission.can() or org_admin_perm.can()):
            return jsonify({'message': 'No permission to create channels in this org!'}), 403

        # Crear el canal en la base de datos (sin imagen)
        new_channel = Channel(name=name, organization_id=organization_id)
        db.session.add(new_channel)
        db.session.commit()

        # Obtener el canal nuevamente para recuperar el `id_code` generado por MySQL
        db.session.refresh(new_channel)

        return jsonify({'message': 'Channel created in DB!', 'id_code': new_channel.id_code}), 201

    except Exception as e:
        app.logger.error(f"Error creating channel in DB: {e}")
        return jsonify({'message': 'An error occurred while creating the channel in the database.'}), 500

@app.route('/upload-channel-image', methods=['POST'])
@token_required
def upload_channel_image(current_user):
    try:
        id_code = request.form.get('id_code')
        image = request.files.get('image')
        if image is None:
            app.logger.error("El archivo de imagen es None.")
            return jsonify({'message': 'No se proporcionó ningún archivo de imagen.'}), 400
        if not id_code:
            app.logger.error("❌ `id_code` no recibido en la solicitud.")
            return jsonify({'message': 'id_code is required!'}), 400
        app.logger.info(f"📡 `id_code` recibido en Flask: {id_code}")
        channel = Channel.query.filter_by(id_code=id_code).first()
        if not channel:
            app.logger.error(f"❌ No se encontró el canal con `id_code`: {id_code}")
            return jsonify({'message': f'Channel not found! id_code: {id_code}'}), 404
        app.logger.info(f"✅ Canal encontrado: {channel.name} (ID: {channel.id})")
        filename = secure_filename(image.filename)
        app.logger.info(f"📁 Nombre del archivo recibido: {filename}")
        if not filename:
            app.logger.error("❌ `filename` es None. Posible error en la imagen recibida.")
            return jsonify({'message': 'Invalid image file!'}), 400
        content_type = image.content_type
        app.logger.info(f"📝 Tipo de contenido recibido: {content_type}")
        if not content_type:
            app.logger.error("❌ `content_type` es None. Posible error en la imagen recibida.")
            return jsonify({'message': 'Invalid image type!'}), 400
        image.seek(0, os.SEEK_END)
        image_size = image.tell()
        image.seek(0)
        app.logger.info(f"📏 Tamaño de la imagen recibida: {image_size} bytes")
        if image_size == 0:
            app.logger.error("❌ La imagen está vacía o corrupta.")
            return jsonify({'message': 'Uploaded image is empty!'}), 400
        s3_key = f"app/channels/{id_code}/profile.jpeg"
        app.logger.info(f"📡 Subiendo a S3: {s3_key}")
        s3.upload_fileobj(
            image,
            S3_BUCKET,
            s3_key,
            ExtraArgs={"ACL": "public-read", "ContentType": content_type},
        )
        image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        app.logger.info(f"✅ Imagen subida correctamente: {image_url}")
        channel.image_url = image_url
        # Incrementamos la versión del canal
        channel.version = (channel.version or 1) + 1        
        db.session.commit()
        return jsonify({'message': 'Image uploaded successfully!', 'image_url': image_url}), 200
    except Exception as e:
        app.logger.error(f"❌ Error al subir la imagen a S3: {str(e)}")
        return jsonify({'message': 'An error occurred while uploading the image.', 'error': str(e)}), 500

# --------------- Generate and Upload Thumbnail -------------
def generate_and_upload_thumbnail(original_s3_key, image_bytes, content_type):
    """
    Genera un thumbnail de 400x400 y lo sube a S3

    Args:
        original_s3_key: La clave S3 de la imagen original (ej: "app/posts/channel_47/123.jpg")
        image_bytes: Los bytes de la imagen original
        content_type: El content type de la imagen

    Returns:
        str: URL del thumbnail generado, o None si falla
    """
    try:
        app.logger.info(f"🖼️ Generando thumbnail para: {original_s3_key}")

        # Abrir imagen con PIL
        img = Image.open(io.BytesIO(image_bytes))

        # Convertir RGBA a RGB si es necesario (para PNGs con transparencia)
        if img.mode in ('RGBA', 'LA', 'P'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'P':
                img = img.convert('RGBA')
            background.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
            img = background

        # Generar thumbnail de 400x400 manteniendo el aspect ratio
        img.thumbnail((400, 400), Image.Resampling.LANCZOS)

        # Guardar en bytes
        thumb_buffer = io.BytesIO()
        img.save(thumb_buffer, format='JPEG', quality=85, optimize=True)
        thumb_buffer.seek(0)

        # Determinar la ruta del thumbnail
        # Para /app/posts/channel_XX/filename.ext → /app/posts/channel_XX/thumbnails/thumb_filename.jpg
        # Para /events/filename.ext → /events/thumbnails/thumb_filename.jpg

        if '/posts/' in original_s3_key:
            # Caso: app/posts/channel_47/123.png
            parts = original_s3_key.split('/posts/')
            if len(parts) == 2:
                base_path = parts[0]  # "app"
                rest = parts[1]  # "channel_47/123.png"
                path_parts = rest.split('/')
                if len(path_parts) >= 2:
                    channel_part = path_parts[0]  # "channel_47"
                    filename = path_parts[-1]  # "123.png"
                    filename_base = filename.rsplit('.', 1)[0]  # "123"
                    thumb_s3_key = f"{base_path}/posts/{channel_part}/thumbnails/thumb_{filename_base}.jpg"
                else:
                    app.logger.error(f"❌ Formato inesperado de s3_key: {original_s3_key}")
                    return None
            else:
                app.logger.error(f"❌ No se pudo parsear /posts/ en: {original_s3_key}")
                return None
        elif '/events/' in original_s3_key:
            # Caso: events/123-file.png
            parts = original_s3_key.split('/events/')
            if len(parts) == 2:
                base_path = parts[0] if parts[0] else ''  # Puede estar vacío
                filename = parts[1]  # "123-file.png"
                filename_base = filename.rsplit('.', 1)[0]  # "123-file"
                thumb_s3_key = f"{base_path}/events/thumbnails/thumb_{filename_base}.jpg".lstrip('/')
            else:
                app.logger.error(f"❌ No se pudo parsear /events/ en: {original_s3_key}")
                return None
        else:
            app.logger.warning(f"⚠️ S3 key no soportado para thumbnails: {original_s3_key}")
            return None

        # Subir thumbnail a S3
        app.logger.info(f"📤 Subiendo thumbnail a: {thumb_s3_key}")
        s3.upload_fileobj(
            thumb_buffer,
            S3_BUCKET,
            thumb_s3_key,
            ExtraArgs={"ACL": "public-read", "ContentType": "image/jpeg"},
        )

        # Generar URL del thumbnail
        thumb_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{thumb_s3_key}"
        app.logger.info(f"✅ Thumbnail generado: {thumb_url}")

        return thumb_url

    except Exception as e:
        app.logger.error(f"❌ Error generando thumbnail: {str(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return None

# --------------- Upload Post Image to S3 -------------
@app.route('/upload-post-image', methods=['POST'])
@token_required
def upload_post_image(current_user):
    try:
        app.logger.info("🚀 Iniciando subida de imagen de post a S3...")

        # Obtener archivo de imagen del request
        image = request.files.get('image')
        if image is None:
            app.logger.error("El archivo de imagen es None.")
            return jsonify({'message': 'No se proporcionó ningún archivo de imagen.'}), 400

        # Obtener datos adicionales del formulario
        post_id = request.form.get('post_id')
        channel_id = request.form.get('channel_id', '1')  # Canal por defecto si no se especifica

        # Generar ID único para el post si no se proporciona
        if not post_id:
            post_id = str(int(time.time() * 1000))  # Timestamp en milisegundos

        app.logger.info(f"📝 Datos recibidos: post_id={post_id}, channel_id={channel_id}")

        # Validar archivo
        filename = secure_filename(image.filename)
        if not filename:
            app.logger.error("❌ `filename` es None. Posible error en la imagen recibida.")
            return jsonify({'message': 'Invalid image file!'}), 400

        content_type = image.content_type
        if not content_type:
            app.logger.error("❌ `content_type` es None. Posible error en la imagen recibida.")
            return jsonify({'message': 'Invalid image type!'}), 400

        # Verificar tamaño
        image.seek(0, os.SEEK_END)
        image_size = image.tell()
        image.seek(0)
        app.logger.info(f"📏 Tamaño de la imagen recibida: {image_size} bytes")

        if image_size == 0:
            app.logger.error("❌ La imagen está vacía o corrupta.")
            return jsonify({'message': 'Uploaded image is empty!'}), 400

        # Crear key para S3 basado en canal y post
        file_extension = filename.split('.')[-1] if '.' in filename else 'jpg'
        s3_key = f"app/posts/channel_{channel_id}/{post_id}.{file_extension}"

        app.logger.info(f"📡 Subiendo a S3: {s3_key}")

        # Leer los bytes de la imagen para generar thumbnail
        image.seek(0)
        image_bytes = image.read()
        image.seek(0)  # Resetear para el upload

        # Subir imagen original a S3
        s3.upload_fileobj(
            image,
            S3_BUCKET,
            s3_key,
            ExtraArgs={"ACL": "public-read", "ContentType": content_type},
        )

        # Generar URL pública
        image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        app.logger.info(f"✅ Imagen de post subida correctamente: {image_url}")

        # Generar thumbnail
        thumbnail_url = generate_and_upload_thumbnail(s3_key, image_bytes, content_type)

        return jsonify({
            'message': 'Post image uploaded successfully!',
            'image_url': image_url,
            'thumbnail_url': thumbnail_url,
            'post_id': post_id,
            's3_key': s3_key
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error al subir la imagen del post a S3: {str(e)}")
        return jsonify({'message': 'An error occurred while uploading the post image.', 'error': str(e)}), 500

# --------------- Upload Post Image from URL to S3 -------------
@app.route('/upload-post-image-url', methods=['POST'])
@token_required
def upload_post_image_url(current_user):
    try:
        app.logger.info("🚀 Iniciando subida de imagen desde URL a S3...")

        data = request.get_json()
        image_url = data.get('image_url')
        channel_id = data.get('channel_id', '1')
        post_id = data.get('post_id')

        if not image_url:
            return jsonify({'message': 'image_url is required'}), 400

        # Generar ID único para el post si no se proporciona
        if not post_id:
            post_id = str(int(time.time() * 1000))

        app.logger.info(f"📝 Datos recibidos: image_url={image_url}, channel_id={channel_id}, post_id={post_id}")

        # Descargar la imagen desde la URL
        response = requests.get(image_url, timeout=30)
        if response.status_code != 200:
            app.logger.error(f"❌ Error descargando imagen desde URL: {response.status_code}")
            return jsonify({'message': f'Failed to download image from URL: {response.status_code}'}), 400

        # Determinar extensión del archivo
        content_type = response.headers.get('content-type', 'image/jpeg')
        if 'png' in content_type:
            file_extension = 'png'
        elif 'gif' in content_type:
            file_extension = 'gif'
        else:
            file_extension = 'jpg'

        # Crear key para S3
        s3_key = f"app/posts/channel_{channel_id}/{post_id}.{file_extension}"

        app.logger.info(f"📡 Subiendo a S3: {s3_key}")

        # Guardar bytes de la imagen para generar thumbnail
        image_bytes = response.content

        # Subir imagen original a S3
        s3.upload_fileobj(
            io.BytesIO(image_bytes),
            S3_BUCKET,
            s3_key,
            ExtraArgs={"ACL": "public-read", "ContentType": content_type},
        )

        # Generar URL pública
        s3_image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        app.logger.info(f"✅ Imagen subida a S3 desde URL: {s3_image_url}")

        # Generar thumbnail
        thumbnail_url = generate_and_upload_thumbnail(s3_key, image_bytes, content_type)

        return jsonify({
            'message': 'Post image uploaded successfully from URL!',
            'image_url': s3_image_url,
            'thumbnail_url': thumbnail_url,
            'post_id': post_id,
            's3_key': s3_key
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error al subir imagen desde URL a S3: {str(e)}")
        return jsonify({'message': 'An error occurred while uploading the image from URL.', 'error': str(e)}), 500

# --------------- Upload Post Video to S3 -------------
@app.route('/upload-post-video', methods=['POST'])
@token_required
def upload_post_video(current_user):
    try:
        if 'video' not in request.files:
            app.logger.error("❌ No video file found in request")
            return jsonify({'message': 'No video file provided!'}), 400

        video = request.files['video']
        if not video:
            app.logger.error("❌ Video file is None")
            return jsonify({'message': 'Invalid video file!'}), 400

        # Obtener datos adicionales del formulario
        post_id = request.form.get('post_id')
        channel_id = request.form.get('channel_id', '1')  # Canal por defecto si no se especifica

        # Generar ID único para el post si no se proporciona
        if not post_id:
            post_id = str(int(time.time() * 1000))  # Timestamp en milisegundos

        app.logger.info(f"📝 Video upload data: post_id={post_id}, channel_id={channel_id}")

        # Validar archivo de video
        filename = secure_filename(video.filename)
        if not filename:
            app.logger.error("❌ `filename` es None. Posible error en el video recibido.")
            return jsonify({'message': 'Invalid video file!'}), 400

        content_type = video.content_type
        if not content_type or not content_type.startswith('video'):
            app.logger.error("❌ `content_type` no es video. Posible error en el archivo recibido.")
            return jsonify({'message': 'Invalid video file type!'}), 400

        # Verificar tamaño del video (límite de 100MB para videos)
        video.seek(0, os.SEEK_END)
        video_size = video.tell()
        video.seek(0)
        app.logger.info(f"📏 Tamaño del video recibido: {video_size} bytes")

        if video_size == 0:
            app.logger.error("❌ El video está vacío o corrupto.")
            return jsonify({'message': 'Uploaded video is empty!'}), 400

        if video_size > 100 * 1024 * 1024:  # 100MB límite
            app.logger.error("❌ El video es demasiado grande.")
            return jsonify({'message': 'Video file too large! Maximum 100MB allowed.'}), 400

        # Crear key para S3 basado en canal y post
        file_extension = filename.split('.')[-1] if '.' in filename else 'mp4'
        s3_key = f"app/posts/channel_{channel_id}/videos/{post_id}.{file_extension}"

        app.logger.info(f"📡 Subiendo video a S3: {s3_key}")

        # Subir a S3
        s3.upload_fileobj(
            video,
            S3_BUCKET,
            s3_key,
            ExtraArgs={"ACL": "public-read", "ContentType": content_type},
        )

        # Generar URL pública
        video_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        app.logger.info(f"✅ Video subido correctamente: {video_url}")

        return jsonify({
            'message': 'Video uploaded successfully!',
            'video_url': video_url,
            'post_id': post_id,
            's3_key': s3_key
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error al subir video del post a S3: {str(e)}")
        return jsonify({'message': 'An error occurred while uploading the post video.', 'error': str(e)}), 500

# --------------- Crear Canal (SUPERADMIN o ORG_ADMIN) -------------
@app.route('/create-channel', methods=['POST'])
@token_required
def create_channel(current_user):
    try:
        data = request.get_json()
        channel_name = data.get('name')
        organization_id = data.get('organization_id')

        if not channel_name or not organization_id:
            return jsonify({'message': 'Channel name and organization_id are required!'}), 400

        if Channel.query.filter_by(name=channel_name).first():
            return jsonify({'message': 'Channel already exists!'}), 400

        # Check permisos
        org_admin_perm = OrganizationAdminPermission(organization_id)

        # SUPERADMIN => skip check
        if superadmin_permission.can():
            pass
        else:
            if not org_admin_perm.can():
                return jsonify({'message': 'No permission to create channels in this org!'}), 403

        new_channel = Channel(name=channel_name, organization_id=organization_id)
        db.session.add(new_channel)
        db.session.commit()

        return jsonify({'message': 'Channel created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating channel: {e}")
        return jsonify({'message': 'An error occurred while creating the channel.'}), 500

@app.route('/assign-channel-admin', methods=['POST'])
@token_required
def assign_channel_admin(current_user):
    """
    Asigna a un usuario como administrador de un canal usando:
    - user_id_code: el id_code único del usuario (en lugar de su id numérico).
    - channel_id_code: el id_code único del canal (en lugar de su id numérico).

    Body JSON esperado:
    {
        "user_id_code": "abc123_user",
        "channel_id_code": "xyz789_channel"
    }
    """
    try:
        data = request.get_json()
        user_id_code = data.get('user_id_code')
        channel_id_code = data.get('channel_id_code')

        # Validaciones básicas
        if not user_id_code or not channel_id_code:
            return jsonify({
                'message': 'user_id_code and channel_id_code are required!'
            }), 400

        # 1) Buscar el canal por su id_code
        channel = Channel.query.filter_by(id_code=channel_id_code).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # 2) Verificar permisos:
        #    - SUPERADMIN, o
        #    - ORG_ADMIN de la organización a la que pertenece el canal
        if not superadmin_permission.can():
            org_admin_perm = OrganizationAdminPermission(channel.organization_id)
            if not org_admin_perm.can():
                return jsonify({
                    'message': 'No permission to assign admin in this channel!'
                }), 403

        # 3) Buscar el usuario por su id_code
        user_obj = User.query.filter_by(id_code=user_id_code).first()
        if not user_obj:
            return jsonify({'message': 'Target user not found!'}), 404

        # 4) Crear o actualizar registro en la tabla UserChannel
        #    Nota: UserChannel guarda los IDs numéricos (user_id, channel_id),
        #    así que usamos user_obj.id y channel.id
        existing = UserChannel.query.filter_by(
            user_id=user_obj.id, 
            channel_id=channel.id
        ).first()
        if existing:
            existing.role = 'CHANNEL_ADMIN'
        else:
            new_uc = UserChannel(
                user_id=user_obj.id,
                channel_id=channel.id,
                role='CHANNEL_ADMIN'
            )
            db.session.add(new_uc)

        # 5) Actualizar la lista channels_admin en la tabla User
        channels_admin = []
        if user_obj.channels_admin:
            try:
                if isinstance(user_obj.channels_admin, str):
                    channels_admin = json.loads(user_obj.channels_admin)
                elif isinstance(user_obj.channels_admin, list):
                    channels_admin = user_obj.channels_admin
                else:
                    raise ValueError("Unexpected channels_admin format")
            except (json.JSONDecodeError, ValueError, TypeError) as e:
                app.logger.error(
                    f"Invalid JSON format in channels_admin field for user {user_obj.id}: {e}. " 
                    "Resetting to empty list."
                )
                channels_admin = []

        # Si el canal en cuestión no está aún en la lista, se añade
        if channel.id_code not in channels_admin:
            channels_admin.append(channel.id_code)

        user_obj.channels_admin = json.dumps(channels_admin)

        # 6) Guardar cambios
        db.session.commit()

        return jsonify({
            'message': 'User assigned as CHANNEL_ADMIN successfully!',
            'channels_admin': channels_admin
        }), 200

    except Exception as e:
        app.logger.error(f"Error assigning channel admin: {e}")
        return jsonify({
            'message': 'An error occurred while assigning channel admin.',
            'error': str(e)
        }), 500


@app.route('/remove-channel-admin', methods=['POST'])
@token_required
def remove_channel_admin(current_user):
    """
    Quita a un usuario de la lista de administradores de un canal,
    usando el id_code del usuario y el id_code del canal.
    
    Body JSON esperado:
    {
        "user_id_code": "abc123_user",
        "channel_id_code": "xyz789_channel"
    }
    """
    try:
        data = request.get_json() or {}
        user_id_code = data.get('user_id_code')
        channel_id_code = data.get('channel_id_code')

        # Validaciones
        if not user_id_code or not channel_id_code:
            return jsonify({
                'message': 'user_id_code and channel_id_code are required!'
            }), 400

        # 1) Buscar el canal por su id_code
        channel = Channel.query.filter_by(id_code=channel_id_code).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # 2) Buscar el usuario por su id_code
        user_obj = User.query.filter_by(id_code=user_id_code).first()
        if not user_obj:
            return jsonify({'message': 'User not found!'}), 404

        # 3) Buscar la relación en la tabla UserChannel
        #    (donde se guarda el rol: CHANNEL_ADMIN, etc.)
        user_channel = UserChannel.query.filter_by(
            user_id=user_obj.id,
            channel_id=channel.id
        ).first()

        if user_channel and user_channel.role == 'CHANNEL_ADMIN':
            db.session.delete(user_channel)
        else:
            return jsonify({
                'message': 'User is not an admin of this channel!'
            }), 400

        # 4) Actualizar la lista channels_admin en la tabla User
        channels_admin = []
        if user_obj.channels_admin:
            try:
                if isinstance(user_obj.channels_admin, str):
                    channels_admin = json.loads(user_obj.channels_admin)
                elif isinstance(user_obj.channels_admin, list):
                    channels_admin = user_obj.channels_admin
                else:
                    channels_admin = []
            except (json.JSONDecodeError, ValueError, TypeError) as e:
                app.logger.error(
                    f"Error parsing channels_admin for user {user_obj.id_code}: {e}"
                )
                channels_admin = []

        # Si el canal estaba en la lista, lo quitamos
        if channel.id_code in channels_admin:
            channels_admin.remove(channel.id_code)
            user_obj.channels_admin = (
                json.dumps(channels_admin) if channels_admin else json.dumps([])
            )

        db.session.commit()

        return jsonify({
            'message': 'User removed as CHANNEL_ADMIN successfully!',
            'channels_admin': channels_admin
        }), 200

    except Exception as e:
        app.logger.error(f"Error removing channel admin: {e}")
        return jsonify({
            'message': 'An error occurred while removing channel admin.',
            'error': str(e)
        }), 500


@app.route('/channels', methods=['GET'])
@token_required
def get_channels(current_user):
    """
    Obtiene la lista de canales disponibles para el usuario
    """
    try:
        # Obtener organizaciones del usuario
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id).all()

        if not user_orgs:
            # Si no tiene organizaciones, usar organización por defecto
            organization_ids = [1]
        else:
            organization_ids = [uo.organization_id for uo in user_orgs]

        # Obtener canales de las organizaciones del usuario
        channels = Channel.query.filter(
            Channel.organization_id.in_(organization_ids)
        ).all()

        channels_list = []
        for channel in channels:
            # Construir URL de la imagen del canal
            image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/app/channels/{channel.id_code}/profile.jpeg"

            channels_list.append({
                'id': channel.id,
                'id_code': channel.id_code,
                'name': channel.name,
                'organization_id': channel.organization_id,
                'image': image_url
            })

        return jsonify({
            'success': True,
            'channels': channels_list
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo canales: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/channels/discover', methods=['GET'])
@token_required
def discover_channels(current_user):
    """
    Descubre canales disponibles para el usuario, excluyendo los que ya sigue
    """
    try:
        # Obtener organizaciones del usuario
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id).all()

        if not user_orgs:
            organization_ids = [1]
        else:
            organization_ids = [uo.organization_id for uo in user_orgs]

        # Obtener suscripciones actuales del usuario
        user_subscriptions = current_user.channel_subscriptions or []
        subscribed_channel_ids = [sub.get('channel_id') for sub in user_subscriptions if sub.get('channel_id')]

        # Obtener canales de las organizaciones del usuario que NO sigue
        query = Channel.query.filter(Channel.organization_id.in_(organization_ids))

        if subscribed_channel_ids:
            query = query.filter(~Channel.id.in_(subscribed_channel_ids))

        channels = query.all()

        channels_list = []
        for channel in channels:
            image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/app/channels/{channel.id_code}/profile.jpeg"

            channels_list.append({
                'id': channel.id,
                'id_code': channel.id_code,
                'name': channel.name,
                'organization_id': channel.organization_id,
                'image_url': image_url,
                'description': getattr(channel, 'description', None)
            })

        return jsonify({
            'success': True,
            'channels': channels_list
        }), 200

    except Exception as e:
        app.logger.error(f"Error discovering channels: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/automatic-channels', methods=['GET'])
@token_required
def get_automatic_channels_alias(current_user):
    """
    Obtiene canales automáticos/litúrgicos
    Alias de /prayer-life/automatic-channels para compatibilidad
    """
    try:
        app.logger.info(f"📡 [/automatic-channels] Llamada recibida de usuario {current_user.id}")
        # Llamar directamente a la función existente
        response = get_automatic_prayer_channels(current_user)
        app.logger.info(f"✅ [/automatic-channels] Respuesta exitosa")
        return response
    except Exception as e:
        app.logger.error(f"❌ [/automatic-channels] Error: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        # Retornar respuesta vacía en lugar de error
        return jsonify({'channels': []}), 200

@app.route('/channels-admin', methods=['GET'])
@token_required
def get_channels_admin(current_user):
    try:
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id).all()
        org_admin_ids = [uo.organization_id for uo in user_orgs if uo.role == 'ORG_ADMIN']
        user_channels_admin = json.loads(current_user.channels_admin) if current_user.channels_admin else []
        org_channels = Channel.query.filter(Channel.organization_id.in_(org_admin_ids)).all()
        org_channels_ids = [channel.id_code for channel in org_channels]
        all_admin_channels = list(set(user_channels_admin + org_channels_ids))
        return jsonify({'channels_admin': all_admin_channels}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving admin channels: {e}")
        return jsonify({'message': 'An error occurred while retrieving admin channels.'}), 500

@app.route('/list-channels', methods=['POST'])
@token_required
def list_channels(current_user):
    try:
        data = request.get_json() or {}
        filter_subscribed = data.get("subscribed", False)
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id).all()
        if not user_orgs:
            organization_ids = [1]
            org_admin_ids = []
        else:
            organization_ids = [uo.organization_id for uo in user_orgs]
            org_admin_ids = [uo.organization_id for uo in user_orgs if uo.role == 'ORG_ADMIN']
        channels = Channel.query.filter(Channel.organization_id.in_(organization_ids)).all()
        # Handle donating field - puede ser string JSON o dict/list
        if current_user.donating:
            if isinstance(current_user.donating, str):
                user_donating_raw = json.loads(current_user.donating)
            else:
                user_donating_raw = current_user.donating
        else:
            user_donating_raw = []

        # Handle channels_admin field - puede ser string JSON o dict/list
        if current_user.channels_admin:
            if isinstance(current_user.channels_admin, str):
                user_channels_admin = json.loads(current_user.channels_admin)
            else:
                user_channels_admin = current_user.channels_admin
        else:
            user_channels_admin = []

        # Handle multiple formats: array, simple object, and extended object
        user_donating_dict = {}
        if isinstance(user_donating_raw, list):
            # Old format: ["ch123", "ch456"] -> convert to new format
            user_donating_dict = {channel_id: {"amount": 0, "hidden": False} for channel_id in user_donating_raw}
        elif isinstance(user_donating_raw, dict):
            # Handle both old dict format {"ch123": 10} and new format {"ch123": {"amount": 10, "hidden": false}}
            for ch_id, value in user_donating_raw.items():
                if isinstance(value, dict):
                    # New format already
                    user_donating_dict[ch_id] = value
                else:
                    # Old format, convert to new format
                    user_donating_dict[ch_id] = {"amount": value, "hidden": False}

        channel_list = []
        for channel in channels:
            image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/app/channels/{channel.id_code}/profile.jpeg"
            try:
                response = requests.head(image_url, timeout=5)
                if response.status_code == 403:
                    image_url = None
            except requests.RequestException:
                image_url = None
            is_admin = (channel.id_code in user_channels_admin) or (channel.organization_id in org_admin_ids)
            is_subscribed = channel.id_code in user_donating_dict

            # Extract donation info from new format
            donation_info = user_donating_dict.get(channel.id_code, {"amount": 0, "hidden": False, "session_id": None})
            donation_amount = donation_info.get("amount", 0)
            hide_amount = donation_info.get("hidden", False)
            session_id = donation_info.get("session_id", None)

            # Get organization name using the relationship
            organization_name = channel.organization.name if channel.organization else None

            if filter_subscribed and not is_subscribed:
                continue
            channel_list.append({
                'id': channel.id,
                'name': channel.name,
                'id_code': channel.id_code,
                'organization_id': channel.organization_id,
                'organization_name': organization_name,
                'created_at': channel.created_at.isoformat(),
                'image_url': image_url,
                'subscribed': is_subscribed,
                'is_admin': is_admin,
                'version': channel.version,
                'donation_amount': donation_amount,
                'hide_amount': hide_amount,
                'session_id': session_id
            })
        return jsonify({'channels': channel_list}), 200
    except Exception as e:
        app.logger.error(f"Error listing channels: {e}")
        return jsonify({'message': 'An error occurred while retrieving channels.'}), 500

@app.route('/list-channel-admins/<string:id_code_channel>', methods=['GET'])
@token_required
def list_channel_admins(current_user, id_code_channel):
    """
    Retorna un listado de todos los administradores de un canal:
    - CHANNEL_ADMIN (a nivel de canal)
    - ORG_ADMIN (a nivel de organización dueña del canal)
    
    Incluye en la respuesta: id_code, username, email, y el rol que ejerce en el canal.
    """
    try:
        # 1) Buscar el canal por su id_code
        channel = Channel.query.filter_by(id_code=id_code_channel).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # 2) (Opcional) Verificar permisos si lo deseas
        # org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        # chan_admin_perm = ChannelAdminPermission(channel.id)
        # if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        #     return jsonify({'message': 'No permission to list channel admins!'}), 403

        # 3) Buscar los CHANNEL_ADMIN de este canal
        channel_admins = UserChannel.query.filter_by(channel_id=channel.id, role='CHANNEL_ADMIN').all()

        # 4) Buscar los ORG_ADMIN de la organización dueña
        org_admins = UserOrganization.query.filter_by(organization_id=channel.organization_id, role='ORG_ADMIN').all()

        # 5) Combinar los resultados y construir la respuesta
        user_data = []

        # a) Agregar CHANNEL_ADMIN
        for uc in channel_admins:
            user_obj = uc.user  # relación con la tabla User
            if user_obj:
                user_data.append({
                    'id_code':  user_obj.id_code,
                    'username': user_obj.username,
                    'email':    user_obj.email,
                    'role':     'CHANNEL_ADMIN'
                })

        # b) Agregar ORG_ADMIN
        for oa in org_admins:
            user_obj = oa.user  # relación con la tabla User
            if user_obj:
                user_data.append({
                    'id_code':  user_obj.id_code,
                    'username': user_obj.username,
                    'email':    user_obj.email,
                    'role':     'ORG_ADMIN'
                })

        # 6) (Opcional) Eliminar duplicados si un usuario es ORG_ADMIN y CHANNEL_ADMIN a la vez
        #    Podemos usar un diccionario clave = id_code
        unique_data = {}
        for item in user_data:
            uid = item['id_code']
            if uid not in unique_data:
                unique_data[uid] = item
            else:
                # Si ya existe, podemos concatenar roles, etc. (opcional)
                existing_roles = unique_data[uid]['role']
                new_role       = item['role']
                # Por simplicidad, unimos ambos roles con una coma
                if new_role not in existing_roles:
                    unique_data[uid]['role'] = f"{existing_roles},{new_role}"

        # convertimos unique_data en lista final
        final_admins_list = list(unique_data.values())

        return jsonify({'admins': final_admins_list}), 200

    except Exception as e:
        app.logger.error(f"Error en /list-channel-admins/<id_code_channel>: {e}")
        return jsonify({'message': 'Error retrieving admins for channel', 'error': str(e)}), 500

       

@app.route('/lists-users-channel/<string:id_code_channel>', methods=['GET'])
@token_required
def list_users_in_channel(current_user, id_code_channel):
    """
    Dado el id_code de un canal, retorna un listado
    de los usuarios (id_code, username, email, profile_image) 
    que están suscritos, incluyendo su imagen de perfil en S3.
    """
    try:
        channel = Channel.query.filter_by(id_code=id_code_channel).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # (Opcional) Verificar permisos si lo deseas:
        # org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        # chan_admin_perm = ChannelAdminPermission(channel.id)
        # if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        #     return jsonify({'message': 'No permission to list channel users!'}), 403

        # subscribers_json puede ser una lista o string JSON
        subscribers_list = channel.subscribers_json or []
        if isinstance(subscribers_list, str):
            try:
                subscribers_list = json.loads(subscribers_list)
            except:
                subscribers_list = []

        # Para cada user_id_code en la lista, buscamos al usuario y añadimos su imagen de perfil
        user_data = []
        for user_id_code in subscribers_list:
            user_obj = User.query.filter_by(id_code=user_id_code).first()
            if user_obj:
                # Construimos la URL de la imagen de perfil en S3
                profile_image_url = (
                    f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                    f"app/user/{user_obj.id_code}/profile.jpeg"
                )
                # Verificamos si existe (HEAD). Puedes omitir esta comprobación si no es necesaria.
                try:
                    resp = requests.head(profile_image_url, timeout=3)
                    if resp.status_code >= 400:
                        # Si es 403/404, dejamos None para indicar que no existe
                        profile_image_url = None
                except:
                    profile_image_url = None

                user_data.append({
                    'id_code':       user_obj.id_code,
                    'username':      user_obj.username,
                    'email':         user_obj.email,
                    'profile_image': profile_image_url
                })

        return jsonify({'subscribers': user_data}), 200

    except Exception as e:
        app.logger.error(f"Error en /lists-users/channel/<id_code_channel>: {e}")
        return jsonify({
            'message': 'Error retrieving user list from channel',
            'error': str(e)
        }), 500

@app.route('/current_user', methods=['GET'])
@token_required
def get_current_user(current_user):
    """
    Retorna el id_code del usuario en curso (aquél que envió el token).
    """
    try:
        return jsonify({
            'id_code': current_user.id_code
        }), 200
    except Exception as e:
        app.logger.error(f"Error in /current_user: {e}")
        return jsonify({
            'message': 'An error occurred while retrieving the current user.',
            'error': str(e)
        }), 500
    
@app.route('/toggle-notifications', methods=['POST'])
@token_required
def toggle_notifications(current_user):
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        notification_types = data.get('notification_types', [])
        if not channel_id:
            return jsonify({'message': 'Channel ID is required!'}), 400
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404
        user_notifications = {}
        if channel.user_notifications:
            try:
                user_notifications = json.loads(channel.user_notifications)
            except (json.JSONDecodeError, TypeError):
                app.logger.error(f"Invalid JSON format in user_notifications for channel {channel_id}. Resetting.")
                user_notifications = {}
        if notification_types:
            user_notifications[str(current_user.id)] = notification_types
        else:
            user_notifications.pop(str(current_user.id), None)
        channel.user_notifications = json.dumps(user_notifications)
        db.session.commit()
        return jsonify({'message': 'Notification preferences updated!', 'user_notifications': user_notifications}), 200
    except Exception as e:
        app.logger.error(f"Error toggling notifications: {e}")
        return jsonify({'message': 'An error occurred while updating notifications.'}), 500

# --------------------------------------------------------------------
#                      EJEMPLO DE RUTAS DE USUARIO
# --------------------------------------------------------------------
@app.route('/update-user-setting', methods=['POST'])
@token_required
def update_user_setting(current_user):
    try:
        app.logger.info(f"🔧 UPDATE_USER_SETTING - Iniciando para usuario {current_user.id}")
        data = request.get_json()
        key = data.get('key')
        value = data.get('value')

        app.logger.info(f"🔧 UPDATE_USER_SETTING - Key: {key}, Value: {value}")

        if not key:
            return jsonify({'message': 'Key is required!'}), 400
        if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
            return jsonify({'message': 'Invalid value type!'}), 400

        # Handle user_settings properly (might be dict, string, or None)
        app.logger.info(f"🔧 UPDATE_USER_SETTING - Settings actuales: {current_user.user_settings}")
        app.logger.info(f"🔧 UPDATE_USER_SETTING - Tipo de settings: {type(current_user.user_settings)}")

        user_settings = current_user.user_settings or {}
        if isinstance(user_settings, str):
            try:
                user_settings = json.loads(user_settings)
            except Exception as json_err:
                app.logger.error(f"Error parsing JSON: {json_err}")
                user_settings = {}
        elif not isinstance(user_settings, dict):
            user_settings = {}

        app.logger.info(f"🔧 UPDATE_USER_SETTING - Settings después de parsear: {user_settings}")

        user_settings[key] = value
        current_user.user_settings = user_settings

        app.logger.info(f"🔧 UPDATE_USER_SETTING - Settings finales: {user_settings}")

        # Mark as modified for SQLAlchemy to detect changes
        flag_modified(current_user, "user_settings")

        db.session.commit()

        app.logger.info(f"🔧 UPDATE_USER_SETTING - Guardado exitosamente")

        return jsonify({'message': 'User setting updated successfully!', 'user_settings': user_settings}), 200
    except Exception as e:
        app.logger.error(f"Error updating user setting: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'message': 'An error occurred while updating user setting.'}), 500

@app.route('/get-user-settings', methods=['GET'])
@token_required
def get_user_settings(current_user):
    try:
        user_settings = {}
        if current_user.user_settings:
            try:
                if isinstance(current_user.user_settings, str):
                    user_settings = json.loads(current_user.user_settings)
                elif isinstance(current_user.user_settings, dict):
                    user_settings = current_user.user_settings
                else:
                    user_settings = {}
            except json.JSONDecodeError as json_error:
                app.logger.error(f"Invalid JSON in user_settings for user {current_user.id}: {json_error}")
                user_settings = {}

        return jsonify({'user_settings': user_settings}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving user settings: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'message': 'An error occurred while retrieving user settings.'}), 500

# --------------------------------------------------------------------
#                      CHANNEL SETTINGS ENDPOINTS
# --------------------------------------------------------------------
@app.route('/get-channel-setting/<string:channel_id>/<string:key>', methods=['GET'])
@token_required
def get_channel_setting(current_user, channel_id, key):
    try:
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        channel_settings = {}
        if channel.user_settings:
            try:
                if isinstance(channel.user_settings, str):
                    channel_settings = json.loads(channel.user_settings)
                elif isinstance(channel.user_settings, dict):
                    channel_settings = channel.user_settings
            except json.JSONDecodeError as json_error:
                app.logger.error(f"Invalid JSON in user_settings for channel {channel_id}: {json_error}")
                channel_settings = {}

        value = channel_settings.get(key)
        return jsonify({'key': key, 'value': value}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving channel setting: {e}")
        return jsonify({'message': 'An error occurred while retrieving channel setting.'}), 500

@app.route('/upload-channel-background', methods=['POST'])
@token_required
def upload_channel_background(current_user):
    try:
        app.logger.info(f"📤 Upload channel background request from user {current_user.id}")

        if 'file' not in request.files:
            app.logger.error("❌ No file in request.files")
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        channel_id = request.form.get('channel_id')
        app.logger.info(f"📝 Channel ID: {channel_id}, File: {file.filename}")

        if not channel_id:
            app.logger.error("❌ No channel_id provided")
            return jsonify({'error': 'Channel ID is required'}), 400

        # Verificar que el canal existe
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            app.logger.error(f"❌ Channel not found: {channel_id}")
            return jsonify({'error': 'Channel not found'}), 404

        app.logger.info(f"✅ Channel found: {channel.name}, org_id: {channel.organization_id}")

        # Verificar permisos jerárquicos: superadmin > org_admin > channel_admin
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        channel_admin_perm = ChannelAdminPermission(channel.id)

        app.logger.info(f"🔐 Checking permissions - superadmin: {superadmin_permission.can()}, org_admin: {org_admin_perm.can()}, channel_admin: {channel_admin_perm.can()}")

        if not (superadmin_permission.can() or org_admin_perm.can() or channel_admin_perm.can()):
            app.logger.error(f"❌ User {current_user.id} not authorized for channel {channel_id}")
            return jsonify({'error': 'Not authorized to upload channel background'}), 403

        if file.filename == '':
            app.logger.error("❌ Empty filename")
            return jsonify({'error': 'No selected file'}), 400

        # Generar nombre único para el archivo
        file_extension = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
        filename = f"channel_background_{channel_id}_{int(time.time())}.{file_extension}"
        app.logger.info(f"📁 Generated filename: {filename}")

        # Subir a S3
        s3_key = f"app/channels/{channel_id}/backgrounds/{filename}"
        app.logger.info(f"☁️ Uploading to S3: {s3_key}")

        s3.upload_fileobj(
            file,
            S3_BUCKET,
            s3_key,
            ExtraArgs={
                'ContentType': file.content_type or 'image/jpeg',
                'ACL': 'public-read'
            }
        )

        # Construir URL de la imagen
        image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"

        app.logger.info(f"✅ Channel background uploaded successfully: {image_url}")

        return jsonify({'success': True, 'image_url': image_url}), 200

    except Exception as e:
        app.logger.error(f"Error uploading channel background: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Failed to upload channel background'}), 500

@app.route('/get-login-activity', methods=['GET'])
@token_required
def get_login_activity(current_user):
    try:
        # Obtener parámetros de paginación
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)

        # Limitar per_page para evitar sobrecarga
        per_page = min(per_page, 100)

        # Obtener logs de login del campo JSON del usuario
        login_activity = current_user.login_activity or []

        # Aplicar límite de paginación
        limited_logs = login_activity[:per_page]

        # Formatear respuesta (agregar ID incremental para compatibilidad)
        logs_data = []
        for index, log in enumerate(limited_logs):
            log_data = {
                'id': index + 1,
                'ip_address': log.get('ip_address'),
                'device_info': log.get('device_info'),
                'login_time': log.get('login_time'),
                'success': log.get('success'),
                'user_agent': log.get('user_agent')[:100] + '...' if log.get('user_agent') and len(log.get('user_agent', '')) > 100 else log.get('user_agent')
            }
            logs_data.append(log_data)

        return jsonify({
            'login_activity': logs_data,
            'total': len(logs_data)
        }), 200
    except Exception as e:
        app.logger.error(f"Error retrieving login activity: {e}")
        return jsonify({'message': 'An error occurred while retrieving login activity.'}), 500

@app.route('/delete-user-setting', methods=['POST'])
@token_required
def delete_user_setting(current_user):
    try:
        data = request.get_json()
        key = data.get('key')
        if not key:
            return jsonify({'message': 'Key is required!'}), 400

        user_settings = json.loads(current_user.user_settings) if current_user.user_settings else {}
        if key in user_settings:
            del user_settings[key]
            current_user.user_settings = json.dumps(user_settings) if user_settings else json.dumps({})
            db.session.commit()
            return jsonify({'message': 'User setting deleted successfully!', 'user_settings': user_settings}), 200
        else:
            return jsonify({'message': 'Key not found in user settings!'}), 404
    except Exception as e:
        app.logger.error(f"Error deleting user setting: {e}")
        return jsonify({'message': 'An error occurred while deleting user setting.'}), 500

# --------------------------------------------------------------------
#                      EJEMPLO DE RUTAS DE CANAL
# --------------------------------------------------------------------
@app.route('/update-channel-setting/<string:channel_id>', methods=['POST'])
@token_required
def update_channel_setting(current_user, channel_id):
    try:
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # Verificar permisos jerárquicos: superadmin > org_admin > channel_admin
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        channel_admin_perm = ChannelAdminPermission(channel.id)
        if not (superadmin_permission.can() or org_admin_perm.can() or channel_admin_perm.can()):
            return jsonify({'message': 'No permission to update channel settings!'}), 403

        data = request.get_json() or {}
        key = data.get('key')
        value = data.get('value')
        if not key:
            return jsonify({'message': 'Key is required!'}), 400
        if not isinstance(value, (str, int, float, bool, list, dict, type(None))):
            return jsonify({'message': 'Invalid value type!'}), 400

        # 1) Convertir channel.user_settings a dict si es str
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            import json
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        # 2) Modificamos el diccionario
        channel_settings[key] = value

        # 3) Reasignamos a channel.user_settings
        channel.user_settings = channel_settings

        # 4) Avisamos a SQLAlchemy de que se modificó
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(channel, "user_settings")

        # 5) Aumentar la versión y hacer commit
        channel.version = (channel.version or 1) + 1
        db.session.commit()

        channel_settings["is_gtoken"] = ("token_gcalendar" in channel_settings)

        return jsonify({
            'message': 'Channel setting updated successfully!',
            'channel_settings': channel_settings
        }), 200

    except Exception as e:
        app.logger.error(f"Error updating channel setting: {e}")
        return jsonify({'message': 'An error occurred while updating channel setting.'}), 500


@app.route('/get-channel-settings/<string:channel_id>', methods=['GET'])
@token_required
def get_channel_settings(current_user, channel_id):
    try:
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found'}), 404

        channel_settings_value = channel.user_settings

        # Detectar si ya es dict o es string
        if isinstance(channel_settings_value, dict):
            channel_settings = channel_settings_value
        elif isinstance(channel_settings_value, str) and channel_settings_value:
            import json
            channel_settings = json.loads(channel_settings_value)
        else:
            channel_settings = {}

        # Añadimos 'gtoken' dentro de channel_settings
        channel_settings['is_gtoken'] = ('token_gcalendar' in channel_settings)

        return jsonify({
            'channel-name': channel.name,
            'channel_settings': channel_settings
        }), 200

    except Exception as e:
        app.logger.error(f"Error retrieving channel settings: {e}")
        return jsonify({'message': 'An error occurred while retrieving channel settings.'}), 500


@app.route('/delete-channel-setting/<string:channel_id>', methods=['POST'])
@token_required
def delete_channel_setting(current_user, channel_id):
    try:
        data = request.get_json()
        key = data.get('key')
        if not key:
            return jsonify({'message': 'Key is required!'}), 400

        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # Verificar permisos jerárquicos: superadmin > org_admin > channel_admin
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        channel_admin_perm = ChannelAdminPermission(channel.id)
        if not (superadmin_permission.can() or org_admin_perm.can() or channel_admin_perm.can()):
            return jsonify({'message': 'No permission to delete channel settings!'}), 403

        channel_settings = json.loads(channel.user_settings) if channel.user_settings else {}

        if key in channel_settings:
            del channel_settings[key]
            channel.user_settings = json.dumps(channel_settings) if channel_settings else None
            db.session.commit()
            return jsonify({
                'message': 'Channel setting deleted successfully!',
                'channel_settings': channel_settings
            }), 200
        else:
            return jsonify({'message': 'Key not found in channel settings!'}), 404

    except Exception as e:
        app.logger.error(f"Error deleting channel setting: {e}")
        return jsonify({'message': 'An error occurred while deleting channel setting.'}), 500

# --------------------------------------------------------------------
#        EJEMPLO DE RUTAS PARA KEYS: USER vs. CHANNEL
# --------------------------------------------------------------------
@app.route('/create-user-setting-key', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def create_user_setting_key(current_user):
    try:
        data = request.get_json()
        key_name = data.get('key_name')
        description = data.get('description', '')
        placeholder = data.get('placeholder', '')
        id_category = data.get('id_category')
        data_type = data.get('data_type')
        if not key_name or not data_type:
            return jsonify({'message': 'key_name and data_type are required!'}), 400
        if UserSettingKeys.query.filter_by(key_name=key_name).first():
            return jsonify({'message': 'Key already exists!'}), 400

        new_key = UserSettingKeys(
            key_name=key_name,
            description=description,
            placeholder=placeholder,
            id_category=id_category,
            data_type=data_type
        )
        db.session.add(new_key)
        db.session.commit()
        return jsonify({'message': 'User setting key created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating user setting key: {e}")
        return jsonify({'message': 'An error occurred while creating the user setting key.'}), 500

@app.route('/get-user-setting-keys', methods=['GET'])
@token_required
def get_user_setting_keys(current_user):
    try:
        keys = UserSettingKeys.query.all()
        response = [{
            'id': key.id,
            'key_name': key.key_name,
            'description': key.description,
            'placeholder': key.placeholder,
            'id_category': key.id_category,
            'data_type': key.data_type
        } for key in keys]
        return jsonify({'user_setting_keys': response}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving user setting keys: {e}")
        return jsonify({'message': 'An error occurred while retrieving user setting keys.'}), 500

@app.route('/get-channel-setting-keys', methods=['GET'])
@token_required
def get_channel_setting_keys(current_user):
    try:
        # Actualmente, no filtras nada por canal_id, 
        # simplemente devuelves TODAS las ChannelSettingKeys.
        keys = ChannelSettingKeys.query.all()
        response = [{
            'id': key.id,
            'key_name': key.key_name,
            'description': key.description,
            'placeholder': key.placeholder,
            'id_category': key.id_category,
            'data_type': key.data_type
        } for key in keys]
        return jsonify({'channel_setting_keys': response}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving user setting keys: {e}")
        return jsonify({'message': 'An error occurred while retrieving user setting keys.'}), 500

@app.route('/update-user-setting-key', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def update_user_setting_key(current_user):
    try:
        data = request.get_json()
        key_id = data.get('id')
        key_name = data.get('key_name')
        description = data.get('description')
        placeholder = data.get('placeholder')
        id_category = data.get('id_category')
        data_type = data.get('data_type')

        key = UserSettingKeys.query.get(key_id)
        if not key:
            return jsonify({'message': 'Key not found!'}), 404

        if key_name:
            key.key_name = key_name
        if description is not None:
            key.description = description
        if placeholder is not None:
            key.placeholder = placeholder
        if id_category is not None:
            key.id_category = id_category
        if data_type:
            key.data_type = data_type

        db.session.commit()
        return jsonify({'message': 'User setting key updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error updating user setting key: {e}")
        return jsonify({'message': 'An error occurred while updating user setting key.'}), 500

@app.route('/delete-user-setting-key/<int:key_id>', methods=['DELETE'])
@token_required
@superadmin_permission.require(http_exception=403)
def delete_user_setting_key(current_user, key_id):
    try:
        key = UserSettingKeys.query.get(key_id)
        if not key:
            return jsonify({'message': 'Key not found!'}), 404
        db.session.delete(key)
        db.session.commit()
        return jsonify({'message': 'User setting key deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting user setting key: {e}")
        return jsonify({'message': 'An error occurred while deleting user setting key.'}), 500

# -- CRUD análogo para ChannelSettingKeys (si lo requieres) --
@app.route('/create-channel-setting-key', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def create_channel_setting_key(current_user):
    try:
        data = request.get_json()
        key_name = data.get('key_name')
        description = data.get('description', '')
        placeholder = data.get('placeholder', '')
        id_category = data.get('id_category')
        data_type = data.get('data_type')
        if not key_name or not data_type:
            return jsonify({'message': 'key_name and data_type are required!'}), 400

        if ChannelSettingKeys.query.filter_by(key_name=key_name).first():
            return jsonify({'message': 'Key already exists!'}), 400

        new_key = ChannelSettingKeys(
            key_name=key_name,
            description=description,
            placeholder=placeholder,
            id_category=id_category,
            data_type=data_type
        )
        db.session.add(new_key)
        db.session.commit()
        return jsonify({'message': 'Channel setting key created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating channel setting key: {e}")
        return jsonify({'message': 'An error occurred while creating the channel setting key.'}), 500

@app.route('/update-channel-setting-key', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def update_channel_setting_key(current_user):
    try:
        data = request.get_json()
        key_id = data.get('id')
        key_name = data.get('key_name')
        description = data.get('description')
        placeholder = data.get('placeholder')
        id_category = data.get('id_category')
        data_type = data.get('data_type')

        key = ChannelSettingKeys.query.get(key_id)
        if not key:
            return jsonify({'message': 'Key not found!'}), 404

        if key_name:
            key.key_name = key_name
        if description is not None:
            key.description = description
        if placeholder is not None:
            key.placeholder = placeholder
        if id_category is not None:
            key.id_category = id_category
        if data_type:
            key.data_type = data_type

        db.session.commit()
        return jsonify({'message': 'Channel setting key updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error updating channel setting key: {e}")
        return jsonify({'message': 'An error occurred while updating channel setting key.'}), 500

@app.route('/delete-channel-setting-key/<int:key_id>', methods=['DELETE'])
@token_required
@superadmin_permission.require(http_exception=403)
def delete_channel_setting_key(current_user, key_id):
    try:
        key = ChannelSettingKeys.query.get(key_id)
        if not key:
            return jsonify({'message': 'Key not found!'}), 404
        db.session.delete(key)
        db.session.commit()
        return jsonify({'message': 'Channel setting key deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting channel setting key: {e}")
        return jsonify({'message': 'An error occurred while deleting channel setting key.'}), 500

# --------------------------------------------------------------------
#        EJEMPLO DE RUTAS PARA CATEGORÍAS: USER vs. CHANNEL
# --------------------------------------------------------------------

@app.route('/create-user-setting-category', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def create_user_setting_category(current_user):
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        icon = data.get('icon', '')
        if not name:
            return jsonify({'message': 'Category name is required!'}), 400
        if UserSettingCategories.query.filter_by(name=name).first():
            return jsonify({'message': 'Category already exists!'}), 400

        new_category = UserSettingCategories(
            name=name,
            description=description,
            icon=icon
        )
        db.session.add(new_category)
        db.session.commit()
        return jsonify({'message': 'Category created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating category: {e}")
        return jsonify({'message': 'An error occurred while creating the category.'}), 500

@app.route('/get-user-setting-categories', methods=['GET'])
@token_required
def get_user_setting_categories(current_user):
    try:
        categories = UserSettingCategories.query.order_by(UserSettingCategories.order.asc()).all()

        # Verificar permisos del usuario
        is_superadmin = (current_user.role.upper() == "SUPERADMIN")
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id, role='ORG_ADMIN').all()
        org_admin_ids = [uo.organization_id for uo in user_orgs]
        is_org_admin = (len(org_admin_ids) > 0)
        user_channels_admin_count = UserChannel.query.filter_by(
            user_id=current_user.id, role='CHANNEL_ADMIN'
        ).count()
        is_channel_admin = (user_channels_admin_count > 0)

        visible_categories = []
        for category in categories:
            perms = category.permissions
            if not perms:
                # Sin permisos => visible a todos
                visible_categories.append(category)
            elif perms == 'channel':
                if is_superadmin or is_org_admin or is_channel_admin:
                    visible_categories.append(category)
            elif perms == 'organization':
                if is_superadmin or is_org_admin:
                    visible_categories.append(category)
            elif perms == 'superadmin':
                if is_superadmin:
                    visible_categories.append(category)
            # else: no lo mostramos

        response = [{
            'id': cat.id,
            'name': cat.name,
            'description': cat.description,
            'icon': cat.icon,
            'action': cat.action
        } for cat in visible_categories]

        return jsonify({'categories_user': response}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving categories: {e}")
        return jsonify({'message': 'An error occurred while retrieving categories.'}), 500

@app.route('/update-user-setting-category', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def update_user_setting_category(current_user):
    try:
        data = request.get_json()
        category_id = data.get('id')
        name = data.get('name')
        description = data.get('description')
        icon = data.get('icon')

        category = UserSettingCategories.query.get(category_id)
        if not category:
            return jsonify({'message': 'Category not found!'}), 404

        if name:
            category.name = name
        if description is not None:
            category.description = description
        if icon is not None:
            category.icon = icon

        db.session.commit()
        return jsonify({'message': 'Category updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error updating category: {e}")
        return jsonify({'message': 'An error occurred while updating the category.'}), 500

@app.route('/delete-user-setting-category/<int:category_id>', methods=['DELETE'])
@token_required
@superadmin_permission.require(http_exception=403)
def delete_user_setting_category(current_user, category_id):
    try:
        category = UserSettingCategories.query.get(category_id)
        if not category:
            return jsonify({'message': 'Category not found!'}), 404
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Category deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting category: {e}")
        return jsonify({'message': 'An error occurred while deleting the category.'}), 500

# ---- NUEVAS RUTAS PARA ChannelSettingCategories (CRUD) ----
@app.route('/create-channel-setting-category', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def create_channel_setting_category(current_user):
    """
    Crea una nueva categoría de configuración de canal (p.ej. para clasificar las ChannelSettingKeys).
    """
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        icon = data.get('icon', '')
        if not name:
            return jsonify({'message': 'Category name is required!'}), 400

        if ChannelSettingCategories.query.filter_by(name=name).first():
            return jsonify({'message': 'Category already exists!'}), 400

        new_category = ChannelSettingCategories(
            name=name,
            description=description,
            icon=icon
        )
        db.session.add(new_category)
        db.session.commit()
        return jsonify({'message': 'Channel Setting Category created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating channel setting category: {e}")
        return jsonify({'message': 'An error occurred while creating the channel setting category.'}), 500

@app.route('/get-channel-setting-categories', methods=['GET'])
@token_required
def get_channel_setting_categories(current_user):
    """
    Devuelve la lista de categorías de configuración de canal, 
    ordenadas por 'order', filtradas según permisos (opcional).
    """
    try:
        categories = ChannelSettingCategories.query.order_by(ChannelSettingCategories.order.asc()).all()

        # Verificar permisos del usuario
        is_superadmin = (current_user.role.upper() == "SUPERADMIN")
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id, role='ORG_ADMIN').all()
        org_admin_ids = [uo.organization_id for uo in user_orgs]
        is_org_admin = (len(org_admin_ids) > 0)
        user_channels_admin_count = UserChannel.query.filter_by(
            user_id=current_user.id, 
            role='CHANNEL_ADMIN'
        ).count()
        is_channel_admin = (user_channels_admin_count > 0)

        visible_categories = []
        for category in categories:
            perms = category.permissions
            if not perms:
                # Sin permisos => visible a todos
                visible_categories.append(category)
            elif perms == 'channel':
                if is_superadmin or is_org_admin or is_channel_admin:
                    visible_categories.append(category)
            elif perms == 'organization':
                if is_superadmin or is_org_admin:
                    visible_categories.append(category)
            elif perms == 'superadmin':
                if is_superadmin:
                    visible_categories.append(category)
            # else: no se muestra

        response = [{
            'id': cat.id,
            'name': cat.name,
            'description': cat.description,
            'icon': cat.icon,
            'action': cat.action,
            'key_name': cat.key_name,
            'placeholder': cat.placeholder,
            'id_category': cat.id,
            'data_type': cat.data_type
        } for cat in visible_categories]

        return jsonify({'categories': response}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving channel setting categories: {e}")
        return jsonify({'message': 'An error occurred while retrieving channel setting categories.'}), 500

@app.route('/update-channel-setting-category', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def update_channel_setting_category(current_user):
    """
    Actualiza una categoría de configuración de canal.
    """
    try:
        data = request.get_json()
        category_id = data.get('id')
        name = data.get('name')
        description = data.get('description')
        icon = data.get('icon')

        category = ChannelSettingCategories.query.get(category_id)
        if not category:
            return jsonify({'message': 'Channel Setting Category not found!'}), 404

        if name:
            category.name = name
        if description is not None:
            category.description = description
        if icon is not None:
            category.icon = icon

        db.session.commit()
        return jsonify({'message': 'Channel setting category updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error updating channel setting category: {e}")
        return jsonify({'message': 'An error occurred while updating the channel setting category.'}), 500

@app.route('/delete-channel-setting-category/<int:category_id>', methods=['DELETE'])
@token_required
@superadmin_permission.require(http_exception=403)
def delete_channel_setting_category(current_user, category_id):
    """
    Elimina una categoría de configuración de canal.
    """
    try:
        category = ChannelSettingCategories.query.get(category_id)
        if not category:
            return jsonify({'message': 'Channel Setting Category not found!'}), 404
        db.session.delete(category)
        db.session.commit()
        return jsonify({'message': 'Channel setting category deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting channel setting category: {e}")
        return jsonify({'message': 'An error occurred while deleting the channel setting category.'}), 500


@app.route('/get-channel/<string:id_code>', methods=['GET'])
@token_required
def get_channel(current_user, id_code):
    try:
        channel = Channel.query.filter_by(id_code=id_code).first()
        if not channel:
            return jsonify({'message': 'Channel not found'}), 404

        # Verifica si la imagen de perfil existe en S3
        image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/app/channels/{id_code}/profile.jpeg"
        try:
            response = requests.head(image_url, timeout=5)
            if response.status_code == 403:
                image_url = None
        except requests.RequestException:
            image_url = None

        # Determina si el usuario es administrador de este canal
        # Handle channels_admin field - puede ser string JSON o dict/list
        if current_user.channels_admin:
            if isinstance(current_user.channels_admin, str):
                user_channels_admin = json.loads(current_user.channels_admin)
            else:
                user_channels_admin = current_user.channels_admin
        else:
            user_channels_admin = []

        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id, role='ORG_ADMIN').all()
        org_admin_ids = [uo.organization_id for uo in user_orgs]
        is_admin = (channel.id_code in user_channels_admin) or (channel.organization_id in org_admin_ids)

        # Determina si el usuario está suscrito a este canal
        # Handle donating field - puede ser string JSON o dict/list
        if current_user.donating:
            if isinstance(current_user.donating, str):
                donating_raw = json.loads(current_user.donating)
            else:
                donating_raw = current_user.donating
        else:
            donating_raw = []

        # Convert to list of channel IDs if it's in the new dict format
        if isinstance(donating_raw, dict):
            donating_list = list(donating_raw.keys())
        else:
            donating_list = donating_raw
        is_subscribed = channel.id_code in donating_list

        # Recolecta datos del canal
        post_count = len(channel.posts)
        channel_data = {
            'id': channel.id,
            'name': channel.name,
            'id_code': channel.id_code,
            'organization_id': channel.organization_id,
            'organization_name': channel.organization.name if channel.organization else None,
            'created_at': channel.created_at.isoformat(),
            'image_url': image_url,
            'is_admin': is_admin,
            'post_count': post_count,
            'subscribers_count': channel.subscribers_count,
            'version': channel.version,    # Versión del canal
            'is_subscribed': is_subscribed # ¡Aquí agregas el nuevo campo!
        }

        app.logger.info(channel_data)
        return jsonify({'channel': channel_data}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving channel: {e}")
        return jsonify({'message': 'An error occurred while retrieving the channel.'}), 500


@app.route('/subscribe-channel', methods=['POST'])
@token_required
def subscribe_channel(current_user):
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        donation_amount = data.get('donation_amount', 0)  # Default to 0 if not provided

        if not channel_id:
            return jsonify({'message': 'Channel ID is required!'}), 400

        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # Handle both old format (array) and new format (object with amounts)
        # Handle donating field - puede ser string JSON o dict/list
        if current_user.donating:
            if isinstance(current_user.donating, str):
                user_donating_raw = json.loads(current_user.donating)
            else:
                user_donating_raw = current_user.donating
        else:
            user_donating_raw = []
        user_donating_dict = {}

        if isinstance(user_donating_raw, list):
            # Convert old format to new format
            user_donating_dict = {ch_id: {"amount": 0, "hidden": False, "session_id": None} for ch_id in user_donating_raw}
        elif isinstance(user_donating_raw, dict):
            # Handle both old dict format {"ch123": 10} and new format {"ch123": {"amount": 10, "hidden": false}}
            for ch_id, value in user_donating_raw.items():
                if isinstance(value, dict):
                    # New format already
                    user_donating_dict[ch_id] = value
                else:
                    # Old format, convert to new format
                    user_donating_dict[ch_id] = {"amount": value, "hidden": False, "session_id": None}

        if channel.id_code in user_donating_dict:
            return jsonify({'message': 'Already subscribed to this channel!'}), 400

        # Add subscription with donation amount using consistent format
        user_donating_dict[channel.id_code] = {
            "amount": donation_amount,
            "hidden": False,
            "session_id": None
        }
        current_user.donating = json.dumps(user_donating_dict)

        # -- (2) Actualizar channel.subscribers_count --
        channel.subscribers_count = (channel.subscribers_count or 0) + 1

        # -- (3) Nueva lógica para channel.subscribers_json --
        subscribers_list = channel.subscribers_json or []
        # Si está guardado como string, conviértelo en lista
        if isinstance(subscribers_list, str):
            try:
                subscribers_list = json.loads(subscribers_list)
            except:
                subscribers_list = []
        
        # Si el id_code del user no está, se añade
        if current_user.id_code not in subscribers_list:
            subscribers_list.append(current_user.id_code)
        
        channel.subscribers_json = subscribers_list
        
        # -- IMPORTANTE: si usas JSON con SQLAlchemy, avísale que se modificó
        flag_modified(channel, "subscribers_json")

        # Guardar en BD
        db.session.commit()
        
        return jsonify({'message': 'Subscribed successfully!', 'donating': user_donating_dict}), 200
    
    except Exception as e:
        app.logger.error(f"Error subscribing to channel: {e}")
        return jsonify({'message': 'An error occurred while subscribing to the channel.'}), 500


@app.route('/subscribed-channels', methods=['GET'])
@token_required
def subscribed_channels(current_user):
    try:
        user_donating = json.loads(current_user.donating) if current_user.donating else []
        return jsonify({'donating': user_donating}), 200
    except Exception as e:
        app.logger.error(f"Error retrieving subscribed channels: {e}")
        return jsonify({'message': 'An error occurred while retrieving subscribed channels.'}), 500

@app.route('/unsubscribe-channel', methods=['POST'])
@token_required
def unsubscribe_channel(current_user):
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        if not channel_id:
            return jsonify({'message': 'Channel ID is required!'}), 400
        
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404
        
        # Handle both old format (array) and new format (object with amounts)
        user_donating_raw = json.loads(current_user.donating) if current_user.donating else []
        user_donating_dict = {}

        if isinstance(user_donating_raw, list):
            # Convert old format to new format
            user_donating_dict = {ch_id: 0 for ch_id in user_donating_raw}
        elif isinstance(user_donating_raw, dict):
            user_donating_dict = user_donating_raw

        if channel.id_code not in user_donating_dict:
            return jsonify({'message': 'Not subscribed to this channel!'}), 400

        # Remove subscription
        del user_donating_dict[channel.id_code]

        # Resta 1 al contador de suscriptores (siempre y cuando sea >0)
        if channel.subscribers_count and channel.subscribers_count > 0:
            channel.subscribers_count -= 1

        current_user.donating = json.dumps(user_donating_dict) if user_donating_dict else json.dumps({})

        # -- (2) Nueva lógica para channel.subscribers_json --
        subscribers_list = channel.subscribers_json or []
        if isinstance(subscribers_list, str):
            try:
                subscribers_list = json.loads(subscribers_list)
            except:
                subscribers_list = []

        # Si estaba el user_id_code en la lista, se quita
        if current_user.id_code in subscribers_list:
            subscribers_list.remove(current_user.id_code)
        
        channel.subscribers_json = subscribers_list
        flag_modified(channel, "subscribers_json")
        
        # Guardar en BD
        db.session.commit()
        
        return jsonify({'message': 'Unsubscribed successfully!', 'donating': user_donating_dict}), 200
    
    except Exception as e:
        app.logger.error(f"Error unsubscribing from channel: {e}")
        return jsonify({'message': 'An error occurred while unsubscribing from the channel.'}), 500

@app.route('/channels/<string:channel_id>/send-alert', methods=['POST'])
@token_required
def send_channel_alert(current_user, channel_id):
    """
    Envía una alerta/notificación a todos los miembros de un canal.
    Solo los administradores del canal pueden enviar alertas.
    """
    try:
        app.logger.info(f"📣 Iniciando envío de alerta para canal {channel_id}")

        # Obtener el mensaje del body
        data = request.get_json()
        message = data.get('message', '').strip()

        if not message:
            app.logger.warning("❌ Mensaje vacío")
            return jsonify({'error': 'El mensaje es requerido'}), 400

        # Verificar que el canal existe
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            app.logger.warning(f"❌ Canal {channel_id} no encontrado")
            return jsonify({'error': 'Canal no encontrado'}), 404

        app.logger.info(f"✅ Canal encontrado: {channel.name}")

        # Verificar que el usuario es admin del canal
        is_admin = False

        # Verificar si es super admin
        if current_user.role and current_user.role.upper() == 'SUPERADMIN':
            is_admin = True
            app.logger.info(f"✅ Usuario es SUPERADMIN")
        else:
            try:
                # Verificar si es org admin
                user_org = UserOrganization.query.filter_by(
                    user_id=current_user.id,
                    organization_id=channel.organization_id,
                    role='ORG_ADMIN'
                ).first()
                if user_org:
                    is_admin = True
                    app.logger.info(f"✅ Usuario es ORG_ADMIN")
                else:
                    # Verificar si es admin del canal específico (en channels_admin JSON)
                    try:
                        channels_admin = json.loads(current_user.channels_admin) if current_user.channels_admin else []
                        if channel.id_code in channels_admin:
                            is_admin = True
                            app.logger.info(f"✅ Usuario es CHANNEL_ADMIN")
                    except Exception as json_error:
                        app.logger.error(f"❌ Error parsing channels_admin: {json_error}")
                        channels_admin = []
            except Exception as perm_error:
                app.logger.error(f"❌ Error verificando permisos: {perm_error}")

        if not is_admin:
            app.logger.warning(f"❌ Usuario {current_user.id} sin permisos")
            return jsonify({'error': 'No tienes permisos para enviar alertas en este canal'}), 403

        # Obtener todos los suscriptores del canal
        subscribers_list = channel.subscribers_json or []
        if isinstance(subscribers_list, str):
            try:
                subscribers_list = json.loads(subscribers_list)
            except Exception as sub_error:
                app.logger.error(f"❌ Error parsing subscribers_json: {sub_error}")
                subscribers_list = []

        app.logger.info(f"📋 Suscriptores encontrados: {len(subscribers_list)}")

        if not subscribers_list:
            app.logger.warning("❌ Canal sin suscriptores")
            return jsonify({'error': 'Este canal no tiene suscriptores'}), 400

        # Crear notificación para cada suscriptor
        app.logger.info(f"📨 Iniciando envío a {len(subscribers_list)} suscriptores...")
        notifications_sent = 0
        for user_id_code in subscribers_list:
            # Buscar el usuario por id_code
            subscriber = User.query.filter_by(id_code=user_id_code).first()
            if subscriber:  # Enviar a todos los suscriptores incluyendo al admin
                try:
                    create_notification(
                        recipient_user_id=subscriber.id,
                        notification_type='channel_alert',
                        title=f'Alerta de {channel.name}',
                        message=message,
                        sender_user_id=current_user.id,
                        data={'channel_id': channel.id_code, 'channel_name': channel.name}
                    )
                    notifications_sent += 1
                except Exception as notif_error:
                    app.logger.error(f"❌ Error creando notificación para usuario {subscriber.id}: {notif_error}")
                    import traceback
                    app.logger.error(traceback.format_exc())

        app.logger.info(f"✅ Alertas enviadas: {notifications_sent}/{len(subscribers_list)}")

        return jsonify({
            'message': f'Alerta enviada correctamente a {notifications_sent} miembro(s)',
            'notifications_sent': notifications_sent
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error en send_channel_alert: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/channels/<string:channel_id>/alert-history', methods=['GET'])
@token_required
def get_channel_alert_history(current_user, channel_id):
    """
    Obtiene el historial de alertas enviadas a un canal.
    Solo accesible para administradores del canal.
    """
    try:
        app.logger.info(f"📋 Obteniendo historial de alertas para canal {channel_id}")

        # Verificar que el canal existe
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            app.logger.warning(f"❌ Canal {channel_id} no encontrado")
            return jsonify({'error': 'Canal no encontrado'}), 404

        app.logger.info(f"✅ Canal encontrado: {channel.name}")

        # Verificar permisos
        is_admin = False
        if current_user.role and current_user.role.upper() == 'SUPERADMIN':
            is_admin = True
            app.logger.info(f"✅ Usuario es SUPERADMIN")
        else:
            try:
                user_org = UserOrganization.query.filter_by(
                    user_id=current_user.id,
                    organization_id=channel.organization_id,
                    role='ORG_ADMIN'
                ).first()
                if user_org:
                    is_admin = True
                    app.logger.info(f"✅ Usuario es ORG_ADMIN")
                else:
                    try:
                        channels_admin = json.loads(current_user.channels_admin) if current_user.channels_admin else []
                        if channel.id_code in channels_admin:
                            is_admin = True
                            app.logger.info(f"✅ Usuario es CHANNEL_ADMIN")
                    except Exception as json_error:
                        app.logger.error(f"❌ Error parsing channels_admin: {json_error}")
                        channels_admin = []
            except Exception as perm_error:
                app.logger.error(f"❌ Error verificando permisos: {perm_error}")

        if not is_admin:
            app.logger.warning(f"❌ Usuario {current_user.id} sin permisos para canal {channel_id}")
            return jsonify({'error': 'No tienes permisos para ver las alertas de este canal'}), 403

        # Obtener alertas del canal (notificaciones tipo 'channel_alert')
        # Buscamos en la tabla de notificaciones las que tienen el channel_id en el campo data
        app.logger.info(f"🔍 Buscando notificaciones tipo channel_alert...")
        notifications = Notification.query.filter_by(notification_type='channel_alert').order_by(Notification.created_at.desc()).limit(50).all()
        app.logger.info(f"📊 Encontradas {len(notifications)} notificaciones channel_alert en total")

        # Filtrar solo las del canal específico
        channel_alerts = []
        seen_messages = set()  # Para evitar duplicados por mensaje + fecha

        for notif in notifications:
            try:
                notif_data = json.loads(notif.data) if notif.data else {}
                if notif_data.get('channel_id') == channel_id:
                    # Crear una clave única basada en mensaje y fecha (redondeada a minuto)
                    created_at_str = notif.created_at.strftime('%Y-%m-%d %H:%M') if notif.created_at else ''
                    message_key = f"{notif.message}_{created_at_str}"

                    if message_key not in seen_messages:
                        seen_messages.add(message_key)

                        # Obtener información del remitente
                        sender = User.query.get(notif.sender_user_id) if notif.sender_user_id else None
                        sender_name = sender.username if sender else 'Administrador'

                        # Contar cuántos suscriptores había en ese momento (aproximación)
                        subscribers_list = channel.subscribers_json or []
                        if isinstance(subscribers_list, str):
                            try:
                                subscribers_list = json.loads(subscribers_list)
                            except:
                                subscribers_list = []

                        channel_alerts.append({
                            'id': notif.id,
                            'message': notif.message,
                            'sender_name': sender_name,
                            'created_at': notif.created_at.isoformat() if notif.created_at else None,
                            'recipients_count': len(subscribers_list)
                        })
            except Exception as e:
                app.logger.error(f"❌ Error procesando notificación {notif.id}: {e}")
                import traceback
                app.logger.error(traceback.format_exc())
                continue

        app.logger.info(f"✅ Devolviendo {len(channel_alerts)} alertas para el canal {channel_id}")

        return jsonify({
            'alerts': channel_alerts,
            'count': len(channel_alerts)
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error en get_channel_alert_history: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/channels/<string:channel_id>/send-poll', methods=['POST'])
@token_required
def send_channel_poll(current_user, channel_id):
    """Crear y enviar encuesta a todos los miembros del canal"""
    try:
        data = request.get_json()
        question = data.get('question')
        options = data.get('options', [])  # Lista de opciones
        multiple_choice = data.get('multiple_choice', False)
        anonymous = data.get('anonymous', False)
        expires_in_hours = data.get('expires_in_hours')  # Opcional: horas hasta expirar
        
        if not question or len(options) < 2:
            return jsonify({'error': 'Se requiere una pregunta y al menos 2 opciones'}), 400
        
        # Verificar que el usuario es admin del canal
        is_admin = False
        if current_user.role.upper() == 'SUPERADMIN':
            is_admin = True
        else:
            channels_admin = json.loads(current_user.channels_admin) if current_user.channels_admin else []
            if channel_id in channels_admin:
                is_admin = True
        
        if not is_admin:
            return jsonify({'error': 'Solo los administradores pueden enviar encuestas'}), 403
        
        # Calcular fecha de expiración si se especificó
        expires_at = None
        if expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=int(expires_in_hours))
        
        # Crear la encuesta
        poll = ChannelPoll(
            channel_id=channel_id,
            creator_user_id=current_user.id,
            question=question,
            options=options,
            multiple_choice=multiple_choice,
            anonymous=anonymous,
            expires_at=expires_at
        )
        db.session.add(poll)
        db.session.flush()  # Para obtener el poll.id
        
        # Obtener canal info
        channel = Channel.query.filter_by(channel_id=channel_id).first()
        
        # Enviar notificación a todos los suscriptores
        subscribers = ChannelSubscriber.query.filter_by(channel_id=channel_id).all()
        
        for subscriber in subscribers:
            notification_data = {
                'id': None,  # Se asignará después de crear
                'notification_type': 'channel_poll',
                'title': f'📊 Encuesta en {channel.name}',
                'message': question,
                'poll_id': poll.id,
                'poll_data': {
                    'question': question,
                    'options': options,
                    'multiple_choice': multiple_choice,
                    'anonymous': anonymous,
                    'expires_at': expires_at.isoformat() if expires_at else None
                }
            }
            
            # Crear notificación en BD
            notification = create_notification(
                recipient_user_id=subscriber.user_id,
                sender_user_id=current_user.id,
                notification_type='channel_poll',
                title=f'📊 Encuesta en {channel.name}',
                message=question,
                data={'poll_id': poll.id}
            )
            
            notification_data['id'] = notification.id
            
            # Enviar via WebSocket
            emit_notification_to_user(subscriber.user_id, notification_data)
        
        db.session.commit()
        
        app.logger.info(f"📊 Encuesta creada y enviada a {len(subscribers)} usuarios del canal {channel_id}")
        
        return jsonify({
            'message': 'Encuesta enviada exitosamente',
            'poll_id': poll.id,
            'recipients': len(subscribers)
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error enviando encuesta: {e}")
        return jsonify({'error': 'Error enviando encuesta'}), 500


@app.route('/polls/<int:poll_id>/vote', methods=['POST'])
@token_required
def vote_in_poll(current_user, poll_id):
    """Votar en una encuesta"""
    try:
        data = request.get_json()
        option_indices = data.get('option_indices', [])  # Lista de índices (para múltiple elección)
        
        if not option_indices:
            return jsonify({'error': 'Debes seleccionar al menos una opción'}), 400
        
        poll = ChannelPoll.query.get_or_404(poll_id)
        
        # Verificar si la encuesta expiró
        if poll.expires_at and datetime.utcnow() > poll.expires_at:
            return jsonify({'error': 'Esta encuesta ha expirado'}), 400
        
        # Verificar que el usuario es suscriptor del canal
        subscriber = ChannelSubscriber.query.filter_by(
            channel_id=poll.channel_id,
            user_id=current_user.id
        ).first()
        
        if not subscriber:
            return jsonify({'error': 'No eres miembro de este canal'}), 403
        
        # Verificar si permite múltiple elección
        if not poll.multiple_choice and len(option_indices) > 1:
            return jsonify({'error': 'Esta encuesta solo permite una respuesta'}), 400
        
        # Eliminar votos anteriores del usuario en esta encuesta
        PollVote.query.filter_by(poll_id=poll_id, user_id=current_user.id).delete()
        
        # Crear nuevos votos
        for option_index in option_indices:
            if option_index < 0 or option_index >= len(poll.options):
                return jsonify({'error': f'Opción inválida: {option_index}'}), 400
            
            vote = PollVote(
                poll_id=poll_id,
                user_id=current_user.id,
                option_index=option_index
            )
            db.session.add(vote)
        
        db.session.commit()
        
        app.logger.info(f"✅ Usuario {current_user.id} votó en encuesta {poll_id}")
        
        # Retornar resultados actualizados
        results = get_poll_results(poll)
        
        return jsonify({
            'message': 'Voto registrado exitosamente',
            'results': results
        }), 200
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error votando en encuesta: {e}")
        return jsonify({'error': 'Error registrando voto'}), 500


@app.route('/polls/<int:poll_id>/results', methods=['GET'])
@token_required
def get_poll_results_endpoint(current_user, poll_id):
    """Obtener resultados de una encuesta"""
    try:
        poll = ChannelPoll.query.get_or_404(poll_id)
        
        # Verificar que el usuario es suscriptor del canal
        subscriber = ChannelSubscriber.query.filter_by(
            channel_id=poll.channel_id,
            user_id=current_user.id
        ).first()
        
        if not subscriber:
            return jsonify({'error': 'No eres miembro de este canal'}), 403
        
        results = get_poll_results(poll)
        
        # Verificar si el usuario ya votó
        user_votes = PollVote.query.filter_by(
            poll_id=poll_id,
            user_id=current_user.id
        ).all()
        
        user_voted_indices = [v.option_index for v in user_votes] if user_votes else []
        
        return jsonify({
            'poll_id': poll.id,
            'question': poll.question,
            'options': poll.options,
            'multiple_choice': poll.multiple_choice,
            'anonymous': poll.anonymous,
            'expires_at': poll.expires_at.isoformat() if poll.expires_at else None,
            'created_at': poll.created_at.isoformat(),
            'creator': poll.creator.username,
            'results': results,
            'user_voted': user_voted_indices,
            'total_votes': sum([r['count'] for r in results])
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error obteniendo resultados: {e}")
        return jsonify({'error': 'Error obteniendo resultados'}), 500


def get_poll_results(poll):
    """Función auxiliar para calcular resultados de encuesta"""
    results = []
    total_votes = len(set([v.user_id for v in poll.votes]))  # Usuarios únicos que votaron
    
    for idx, option in enumerate(poll.options):
        votes_for_option = PollVote.query.filter_by(
            poll_id=poll.id,
            option_index=idx
        ).all()
        
        count = len(votes_for_option)
        percentage = (count / total_votes * 100) if total_votes > 0 else 0
        
        result = {
            'option': option,
            'count': count,
            'percentage': round(percentage, 1)
        }
        
        # Si no es anónima, incluir quiénes votaron
        if not poll.anonymous:
            voters = [User.query.get(v.user_id).username for v in votes_for_option]
            result['voters'] = voters
        
        results.append(result)
    
    return results



@app.route('/update-donation-amount', methods=['POST'])
@token_required
def update_donation_amount(current_user):
    """Update the donation amount for a specific channel without subscribing/unsubscribing"""
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        donation_amount = data.get('donation_amount', 0)
        hide_amount = data.get('hide_amount', False)
        session_id = data.get('session_id', None)

        if not channel_id:
            return jsonify({'message': 'Channel ID is required!'}), 400

        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # Handle multiple formats: array, simple object, and extended object
        # Handle donating field - puede ser string JSON o dict/list
        if current_user.donating:
            if isinstance(current_user.donating, str):
                user_donating_raw = json.loads(current_user.donating)
            else:
                user_donating_raw = current_user.donating
        else:
            user_donating_raw = []
        user_donating_dict = {}

        if isinstance(user_donating_raw, list):
            # Convert old format ["ch123", "ch456"] to new format
            user_donating_dict = {ch_id: {"amount": 0, "hidden": False, "session_id": None} for ch_id in user_donating_raw}
        elif isinstance(user_donating_raw, dict):
            # Handle both old dict format {"ch123": 10} and new format {"ch123": {"amount": 10, "hidden": false, "session_id": "..."}}
            for ch_id, value in user_donating_raw.items():
                if isinstance(value, dict):
                    # New format already - ensure session_id exists
                    user_donating_dict[ch_id] = {
                        "amount": value.get("amount", 0),
                        "hidden": value.get("hidden", False),
                        "session_id": value.get("session_id", None)
                    }
                else:
                    # Old format, convert to new format
                    user_donating_dict[ch_id] = {"amount": value, "hidden": False, "session_id": None}

        if channel.id_code not in user_donating_dict:
            return jsonify({'message': 'Not subscribed to this channel! Subscribe first before setting donation amount.'}), 400

        # If updating with a new session_id and there's an existing donation > 0, cancel previous subscription
        existing_info = user_donating_dict.get(channel.id_code, {})
        old_session_id = existing_info.get('session_id')
        old_amount = existing_info.get('amount', 0)

        if session_id and old_session_id and old_session_id != session_id and old_amount > 0 and donation_amount > 0:
            try:
                app.logger.info(f"Cancelling previous subscription {old_session_id} before creating new one")
                stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

                # Retrieve the old checkout session
                old_checkout_session = stripe.checkout.Session.retrieve(old_session_id)
                if old_checkout_session.subscription:
                    # Cancel the old subscription
                    stripe.Subscription.modify(
                        old_checkout_session.subscription,
                        cancel_at_period_end=True
                    )
                    app.logger.info(f"Successfully cancelled previous subscription {old_checkout_session.subscription}")
            except Exception as e:
                app.logger.error(f"Error cancelling previous subscription: {e}")
                # Continue with update even if cancellation fails

        # Update donation amount, hidden status, and session_id
        user_donating_dict[channel.id_code] = {
            "amount": donation_amount,
            "hidden": hide_amount,
            "session_id": session_id
        }
        current_user.donating = json.dumps(user_donating_dict)

        db.session.commit()

        return jsonify({
            'message': 'Donation amount updated successfully!',
            'donating': user_donating_dict,
            'channel_id': channel_id,
            'donation_amount': donation_amount
        }), 200

    except Exception as e:
        app.logger.error(f"Error updating donation amount: {e}")
        return jsonify({'message': 'An error occurred while updating donation amount.'}), 500

@app.route('/cancel-stripe-subscription', methods=['POST'])
@token_required
def cancel_stripe_subscription(current_user):
    """Cancel Stripe subscription when user cancels donation"""
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')

        if not channel_id:
            return jsonify({'message': 'Channel ID is required!'}), 400

        # Get user's donation info for this channel
        user_donating_raw = json.loads(current_user.donating) if current_user.donating else {}
        user_donating_dict = {}

        # Handle format conversion
        if isinstance(user_donating_raw, dict):
            for ch_id, value in user_donating_raw.items():
                if isinstance(value, dict):
                    user_donating_dict[ch_id] = {
                        "amount": value.get("amount", 0),
                        "hidden": value.get("hidden", False),
                        "session_id": value.get("session_id", None)
                    }
                else:
                    user_donating_dict[ch_id] = {"amount": value, "hidden": False, "session_id": None}

        donation_info = user_donating_dict.get(channel_id, {})
        session_id = donation_info.get('session_id')
        donation_amount = donation_info.get('amount', 0)

        app.logger.info(f"Attempting to cancel subscription for channel {channel_id}, donation_amount: {donation_amount}, session_id: {session_id}")

        if not session_id:
            app.logger.warning(f"No session ID found for channel {channel_id}. This might be an old donation created before session_id implementation.")
            if donation_amount > 0:
                return jsonify({'message': 'No session ID found for this channel donation. This appears to be an old donation that cannot be automatically cancelled in Stripe. Please contact support.'}), 404
            else:
                return jsonify({'message': 'No active subscription found for this channel'}), 200

        # Set Stripe API key
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

        # Retrieve the checkout session
        checkout_session = stripe.checkout.Session.retrieve(session_id)

        if checkout_session.subscription:
            # Cancel the subscription
            subscription = stripe.Subscription.modify(
                checkout_session.subscription,
                cancel_at_period_end=True
            )

            return jsonify({
                'message': 'Subscription cancelled successfully',
                'subscription_id': subscription.id,
                'cancel_at_period_end': subscription.cancel_at_period_end
            }), 200
        else:
            return jsonify({'message': 'No active subscription found for this session'}), 404

    except stripe.error.StripeError as e:
        app.logger.error(f"Stripe error cancelling subscription: {e}")
        return jsonify({'message': f'Stripe error: {str(e)}'}), 400
    except Exception as e:
        app.logger.error(f"Error cancelling subscription: {e}")
        return jsonify({'message': 'An error occurred while cancelling subscription.'}), 500

@app.route('/debug-donation-info', methods=['GET'])
@token_required
def debug_donation_info(current_user):
    """Debug endpoint to check donation info for current user"""
    try:
        user_donating_raw = json.loads(current_user.donating) if current_user.donating else {}

        # Process donation data to show detailed info
        detailed_info = {}
        for channel_id, donation_data in user_donating_raw.items():
            if isinstance(donation_data, dict):
                detailed_info[channel_id] = {
                    "amount": donation_data.get("amount", 0),
                    "hidden": donation_data.get("hidden", False),
                    "session_id": donation_data.get("session_id", "NOT_SET"),
                    "has_session_id": bool(donation_data.get("session_id"))
                }
            else:
                detailed_info[channel_id] = {
                    "amount": donation_data,
                    "hidden": False,
                    "session_id": "OLD_FORMAT",
                    "has_session_id": False
                }

        return jsonify({
            'user_id': current_user.id,
            'username': current_user.username,
            'raw_donating_data': user_donating_raw,
            'detailed_donation_info': detailed_info
        }), 200

    except Exception as e:
        app.logger.error(f"Error in debug donation info: {e}")
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/delete-channel/<string:id_code>', methods=['DELETE'])
@token_required
def delete_channel(current_user, id_code):
    try:
        channel = Channel.query.filter_by(id_code=id_code).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        if not (superadmin_permission.can() or org_admin_perm.can()):
            return jsonify({'message': 'No permission to delete this channel!'}), 403
        db.session.delete(channel)
        db.session.commit()
        return jsonify({'message': 'Channel deleted successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error deleting channel: {e}")
        return jsonify({'message': 'An error occurred while deleting the channel.'}), 500

@app.route('/add-token/<string:id_code_channel>', methods=['POST'])
@token_required
def add_token_to_channel(current_user, id_code_channel):
    """
    Crea o actualiza un token para el canal cuyo id_code es `id_code_channel`.
    
    Se espera un JSON en el body, por ejemplo:
    {
       "token_name": "youtube_api",
       "token_value": "fhdsiugh8943u2heuwdksjhiru2398y14uirh432"
    }

    - Si el canal no existe => 404
    - Si el usuario no tiene permisos => 403 (opcional, si deseas restringir acceso)
    - Si se proporciona un token_name ya existente, se actualiza su valor.
    - De lo contrario, se añade como nuevo token.
    """
    try:
        # 1) Obtenemos el canal por su id_code
        channel = Channel.query.filter_by(id_code=id_code_channel).first()
        if not channel:
            return jsonify({'message': f'Canal con id_code={id_code_channel} no encontrado.'}), 404

        # 2) Verificamos permisos (opcional pero recomendable)
        #    Solo SUPERADMIN, ORG_ADMIN de la org del canal o CHANNEL_ADMIN del canal
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        chan_admin_perm = ChannelAdminPermission(channel.id)
        if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
            return jsonify({
                'message': 'No tienes permisos para modificar tokens en este canal.'
            }), 403

        # 3) Leemos el JSON del body
        data = request.get_json() or {}
        token_name = data.get('token_name')
        token_value = data.get('token_value')

        if not token_name or not token_value:
            return jsonify({
                'message': 'Faltan campos: token_name y token_value son obligatorios.'
            }), 400

        # 4) Cargamos el user_settings del canal como dict
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            # Si en la BD está guardado como string JSON
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        # 5) Aseguramos que exista un sub-dict "tokens"
        if "tokens" not in channel_settings or not isinstance(channel_settings["tokens"], dict):
            channel_settings["tokens"] = {}

        # 6) Creamos o actualizamos el token
        channel_settings["tokens"][token_name] = token_value

        # 7) Persistimos en la BD
        channel.user_settings = channel_settings
        # Incrementar la versión del canal para forzar actualización en apps cliente
        channel.version = (channel.version or 1) + 1
        
        # Notificamos a SQLAlchemy de cambio en el JSON si fuera necesario
        flag_modified(channel, "user_settings")

        db.session.commit()

        return jsonify({
            'message': f'Token "{token_name}" agregado/actualizado exitosamente en el canal {channel.name}.'
        }), 200

    except Exception as e:
        app.logger.error(f"Error en add_token_to_channel: {e}")
        return jsonify({'message': 'Error al crear/actualizar el token.', 'error': str(e)}), 500


# --------------------------- Update Channel ------------------------------------
@app.route('/update-channel', methods=['POST'])
@token_required
def update_channel(current_user):
    """
    Actualiza los datos de un canal existente. Se puede enviar 'id_code' o 'id_channel'
    junto con los campos a actualizar.
    
    Ejemplo de JSON de entrada:
    {
      "id_code": "abc123xyz",
      "name": "Nuevo nombre de canal",
      "subscribers_count": 999,
      "user_notifications": { ... },
      ...
    }
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'message': 'No se recibió ningún dato para actualizar.'}), 400

        # 1) Buscar el canal por id_code o por id (id_channel)
        channel = None
        id_code = data.get('id_code')
        id_channel = data.get('id_channel')

        if id_code:
            channel = Channel.query.filter_by(id_code=id_code).first()
        elif id_channel:
            channel = Channel.query.get(id_channel)

        if not channel:
            return jsonify({'message': 'Canal no encontrado.'}), 404

        # 2) Verificar permisos:
        #    - SUPERADMIN
        #    - ORG_ADMIN de la organización dueña del canal
        #    - CHANNEL_ADMIN del canal
        # Para eso, podemos utilizar los permisos ya definidos:
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        chan_admin_perm = ChannelAdminPermission(channel.id)

        # Si NO es superadmin y además NO es org_admin de la org, y NO es channel_admin
        if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
            return jsonify({'message': 'No tienes permisos para actualizar este canal.'}), 403

        # 3) Actualizar campos permitidos
        #    Define aquí los campos que quieras permitir actualizar.
        #    (Por ejemplo: name, user_notifications, subscribers_count, etc.)
        #    O si prefieres actualizar todos los campos dinámicamente, puedes
        #    tener cuidado de no pisar campos que no quieras exponer.

        # Ejemplo: Actualizamos algunos campos si vienen en el JSON
        if 'name' in data:
            channel.name = data['name']
        if 'subscribers_count' in data:
            # Asegúrate de que sea un entero
            try:
                channel.subscribers_count = int(data['subscribers_count'])
            except ValueError:
                return jsonify({'message': 'subscribers_count debe ser un número entero.'}), 400
        if 'user_notifications' in data:
            # Asegúrate de que sea un JSON válido
            if isinstance(data['user_notifications'], dict):
                channel.user_notifications = json.dumps(data['user_notifications'])
            else:
                return jsonify({'message': 'user_notifications debe ser un objeto JSON.'}), 400

        # Incrementar la versión del canal
        channel.version = (channel.version or 1) + 1

        # 4) Guarda los cambios
        db.session.commit()

        return jsonify({'message': 'Canal actualizado correctamente!'}), 200

    except Exception as e:
        app.logger.error(f"Error al actualizar canal: {e}")
        return jsonify({'message': f'Ha ocurrido un error al actualizar el canal: {str(e)}'}), 500

# --------------------- Create Post ---------------------------
@app.route('/create-post', methods=['POST'])
@token_required
def create_post(current_user):
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        text = data.get('text')
        image_url = data.get('image_url')
        image_urls = data.get('image_urls')  # Array de URLs para carrusel
        video_urls = data.get('video_urls')  # Array de URLs de videos
        event_date_str = data.get('event_date')
        posttag = data.get('posttag')

        app.logger.info(f"📝 Creating post with data: channel_id={channel_id}, text='{text[:50]}...', image_url={image_url}, image_urls={image_urls}, video_urls={video_urls}, posttag='{posttag}'")

        if not channel_id or not text:
            return jsonify({'message': 'channel_id and text are required!'}), 400
        channel = Channel.query.get(channel_id)
        if not channel:
            return jsonify({'message': 'Channel does not exist!'}), 404

        # Verificar permisos jerárquicos: superadmin > org_admin > channel_admin
        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        channel_admin_perm = ChannelAdminPermission(channel_id)
        if not (superadmin_permission.can() or org_admin_perm.can() or channel_admin_perm.can()):
            return jsonify({'message': 'No permission to create a post in this channel!'}), 403
        event_date = None
        if event_date_str:
            try:
                event_date = datetime.strptime(event_date_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    event_date = datetime.strptime(event_date_str, '%Y-%m-%d')
                except ValueError:
                    return jsonify({'message': 'Invalid event_date format!'}), 400

        # Procesar múltiples imágenes para carrusel
        postimage_json = None
        reelsvideo_json = None

        # Procesar videos
        if video_urls and isinstance(video_urls, list) and len(video_urls) > 0:
            # Es un post con videos
            reelsvideo_json = [{"video": url} for url in video_urls]
            app.logger.info(f"🎥 Creating video post with {len(video_urls)} videos")
        elif image_urls and isinstance(image_urls, list) and len(image_urls) > 1:
            # Es un carrusel con múltiples imágenes
            postimage_json = [{"image": url} for url in image_urls]
            app.logger.info(f"📸 Creating carousel post with {len(image_urls)} images")
        elif image_urls and isinstance(image_urls, list) and len(image_urls) == 1:
            # Una sola imagen en el array, usar image_url normal
            image_url = image_urls[0]
            app.logger.info(f"📸 Creating single image post")

        new_post = Post(
            channel_id=channel_id,
            text=text,
            image_url=image_url,
            postimage_json=postimage_json,
            reelsvideo_json=reelsvideo_json,
            event_date=event_date,
            posttag=posttag
        )
        db.session.add(new_post)
        db.session.commit()
        return jsonify({'message': 'Post created successfully!'}), 201
    except Exception as e:
        app.logger.error(f"Error creating post: {e}")
        return jsonify({'message': 'An error occurred while creating the post.'}), 500

# --------------------- Get Post ---------------------------
@app.route('/post/<string:post_id_code>', methods=['GET'])
@token_required
def get_post(current_user, post_id_code):
    try:
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': 'Post not found!'}), 404

        # Verificar permisos básicos de lectura
        channel = Channel.query.get(post.channel_id)
        if not channel:
            return jsonify({'message': 'Channel does not exist!'}), 404

        post_data = {
            'id': post.id,
            'id_code': post.id_code,
            'channel_id': post.channel_id,
            'text': post.text,
            'image_url': post.image_url,
            'postimage_json': post.postimage_json,
            'reelsvideo_json': post.reelsvideo_json,
            'posttag': post.posttag,
            'event_date': post.event_date.isoformat() if post.event_date else None,
            'created_at': post.created_at.isoformat() if post.created_at else None,
            'like_count': post.like_count,
            'comment_count': post.comment_count
        }

        app.logger.info(f"📄 Retrieved post {post_id_code} data")
        return jsonify(post_data), 200
    except Exception as e:
        app.logger.error(f"Error getting post: {e}")
        return jsonify({'message': 'An error occurred while getting the post.'}), 500

# --------------------- Edit Post ---------------------------
@app.route('/edit-post/<string:post_id_code>', methods=['PUT'])
@token_required
def edit_post(current_user, post_id_code):
    try:
        data = request.get_json()
        channel_id = data.get('channel_id')
        text = data.get('text')
        image_url = data.get('image_url')
        image_urls = data.get('image_urls')  # Array de URLs para carrusel
        video_urls = data.get('video_urls')  # Array de URLs de videos
        posttag = data.get('posttag')

        app.logger.info(f"📝 Editing post {post_id_code} with data: channel_id={channel_id}, text='{text[:50] if text else ''}...', image_url={image_url}, image_urls={image_urls}, video_urls={video_urls}, posttag='{posttag}'")

        # Buscar el post por id_code
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': 'Post not found!'}), 404

        # Verificar permisos jerárquicos: superadmin > org_admin > channel_admin
        channel = Channel.query.get(post.channel_id)
        if not channel:
            return jsonify({'message': 'Channel does not exist!'}), 404

        org_admin_perm = OrganizationAdminPermission(channel.organization_id)
        channel_admin_perm = ChannelAdminPermission(post.channel_id)
        if not (superadmin_permission.can() or org_admin_perm.can() or channel_admin_perm.can()):
            return jsonify({'message': 'No permission to edit this post!'}), 403

        # Actualizar campos del post
        if text is not None:
            post.text = text
        if posttag is not None:
            post.posttag = posttag

        # Procesar videos o imágenes
        if video_urls and isinstance(video_urls, list) and len(video_urls) > 0:
            # Es un post con videos
            post.reelsvideo_json = [{"video": url} for url in video_urls]
            post.postimage_json = None  # Limpiar imágenes si hay videos
            post.image_url = None
            app.logger.info(f"🎥 Updating video post with {len(video_urls)} videos")
        elif image_urls and isinstance(image_urls, list):
            if len(image_urls) > 1:
                # Es un carrusel con múltiples imágenes
                post.postimage_json = [{"image": url} for url in image_urls]
                post.image_url = image_urls[0]  # Primera imagen para compatibilidad
                post.reelsvideo_json = None  # Limpiar videos si hay imágenes
                app.logger.info(f"📸 Updating carousel post with {len(image_urls)} images")
            elif len(image_urls) == 1:
                # Una sola imagen
                post.image_url = image_urls[0]
                post.postimage_json = None
                post.reelsvideo_json = None  # Limpiar videos si hay imágenes
                app.logger.info(f"📸 Updating single image post")
        elif image_url:
            # Actualizar imagen única
            post.image_url = image_url
            post.postimage_json = None
            post.reelsvideo_json = None  # Limpiar videos si hay imágenes

        db.session.commit()

        # Emitir evento WebSocket para actualizar el post en tiempo real
        try:
            # Preparar datos del post actualizado
            post_data = {
                'post_id_code': post_id_code,
                'text': post.text,
                'posttag': post.posttag,
                'image_url': post.image_url,
                'images': [],
                'videos': []
            }

            # Agregar imágenes
            if post.postimage_json:
                post_data['images'] = [img.get('image') for img in post.postimage_json if img.get('image')]
            elif post.image_url:
                post_data['images'] = [post.image_url]

            # Agregar videos
            if post.reelsvideo_json:
                post_data['videos'] = [vid.get('video') for vid in post.reelsvideo_json if vid.get('video')]

            app.logger.info(f"🔊 [WebSocket] Emitting post_updated: {post_data}")
            socketio.emit('post_updated', post_data)
            app.logger.info(f"✅ [WebSocket] post_updated event emitted successfully")
        except Exception as ws_error:
            app.logger.error(f"❌ [WebSocket] Emit failed in /edit-post: {ws_error}", exc_info=True)

        return jsonify({'message': 'Post updated successfully!'}), 200
    except Exception as e:
        app.logger.error(f"Error editing post: {e}")
        return jsonify({'message': 'An error occurred while editing the post.'}), 500

# --------------------- Hide Post ---------------------------
@app.route('/hide_post/<string:post_id_code>', methods=['POST'])
@token_required
def hide_post(current_user, post_id_code):
    try:
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({"message": f"Post not found with id_code: {post_id_code}"}), 404

        hide_posts_list = current_user.hide_posts or []
        if isinstance(hide_posts_list, str):
            try:
                hide_posts_list = json.loads(hide_posts_list)
            except:
                hide_posts_list = []

        # Si ya está oculto, devolvemos 200 y mensaje
        is_already_hidden = any(hp["post_id_code"] == post_id_code for hp in hide_posts_list)
        if is_already_hidden:
            return jsonify({"message": "Este post ya estaba oculto."}), 200

        import time
        hide_posts_list.append({
            "post_id_code": post_id_code,
            "hidden_at": int(time.time())
        })

        current_user.hide_posts = hide_posts_list

        # FORZAR A SQLAlchemy A RECONOCER CAMBIOS EN LA COLUMNA JSON
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(current_user, "hide_posts")

        db.session.commit()
        return jsonify({"message": "Post ocultado con éxito."}), 200

    except Exception as e:
        app.logger.error(f"Error in /hide_post/<id_code>: {e}")
        return jsonify({"message": "An error occurred while hiding the post."}), 500

@app.route('/unhide_post/<string:post_id_code>', methods=['POST'])
@token_required
def unhide_post(current_user, post_id_code):
    """Remove a post from the user's hidden posts list"""
    try:
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({"message": f"Post not found with id_code: {post_id_code}"}), 404

        hide_posts_list = current_user.hide_posts or []
        if isinstance(hide_posts_list, str):
            try:
                hide_posts_list = json.loads(hide_posts_list)
            except:
                hide_posts_list = []

        # Remove the post from hidden list
        new_hide_posts = [hp for hp in hide_posts_list if hp["post_id_code"] != post_id_code]

        if len(new_hide_posts) == len(hide_posts_list):
            return jsonify({"message": "Este post no estaba oculto."}), 400

        current_user.hide_posts = new_hide_posts

        # Flag modified to force SQLAlchemy to recognize JSON changes
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(current_user, "hide_posts")

        db.session.commit()
        return jsonify({"message": "Post visible de nuevo."}), 200

    except Exception as e:
        app.logger.error(f"Error in /unhide_post/<id_code>: {e}")
        return jsonify({"message": "An error occurred while unhiding the post."}), 500

@app.route('/get-hidden-posts', methods=['GET'])
@token_required
def get_hidden_posts(current_user):
    """
    Retorna los posts ocultos del usuario con toda su información.
    """
    try:
        # Obtener posts ocultos del usuario
        hide_posts_list = current_user.hide_posts or []
        if isinstance(hide_posts_list, str):
            try:
                hide_posts_list = json.loads(hide_posts_list)
            except:
                hide_posts_list = []

        # Obtener detalles de cada post oculto
        hidden_posts = []
        for hide_item in hide_posts_list:
            post_id_code = hide_item['post_id_code']
            post = Post.query.filter_by(id_code=post_id_code).first()

            if post:
                # Obtener información del canal
                channel = Channel.query.get(post.channel_id)
                channel_name = channel.name if channel else "Canal desconocido"
                channel_id_code = channel.id_code if channel else None

                # Construir URL de imagen del canal desde S3
                channel_image_url = (
                    f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                    f"app/channels/{channel_id_code}/profile.jpeg"
                ) if channel_id_code else None

                post_data = {
                    'id': post.id,
                    'id_code': post.id_code,
                    'channel_id': post.channel_id,
                    'channel_id_code': channel_id_code,
                    'channel_name': channel_name,
                    'channel_image_url': channel_image_url,
                    'text': post.text,
                    'image_url': post.image_url,
                    'postimage_json': post.postimage_json,
                    'reelsvideo_json': post.reelsvideo_json,
                    'posttag': post.posttag,
                    'event_date': post.event_date.isoformat() if post.event_date else None,
                    'created_at': post.created_at.isoformat() if post.created_at else None,
                    'like_count': len(post.post_likes or []),
                    'comment_count': len(post.post_comments or []),
                    'total_prays': len(post.post_prays or []),
                    'hidden_at': hide_item.get('hidden_at', 0)
                }
                hidden_posts.append(post_data)

        # Ordenar por fecha de ocultado (más recientes primero)
        hidden_posts.sort(key=lambda x: x['hidden_at'], reverse=True)

        return jsonify({'hidden_posts': hidden_posts}), 200

    except Exception as e:
        app.logger.error(f"Error in /get-hidden-posts: {e}")
        return jsonify({"message": "An error occurred while getting hidden posts."}), 500

# --------------------- Get Posts ---------------------------
# --------------------- Get Posts ---------------------------
@app.route('/get-posts', methods=['GET'])
@token_required
def get_posts(current_user):
    try:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=87600)
        from sqlalchemy import or_, and_

        # Obtener parámetros de filtro
        channel_ids_filter = request.args.get('channel_ids', '').strip()

        # 1) Obtener canales suscritos del usuario
        user_subscribed_channels = []
        if current_user.donating:
            if isinstance(current_user.donating, str):
                try:
                    donating_data = json.loads(current_user.donating)
                except:
                    donating_data = []
            else:
                donating_data = current_user.donating

            # Extraer IDs de canales suscritos
            if isinstance(donating_data, dict):
                user_subscribed_channels = list(donating_data.keys())
            elif isinstance(donating_data, list):
                user_subscribed_channels = donating_data

        # 2) Cargar los posts base - SOLO de canales suscritos
        if user_subscribed_channels:
            posts_query = Post.query.join(Channel).filter(
                and_(
                    Channel.id_code.in_(user_subscribed_channels),
                    or_(
                        Post.created_at >= cutoff,
                        and_(Post.event_date != None, Post.event_date >= now)
                    )
                )
            )

            # 2.1) Aplicar filtro adicional por channel_ids si viene del frontend
            if channel_ids_filter:
                try:
                    channel_ids = [int(cid.strip()) for cid in channel_ids_filter.split(',') if cid.strip()]
                    if channel_ids:
                        posts_query = posts_query.filter(Channel.id.in_(channel_ids))
                        app.logger.info(f"🔍 Filtering posts by channel IDs: {channel_ids}")
                except ValueError as e:
                    app.logger.warning(f"⚠️ Invalid channel_ids format: {e}")

            posts_query = posts_query.order_by(Post.created_at.desc())
        else:
            # Si no está suscrito a ningún canal, no mostrar posts
            posts_query = Post.query.filter(Post.id == -1)  # Query que no devuelve nada

        # 3) Cargar los post_id_code ocultos del usuario
        hide_posts_list = current_user.hide_posts or []
        if isinstance(hide_posts_list, str):
            try:
                hide_posts_list = json.loads(hide_posts_list)
            except:
                hide_posts_list = []
        # Convertirlos en un conjunto
        hidden_id_codes = set(item['post_id_code'] for item in hide_posts_list)

        # Función recursiva que cuenta todos los comentarios + sus respuestas
        def count_nested_comments(comments_list):
            total = 0
            for c in comments_list:
                total += 1  # Se cuenta este comentario
                # Si hay 'replies', se llama recursivamente
                if 'replies' in c and isinstance(c['replies'], list):
                    total += count_nested_comments(c['replies'])
            return total

        results = []
        for p in posts_query:
            # 4) Omitir el post si su id_code está en la lista de ocultos
            if p.id_code in hidden_id_codes:
                continue

            # 5) Obtener imágenes de múltiples fuentes
            images = []

            # 4.1) Primero, obtener imágenes de S3
            prefix = f"app/posts/{p.id_code}/"
            s3_response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
            if 'Contents' in s3_response:
                for item in s3_response['Contents']:
                    key = item['Key']
                    if key == prefix:
                        continue
                    key_encoded = '/'.join(quote_plus(segment) for segment in key.split('/'))
                    image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{key_encoded}"
                    images.append(image_url)

            # 4.2) Si no hay imágenes de S3, usar las del campo image_url
            if not images and p.image_url:
                images.append(p.image_url)

            # 4.3) También considerar postimage_json (para carruseles)
            if p.postimage_json:
                try:
                    postimage_data = p.postimage_json
                    if isinstance(postimage_data, str):
                        postimage_data = json.loads(postimage_data)

                    if isinstance(postimage_data, list):
                        for img_obj in postimage_data:
                            if isinstance(img_obj, dict) and 'image' in img_obj:
                                images.append(img_obj['image'])
                except (json.JSONDecodeError, TypeError) as e:
                    app.logger.error(f"Error parsing postimage_json for post {p.id_code}: {e}")

            # 4.4) Manejar videos de reelsvideo_json
            reels_video = None
            if p.reelsvideo_json:
                try:
                    reelsvideo_data = p.reelsvideo_json
                    if isinstance(reelsvideo_data, str):
                        reelsvideo_data = json.loads(reelsvideo_data)

                    if isinstance(reelsvideo_data, list) and len(reelsvideo_data) > 0:
                        video_obj = reelsvideo_data[0]
                        if isinstance(video_obj, dict) and 'video' in video_obj:
                            video_url = video_obj['video']
                            # Verificar que video_url no sea None antes de usar startswith
                            if video_url and isinstance(video_url, str):
                                if video_url.startswith('VIDEO.'):
                                    # Esto sería para videos locales, pero por ahora manejemos solo URLs
                                    reels_video = None
                                else:
                                    reels_video = { 'uri': video_url }
                            else:
                                reels_video = None
                except (json.JSONDecodeError, TypeError) as e:
                    app.logger.error(f"Error parsing reelsvideo_json for post {p.id_code}: {e}")

            # 5) Imagen de perfil del canal
            profile_image = (
                f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                f"app/channels/{p.channel.id_code}/profile.jpeg"
            )

            # 5.1) Verificar user_settings del canal para saber si 'comment': false
            try:
                channel_settings = p.channel.user_settings
                if channel_settings and isinstance(channel_settings, str):
                    channel_settings = json.loads(channel_settings)
                elif not channel_settings:
                    channel_settings = {}
            except:
                channel_settings = {}

            # Si "comment" es estrictamente False => is_comment=False, en caso contrario True
            is_comment = not (channel_settings.get("comment") is False)

            # 6) Determinar la cantidad de oraciones (prays)
            post_prays = p.post_prays or []
            if isinstance(post_prays, str):
                try:
                    post_prays = json.loads(post_prays)
                except:
                    post_prays = []
            pray_count = len(post_prays)
            user_id_code = current_user.id_code
            is_prayed = any(entry.get('user_id_code') == user_id_code for entry in post_prays)

            # 6.5) Calcular is_liked (mismo patrón que is_prayed)
            post_likes = p.post_likes or []
            if isinstance(post_likes, str):
                try:
                    post_likes = json.loads(post_likes)
                except:
                    post_likes = []
            like_count = len(post_likes)
            is_liked = any(entry.get('user_id_code') == user_id_code for entry in post_likes)

            # 7) Calcular la cantidad real de comentarios (recursivamente)
            post_comments = p.post_comments or []
            if isinstance(post_comments, str):
                try:
                    post_comments = json.loads(post_comments)
                except:
                    post_comments = []
            real_comment_count = count_nested_comments(post_comments)

            # 8) Construir el objeto de salida
            results.append({
                'id': p.id_code,
                'channel_id': p.channel_id,
                'channel_id_code': p.channel.id_code,
                'name': p.channel.name,
                'text': p.text,
                'images': images,
                'reels_video': reels_video,
                'profile_image': profile_image,
                'event_date': p.event_date.isoformat() if p.event_date else None,
                'created_at': p.created_at.isoformat(),
                'pray_count': pray_count,
                'like_count': like_count,
                'comment_count': real_comment_count,
                'is_prayed': is_prayed,
                'is_liked': is_liked,
                'is_comment': is_comment,  # <= Nuevo campo
                'posttag': p.posttag,  # <= Campo agregado
                'is_published': p.is_published  # <= Campo de publicación
            })

        app.logger.info(results)
        return jsonify({'posts': results}), 200

    except Exception as e:
        app.logger.error(f"Error fetching posts: {e}")
        return jsonify({'message': 'An error occurred while fetching posts.'}), 500



@app.route('/get-post-prays-extended/<string:post_id_code>', methods=['GET'])
@token_required
def get_post_prays_extended(current_user, post_id_code):
    try:
        # 1) Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # 2) Carga la lista de oraciones (post_prays).
        #    Puede ser una lista de dicts como [{'user_id_code': 'abc123', 'pray_at': 1679999999}, ...]
        post_prays = post.post_prays or []
        if isinstance(post_prays, str):
            # Si en la base de datos está guardado como string JSON, lo convertimos a lista
            try:
                post_prays = json.loads(post_prays)
            except:
                post_prays = []

        # 3) Para cada user_id_code en la lista, buscamos al usuario y construimos la respuesta extendida
        results = []
        for entry in post_prays:
            user_id_code = entry.get('user_id_code')
            if not user_id_code:
                continue  # Si por alguna razón no viene el user_id_code, lo saltamos

            user_obj = User.query.filter_by(id_code=user_id_code).first()
            if not user_obj:
                # Si no existe el usuario en la BD (caso raro), lo omitimos
                continue

            # Construimos la URL de la imagen de perfil tal como quieres (almacenada en channels/):
            # Ojo: si guardas las imágenes de usuarios en otra ruta S3, ajusta aquí el path
            # Según tu snippet, deseas: /app/channels/<user_id_code>/profile.jpeg
            profile_url = (
                f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                f"app/channels/{user_obj.id_code}/profile.jpeg"
            )

            # Añade al resultado el diccionario con la estructura solicitada:
            results.append({
                "id": user_obj.id_code,
                "title": user_obj.username,       # o user_obj.name si lo usas en la BD
                "image": profile_url,
                "text": "alex_techie_2123",       # Literal según tu ejemplo (o podrías usar user_obj.username)
                "hasStory": False
            })

        # 4) Retornamos la lista con la clave que prefieras. Por ejemplo "post_prays_extended"
        return jsonify({"post_prays_extended": results}), 200

    except Exception as e:
        app.logger.error(f"Error in /get-post-prays-extended: {e}")
        return jsonify({"message": "An error occurred while retrieving extended post prays."}), 500


@app.route('/get-translation', methods=['POST'])
def get_translation():
    try:
        data = request.get_json()
        language = data.get('language')
        key = data.get('key')
        if not language or not key:
            return jsonify({'message': 'Language and key are required'}), 400
        translation_entry = Translation.query.filter_by(language=language, key=key).first()
        if translation_entry:
            return jsonify({'translation': translation_entry.translation}), 200
        else:
            return jsonify({'translation': None}), 200
    except Exception as e:
        return jsonify({'message': f'Error fetching translation: {str(e)}'}), 500

@app.route('/save-translation', methods=['POST'])
def save_translation():
    try:
        data = request.get_json()
        language = data.get('language')
        key = data.get('key')
        translation = data.get('translation')
        if not language or not key or not translation:
            return jsonify({'message': 'Language, key, and translation are required'}), 400

        # Usar merge para hacer upsert automático
        existing_translation = Translation.query.filter_by(language=language, key=key).first()
        if existing_translation:
            # Si existe, actualizar
            existing_translation.translation = translation
            db.session.commit()
        else:
            # Si no existe, intentar crear con manejo de duplicados
            try:
                new_translation = Translation(language=language, key=key, translation=translation)
                db.session.add(new_translation)
                db.session.commit()
            except Exception as insert_error:
                # Si falla por duplicado, hacer rollback y actualizar
                db.session.rollback()
                existing_translation = Translation.query.filter_by(language=language, key=key).first()
                if existing_translation:
                    existing_translation.translation = translation
                    db.session.commit()
                else:
                    raise insert_error

        return jsonify({'message': 'Translation saved successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Error saving translation: {str(e)}'}), 500

@app.route('/update-followers', methods=['POST'])
@token_required
@superadmin_permission.require(http_exception=403)
def update_followers(current_user):
    try:
        followers_count = {}
        users = User.query.all()
        for user in users:
            donating_list = []
            if user.donating:
                try:
                    if isinstance(user.donating, str):
                        donating_list = json.loads(user.donating)
                    elif isinstance(user.donating, list):
                        donating_list = user.donating
                    else:
                        donating_list = []
                except (json.JSONDecodeError, ValueError, TypeError) as e:
                    app.logger.error(f"Error parsing donating for user {user.id}: {e}")
                    donating_list = []
            for channel_id in donating_list:
                followers_count[channel_id] = followers_count.get(channel_id, 0) + 1
        channels = Channel.query.all()
        updated_channels = []
        for channel in channels:
            count = followers_count.get(channel.id_code, 0)
            channel.subscribers_count = count
            updated_channels.append({
                "id_code": channel.id_code,
                "name": channel.name,
                "subscribers_count": count
            })
        db.session.commit()
        return jsonify({
            "message": "Followers updated successfully.",
            "channels": updated_channels
        }), 200
    except Exception as e:
        app.logger.error(f"Error updating followers: {e}")
        return jsonify({
            "message": "An error occurred while updating followers.",
            "error": str(e)
        }), 500

@app.route('/post-fav/<string:post_id_code>', methods=['POST'])
@token_required
def post_fav(current_user, post_id_code):
    """
    Añade el post (id_code) a la lista de favoritos del usuario.
    Guarda en user.post_fav un dict { 'post_id_code': ..., 'fav_at': epoch }.
    """
    try:
        # Verificar que el Post exista (opcional, para no marcar como favorito uno inexistente):
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Cargar favoritos del usuario
        user_favs = current_user.post_fav or []  # si es None => lista vacía
        if isinstance(user_favs, str):
            # Por si en la BD quedó como string JSON
            try:
                user_favs = json.loads(user_favs)
            except:
                user_favs = []

        # Verificar si ya existe en la lista de favoritos
        already_fav = any(item['post_id_code'] == post_id_code for item in user_favs)
        if already_fav:
            return jsonify({'message': 'Post is already in favorites'}), 400

        # Agregarlo con la marca de tiempo
        import time
        fav_at = int(time.time())
        user_favs.append({
            'post_id_code': post_id_code,
            'fav_at': fav_at
        })

        # Guardar la lista actualizada
        app.logger.error(f"💾 POST_FAV - Antes de guardar: {user_favs}")
        current_user.post_fav = user_favs

        # Force SQLAlchemy to detect the change
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(current_user, "post_fav")

        app.logger.error(f"💾 POST_FAV - Antes de commit, user.post_fav = {current_user.post_fav}")
        db.session.commit()
        app.logger.error(f"💾 POST_FAV - Después de commit, user.post_fav = {current_user.post_fav}")

        return jsonify({'message': 'Post marked as favorite successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in post_fav: {e}")
        return jsonify({'message': 'An error occurred while marking post as favorite.'}), 500

@app.route('/get-post-fav', methods=['GET'])
@token_required
def get_post_fav(current_user):
    """
    Retorna el listado de id_code de todos los posts 
    que el usuario en sesión ha marcado como 'favoritos'.
    """
    try:
        user_favs = current_user.post_fav or []
        if isinstance(user_favs, str):
            try:
                user_favs = json.loads(user_favs)
            except:
                user_favs = []

        # Extraemos solo el post_id_code
        fav_codes = [item['post_id_code'] for item in user_favs]

        return jsonify({'post_favorites': fav_codes}), 200

    except Exception as e:
        app.logger.error(f"Error in get_post_fav: {e}")
        return jsonify({'message': 'An error occurred while retrieving the favorites.'}), 500

@app.route('/post-unfav/<string:post_id_code>', methods=['POST'])
@token_required
def post_unfav(current_user, post_id_code):
    """
    Elimina un post (id_code) de la lista de favoritos del usuario.
    """
    # Debug inmediato al entrar en la función
    print(f"🗑️🗑️🗑️ POST_UNFAV REACHED - Usuario: {current_user.email}, Post: {post_id_code}")
    app.logger.error(f"🗑️🗑️🗑️ POST_UNFAV REACHED - Usuario: {current_user.email}, Post: {post_id_code}")

    try:
        app.logger.info(f"🗑️ POST_UNFAV - Usuario: {current_user.email}, Post: {post_id_code}")

        user_favs = current_user.post_fav or []
        app.logger.info(f"🗑️ POST_UNFAV - user_favs inicial: {user_favs}")

        if isinstance(user_favs, str):
            try:
                user_favs = json.loads(user_favs)
                app.logger.info(f"🗑️ POST_UNFAV - user_favs después de JSON.loads: {user_favs}")
            except:
                user_favs = []
                app.logger.info(f"🗑️ POST_UNFAV - Error parsing JSON, usando lista vacía")

        # Log de cada item en la lista para debugging
        for i, item in enumerate(user_favs):
            app.logger.info(f"🗑️ POST_UNFAV - Favorito {i}: {item}")
            app.logger.info(f"🗑️ POST_UNFAV - Comparando '{item.get('post_id_code')}' vs '{post_id_code}'")

        # Nueva lista sin ese post_id_code
        new_favs = [item for item in user_favs if item.get('post_id_code') != post_id_code]
        app.logger.info(f"🗑️ POST_UNFAV - new_favs: {new_favs}")
        app.logger.info(f"🗑️ POST_UNFAV - Longitud original: {len(user_favs)}, nueva: {len(new_favs)}")

        # Si no cambió nada, significa que no estaba en la lista
        if len(new_favs) == len(user_favs):
            app.logger.warning(f"🗑️ POST_UNFAV - Post {post_id_code} no encontrado en favoritos")
            return jsonify({'message': 'Post not found in favorites.'}), 400

        current_user.post_fav = new_favs
        db.session.commit()

        app.logger.info(f"🗑️ POST_UNFAV - Post {post_id_code} eliminado de favoritos exitosamente")
        return jsonify({'message': 'Post removed from favorites successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in post_unfav: {e}")
        return jsonify({'message': 'An error occurred while removing the post from favorites.'}), 500

@app.route('/get-saved-posts', methods=['GET'])
@token_required
def get_saved_posts(current_user):
    """
    Retorna los posts guardados del usuario con toda su información.
    """
    try:
        # Obtener favoritos del usuario
        user_favs = current_user.post_fav or []
        if isinstance(user_favs, str):
            try:
                user_favs = json.loads(user_favs)
            except:
                user_favs = []

        # Obtener detalles de cada post guardado
        saved_posts = []
        for fav_item in user_favs:
            post_id_code = fav_item['post_id_code']
            post = Post.query.filter_by(id_code=post_id_code).first()

            if post:
                # Obtener información del canal
                channel = Channel.query.get(post.channel_id)
                channel_name = channel.name if channel else "Canal desconocido"

                # Posts don't have user_id field in this schema, use channel info instead
                post_data = {
                    'id': post.id,
                    'id_code': post.id_code,
                    'channel_id': post.channel_id,
                    'channel_name': channel_name,
                    'user_id': None,
                    'username': channel_name,
                    'text': post.text,
                    'image_url': post.image_url,
                    'postimage_json': post.postimage_json,
                    'reelsvideo_json': post.reelsvideo_json,
                    'posttag': post.posttag,
                    'event_date': post.event_date.isoformat() if post.event_date else None,
                    'created_at': post.created_at.isoformat() if post.created_at else None,
                    'like_count': post.like_count,
                    'comment_count': post.comment_count,
                    'saved_at': fav_item.get('fav_at', 0)
                }
                saved_posts.append(post_data)

        # Ordenar por fecha de guardado (más recientes primero)
        saved_posts.sort(key=lambda x: x['saved_at'], reverse=True)

        return jsonify({'saved_posts': saved_posts}), 200

    except Exception as e:
        app.logger.error(f"Error in get_saved_posts: {e}")
        return jsonify({'message': 'An error occurred while retrieving saved posts.'}), 500

# --------------------------- Post pray ------------------------------------
@app.route('/post-pray/<string:post_id_code>', methods=['POST'])
@token_required
def post_pray(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Cargar la lista de post_prays del usuario
        user_prays = current_user.post_prays or []
        if isinstance(user_prays, str):
            try:
                user_prays = json.loads(user_prays)
            except:
                user_prays = []

        # Revisar si ya existe el post en post_prays del usuario
        already_prayed = any(item['post_id_code'] == post_id_code for item in user_prays)
        if already_prayed:
            return jsonify({
                'message': 'You have already prayed for this post.',
                'already_prayed': True
            }), 200

        # Agregarlo con marca de tiempo (epoch)
        current_epoch = int(time.time())
        user_prays.append({
            'post_id_code': post_id_code,
            'pray_at': current_epoch
        })
        current_user.post_prays = user_prays
        flag_modified(current_user, 'post_prays')

        # Ahora, en la tabla post, agregamos el user_id_code del usuario actual
        post_prays = post.post_prays or []
        if isinstance(post_prays, str):
            try:
                post_prays = json.loads(post_prays)
            except:
                post_prays = []

        post_prays.append({
            'user_id_code': current_user.id_code,
            'pray_at': current_epoch
        })
        post.post_prays = post_prays
        flag_modified(post, 'post_prays')

        db.session.commit()

        # Emitir evento WebSocket para actualizar contadores en tiempo real
        try:
            pray_count = len(post_prays)
            like_count = len(post.post_likes or []) if post.post_likes else 0

            event_data = {
                'post_id_code': post_id_code,
                'pray_count': pray_count,
                'like_count': like_count,
                'comment_count': len(post.post_comments or []) if post.post_comments else 0,
                'action': 'pray'
            }

            app.logger.info(f"🔊 [WebSocket] Emitting post_interaction_updated: {event_data}")
            socketio.emit('post_interaction_updated', event_data)
            app.logger.info(f"✅ [WebSocket] Event emitted successfully")
        except Exception as ws_error:
            app.logger.error(f"❌ [WebSocket] Emit failed in /post-pray: {ws_error}", exc_info=True)

        return jsonify({'message': 'Post prayed successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in /post-pray: {e}")
        return jsonify({'message': 'An error occurred while performing post-pray.'}), 500

# --------------------------- Post unpray ------------------------------------
@app.route('/post-unpray/<string:post_id_code>', methods=['POST'])
@token_required
def post_unpray(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Quitar del user.prays
        user_prays = current_user.post_prays or []
        if isinstance(user_prays, str):
            try:
                user_prays = json.loads(user_prays)
            except:
                user_prays = []

        new_user_prays = [item for item in user_prays if item['post_id_code'] != post_id_code]

        # Quitar del post.prays
        post_prays = post.post_prays or []
        if isinstance(post_prays, str):
            try:
                post_prays = json.loads(post_prays)
            except:
                post_prays = []

        new_post_prays = [item for item in post_prays if item['user_id_code'] != current_user.id_code]

        # Guardar cambios solo si hubo modificación
        if len(new_user_prays) != len(user_prays) or len(new_post_prays) != len(post_prays):
            current_user.post_prays = new_user_prays
            post.post_prays = new_post_prays
            flag_modified(current_user, 'post_prays')
            flag_modified(post, 'post_prays')
            db.session.commit()

            # Emitir evento WebSocket para actualizar contadores en tiempo real
            try:
                pray_count = len(new_post_prays)
                like_count = len(post.post_likes or []) if post.post_likes else 0

                socketio.emit('post_interaction_updated', {
                    'post_id_code': post_id_code,
                    'pray_count': pray_count,
                    'like_count': like_count,
                    'comment_count': len(post.post_comments or []) if post.post_comments else 0,
                    'action': 'unpray'
                })
            except Exception as ws_error:
                app.logger.warning(f"WebSocket emit failed in /post-unpray: {ws_error}")

            return jsonify({'message': 'Post unprayed successfully!'}), 200
        else:
            return jsonify({'message': 'No pray entry found to remove.'}), 400

    except Exception as e:
        app.logger.error(f"Error in /post-unpray: {e}")
        return jsonify({'message': 'An error occurred while performing post-unpray.'}), 500

# --------------------------- Post like (toggle) ------------------------------------
@app.route('/post-like/<string:post_id_code>', methods=['POST'])
@token_required
def post_like_endpoint(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Cargar la lista de post_like del usuario (singular, como está en el modelo)
        user_likes = current_user.post_like or []
        if isinstance(user_likes, str):
            try:
                user_likes = json.loads(user_likes)
            except:
                user_likes = []

        # Revisar si ya existe el post en post_like del usuario
        already_liked = any(item['post_id_code'] == post_id_code for item in user_likes)

        # Toggle: si ya le dio like, quitarlo (unlike)
        if already_liked:
            return jsonify({
                'message': 'You have already liked this post.',
                'already_liked': True
            }), 200

        # Si no le había dado like, agregarlo
        current_epoch = int(time.time())
        user_likes.append({
            'post_id_code': post_id_code,
            'liked_at': current_epoch
        })
        current_user.post_like = user_likes

        # Ahora, en la tabla post, agregamos el user_id_code del usuario actual
        post_likes = post.post_likes or []
        if isinstance(post_likes, str):
            try:
                post_likes = json.loads(post_likes)
            except:
                post_likes = []

        post_likes.append({
            'user_id_code': current_user.id_code,
            'liked_at': current_epoch
        })
        post.post_likes = post_likes

        flag_modified(current_user, 'post_like')
        flag_modified(post, 'post_likes')

        db.session.commit()

        # Emitir evento WebSocket para actualizar contadores en tiempo real
        try:
            like_count = len(post_likes)
            pray_count = len(post.post_prays or []) if post.post_prays else 0

            socketio.emit('post_interaction_updated', {
                'post_id_code': post_id_code,
                'pray_count': pray_count,
                'like_count': like_count,
                'comment_count': len(post.post_comments or []) if post.post_comments else 0,
                'action': 'like'
            })
        except Exception as ws_error:
            app.logger.warning(f"WebSocket emit failed in /post-like (like): {ws_error}")

        return jsonify({
            'message': 'Post liked successfully!',
            'liked': True
        }), 200

    except Exception as e:
        app.logger.error(f"Error in /post-like: {e}")
        return jsonify({'message': 'An error occurred while performing post-like.'}), 500

# --------------------------- Post unlike ------------------------------------
@app.route('/post-unlike/<string:post_id_code>', methods=['POST'])
@token_required
def post_unlike(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Quitar del user.likes
        user_likes = current_user.post_like or []
        if isinstance(user_likes, str):
            try:
                user_likes = json.loads(user_likes)
            except:
                user_likes = []

        new_user_likes = [item for item in user_likes if item['post_id_code'] != post_id_code]

        # Quitar del post.likes
        post_likes = post.post_likes or []
        if isinstance(post_likes, str):
            try:
                post_likes = json.loads(post_likes)
            except:
                post_likes = []

        new_post_likes = [item for item in post_likes if item['user_id_code'] != current_user.id_code]

        # Guardar cambios solo si hubo modificación
        if len(new_user_likes) != len(user_likes) or len(new_post_likes) != len(post_likes):
            current_user.post_like = new_user_likes
            post.post_likes = new_post_likes
            flag_modified(current_user, 'post_like')
            flag_modified(post, 'post_likes')
            db.session.commit()

            # Emitir evento WebSocket para actualizar contadores en tiempo real
            try:
                like_count = len(new_post_likes)
                pray_count = len(post.post_prays or []) if post.post_prays else 0

                socketio.emit('post_interaction_updated', {
                    'post_id_code': post_id_code,
                    'pray_count': pray_count,
                    'like_count': like_count,
                    'comment_count': len(post.post_comments or []) if post.post_comments else 0,
                    'action': 'unlike'
                })
            except Exception as ws_error:
                app.logger.warning(f"WebSocket emit failed in /post-unlike: {ws_error}")

            return jsonify({'message': 'Post unliked successfully!'}), 200
        else:
            return jsonify({'message': 'No like entry found to remove.'}), 400

    except Exception as e:
        app.logger.error(f"Error in /post-unlike: {e}")
        return jsonify({'message': 'An error occurred while performing post-unlike.'}), 500

# --------------------------- Post get users prays ------------------------------------
@app.route('/get-post-prays/<string:post_id_code>', methods=['GET'])
@token_required
def get_post_prays(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Cargar la lista post_prays
        post_prays = post.post_prays or []
        if isinstance(post_prays, str):
            try:
                post_prays = json.loads(post_prays)
            except:
                post_prays = []

        # Queremos solo los user_id_code (o los objetos completos, dependiendo tus necesidades)
        user_ids = [entry.get('user_id_code') for entry in post_prays]

        return jsonify({'post_prays': user_ids}), 200

    except Exception as e:
        app.logger.error(f"Error in /get-post-prays: {e}")
        return jsonify({'message': 'An error occurred while retrieving post prays.'}), 500

# --------------------------- Post publish (admin) ------------------------------------
@app.route('/post-publish/<string:post_id_code>', methods=['POST'])
@token_required
def post_publish(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Publicar el post
        post.is_published = True
        db.session.commit()

        return jsonify({'message': 'Post published successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in /post-publish: {e}")
        return jsonify({'message': 'An error occurred while publishing post.'}), 500

# --------------------------- Post unpublish (admin) ------------------------------------
@app.route('/post-unpublish/<string:post_id_code>', methods=['POST'])
@token_required
def post_unpublish(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Despublicar el post
        post.is_published = False
        db.session.commit()

        return jsonify({'message': 'Post unpublished successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in /post-unpublish: {e}")
        return jsonify({'message': 'An error occurred while unpublishing post.'}), 500

# --------------------------- Post mark as reviewed (admin) ------------------------------------
@app.route('/post-mark-reviewed/<string:post_id_code>', methods=['POST'])
@token_required
def post_mark_reviewed(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Marcar como revisado (esto puede ser un campo booleano o timestamp)
        # Por ahora lo dejamos como publicado si no estaba
        if not post.is_published:
            post.is_published = True
            db.session.commit()

        return jsonify({'message': 'Post marked as reviewed successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in /post-mark-reviewed: {e}")
        return jsonify({'message': 'An error occurred while marking post as reviewed.'}), 500

# --------------------------- Post delete (superadmin only) ------------------------------------
@app.route('/post-delete/<string:post_id_code>', methods=['DELETE'])
@token_required
def post_delete(current_user, post_id_code):
    try:
        # Verifica que el post exista
        post = Post.query.filter_by(id_code=post_id_code).first()
        if not post:
            return jsonify({'message': f'Post not found with id_code: {post_id_code}'}), 404

        # Eliminar el post
        db.session.delete(post)
        db.session.commit()

        return jsonify({'message': 'Post deleted successfully!'}), 200

    except Exception as e:
        app.logger.error(f"Error in /post-delete: {e}")
        return jsonify({'message': 'An error occurred while deleting post.'}), 500

# --------------------------- Onboarding endpoints ------------------------------------
@app.route('/check-nickname', methods=['POST'])
@token_required
def check_nickname(current_user):
    """
    Check if a nickname is available and valid
    Expects JSON: { "nickname": "@username" }
    """
    try:
        data = request.get_json()
        nickname = data.get('nickname', '').strip()

        # Validate format
        if not nickname:
            return jsonify({
                'available': False,
                'message': 'El nickname no puede estar vacío'
            }), 400

        if not nickname.startswith('@'):
            return jsonify({
                'available': False,
                'message': 'El nickname debe empezar con @'
            }), 400

        if len(nickname) < 4:  # @ + at least 3 characters
            return jsonify({
                'available': False,
                'message': 'El nickname debe tener al menos 3 caracteres después del @'
            }), 400

        # Check if nickname already exists
        existing_user = User.query.filter_by(nickname=nickname).first()
        if existing_user and existing_user.id != current_user.id:
            return jsonify({
                'available': False,
                'message': 'Este nickname ya está en uso'
            }), 200

        return jsonify({
            'available': True,
            'message': 'Nickname disponible'
        }), 200

    except Exception as e:
        app.logger.error(f"Error in /check-nickname: {e}")
        return jsonify({'message': 'Error al verificar nickname'}), 500

@app.route('/get-parroquias', methods=['GET'])
@token_required
def get_parroquias(current_user):
    """
    Get list of all available parishes (organizations)
    Query params:
    - all: if 'true', returns all organizations including inactive ones
    """
    try:
        # Check if we should return all organizations
        get_all = request.args.get('all', 'false').lower() == 'true'

        if get_all:
            organizations = Organization.query.all()
        else:
            organizations = Organization.query.filter_by(is_active=True).all()

        parroquias_list = []
        for org in organizations:
            parroquias_list.append({
                'id': org.id,
                'name': org.name,
                'diocese': org.diocese_name if hasattr(org, 'diocese_name') else None,
                'parish_name': org.parish_name if hasattr(org, 'parish_name') else None,
                'city': org.city if hasattr(org, 'city') else None,
            })

        return jsonify({
            'parroquias': parroquias_list
        }), 200

    except Exception as e:
        app.logger.error(f"Error in /get-parroquias: {e}")
        return jsonify({'message': 'Error al obtener parroquias'}), 500

@app.route('/complete-profile', methods=['POST'])
@token_required
def complete_profile(current_user):
    """
    Complete user profile with onboarding data
    Expects JSON: {
        "nickname": "@username",
        "parroquia_principal_id": 123,
        "auto_subscribe_enabled": true
    }
    """
    try:
        data = request.get_json()
        nickname = data.get('nickname', '').strip()
        parroquia_principal_id = data.get('parroquia_principal_id')
        auto_subscribe_enabled = data.get('auto_subscribe_enabled', False)

        # Validate nickname
        if not nickname or not nickname.startswith('@'):
            return jsonify({'message': 'Nickname inválido'}), 400

        # Check if nickname is taken by another user
        existing_user = User.query.filter_by(nickname=nickname).first()
        if existing_user and existing_user.id != current_user.id:
            return jsonify({'message': 'Nickname ya está en uso'}), 400

        # Validate parroquia exists (only if provided)
        if parroquia_principal_id is not None and parroquia_principal_id > 0:
            parroquia = Organization.query.filter_by(id=parroquia_principal_id).first()
            if not parroquia:
                return jsonify({'message': 'Parroquia no encontrada'}), 404
        else:
            # If no parroquia selected, set to None
            parroquia_principal_id = None

        # Update user profile
        current_user.nickname = nickname
        current_user.parroquia_principal_id = parroquia_principal_id
        current_user.auto_subscribe_enabled = auto_subscribe_enabled
        current_user.onboarding_completed = True

        # Auto-subscribe to channels if enabled and parroquia is selected
        subscribed_channels = []
        if auto_subscribe_enabled and parroquia_principal_id is not None and parroquia_principal_id > 0:
            parroquia = Organization.query.filter_by(id=parroquia_principal_id).first()

            # Get all channels from the parish
            parish_channels = Channel.query.filter_by(organization_id=parroquia_principal_id).all()

            # Get diocese channels if available
            diocese_channels = []
            if parroquia and hasattr(parroquia, 'diocese_name') and parroquia.diocese_name:
                # Find diocese organization
                diocese_org = Organization.query.filter_by(name=parroquia.diocese_name).first()
                if diocese_org:
                    diocese_channels = Channel.query.filter_by(organization_id=diocese_org.id).all()

            # Subscribe to all channels
            all_channels = parish_channels + diocese_channels
            for channel in all_channels:
                # Get current subscribers list from JSON field
                subscribers_list = channel.subscribers_json if channel.subscribers_json else []

                if current_user.id not in subscribers_list:
                    subscribers_list.append(current_user.id)
                    channel.subscribers_json = subscribers_list
                    flag_modified(channel, 'subscribers_json')
                    subscribed_channels.append({
                        'id_code': channel.id_code,
                        'name': channel.name
                    })

        db.session.commit()

        return jsonify({
            'message': 'Perfil completado exitosamente',
            'subscribed_channels': subscribed_channels
        }), 200

    except Exception as e:
        app.logger.error(f"Error in /complete-profile: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error al completar perfil'}), 500

# --------------------------- Post add comment ------------------------------------
from flask import request, jsonify
from flask_cors import CORS
from sqlalchemy.orm.attributes import flag_modified
import time, json

@app.route("/post_add_comment/<string:id_code>", methods=["POST"])
@token_required
def post_add_comment(current_user, id_code):
    """
    Añade un comentario a un post. Valida moderación con OpenAI:
    - Si está flagged, se añade a channel.suspect_comments.
    - Si no está flagged, se añade al array post.post_comments (top-level o reply).
    """
    app.logger.info("===== post_add_comment - INICIO =====")
    app.logger.info(f"ID_CODE (ruta): {id_code}")

    try:
        # 1) Buscar el Post por su id_code
        post = Post.query.filter_by(id_code=id_code).first()
        if not post:
            return jsonify({"message": f"No se encontró el post con id_code: {id_code}"}), 404

        data = request.get_json() or {}

        # 2) Texto del comentario recibido
        text_comment = data.get("text_comment", "")

        # 3) Llamar a la verificación de contenido ofensivo
        flagged = check_offensive_content(text_comment)
        if flagged:
            # 3A) Guardar el comentario en suspect_comments del canal
            channel = post.channel
            if channel is None:
                return jsonify({"message": "Este post no tiene canal asociado."}), 400

            # Convertimos a lista
            suspect_list = channel.suspect_comments or []
            if isinstance(suspect_list, str):
                try:
                    suspect_list = json.loads(suspect_list)
                except:
                    suspect_list = []

            # Añadimos la info del comentario sospechoso
            suspect_list.append({
                "post_id": post.id_code,
                "epoch_time": int(time.time()),
                "text_comment": text_comment,
                "motivo": "Posible infracción de normas",
                "user_id": current_user.id_code   # si tu User tiene id_code
            })

            # Reasignar y marcar como modificado
            channel.suspect_comments = suspect_list
            flag_modified(channel, "suspect_comments")
            db.session.commit()

            # 3B) Retornar el mensaje al front
            return jsonify({
                "message": "Comentario en supervisión. Este comentario se ha marcado como sospechoso "
                           "por potencial infracción de nuestras normas de conducta."
            }), 210

        # 4) Si el comentario NO está flaggeado => lo agregamos a post.post_comments
        pattern_id = data.get("pattern_id_code_comment", "")
        new_comment_id = generate_random_code()  # tu generador de códigos
        epoch_now = int(time.time())

        # Cargamos/definimos la lista de comentarios
        original_comments = post.post_comments or []
        if isinstance(original_comments, str):
            try:
                original_comments = json.loads(original_comments)
            except:
                original_comments = []

        # Construye el diccionario del nuevo comentario
        new_comment = {
            "id": new_comment_id,
            "epoch_time": epoch_now,
            "comment": text_comment,
            "likes": [],
            "replies": [],
            "user_id_code": current_user.id_code
        }

        # 5) Verificamos si es top-level o reply
        if not pattern_id:
            # Comentario TOP-LEVEL
            app.logger.info("Es un comentario TOP-LEVEL")
            original_comments.append(new_comment)
        else:
            # Comentario hijo (reply)
            app.logger.info(f"Es una RESPUESTA al comentario padre con id={pattern_id}")
            parent = find_comment_by_id(original_comments, pattern_id)
            if not parent:
                return jsonify({"message": f"No existe comentario padre {pattern_id}"}), 400
            if "replies" not in parent:
                parent["replies"] = []
            parent["replies"].append(new_comment)

        # 6) Guardamos la estructura de comentarios en la BD
        post.post_comments = original_comments
        post.comment_count = (post.comment_count or 0) + 1
        # Asegurarnos de notificar a SQLAlchemy
        flag_modified(post, "post_comments")
        db.session.commit()

        app.logger.info("===== post_add_comment - FIN =====")

        return jsonify({
            "message": "Comentario agregado con éxito",
            "comment_id": new_comment_id
        }), 201

    except Exception as e:
        app.logger.error(f"Error en /post_add_comment: {e}")
        return jsonify({"message": "Error al agregar comentario", "error": str(e)}), 500


# --------------------------- Post get comment ------------------------------------
@app.route('/post_get_comment/<string:id_code>', methods=['GET'])
@token_required
def post_get_comment(current_user, id_code):
    """
    Retorna el array completo de comentarios (y replies) del post con id_code.
    Reemplaza 'title' con user.username (según user_id_code),
    genera la URL de la imagen de perfil en 'image',
    añade 'like_count' = len(likes),
    fija 'hasStory' = false (o true si lo deseas),
    y añade 'is_like' = True o False si el usuario actual ha dado like.
    """
    try:
        post = Post.query.filter_by(id_code=id_code).first()
        if not post:
            return jsonify({"message": f"No se encontró el post con id_code: {id_code}"}), 404

        comments = post.post_comments or []
        if isinstance(comments, str):
            try:
                comments = json.loads(comments)
            except:
                comments = []

        def enrich_comments(comments_list):
            for c in comments_list:
                # 1) Cantidad de likes
                likes = c.get('likes', [])
                c['like_count'] = len(likes)

                # 2) Verificar si el user actual ha hecho like
                c['is_like'] = (current_user.id_code in likes)

                # 3) Buscamos al user según user_id_code
                user_id_code = c.get('user_id_code')
                if user_id_code:
                    user_obj = User.query.filter_by(id_code=user_id_code).first()
                    if user_obj:
                        c['title'] = user_obj.username
                        c['image'] = (
                            f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                            f"app/user/{user_id_code}/profile.jpeg"
                        )

                # 4) hasStory en false o true, según tu lógica
                c['hasStory'] = False

                # 5) Recursividad para replies
                if 'replies' in c and c['replies']:
                    enrich_comments(c['replies'])

        enrich_comments(comments)

        return jsonify(comments), 200

    except Exception as e:
        app.logger.error(f"Error en /post_get_comment: {e}")
        return jsonify({
            "message": "Ocurrió un error al obtener comentarios",
            "error": str(e)
        }), 500


# --------------------------- Post like comment ------------------------------------
@app.route('/post_like_comment/<string:id_code>', methods=['POST'])
@token_required
def post_like_comment(current_user, id_code):
    """
    Añade el 'id_code' del usuario actual a la lista de 'likes' de un comentario específico.
    Body JSON ejemplo:
    {
      "comment_id": "ID_DEL_COMENTARIO"
    }
    """
    try:
        post = Post.query.filter_by(id_code=id_code).first()
        if not post:
            return jsonify({"message": f"No se encontró el post con id_code: {id_code}"}), 404

        data = request.get_json() or {}
        comment_id = data.get('comment_id')
        if not comment_id:
            return jsonify({"message": "Falta comment_id en el body"}), 400

        comments = post.post_comments or []
        if isinstance(comments, str):
            try:
                comments = json.loads(comments)
            except:
                comments = []

        # Buscar el comentario
        comment_obj = find_comment_by_id(comments, comment_id)
        if not comment_obj:
            return jsonify({"message": f"No se encontró el comentario con id={comment_id}"}), 404

        # Añadir el user_id_code a la lista "likes" si no está ya
        user_id_code = current_user.id_code
        like_list = comment_obj.get("likes", [])
        if user_id_code not in like_list:
            like_list.append(user_id_code)
            comment_obj["likes"] = like_list
        else:
            return jsonify({"message": "Ya has dado like a este comentario"}), 400

        # Guardar cambios y forzar que SQLAlchemy actualice la columna
        post.post_comments = comments
        flag_modified(post, "post_comments")  # <--- IMPORTANTE
        db.session.commit()

        return jsonify({"message": "Like agregado con éxito"}), 200

    except Exception as e:
        app.logger.error(f"Error en /post_like_comment: {e}")
        return jsonify({"message": "Error al dar like al comentario", "error": str(e)}), 500

# --------------------------- Post unlike comment ------------------------------------
@app.route('/post_unlike_comment/<string:id_code>', methods=['POST'])
@token_required
def post_unlike_comment(current_user, id_code):
    """
    Elimina el 'id_code' del usuario actual de la lista de 'likes' de un comentario específico.
    Body JSON ejemplo:
    {
      "comment_id": "ID_DEL_COMENTARIO"
    }
    """
    try:
        post = Post.query.filter_by(id_code=id_code).first()
        if not post:
            return jsonify({"message": f"No se encontró el post con id_code: {id_code}"}), 404

        data = request.get_json() or {}
        comment_id = data.get('comment_id')
        if not comment_id:
            return jsonify({"message": "Falta comment_id en el body"}), 400

        comments = post.post_comments or []
        if isinstance(comments, str):
            try:
                comments = json.loads(comments)
            except:
                comments = []

        # Buscar el comentario en la estructura
        comment_obj = find_comment_by_id(comments, comment_id)
        if not comment_obj:
            return jsonify({"message": f"No se encontró el comentario con id={comment_id}"}), 404

        # Remover el user_id_code de la lista "likes"
        user_id_code = current_user.id_code
        like_list = comment_obj.get("likes", [])
        if user_id_code in like_list:
            like_list.remove(user_id_code)
            comment_obj["likes"] = like_list
        else:
            return jsonify({"message": "No habías dado like a este comentario"}), 400

        # Guardar cambios y forzar que SQLAlchemy reconozca la modificación del JSON
        post.post_comments = comments
        flag_modified(post, "post_comments")  # <--- LÍNEA IMPORTANTE
        db.session.commit()

        return jsonify({"message": "Like removido con éxito"}), 200

    except Exception as e:
        app.logger.error(f"Error en /post_unlike_comment: {e}")
        return jsonify({"message": "Error al quitar like al comentario", "error": str(e)}), 500

@app.route("/suspect_post/<string:id_code>", methods=["POST"])
@token_required
def suspect_post(current_user, id_code):
    """
    Marca un post como sospechoso. El <id_code> es del post en la tabla Post.

    - Si el post no existe => 404
    - Si el canal es None => 400
    - Si el user ya reportó antes el mismo post => 400 con mensaje
    - De lo contrario => se guarda en channel.suspect_posts y retorna 201
    """
    try:
        # 1) Verificar que exista el Post
        post = Post.query.filter_by(id_code=id_code).first()
        if not post:
            return jsonify({"message": f"No se encontró el post con id_code: {id_code}"}), 404

        channel = post.channel
        if not channel:
            return jsonify({"message": "El post no tiene un canal asociado."}), 400

        # 2) Cargar el body JSON (opcional)
        data = request.get_json() or {}

        # 3) Convertir channel.suspect_posts en lista Python
        suspect_list = channel.suspect_posts or []
        if isinstance(suspect_list, str):
            try:
                suspect_list = json.loads(suspect_list)
            except:
                suspect_list = []

        # 4) Verificar si este user ya reportó antes este post
        already_reported = any(
            item.get("post_id_code") == id_code and 
            item.get("user_report") == current_user.id_code
            for item in suspect_list
        )
        if already_reported:
            # Si existe, retornamos 400 y un JSON con un "message"
            return jsonify({"message": "Ya has reportado este post anteriormente"}), 200

        # 5) Preparar el nuevo registro
        data["post_id_code"] = id_code
        data["user_report"] = current_user.id_code

        # 6) Agregarlo a la lista
        suspect_list.append(data)
        channel.suspect_posts = suspect_list

        # 7) Guardar cambios en la BD
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(channel, "suspect_posts")
        db.session.commit()

        return jsonify({"message": "Post sospechoso registrado con éxito"}), 201

    except Exception as e:
        app.logger.error(f"Error en /suspect_post/<id_code>: {e}")
        return jsonify({"message": "Error al registrar post sospechoso", "error": str(e)}), 500


# -------------------- Ruta Current User -----------------------------
@app.route('/current-user', methods=['GET'])
@token_required
def get_current_user_data(current_user):
    """
    Retorna toda la información del usuario en curso,
    omitiendo los campos 'id', 'password', 'reset_code',
    y añadiendo contadores de arrays.
    """
    import json

    # Helper para obtener la longitud de una lista que podría venir como JSON o directamente como list
    def get_count(field_value):
        if not field_value:
            return 0
        # Si es string, intentamos parsearlo como JSON
        if isinstance(field_value, str):
            try:
                parsed = json.loads(field_value)
            except (ValueError, TypeError):
                return 0  # No se pudo parsear => lo tratamos como vacío
            if isinstance(parsed, list):
                return len(parsed)
            else:
                return 0
        # Si ya es lista, devolvemos la longitud
        if isinstance(field_value, list):
            return len(field_value)
        # Cualquier otro caso, 0
        return 0

    # Construimos un diccionario con los datos del usuario que sí exponemos
    user_info = {
        "id_code": current_user.id_code,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "donating": current_user.donating,
        "channels_admin": current_user.channels_admin,
        "user_settings": current_user.user_settings,
        "post_like": current_user.post_like,
        "post_fav": current_user.post_fav,
        "post_prays": current_user.post_prays,
        "hide_posts": current_user.hide_posts,
        "profile_image_url": current_user.profile_image_url,  # Imagen de perfil
        "cover_image_url": current_user.cover_image_url if hasattr(current_user, 'cover_image_url') else None,  # Imagen de portada
        # ...

        # Y ahora, añadimos los contadores
        "post_like_count": get_count(current_user.post_like),
        "post_fav_count": get_count(current_user.post_fav),
        "post_prays_count": get_count(current_user.post_prays),
        "hide_posts_count": get_count(current_user.hide_posts),
        "donating_count": get_count(current_user.donating),
        "channels_admin_count": get_count(current_user.channels_admin)
    }

    return jsonify({"current_user": user_info}), 200

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Obtener perfil del usuario actual"""
    try:
        user_info = {
            "id": current_user.id,
            "id_code": current_user.id_code,
            "username": current_user.username,
            "email": current_user.email,
            "role": current_user.role,
            "profile_image_url": current_user.profile_image_url,
            "nickname": current_user.nickname,
            "parroquia_principal_id": current_user.parroquia_principal_id,
            "primary_organization_id": current_user.primary_organization_id,
            "onboarding_completed": current_user.onboarding_completed if hasattr(current_user, 'onboarding_completed') else False,
            "auto_subscribe_enabled": current_user.auto_subscribe_enabled if hasattr(current_user, 'auto_subscribe_enabled') else False
        }
        app.logger.info(f"🔍 Profile response for {current_user.email}: role={current_user.role}")
        return jsonify(user_info), 200
    except Exception as e:
        app.logger.error(f"Error retrieving profile: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# --------------------------------------------------------------------
#           SISTEMA DE SEGUIMIENTO DE USUARIOS
# --------------------------------------------------------------------

@app.route('/users/search-friends', methods=['GET'])
@token_required
def search_friends(current_user):
    """Buscar usuarios por nombre de usuario"""
    try:
        query = request.args.get('q', '').strip()
        app.logger.info(f"🔍 User search request - Query: '{query}' by user: {current_user.id}")

        if not query or len(query) < 2:
            app.logger.info("🔍 Query too short, returning empty results")
            return jsonify({'users': []}), 200

        # Buscar usuarios excluyendo al usuario actual
        users = User.query.filter(
            User.username.ilike(f'%{query}%'),
            User.id != current_user.id
        ).limit(20).all()

        app.logger.info(f"🔍 Found {len(users)} users matching query")

        # Obtener estados de seguimiento para cada usuario
        user_ids = [user.id for user in users]
        follow_requests = UserFollow.query.filter(
            UserFollow.follower_id == current_user.id,
            UserFollow.following_id.in_(user_ids)
        ).all()

        follow_status_map = {req.following_id: req.status for req in follow_requests}

        users_data = []
        for user in users:
            follow_status = follow_status_map.get(user.id, 'none')
            user_data = {
                'id': user.id,
                'username': user.username,
                'profile_image_url': user.profile_image_url,
                'follow_status': follow_status
            }
            users_data.append(user_data)
            app.logger.info(f"🔍 User found: {user.username} (ID: {user.id})")

        app.logger.info(f"🔍 Returning {len(users_data)} users")
        return jsonify({'users': users_data}), 200

    except Exception as e:
        app.logger.error(f"❌ Error searching users: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/debug/users', methods=['GET'])
@token_required
def debug_users(current_user):
    """Endpoint de debug para ver usuarios en la base de datos"""
    try:
        total_users = User.query.count()
        recent_users = User.query.order_by(User.id.desc()).limit(5).all()

        users_data = []
        for user in recent_users:
            user_dict = {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
            # Agregar created_at solo si existe en el modelo
            if hasattr(user, 'created_at') and user.created_at:
                try:
                    user_dict['created_at'] = user.created_at.isoformat()
                except:
                    user_dict['created_at'] = None

            users_data.append(user_dict)

        return jsonify({
            'total_users': total_users,
            'current_user': current_user.id,
            'recent_users': users_data
        }), 200
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        app.logger.error(f"❌ Error in debug endpoint: {e}")
        app.logger.error(f"Traceback: {error_trace}")
        return jsonify({'error': str(e), 'trace': error_trace}), 500

@app.route('/debug/notifications', methods=['GET'])
@token_required
def debug_notifications(current_user):
    """Endpoint de debug para ver notificaciones"""
    try:
        # Obtener notificaciones recientes del usuario actual
        result = db.session.execute(
            db.text('''
                SELECT id, recipient_user_id, sender_user_id, type, title, message,
                       data, status, is_read, created_at
                FROM notification
                WHERE recipient_user_id = :user_id
                ORDER BY created_at DESC
                LIMIT 10
            '''),
            {'user_id': current_user.id}
        )
        user_notifications = result.fetchall()

        # Obtener total de notificaciones en el sistema
        total_result = db.session.execute(db.text('SELECT COUNT(*) as count FROM notification'))
        total_count = total_result.fetchone().count

        notifications_data = []
        for notif in user_notifications:
            notifications_data.append({
                'id': notif.id,
                'recipient_user_id': notif.recipient_user_id,
                'sender_user_id': notif.sender_user_id,
                'type': notif.type,
                'title': notif.title,
                'message': notif.message,
                'data': notif.data,
                'status': notif.status,
                'is_read': bool(notif.is_read),
                'created_at': notif.created_at.isoformat() if notif.created_at else None
            })

        return jsonify({
            'current_user_id': current_user.id,
            'total_notifications_in_system': total_count,
            'user_notifications_count': len(notifications_data),
            'user_notifications': notifications_data
        }), 200
    except Exception as e:
        app.logger.error(f"❌ Error in debug notifications endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/users/follow', methods=['POST'])
@token_required
def send_follow_request(current_user):
    """Enviar solicitud de seguimiento"""
    try:
        data = request.get_json()
        following_id = data.get('user_id')

        if not following_id:
            return jsonify({'error': 'ID de usuario requerido'}), 400

        if following_id == current_user.id:
            return jsonify({'error': 'No puedes seguirte a ti mismo'}), 400

        # Verificar que el usuario existe
        following_user = User.query.get(following_id)
        if not following_user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        # Verificar si ya existe una solicitud
        existing_request = UserFollow.query.filter_by(
            follower_id=current_user.id,
            following_id=following_id
        ).first()

        if existing_request:
            if existing_request.status == 'pending':
                return jsonify({'error': 'Ya tienes una solicitud pendiente'}), 400
            elif existing_request.status == 'accepted':
                return jsonify({'error': 'Ya sigues a este usuario'}), 400
            elif existing_request.status == 'rejected':
                # Actualizar solicitud rechazada a pendiente
                existing_request.status = 'pending'
        else:
            # Crear nueva solicitud
            follow_request = UserFollow(
                follower_id=current_user.id,
                following_id=following_id,
                status='pending'
            )
            db.session.add(follow_request)

        db.session.commit()

        # Crear notificación para el usuario que recibe la solicitud usando SQL directo
        db.session.execute(
            db.text('''
                INSERT INTO notification
                (recipient_user_id, sender_user_id, type, title, message, data, status, is_read, created_at, updated_at)
                VALUES (:recipient_id, :sender_id, :type, :title, :message, :data, :status, :is_read, NOW(), NOW())
            '''),
            {
                'recipient_id': following_id,
                'sender_id': current_user.id,
                'type': 'follow_request',
                'title': 'Nueva solicitud de seguimiento',
                'message': f'{current_user.username} quiere seguirte',
                'data': json.dumps({
                    'follower_id': current_user.id,
                    'follower_username': current_user.username,
                    'follower_image': current_user.profile_image_url
                }),
                'status': 'pending',
                'is_read': 0
            }
        )
        db.session.commit()

        return jsonify({'message': 'Solicitud de seguimiento enviada'}), 200

    except Exception as e:
        app.logger.error(f"Error sending follow request: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/unfollow', methods=['POST'])
@token_required
def unfollow_user(current_user):
    """Dejar de seguir a un usuario"""
    try:
        data = request.get_json()
        following_id = data.get('user_id')

        if not following_id:
            return jsonify({'error': 'ID de usuario requerido'}), 400

        # Buscar cualquier relación de seguimiento (aceptada o pendiente)
        follow_request = UserFollow.query.filter_by(
            follower_id=current_user.id,
            following_id=following_id
        ).filter(UserFollow.status.in_(['accepted', 'pending'])).first()

        if not follow_request:
            return jsonify({'error': 'No tienes relación con este usuario'}), 404

        # Eliminar la relación
        db.session.delete(follow_request)
        db.session.commit()

        return jsonify({'message': 'Has dejado de seguir al usuario'}), 200

    except Exception as e:
        app.logger.error(f"Error unfollowing user: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/follow-requests', methods=['GET'])
@token_required
def get_follow_requests(current_user):
    """Obtener solicitudes de seguimiento pendientes"""
    try:
        requests = UserFollow.query.filter_by(
            following_id=current_user.id,
            status='pending'
        ).order_by(UserFollow.created_at.desc()).all()

        requests_data = []
        for req in requests:
            follower = req.follower
            requests_data.append({
                'id': req.id,
                'follower': {
                    'id': follower.id,
                    'username': follower.username,
                    'profile_image_url': follower.profile_image_url
                },
                'created_at': req.created_at.isoformat()
            })

        return jsonify({'requests': requests_data}), 200

    except Exception as e:
        app.logger.error(f"Error getting follow requests: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/follow-requests/<int:request_id>/accept', methods=['POST'])
@token_required
def accept_follow_request(current_user, request_id):
    """Aceptar solicitud de seguimiento"""
    try:
        follow_request = UserFollow.query.filter_by(
            id=request_id,
            following_id=current_user.id,
            status='pending'
        ).first()

        if not follow_request:
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        # Actualizar estado a aceptado
        follow_request.status = 'accepted'
        db.session.commit()

        # Marcar la notificación original de follow_request como leída
        db.session.execute(
            db.text('''
                UPDATE notification
                SET is_read = 1, status = 'accepted'
                WHERE recipient_user_id = :recipient_id
                  AND sender_user_id = :sender_id
                  AND type = 'follow_request'
                  AND is_read = 0
            '''),
            {
                'recipient_id': current_user.id,
                'sender_id': follow_request.follower_id
            }
        )

        # Crear notificación para el solicitante usando SQL directo
        db.session.execute(
            db.text('''
                INSERT INTO notification
                (recipient_user_id, sender_user_id, type, title, message, data, status, is_read, created_at, updated_at)
                VALUES (:recipient_id, :sender_id, :type, :title, :message, :data, :status, :is_read, NOW(), NOW())
            '''),
            {
                'recipient_id': follow_request.follower_id,
                'sender_id': current_user.id,
                'type': 'follow_accepted',
                'title': 'Solicitud aceptada',
                'message': f'{current_user.username} ha aceptado tu solicitud de seguimiento',
                'data': json.dumps({
                    'following_id': current_user.id,
                    'following_username': current_user.username,
                    'following_image': current_user.profile_image_url
                }),
                'status': 'accepted',
                'is_read': 0
            }
        )
        db.session.commit()

        return jsonify({'message': 'Solicitud aceptada'}), 200

    except Exception as e:
        app.logger.error(f"Error accepting follow request: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/follow-requests/<int:request_id>/reject', methods=['POST'])
@token_required
def reject_follow_request(current_user, request_id):
    """Rechazar solicitud de seguimiento"""
    try:
        follow_request = UserFollow.query.filter_by(
            id=request_id,
            following_id=current_user.id,
            status='pending'
        ).first()

        if not follow_request:
            return jsonify({'error': 'Solicitud no encontrada'}), 404

        # Actualizar estado a rechazado
        follow_request.status = 'rejected'
        follow_request.updated_at = datetime.utcnow()
        db.session.commit()

        # No enviamos notificación cuando se rechaza (según las especificaciones)

        return jsonify({'message': 'Solicitud rechazada'}), 200

    except Exception as e:
        app.logger.error(f"Error rejecting follow request: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/<int:user_id>/followers', methods=['GET'])
@token_required
def get_user_followers(current_user, user_id):
    """Obtener seguidores de un usuario"""
    try:
        follows = UserFollow.query.filter_by(
            following_id=user_id,
            status='accepted'
        ).all()

        followers = []
        for follow in follows:
            follower = follow.follower
            followers.append({
                'id': follower.id,
                'username': follower.username,
                'profile_image_url': follower.profile_image_url
            })

        return jsonify({
            'followers': followers,
            'count': len(followers)
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting followers: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/<int:user_id>/following', methods=['GET'])
@token_required
def get_user_following(current_user, user_id):
    """Obtener usuarios que sigue un usuario"""
    try:
        follows = UserFollow.query.filter_by(
            follower_id=user_id,
            status='accepted'
        ).all()

        following = []
        for follow in follows:
            following_user = follow.following
            following.append({
                'id': following_user.id,
                'username': following_user.username,
                'profile_image_url': following_user.profile_image_url
            })

        return jsonify({
            'following': following,
            'count': len(following)
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting following: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/users/pending-requests', methods=['GET'])
@token_required
def get_pending_requests(current_user):
    """Obtener solicitudes de seguimiento pendientes enviadas por el usuario actual"""
    try:
        # Usar SQL directo para compatibilidad
        pending_follows = db.session.execute(
            db.text('''
                SELECT uf.id, uf.following_id,
                       u.username, u.profile_image_url
                FROM user_follows uf
                JOIN user u ON uf.following_id = u.id
                WHERE uf.follower_id = :user_id AND uf.status = 'pending'
                ORDER BY uf.id DESC
            '''),
            {'user_id': current_user.id}
        ).fetchall()

        pending_requests = []
        for follow in pending_follows:
            pending_requests.append({
                'id': follow.id,
                'user_id': follow.following_id,
                'username': follow.username,
                'profile_image_url': follow.profile_image_url,
                'status': 'pending'
            })

        return jsonify({
            'pending_requests': pending_requests,
            'count': len(pending_requests)
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting pending requests: {e}")
        return jsonify({'error': f'Error interno: {str(e)}'}), 500

@app.route('/users/incoming-requests', methods=['GET'])
@token_required
def get_incoming_requests(current_user):
    """Obtener solicitudes de seguimiento entrantes (recibidas) pendientes"""
    try:
        # Usar SQL directo para compatibilidad - solicitudes donde current_user es el objetivo
        incoming_follows = db.session.execute(
            db.text('''
                SELECT uf.id, uf.follower_id,
                       u.username, u.profile_image_url
                FROM user_follows uf
                JOIN user u ON uf.follower_id = u.id
                WHERE uf.following_id = :user_id AND uf.status = 'pending'
                ORDER BY uf.id DESC
            '''),
            {'user_id': current_user.id}
        ).fetchall()

        incoming_requests = []
        for follow in incoming_follows:
            incoming_requests.append({
                'id': follow.id,
                'user_id': follow.follower_id,
                'username': follow.username,
                'profile_image_url': follow.profile_image_url,
                'status': 'pending'
            })

        return jsonify({
            'incoming_requests': incoming_requests,
            'count': len(incoming_requests)
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting incoming requests: {e}")
        return jsonify({'error': f'Error interno: {str(e)}'}), 500

# --------------------------------------------------------------------
#           GOOGLE CALENDAR: RUTAS DE INTEGRACIÓN OAUTH
# --------------------------------------------------------------------

# --- Endpoint para sincronizar eventos usando las credenciales de un canal ---
@app.route('/calendar/sync_channel', methods=['POST'])
@token_required
def sync_google_calendar_channel(current_user):
    """
    Sincroniza eventos Google Calendar para un canal específico.
    Body JSON:
    {
      "channel_id_code": "abc123",
      "calendar_id": "primary"  // opcional, default 'primary'
    }
    """
    data = request.get_json() or {}
    channel_id_code = data.get('channel_id_code')
    calendar_id = data.get('calendar_id', 'primary')

    if not channel_id_code:
        return jsonify({'error': 'Falta channel_id_code'}), 400

    # Buscar canal
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return jsonify({'error': f'No existe canal con id_code={channel_id_code}'}), 404

    # Verificar permisos:
    org_admin_perm = OrganizationAdminPermission(channel.organization_id)
    chan_admin_perm = ChannelAdminPermission(channel.id)
    if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        return jsonify({'error': 'No tienes permisos para sincronizar Google Calendar en este canal'}), 403

    try:
        service = get_calendar_service_from_channel(channel)

        # EJEMPLO de guardar eventos en tabla 'gcal_events' (puedes cambiar):
        now = datetime.datetime.now(datetime.UTC).isoformat()
        resp = service.events().list(
            calendarId=calendar_id,
            timeMin=now, 
            singleEvents=True,
            orderBy='startTime',
            maxResults=2500
        ).execute()

        items = resp.get('items', [])
        google_ids = set()

        for e in items:
            event_id = e['id']
            summary = e.get('summary', 'Sin título')
            description = e.get('description', '')
            start_str = e['start'].get('dateTime', e['start'].get('date'))
            end_str = e['end'].get('dateTime', e['end'].get('date'))

            start_dt = datetime.datetime.fromisoformat(start_str.replace('Z', '+00:00'))
            end_dt = datetime.datetime.fromisoformat(end_str.replace('Z', '+00:00'))

            # Guarda en la tabla GCalEvent (por ejemplo)
            gcal_evt = GCalEvent.query.get(event_id)
            if not gcal_evt:
                gcal_evt = GCalEvent(id=event_id)
                db.session.add(gcal_evt)

            gcal_evt.summary = summary
            gcal_evt.description = description
            gcal_evt.start = start_dt
            gcal_evt.end = end_dt

            google_ids.add(event_id)

        db.session.commit()

        # Opcional: borrar eventos locales que ya no están en Google
        local_events = GCalEvent.query.all()
        for evt in local_events:
            if evt.id not in google_ids:
                db.session.delete(evt)
        db.session.commit()

        return jsonify({'message': f'Sincronizados {len(items)} eventos desde GCAL.'}), 200

    except Exception as e:
        app.logger.error(f"Error en sync_google_calendar_channel: {e}")
        return jsonify({'error': str(e)}), 500

# ----------------- Autenticación OAuth2 con Google Calendar -----------------
@app.route('/calendar/exchange_code_channel', methods=['POST'])
@token_required
def exchange_code_calendar_channel(current_user):
    """
    Recibe:
    {
      "authorizationCode": "...",
      "channel_id_code": "abc123"   // es el id_code del canal
    }

    - Intercambia el authorizationCode por un token OAuth de Google Calendar.
    - Guarda las credenciales en channel.user_settings["token_gcalendar"].
    """
    data = request.get_json() or {}
    authorization_code = data.get('authorizationCode')
    channel_id_code = data.get('channel_id_code')  # o "id_code", como prefieras

    if not authorization_code or not channel_id_code:
        return jsonify({'error': 'Faltan authorizationCode o channel_id_code'}), 400

    # 1) Buscar el canal por su id_code
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return jsonify({'error': f'No existe canal con id_code={channel_id_code}'}), 404

    # 2) Verificar permisos (opcional)
    #    Revisa si current_user es SUPERADMIN, ORG_ADMIN o CHANNEL_ADMIN de channel.id
    org_admin_perm = OrganizationAdminPermission(channel.organization_id)
    chan_admin_perm = ChannelAdminPermission(channel.id)
    if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        return jsonify({'error': 'No tienes permisos para vincular Google Calendar a este canal'}), 403

    # 3) Crear Flow con credenciales y scopes
    try:
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=GCAL_SCOPES,
            redirect_uri='postmessage'  # o la que hayas usado en Expo
        )

        # 4) Intercambiar el code por token
        flow.fetch_token(code=authorization_code)
        creds = flow.credentials  # Contiene access_token, refresh_token, etc.

        # 5) Convertirlo a dict
        creds_dict = json.loads(creds.to_json())

        # 6) Guardarlo dentro de channel.user_settings["token_gcalendar"]
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        channel_settings["token_gcalendar"] = creds_dict
        channel.user_settings = channel_settings

        # Notificar a SQLAlchemy del cambio en el JSON
        flag_modified(channel, "user_settings")
        db.session.commit()

        return jsonify({'message': 'Credenciales de Google Calendar guardadas en el canal'}), 200

    except Exception as e:
        app.logger.error(f"Error en exchange_code_calendar_channel: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/calendar/oauth_start/<string:channel_id_code>')
def calendar_oauth_start(channel_id_code):
    # 1) Verificar que el canal exista
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    # 2) Cargar user_settings. Si es string, conviértelo en dict con json.loads.
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    # 3) Borrar la clave token_gcalendar si existe
    if "token_gcalendar" in channel_settings:
        del channel_settings["token_gcalendar"]

        # 4) Guardar de nuevo en la columna user_settings
        #    (si tu columna es de tipo JSON en la BD, puedes asignarle directamente el dict;
        #     si fuera TEXT, conviértelo a string con json.dumps)
        channel.user_settings = channel_settings

        # Avisa a SQLAlchemy de que se modificó la columna JSON (si es necesario)
        flag_modified(channel, "user_settings")

        db.session.commit()

    # 5) Crear Flow con redirect_uri
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=GCAL_SCOPES,
        redirect_uri="https://delejove.penwin.cloud:8443/calendar/oauth_callback"
    )

    # 6) Generar URL de autorización, con revalidación
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['oauth_state'] = state
    session['channel_id_code'] = channel_id_code

    return redirect(authorization_url)


@app.route('/calendar/oauth_callback')
def calendar_oauth_callback():
    """
    Google redirige aquí con ?code=...&state=...
    Flask intercambia ese code por un token y lo guarda en channel.user_settings["token_gcalendar"].
    Luego puede redirigir a un deep link para volver a la app o mostrar algo.
    """
    # 1) Recuperar state, channel_id_code (que guardamos en la sesión)
    state = session.get('oauth_state')
    channel_id_code = session.get('channel_id_code')
    if not channel_id_code:
        return "Falta canal en sesión. Inicia el login de nuevo.", 400

    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    # 2) Crear el Flow nuevamente con la misma redirect_uri
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=GCAL_SCOPES,
        redirect_uri="https://delejove.penwin.cloud:8443/calendar/oauth_callback"
    )
    # Asignar el state (si lo usaste)
    flow.fetch_token(authorization_response=request.url)

    # 3) Obtener las credenciales
    creds = flow.credentials
    creds_dict = json.loads(creds.to_json())  # lo que guardarás en DB

    # 4) Guardar en channel.user_settings["token_gcalendar"]
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    channel_settings["token_gcalendar"] = creds_dict
    channel.user_settings = channel_settings
    flag_modified(channel, "user_settings")
    db.session.commit()

    # 5) OPCIÓN A: Redirigir a un deep link que tu app maneje
    # return redirect("delejove://home")  # <- tu esquema nativo

    return """
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Vinculación completada</title>
        </head>
        <body style="font-family: sans-serif;">
            <h2>¡Google Calendar vinculado con éxito!</h2>
            <p>Puedes cerrar esta ventana y volver a la aplicación.</p>
        </body>
        </html>
        """

# ----------------- Ruta Oauth 2.0 Youtube --------------------------------
# ----------------- Autenticación OAuth2 con Youtube ----------------------
@app.route('/youtube/exchange_code_channel', methods=['POST'])
@token_required
def exchange_code_youtube_channel(current_user):
    """
    Recibe:
    {
      "authorizationCode": "...",
      "channel_id_code": "abc123"   // es el id_code del canal
    }

    - Intercambia el authorizationCode por un token OAuth de Google Calendar.
    - Guarda las credenciales en channel.user_settings["token_youtube"].
    """
    data = request.get_json() or {}
    authorization_code = data.get('authorizationCode')
    channel_id_code = data.get('channel_id_code')  # o "id_code", como prefieras

    if not authorization_code or not channel_id_code:
        return jsonify({'error': 'Faltan authorizationCode o channel_id_code'}), 400

    # 1) Buscar el canal por su id_code
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return jsonify({'error': f'No existe canal con id_code={channel_id_code}'}), 404

    # 2) Verificar permisos (opcional)
    #    Revisa si current_user es SUPERADMIN, ORG_ADMIN o CHANNEL_ADMIN de channel.id
    org_admin_perm = OrganizationAdminPermission(channel.organization_id)
    chan_admin_perm = ChannelAdminPermission(channel.id)
    if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        return jsonify({'error': 'No tienes permisos para vincular Google Calendar a este canal'}), 403

    # 3) Crear Flow con credenciales y scopes
    try:
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE,
            scopes=GCAL_SCOPES,
            redirect_uri='postmessage'  # o la que hayas usado en Expo
        )

        # 4) Intercambiar el code por token
        flow.fetch_token(code=authorization_code)
        creds = flow.credentials  # Contiene access_token, refresh_token, etc.

        # 5) Convertirlo a dict
        creds_dict = json.loads(creds.to_json())

        # 6) Guardarlo dentro de channel.user_settings["token_youtube"]
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        channel_settings["token_youtube"] = creds_dict
        channel.user_settings = channel_settings

        # Notificar a SQLAlchemy del cambio en el JSON
        flag_modified(channel, "user_settings")
        db.session.commit()

        return jsonify({'message': 'Credenciales de Google Calendar guardadas en el canal'}), 200

    except Exception as e:
        app.logger.error(f"Error en exchange_code_youtube_channel: {e}")
        return jsonify({'error': str(e)}), 500
    

@app.route('/youtube/oauth_start/<string:channel_id_code>')
def youtube_oauth_start(channel_id_code):
    # 1) Verificar que el canal exista
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    # 2) Cargar user_settings. Si es string, conviértelo en dict con json.loads.
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    # 3) Borrar la clave token_youtube si existe
    if "token_youtube" in channel_settings:
        del channel_settings["token_youtube"]

        # 4) Guardar de nuevo en la columna user_settings
        #    (si tu columna es de tipo JSON en la BD, puedes asignarle directamente el dict;
        #     si fuera TEXT, conviértelo a string con json.dumps)
        channel.user_settings = channel_settings

        # Avisa a SQLAlchemy de que se modificó la columna JSON (si es necesario)
        flag_modified(channel, "user_settings")

        db.session.commit()

    # 5) Crear Flow con redirect_uri
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=GCAL_SCOPES,
        redirect_uri="https://delejove.penwin.cloud:8443/youtube/oauth_callback"
    )

    # 6) Generar URL de autorización, con revalidación
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )

    session['oauth_state'] = state
    session['channel_id_code'] = channel_id_code

    return redirect(authorization_url)


@app.route('/youtube/oauth_callback')
def youtube_oauth_callback():
    """
    Google redirige aquí con ?code=...&state=...
    Flask intercambia ese code por un token y lo guarda en channel.user_settings["token_youtube"].
    Luego puede redirigir a un deep link para volver a la app o mostrar algo.
    """
    # 1) Recuperar state, channel_id_code (que guardamos en la sesión)
    state = session.get('oauth_state')
    channel_id_code = session.get('channel_id_code')
    if not channel_id_code:
        return "Falta canal en sesión. Inicia el login de nuevo.", 400

    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    # 2) Crear el Flow nuevamente con la misma redirect_uri
    flow = Flow.from_client_secrets_file(
        CREDENTIALS_FILE,
        scopes=GCAL_SCOPES,
        redirect_uri="https://delejove.penwin.cloud:8443/youtube/oauth_callback"
    )
    # Asignar el state (si lo usaste)
    flow.fetch_token(authorization_response=request.url)

    # 3) Obtener las credenciales
    creds = flow.credentials
    creds_dict = json.loads(creds.to_json())  # lo que guardarás en DB

    # 4) Guardar en channel.user_settings["token_youtube"]
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    channel_settings["token_youtube"] = creds_dict
    channel.user_settings = channel_settings
    flag_modified(channel, "user_settings")
    db.session.commit()

    # 5) OPCIÓN A: Redirigir a un deep link que tu app maneje
    # return redirect("delejove://home")  # <- tu esquema nativo

    return """
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Vinculación completada</title>
        </head>
        <body style="font-family: sans-serif;">
            <h2>¡Google Calendar vinculado con éxito!</h2>
            <p>Puedes cerrar esta ventana y volver a la aplicación.</p>
        </body>
        </html>
        """

# --------------------------------------------------------------------
#                      RUTA:  /stories   (GET)
# --------------------------------------------------------------------
@app.route('/stories', methods=['GET'])
@token_required
def get_subscribed_stories(current_user):
    """
    Devuelve las stories de los canales a los que el usuario está suscrito
    (user.donating).  Ya NO se lee `channel.story_json`; se inspecciona
    directamente el bucket S3:
         channel/<id_code>/stories/*
    Formato de respuesta:
        { "stories": [ { id,title,image,storyItem:[...] }, ... ] }
    """
    try:
        # 1) Parsear la lista de canales suscritos -------------------
        subscribed_codes = []
        if current_user.donating:
            try:
                donating_raw = (
                    json.loads(current_user.donating)
                    if isinstance(current_user.donating, str)
                    else current_user.donating
                )
                # Handle multiple formats: array, dict, or extended dict
                if isinstance(donating_raw, list):
                    subscribed_codes = donating_raw
                elif isinstance(donating_raw, dict):
                    subscribed_codes = list(donating_raw.keys())
                else:
                    subscribed_codes = []
            except Exception:
                subscribed_codes = []

        if not subscribed_codes:
            return jsonify({"stories": []}), 200

        # 2) Traer esos canales de la BD -----------------------------
        channels = (
            Channel.query
            .filter(Channel.id_code.in_(subscribed_codes))
            .all()
        )

        stories_resp = []

        # 3) Recorrer cada canal y listar el prefijo S3 --------------
        for ch in channels:
            prefix = f"app/channels/{ch.id_code}/stories/"
            s3_response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)

            # No hay stories si el bucket no devuelve objetos
            contents = s3_response.get("Contents", [])
            if not contents:
                continue

            story_urls = []
            for obj in contents:
                key = obj["Key"]
                # saltar el propio prefijo “directorio” (no tendrá `/`)
                if key.endswith("/"):
                    continue
                story_urls.append(
                    f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{key}"
                )

            if not story_urls:
                continue  # canal sin imágenes válidas

            profile_url = (
                f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/"
                f"app/channels/{ch.id_code}/profile.jpeg"
            )

            stories_resp.append({
                "id":        ch.id_code,
                "title":     ch.name,
                "image":     profile_url,
                "storyItem": story_urls,
            })

        # 4) Orden alfabético opcional -------------------------------
        stories_resp.sort(key=lambda s: s["title"].lower())

        return jsonify({"stories": stories_resp}), 200

    except Exception as e:
        app.logger.error(f"Error en /stories: {e}")
        return jsonify({
            "message": "Ha ocurrido un error al recuperar las stories.",
            "error": str(e)
        }), 500


# =========================================
# Ruta para listar los canales de YouTube
# =========================================
@app.route('/list-youtube-channel/<string:channel_id_code>', methods=['GET'])
@token_required
def list_youtube_channel(current_user, channel_id_code):
    """
    Devuelve la lista de canales de YouTube (propiedad del usuario de la cuenta de Google
    asociada) para el canal de la BD cuyo id_code es <channel_id_code>.

    Requiere que en channel.user_settings["token_gcalendar"] se encuentren las credenciales
    OAuth, **incluyendo** el scope de YouTube (p. ej. youtube.force-ssl).
    """
    try:
        # 1) Buscar el "Channel" en tu base de datos por su id_code.
        channel = Channel.query.filter_by(id_code=channel_id_code).first()
        if not channel:
            return jsonify({"error": f"No se encontró canal con id_code={channel_id_code}"}), 404

        # (Opcional) Verificar permisos: SUPERADMIN, ORG_ADMIN del canal o CHANNEL_ADMIN
        # org_admin_perm  = OrganizationAdminPermission(channel.organization_id)
        # chan_admin_perm = ChannelAdminPermission(channel.id)
        # if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        #     return jsonify({"error": "No tienes permisos para listar los canales de YouTube"}), 403

        # 2) Construir el servicio de YouTube con las credenciales guardadas
        youtube_service = get_youtube_service_from_channel(channel)

        # 3) Llamar a la API: channels().list(..., mine=True)
        response = youtube_service.channels().list(
            part="snippet,contentDetails,statistics",
            mine=True
        ).execute()

        # 4) 'items' contendrá la lista de canales
        items = response.get('items', [])

        # Puedes retornar los datos tal cual, o formateados:
        return jsonify({
            "youtube_channels": items
        }), 200
    
    except Exception as e:
        app.logger.error(f"Error listando canales de YouTube: {e}")
        return jsonify({"error": str(e)}), 500


# --------------------------------------------------------------------
#           INTEGRACIÓN CON INSTAGRAM: FLUJO OAUTH Y SINCRONIZACIÓN
# --------------------------------------------------------------------

# Ruta para iniciar el flujo OAuth con Instagram (Graph API)
@app.route('/insta_login')
def insta_login():
    oauth_url = (
        f"{INSTAGRAM_OAUTH_AUTHORIZE_URL}?client_id={INSTAGRAM_CLIENT_ID}"
        f"&enable_fb_login=0"
        f"&force_authentication=1"
        f"&redirect_uri={INSTAGRAM_REDIRECT_URI}"
        f"&scope=instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights"
        f"&response_type=code"
    )
    app.logger.info(oauth_url)
    return redirect(oauth_url)

# Callback para intercambiar el código por un token
@app.route('/insta_callback')
def insta_callback():
    code = request.args.get('code')
    state = request.args.get('state')  # channel_id_code para el nuevo flujo

    if not code:
        return "Error: No se recibió el código de autorización.", 400

    # NUEVO FLUJO: Si tiene state, es para vincular a un canal específico
    if state:
        try:
            # Buscar el canal
            channel = Channel.query.filter_by(id_code=state).first()
            if not channel:
                return f"Error: No se encontró el canal con id_code={state}", 404

            # Intercambiar código por token
            data = {
                'client_id': INSTAGRAM_CLIENT_ID,
                'client_secret': INSTAGRAM_CLIENT_SECRET,
                'redirect_uri': INSTAGRAM_REDIRECT_URI,
                'code': code,
                'grant_type': 'authorization_code'
            }

            response = requests.post(INSTAGRAM_TOKEN_ENDPOINT, data=data)
            if response.status_code != 200:
                return f"Error al obtener el token de Instagram: {response.text}", 400

            token_response = response.json()
            access_token = token_response.get('access_token')
            expires_in = token_response.get('expires_in', 0)

            if not access_token:
                return "Error: No se recibió el token de acceso de Instagram.", 400

            # Guardar token en el canal
            channel_settings = channel.user_settings or {}
            if isinstance(channel_settings, str):
                try:
                    channel_settings = json.loads(channel_settings)
                except:
                    channel_settings = {}

            token_info = {
                'access_token': access_token,
                'expires_in': expires_in,
                'expires_at': (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat(),
                'token_type': 'Bearer',
                'scope': 'instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights',
                'created_at': datetime.utcnow().isoformat()
            }

            channel_settings["token_instagram"] = token_info
            channel.user_settings = channel_settings
            flag_modified(channel, "user_settings")
            channel.version = (channel.version or 1) + 1
            db.session.commit()

            # Página de éxito para webview
            return f"""
            <html>
            <head>
                <meta charset="UTF-8">
                <title>Instagram vinculado</title>
                <script>
                    window.addEventListener('load', function() {{
                        if (window.ReactNativeWebView) {{
                            window.ReactNativeWebView.postMessage(JSON.stringify({{
                                type: 'INSTAGRAM_AUTH_SUCCESS',
                                channel_id: '{state}'
                            }}));
                        }}
                        if (window.parent) {{
                            window.parent.postMessage({{
                                type: 'INSTAGRAM_AUTH_SUCCESS',
                                channel_id: '{state}'
                            }}, '*');
                        }}
                    }});
                    setTimeout(function() {{ window.close(); }}, 3000);
                </script>
            </head>
            <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
                <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <div style="color: #28a745; font-size: 48px; margin-bottom: 20px;">✓</div>
                    <h2 style="color: #333; margin: 0 0 10px 0;">¡Instagram vinculado!</h2>
                    <p style="color: #666; margin: 0 0 20px 0;">El canal ahora tiene acceso a Instagram Business.</p>
                    <p style="color: #999; font-size: 14px;">Esta ventana se cerrará automáticamente...</p>
                </div>
            </body>
            </html>
            """

        except Exception as e:
            app.logger.error(f"Error en Instagram callback (canal): {e}")
            return f"Error interno: {str(e)}", 500

    # FLUJO ANTIGUO: Sin state, usar sesión (compatibilidad)
    else:
        data = {
            'client_id': INSTAGRAM_CLIENT_ID,
            'client_secret': INSTAGRAM_CLIENT_SECRET,
            'redirect_uri': INSTAGRAM_REDIRECT_URI,
            'code': code,
            'grant_type': 'authorization_code'
        }
        response = requests.post(INSTAGRAM_TOKEN_ENDPOINT, data=data)
        if response.status_code != 200:
            return f"Error al obtener el token: {response.text}", 400
        token_data = response.json()
        session['insta_access_token'] = token_data.get('access_token')
        expires_in = token_data.get('expires_in', 0)
        session['insta_token_expires_at'] = datetime.now() + timedelta(seconds=expires_in)
        return f"Este es el token: {session['insta_access_token']}"

# Ruta para refrescar el token de larga duración
@app.route('/refresh_insta')
def refresh_insta():
    if 'insta_access_token' not in session:
        return redirect(url_for('insta_login'))
    current_token = session['insta_access_token']
    refresh_url = f"{INSTAGRAM_REFRESH_ENDPOINT}?grant_type=ig_refresh_token&access_token={current_token}"
    response = requests.get(refresh_url)
    if response.status_code != 200:
        return f"Error al refrescar el token: {response.text}", 400
    token_data = response.json()
    session['insta_access_token'] = token_data.get('access_token')
    expires_in = token_data.get('expires_in', 0)
    session['insta_token_expires_at'] = datetime.now() + timedelta(seconds=expires_in)
    return f"Token actualizado: {session['insta_access_token']}"



# Ruta para sincronizar los posts de Instagram
@app.route('/sync_insta')
def sync_insta():
    if 'insta_access_token' not in session:
        return redirect(url_for('insta_login'))
    access_token = session['insta_access_token']
    posts = get_all_instagram_media(INSTAGRAM_ACCOUNT_ID, access_token)
    if not posts:
        return "No se encontraron publicaciones o hubo un error."
    for media in posts:
        insta_id = media.get("id")
        caption = media.get("caption")
        media_url = media.get("media_url")
        permalink = media.get("permalink")
        media_type = media.get("media_type")
        timestamp_str = media.get("timestamp")
        like_count = media.get("like_count", 0)
        comments_count = media.get("comments_count", 0)
        ts = None
        if timestamp_str:
            try:
                ts = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S%z")
            except Exception as e:
                print(f"Error al convertir el timestamp: {timestamp_str}")
        s3_image_url = None
        if media_type and media_type.upper() == "IMAGE" and media_url:
            s3_image_url = upload_image_to_s3(media_url, insta_id)
        insta_post = InstaPost(
            id=insta_id,
            caption=caption,
            media_url=media_url,
            permalink=permalink,
            media_type=media_type,
            timestamp=ts,
            like_count=like_count,
            comments_count=comments_count,
            s3_image_url=s3_image_url
        )
        db.session.merge(insta_post)
    db.session.commit()
    return f"Se han sincronizado {len(posts)} publicaciones de Instagram."

# Rutas OAuth específicas por canal para Instagram (similar a YouTube)
@app.route('/instagram/oauth_start/<string:channel_id_code>')
def instagram_oauth_start(channel_id_code):
    """
    Inicia el flujo OAuth de Instagram para un canal específico.
    """
    # 1) Verificar que el canal exista
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    # 2) Cargar user_settings. Si es string, conviértelo en dict con json.loads.
    channel_settings = channel.user_settings or {}
    if isinstance(channel_settings, str):
        try:
            channel_settings = json.loads(channel_settings)
        except:
            channel_settings = {}

    # 3) Limpiar todos los tokens anteriores de Instagram si existen (especialmente si force_refresh está presente)
    force_refresh = request.args.get('force_refresh')
    instagram_keys_to_clear = [
        'token_instagram',
        'instagram_access_token',
        'instagram_token_expires',
        'instagram_user_id',
        'instagram_business_account_id',
        'instagram_page_access_token'
    ]

    settings_changed = False
    for key in instagram_keys_to_clear:
        if key in channel_settings:
            del channel_settings[key]
            settings_changed = True

    if settings_changed:
        channel.user_settings = channel_settings
        flag_modified(channel, "user_settings")
        db.session.commit()

    # 4) Construir URL de autorización de Instagram con el channel_id en state
    oauth_url = (
        f"{INSTAGRAM_OAUTH_AUTHORIZE_URL}?client_id={INSTAGRAM_CLIENT_ID}"
        f"&enable_fb_login=0"
        f"&force_authentication=1"
        f"&redirect_uri={INSTAGRAM_REDIRECT_URI}"
        f"&scope=instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights"
        f"&response_type=code"
        f"&state={channel_id_code}"  # Pasar el channel_id como state
    )

    return redirect(oauth_url)

@app.route('/instagram/oauth_callback')
def instagram_oauth_callback():
    """
    Instagram redirige aquí con ?code=...
    Intercambia ese código por un token y lo guarda en channel.user_settings["token_instagram"].
    """
    code = request.args.get('code')
    state = request.args.get('state')  # El channel_id_code viene en el state

    if not code:
        return "Error: No se recibió el código de autorización de Instagram.", 400

    if not state:
        return "Error: No se recibió el parámetro state con el channel_id_code.", 400

    # 1) El channel_id_code viene en el parámetro state
    channel_id_code = state

    # 2) Verificar que el canal existe
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return f"No existe canal con id_code={channel_id_code}", 404

    try:
        # 3) Intercambiar código por token
        data = {
            'client_id': INSTAGRAM_CLIENT_ID,
            'client_secret': INSTAGRAM_CLIENT_SECRET,
            'redirect_uri': INSTAGRAM_REDIRECT_URI,
            'code': code,
            'grant_type': 'authorization_code'
        }

        response = requests.post(INSTAGRAM_TOKEN_ENDPOINT, data=data)
        if response.status_code != 200:
            return f"Error al obtener el token de Instagram: {response.text}", 400

        token_data = response.json()
        access_token = token_data.get('access_token')
        expires_in = token_data.get('expires_in', 0)

        if not access_token:
            return "Error: No se recibió el token de acceso de Instagram.", 400

        # 4) Guardar token en channel.user_settings["token_instagram"]
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        # Crear objeto de token similar al de Google
        token_info = {
            'access_token': access_token,
            'expires_in': expires_in,
            'expires_at': (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat(),
            'token_type': 'Bearer',
            'scope': 'instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights'
        }

        channel_settings["token_instagram"] = token_info
        channel.user_settings = channel_settings
        flag_modified(channel, "user_settings")
        db.session.commit()

        return f"""
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Instagram vinculado</title>
            <script>
                // Enviar mensaje a la app móvil que el proceso se completó
                window.addEventListener('load', function() {{
                    // Para React Native WebView
                    if (window.ReactNativeWebView) {{
                        window.ReactNativeWebView.postMessage(JSON.stringify({{
                            type: 'INSTAGRAM_AUTH_SUCCESS',
                            channel_id: '{channel_id_code}'
                        }}));
                    }}

                    // Para otros tipos de webview
                    if (window.parent) {{
                        window.parent.postMessage({{
                            type: 'INSTAGRAM_AUTH_SUCCESS',
                            channel_id: '{channel_id_code}'
                        }}, '*');
                    }}
                }});

                // Auto cerrar la ventana después de 3 segundos
                setTimeout(function() {{
                    window.close();
                }}, 3000);
            </script>
        </head>
        <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
            <div style="max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                <div style="color: #28a745; font-size: 48px; margin-bottom: 20px;">✓</div>
                <h2 style="color: #333; margin: 0 0 10px 0;">¡Instagram vinculado!</h2>
                <p style="color: #666; margin: 0 0 20px 0;">El canal ahora tiene acceso a Instagram Business.</p>
                <p style="color: #999; font-size: 14px;">Esta ventana se cerrará automáticamente...</p>
            </div>
        </body>
        </html>
        """

    except Exception as e:
        app.logger.error(f"Error en Instagram OAuth callback: {e}")
        return f"Error interno durante la autenticación con Instagram: {str(e)}", 500

# Ruta para intercambiar código de Instagram (para webview en la app)
@app.route('/instagram/exchange_code_channel', methods=['POST'])
@token_required
def exchange_code_instagram_channel(current_user):
    """
    Recibe:
    {
      "authorizationCode": "...",
      "channel_id_code": "abc123"
    }

    - Intercambia el authorizationCode por un token OAuth de Instagram.
    - Guarda las credenciales en channel.user_settings["token_instagram"].
    """
    data = request.get_json() or {}
    authorization_code = data.get('authorizationCode')
    channel_id_code = data.get('channel_id_code')

    if not authorization_code or not channel_id_code:
        return jsonify({'error': 'Faltan authorizationCode o channel_id_code'}), 400

    # 1) Buscar el canal por su id_code
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return jsonify({'error': f'No existe canal con id_code={channel_id_code}'}), 404

    # 2) Verificar permisos (opcional)
    org_admin_perm = OrganizationAdminPermission(channel.organization_id)
    chan_admin_perm = ChannelAdminPermission(channel.id)
    if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        return jsonify({'error': 'No tienes permisos para vincular Instagram a este canal'}), 403

    try:
        # 3) Intercambiar código por token con Instagram
        token_data = {
            'client_id': INSTAGRAM_CLIENT_ID,
            'client_secret': INSTAGRAM_CLIENT_SECRET,
            'redirect_uri': INSTAGRAM_REDIRECT_URI,  # Debe coincidir con la autorización
            'code': authorization_code,
            'grant_type': 'authorization_code'
        }

        response = requests.post(INSTAGRAM_TOKEN_ENDPOINT, data=token_data)

        if response.status_code != 200:
            app.logger.error(f"Error de Instagram API: {response.status_code} - {response.text}")
            return jsonify({'error': f'Error intercambiando código: {response.text}'}), 400

        token_response = response.json()
        access_token = token_response.get('access_token')
        expires_in = token_response.get('expires_in', 0)

        if not access_token:
            return jsonify({'error': 'No se recibió el token de acceso de Instagram'}), 400

        # 4) Crear objeto de credenciales similar al formato de Google
        token_info = {
            'access_token': access_token,
            'expires_in': expires_in,
            'expires_at': (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat(),
            'token_type': 'Bearer',
            'scope': 'instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights',
            'created_at': datetime.utcnow().isoformat()
        }

        # 5) Guardarlo dentro de channel.user_settings["token_instagram"]
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        channel_settings["token_instagram"] = token_info
        channel.user_settings = channel_settings

        # Notificar a SQLAlchemy del cambio en el JSON
        flag_modified(channel, "user_settings")

        # Incrementar versión del canal
        channel.version = (channel.version or 1) + 1

        db.session.commit()

        return jsonify({'message': 'Credenciales de Instagram guardadas en el canal correctamente'}), 200

    except requests.RequestException as e:
        app.logger.error(f"Error de red con Instagram: {e}")
        return jsonify({'error': 'Error de conexión con Instagram'}), 500
    except Exception as e:
        app.logger.error(f"Error en exchange_code_instagram_channel: {e}")
        return jsonify({'error': str(e)}), 500

# Ruta para obtener URL de autorización de Instagram (para webview)
@app.route('/instagram/get_auth_url/<string:channel_id_code>', methods=['GET'])
@token_required
def get_instagram_auth_url(current_user, channel_id_code):
    """
    Genera la URL de autorización de Instagram para usar en webview.
    Retorna la URL que debe abrir el webview de la app.
    """
    # Verificar que el canal exista
    channel = Channel.query.filter_by(id_code=channel_id_code).first()
    if not channel:
        return jsonify({'error': f'No existe canal con id_code={channel_id_code}'}), 404

    # Verificar permisos
    org_admin_perm = OrganizationAdminPermission(channel.organization_id)
    chan_admin_perm = ChannelAdminPermission(channel.id)
    if not (superadmin_permission.can() or org_admin_perm.can() or chan_admin_perm.can()):
        return jsonify({'error': 'No tienes permisos para vincular Instagram a este canal'}), 403

    # Construir URL de autorización usando el callback real (Instagram no acepta 'postmessage')
    auth_url = (
        f"{INSTAGRAM_OAUTH_AUTHORIZE_URL}?client_id={INSTAGRAM_CLIENT_ID}"
        f"&redirect_uri={INSTAGRAM_REDIRECT_URI}"  # Usar callback real
        f"&scope=instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights"
        f"&response_type=code"
        f"&state={channel_id_code}"  # Pasar el channel_id como state para identificarlo
    )

    return jsonify({
        'auth_url': auth_url,
        'channel_id_code': channel_id_code,
        'debug_info': {
            'client_id': INSTAGRAM_CLIENT_ID,
            'redirect_uri': INSTAGRAM_REDIRECT_URI,
            'oauth_authorize_url': INSTAGRAM_OAUTH_AUTHORIZE_URL
        }
    }), 200

# Ruta de diagnóstico para Instagram
@app.route('/instagram/test_config', methods=['GET'])
def instagram_test_config():
    """
    Ruta de diagnóstico para verificar la configuración de Instagram.
    """
    return jsonify({
        'instagram_config': {
            'client_id': INSTAGRAM_CLIENT_ID,
            'redirect_uri': INSTAGRAM_REDIRECT_URI,
            'oauth_authorize_url': INSTAGRAM_OAUTH_AUTHORIZE_URL,
            'token_endpoint': INSTAGRAM_TOKEN_ENDPOINT,
        },
        'test_auth_url': f"{INSTAGRAM_OAUTH_AUTHORIZE_URL}?client_id={INSTAGRAM_CLIENT_ID}&redirect_uri={INSTAGRAM_REDIRECT_URI}&scope=instagram_business_basic,instagram_business_manage_messages,instagram_business_manage_comments,instagram_business_content_publish,instagram_business_manage_insights&response_type=code&state=TEST_CHANNEL",
        'message': 'Verifica que estas URLs estén exactamente configuradas en tu app de Instagram en developers.facebook.com'
    }), 200

# Endpoint para limpiar el token de Instagram de un canal
@app.route('/clear-instagram-token/<string:channel_id>', methods=['POST'])
@token_required
def clear_instagram_token(current_user, channel_id):
    """
    Limpia completamente el token de Instagram de un canal específico.
    """
    try:
        # Buscar el canal (misma lógica que update-channel-setting)
        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'message': 'Channel not found!'}), 404

        # Cargar configuración actual del canal
        channel_settings = channel.user_settings or {}
        if isinstance(channel_settings, str):
            try:
                channel_settings = json.loads(channel_settings)
            except:
                channel_settings = {}

        # Limpiar todos los datos relacionados con Instagram
        instagram_keys_to_clear = [
            'token_instagram',
            'instagram_access_token',
            'instagram_token_expires',
            'instagram_user_id',
            'instagram_business_account_id',
            'instagram_page_access_token'
        ]

        for key in instagram_keys_to_clear:
            if key in channel_settings:
                del channel_settings[key]

        # Guardar la configuración actualizada
        channel.user_settings = channel_settings
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Token de Instagram limpiado correctamente'
        }), 200

    except Exception as e:
        app.logger.error(f"Error al limpiar token de Instagram: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# --------------------------------------------------------------
#           RUTA:  /my/tickets   (GET)
# --------------------------------------------------------------

# Base para issued_tickets
TT_BASE_URL = "https://api.tickettailor.com/v1/issued_tickets"
# Tu clave, normalmente en .env
TT_API_KEY  = "sk_8570_253046_e56d0354669fb997715306e04fe8497a"

@app.route('/my/tickets', methods=['GET'])
@token_required
def list_my_tickets(current_user):
    """
    Devuelve todas las entradas (issued_tickets) que Ticket Tailor tiene
    asociadas al e-mail del usuario logeado, enriquecidas con nombre de
    evento y fechas de inicio y fin.
    """
    if not TT_API_KEY:
        return jsonify({"message": "TT_API_KEY no configurada"}), 500

    # Preparamos la cabecera Basic Auth
    auth = base64.b64encode(f"{TT_API_KEY}:".encode()).decode()
    headers = {"Authorization": f"Basic {auth}"}

    # 1) Descarga paginada de tickets emitidos para el email
    tickets, next_url = [], TT_BASE_URL
    params = {"email": current_user.email, "limit": 100}

    try:
        while next_url:
            resp = requests.get(
                next_url,
                headers=headers,
                params=params if next_url == TT_BASE_URL else None,
                timeout=15
            )
            if resp.status_code != 200:
                app.logger.error(f"TT error {resp.status_code}: {resp.text}")
                return jsonify({
                    "message": "Error consultando Ticket Tailor",
                    "status": resp.status_code,
                    "detail": resp.text
                }), 502

            body = resp.json()
            tickets.extend(body.get("data", []))

            # Avanzamos la paginación
            next_rel = body.get("links", {}).get("next")
            next_url = f"{TT_BASE_URL}{next_rel}" if next_rel else None

        # 2) Enriquecer cada ticket con datos del evento
        #    construimos la URL base de evento a partir del TT_BASE_URL
        events_base = TT_BASE_URL.replace("/issued_tickets", "/events")

        for t in tickets:
            ev_id = t.get("event_id")
            if not ev_id:
                continue

            ev_resp = requests.get(
                f"{events_base}/{ev_id}",
                headers=headers,
                timeout=10
            )
            if ev_resp.ok:
                ev = ev_resp.json()
                # Nombre del evento
                t['event_name'] = ev.get('name')
                # Fechas en ISO 8601
                t['starts_at']  = ev.get('start', {}).get('iso')
                t['ends_at']    = ev.get('end',   {}).get('iso')

            # Renombramos descripción para front
            t['ticket_type'] = t.get('description')

        return jsonify({"tickets": tickets}), 200

    except requests.RequestException as e:
        app.logger.error(f"Network error TT: {e}")
        return jsonify({"message": "No se pudo conectar a Ticket Tailor"}), 502

    except Exception as e:
        app.logger.error(f"Unexpected TT error: {e}")
        return jsonify({"message": "Error interno al recuperar entradas"}), 500







# --------------------------------------------
#  CONFIGURACIÓN
# --------------------------------------------
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "PassSigner.pem")   # ← certificado PEM
KEY_FILE  = os.path.join(BASE_DIR, "PassSigner.key")   # ← clave privada
WWDR_CERT = os.path.join(BASE_DIR, "AppleWWDRCA.pem")
PASS_CERT_PASSWORD = "20141130"

ICON_FILE = os.path.join(BASE_DIR, "icon.png")
LOGO_FILE = os.path.join(BASE_DIR, "logo.png")

PASS_TYPE_ID  = "pass.com.penwin.events"
APPLE_TEAM_ID = "N2SZYHTN44"

if not TT_API_KEY:
    raise RuntimeError("Variable de entorno TT_API_KEY no definida")


# --------------------------------------------
#  AUTH DECORATOR DE EJEMPLO
# --------------------------------------------
# def token_required(f):  # COMENTADO - usa el token_required real definido anteriormente
#     @wraps(f)
#     def wrapper(*args, **kwargs):
#         # …valida tu token aquí…
#         current_user = {"name": "demo"}
#         return f(current_user, *args, **kwargs)
#     return wrapper

# --------------------------------------------
#  Helper: cabeceras Ticket Tailor (Basic <base64(key:)>)
# --------------------------------------------
def _tt_headers():
    encoded = base64.b64encode(f"{TT_API_KEY}:".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}

def _tt_get(url: str):
    """GET robusto a Ticket Tailor (acepta payload con o sin 'data')."""
    resp = requests.get(url, headers=_tt_headers(), timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"TicketTailor {resp.status_code}: {resp.text[:120]}")
    j = resp.json()
    return j["data"] if isinstance(j, dict) and len(j) == 1 and "data" in j else j

# --------------------------------------------
#  Ruta que genera el .pkpass
# --------------------------------------------
@app.route("/passes/<ticket_id>.pkpass", methods=["GET"])
@token_required
def download_pass(current_user, ticket_id):
    try:
        # 1 · Datos del ticket y del evento
        ticket   = _tt_get(f"{TT_BASE_URL}/{ticket_id}")
        event_id = ticket.get("event_id") or ticket.get("event", {}).get("id")
        if not event_id:
            return jsonify({"message": "event_id no encontrado", "payload": ticket}), 502
        ev = _tt_get(f"https://api.tickettailor.com/v1/events/{event_id}")

        # …dentro de download_pass …

        # 2 · Construye el pase (mínimo de 4 argumentos)
        t_info = EventTicket()
        pkpass = Pass(
            t_info,
            passTypeIdentifier = PASS_TYPE_ID,
            organizationName   = "Penwin",
            teamIdentifier     = APPLE_TEAM_ID,
        )

        # Asigna el resto de propiedades obligatorias u opcionales
        pkpass.serialNumber    = ticket_id
        pkpass.description     = ev.get("name", "Evento")
        pkpass.logoText        = ev.get("name", "Evento")
        pkpass.backgroundColor = "rgb(255,255,255)"

        # Imágenes
        pkpass.addFile("icon.png", open(ICON_FILE, "rb"))
        pkpass.addFile("logo.png", open(LOGO_FILE, "rb"))

        # Campos visibles
        t_info.addPrimaryField("event", "Evento", ev.get("name", ""))
        t_info.addSecondaryField(
            "date", "Fecha",
            f"{ev['start']['formatted']} – {ev['end']['time']}"
        )
        t_info.addSecondaryField("type", "Tipo", ticket.get("description", ""))
        t_info.addAuxiliaryField("code", "Codi del bitllet", ticket.get("barcode", ""))

        # Código QR
        pkpass.barcode = Barcode(
            message = ticket.get("barcode", ""),
            format  = BarcodeFormat.QR,
            altText = ticket.get("barcode", "")
        )

        # --------------------------------------------------------------------
        # 3 · Firmar (tu llamada actual)
        pkpass_io = pkpass.create(
            certificate=CERT_FILE,
            key=KEY_FILE,                  # PEM de la clave privada
            wwdr_certificate=WWDR_CERT,
            password=None                  # pon la passphrase si la clave la tiene
        )

        # --------------------------------------------------------------------
        # 3.1 · CORREGIR la firma (convierte Base64 → DER binario)
        import io, zipfile, base64

        buf_in = pkpass_io.getvalue()               # ZIP generado por python-passbook
        z_in   = zipfile.ZipFile(io.BytesIO(buf_in), 'r')

        # Copia todos los ficheros; decodifica signature si empieza por texto “MIIO”
        files = {}
        for name in z_in.namelist():
            data = z_in.read(name)
            if name == "signature" and data[:4] == b"MIIO":   # => está en Base-64
                data = base64.b64decode(data)                 # → ahora DER binario
            files[name] = data
        z_in.close()

        # Crea un ZIP nuevo con la firma ya binaria
        out_io = io.BytesIO()
        with zipfile.ZipFile(out_io, "w", zipfile.ZIP_DEFLATED) as z_out:
            for name, data in files.items():
                z_out.writestr(name, data)

        # --------------------------------------------------------------------
        # 4 · Devuelve el .pkpass corregido
        resp = make_response(out_io.getvalue())
        resp.headers["Content-Type"]        = "application/vnd.apple.pkpass"
        resp.headers["Content-Disposition"] = f'attachment; filename=\"{ticket_id}.pkpass\"'
        return resp


    except Exception as e:
        app.logger.exception("Error generando pase")
        return jsonify({"message": "Error interno", "error": str(e)}), 500


# --------------------------------------------------------------------
#                     FUNCIONES AUXILIARES DE INSTAGRAM
# --------------------------------------------------------------------

def get_all_instagram_media(account_id, access_token):
    """
    Obtiene todos los medios de Instagram de una cuenta de negocio.

    Args:
        account_id (str): ID de la cuenta de Instagram Business
        access_token (str): Token de acceso de larga duración

    Returns:
        list: Lista de objetos media o None si hay error
    """
    try:
        # URL para obtener los medios de la cuenta
        url = f"https://graph.instagram.com/v18.0/{account_id}/media"

        # Campos que queremos obtener de cada post
        fields = "id,caption,media_url,permalink,media_type,timestamp,like_count,comments_count"

        all_media = []

        # Parámetros iniciales
        params = {
            'fields': fields,
            'access_token': access_token,
            'limit': 25  # Instagram permite hasta 25 por petición
        }

        # Paginación para obtener todos los posts
        while url:
            response = requests.get(url, params=params)

            if response.status_code != 200:
                app.logger.error(f"Error obteniendo medios de Instagram: {response.status_code} - {response.text}")
                return None

            data = response.json()

            # Agregar los medios de esta página
            all_media.extend(data.get('data', []))

            # Verificar si hay más páginas
            paging = data.get('paging', {})
            url = paging.get('next')  # URL de la siguiente página
            params = {}  # Para páginas siguientes, los parámetros van en la URL

        app.logger.info(f"Se obtuvieron {len(all_media)} medios de Instagram")
        return all_media

    except requests.RequestException as e:
        app.logger.error(f"Error de red obteniendo medios de Instagram: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error inesperado obteniendo medios de Instagram: {e}")
        return None


def upload_image_to_s3(image_url, filename_prefix):
    """
    Descarga una imagen desde una URL y la sube a S3.

    Args:
        image_url (str): URL de la imagen a descargar
        filename_prefix (str): Prefijo para el nombre del archivo (ej: insta_id)

    Returns:
        str: URL de la imagen en S3 o None si hay error
    """
    try:
        # Descargar la imagen
        response = requests.get(image_url, timeout=30)
        if response.status_code != 200:
            app.logger.error(f"Error descargando imagen: {response.status_code}")
            return None

        # Generar nombre del archivo
        file_extension = "jpg"  # Instagram suele usar JPG
        s3_key = f"app/instagram/{filename_prefix}.{file_extension}"

        # Subir a S3
        s3.upload_fileobj(
            io.BytesIO(response.content),
            S3_BUCKET,
            s3_key,
            ExtraArgs={
                "ACL": "public-read",
                "ContentType": "image/jpeg"
            }
        )

        # Generar URL pública
        s3_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/{s3_key}"
        app.logger.info(f"Imagen subida a S3: {s3_url}")

        return s3_url

    except requests.RequestException as e:
        app.logger.error(f"Error descargando imagen de Instagram: {e}")
        return None
    except Exception as e:
        app.logger.error(f"Error subiendo imagen a S3: {e}")
        return None


@app.route('/create-dynamic-subscription', methods=['POST'])
@token_required
def create_dynamic_subscription(current_user):
    """Crear una suscripción dinámica en Stripe"""
    try:
        data = request.get_json()

        # Validar campos requeridos
        required_fields = ['product_name', 'price', 'currency', 'user_id_code', 'description', 'success_url', 'cancel_url']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo requerido: {field}"}), 400

        # Configurar Stripe
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

        # Crear producto
        product = stripe.Product.create(name=data['product_name'])

        # Crear precio (suscripción mensual)
        price = stripe.Price.create(
            product=product.id,
            unit_amount=int(data['price'] * 100),  # Convertir a centavos
            currency=data['currency'].lower(),
            recurring={'interval': 'month'}
        )

        # Crear sesión de checkout
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price': price.id,
                'quantity': 1,
            }],
            mode='subscription',
            success_url=data['success_url'],
            cancel_url=data['cancel_url'],
            metadata={
                'user_id_code': data['user_id_code'],
                'description': data['description']
            }
        )

        return jsonify({
            "success": True,
            "data": {
                "checkout_url": checkout_session.url,
                "session_id": checkout_session.id,
                "product_id": product.id,
                "price_id": price.id
            }
        }), 200

    except stripe.error.StripeError as e:
        print(f"❌ Error de Stripe: {e}")
        return jsonify({"error": f"Error de Stripe: {str(e)}"}), 400
    except Exception as e:
        print(f"❌ Error creando suscripción: {e}")
        return jsonify({"error": f"Error interno: {str(e)}"}), 500

@app.route('/subscription/success')
def subscription_success():
    """Página de éxito después de completar suscripción"""
    session_id = request.args.get('session_id')

    if session_id:
        try:
            # Obtener información de la sesión de checkout
            checkout_session = stripe.checkout.Session.retrieve(session_id)

            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Suscripción Exitosa</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
                <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                    <div style="color: #28a745; font-size: 64px; margin-bottom: 20px;">✓</div>
                    <h1 style="color: #333; margin: 0 0 20px 0;">¡Suscripción Exitosa!</h1>
                    <p style="color: #666; margin: 0 0 30px 0;">Tu suscripción se ha activado correctamente.</p>
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
                        <p style="margin: 0; color: #666; font-size: 14px;">
                            <strong>ID de Sesión:</strong><br>
                            <code style="background: #e9ecef; padding: 4px 8px; border-radius: 4px; font-size: 12px;">{session_id}</code>
                        </p>
                        <hr style="border: 1px solid #dee2e6; margin: 15px 0;">
                        <p style="margin: 0; color: #666; font-size: 12px;">
                            <strong>Estado:</strong> {checkout_session.status}<br>
                            <strong>Modo:</strong> {checkout_session.mode}<br>
                            <strong>Cantidad:</strong> {checkout_session.amount_total/100 if checkout_session.amount_total else 'N/A'} {checkout_session.currency.upper() if checkout_session.currency else ''}<br>
                        </p>
                    </div>
                    <button onclick="window.close()" style="background: #007bff; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px;">
                        Cerrar Ventana
                    </button>
                </div>
                <script>
                    // Auto-cerrar ventana después de 10 segundos
                    setTimeout(function() {{
                        window.close();
                    }}, 10000);
                </script>
            </body>
            </html>
            """
        except Exception as e:
            return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Error - Suscripción</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
            </head>
            <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
                <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                    <div style="color: #dc3545; font-size: 64px; margin-bottom: 20px;">⚠️</div>
                    <h1 style="color: #333; margin: 0 0 20px 0;">Error verificando suscripción</h1>
                    <p style="color: #666; margin: 0 0 30px 0;">Hubo un problema verificando el estado de tu suscripción, pero el pago se procesó correctamente.</p>
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 30px;">
                        <p style="margin: 0; color: #666; font-size: 12px;">
                            Error: {str(e)[:100]}...
                        </p>
                    </div>
                    <button onclick="window.close()" style="background: #6c757d; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px;">
                        Cerrar Ventana
                    </button>
                </div>
            </body>
            </html>
            """
    else:
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Suscripción Exitosa</title>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
        </head>
        <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
            <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                <div style="color: #28a745; font-size: 64px; margin-bottom: 20px;">✓</div>
                <h1 style="color: #333; margin: 0 0 20px 0;">¡Suscripción Completada!</h1>
                <p style="color: #666; margin: 0 0 30px 0;">Tu suscripción se ha procesado exitosamente.</p>
                <button onclick="window.close()" style="background: #007bff; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px;">
                    Cerrar Ventana
                </button>
            </div>
            <script>
                setTimeout(function() {
                    window.close();
                }, 5000);
            </script>
        </body>
        </html>
        """


@app.route('/subscription/cancel')
def subscription_cancel():
    """Página de cancelación de suscripción"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Suscripción Cancelada</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
    </head>
    <body style="font-family: sans-serif; padding: 20px; text-align: center; background: #f8f9fa;">
        <div style="max-width: 500px; margin: 0 auto; background: white; padding: 40px; border-radius: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
            <div style="color: #ffc107; font-size: 64px; margin-bottom: 20px;">⚠️</div>
            <h1 style="color: #333; margin: 0 0 20px 0;">Suscripción Cancelada</h1>
            <p style="color: #666; margin: 0 0 30px 0;">No se ha procesado ningún pago. Puedes intentar de nuevo cuando quieras.</p>
            <button onclick="window.close()" style="background: #6c757d; color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 16px;">
                Cerrar Ventana
            </button>
        </div>
        <script>
            setTimeout(function() {
                window.close();
            }, 3000);
        </script>
    </body>
    </html>
    """


@app.route('/check-payment-status/<session_id>')
@token_required
def check_payment_status(current_user, session_id):
    """Verifica el estado real de un pago en Stripe"""
    try:
        # Obtener la sesión de checkout de Stripe
        checkout_session = stripe.checkout.Session.retrieve(session_id)

        # Determinar el estado basado en la respuesta de Stripe
        is_paid = checkout_session.payment_status == 'paid'

        return jsonify({
            'session_id': session_id,
            'payment_status': checkout_session.payment_status,
            'status': checkout_session.status,
            'is_paid': is_paid,
            'mode': checkout_session.mode,
            'amount_total': checkout_session.amount_total,
            'currency': checkout_session.currency
        }), 200

    except Exception as e:
        app.logger.error(f"Error checking payment status: {e}")
        return jsonify({
            'error': 'Unable to verify payment status',
            'message': str(e)
        }), 500

@app.route('/verify-payment-session/<session_id>', methods=['GET'])
@token_required
def verify_payment_session(current_user, session_id):
    """Verificar el estado de una sesión de pago de Stripe"""
    try:
        # Configurar Stripe
        stripe.api_key = os.getenv("STRIPE_SECRET_KEY")

        # Obtener información de la sesión
        session = stripe.checkout.Session.retrieve(session_id)

        return jsonify({
            "success": True,
            "payment_status": session.payment_status,
            "status": session.status,
            "session_id": session.id,
            "amount_total": session.amount_total,
            "currency": session.currency
        }), 200

    except stripe.error.StripeError as e:
        print(f"❌ Error de Stripe verificando sesión: {e}")
        return jsonify({"error": f"Error de Stripe: {str(e)}"}), 400
    except Exception as e:
        print(f"❌ Error verificando sesión: {e}")
        return jsonify({"error": f"Error interno: {str(e)}"}), 500


# --------------------------------------------------------------------
#                   GENERACIÓN DE CERTIFICADOS PDF
# --------------------------------------------------------------------

def generate_donation_certificate(user_data, donation_data, year=None):
    """
    Genera un certificado de donaciones en PDF para un usuario

    Args:
        user_data: Diccionario con datos del usuario (name, email, etc.)
        donation_data: Diccionario con información de donaciones por canal
        year: Año del certificado (por defecto año actual)

    Returns:
        BytesIO object con el PDF generado
    """
    if year is None:
        year = datetime.now().year

    # Información legal de los canales (esto debería venir de una base de datos)
    channel_legal_info = {
        'escola_de_pregaria': {
            'legal_name': 'Fundación Escola de Pregaria',
            'cif': 'G12345678',
            'address': 'Calle Example, 123, 08001 Barcelona',
            'registration': 'Registro de Fundaciones: 1234/2020'
        },
        'beapostle': {
            'legal_name': 'Asociación BeApostle',
            'cif': 'G87654321',
            'address': 'Avenida Test, 456, 28001 Madrid',
            'registration': 'Registro Nacional de Asociaciones: 5678/2019'
        }
    }

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    # Crear estilos personalizados
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )

    header_style = ParagraphStyle(
        'CustomHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=12,
        textColor=colors.darkblue
    )

    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=11,
        spaceAfter=6
    )

    # Lista de elementos del PDF
    elements = []

    # Título principal
    title = Paragraph(f"CERTIFICADO DE DONACIONES {year}", title_style)
    elements.append(title)
    elements.append(Spacer(1, 20))

    # Información del donante
    elements.append(Paragraph("DATOS DEL DONANTE", header_style))

    donor_info = [
        ["Nombre:", user_data.get('username', 'N/A')],
        ["Email:", user_data.get('email', 'N/A')],
        ["Fecha de emisión:", datetime.now().strftime("%d de %B de %Y")]
    ]

    donor_table = Table(donor_info, colWidths=[4*cm, 10*cm])
    donor_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 11),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
    ]))

    elements.append(donor_table)
    elements.append(Spacer(1, 25))

    # Resumen de donaciones
    elements.append(Paragraph("RESUMEN DE DONACIONES", header_style))

    total_donated = 0

    for channel_id, channel_data in donation_data.items():
        if channel_data.get('count', 0) > 0:
            channel_info = channel_legal_info.get(channel_id, {})
            legal_name = channel_info.get('legal_name', channel_id.replace('_', ' ').title())
            cif = channel_info.get('cif', 'N/A')

            elements.append(Paragraph(f"<b>{legal_name}</b>", normal_style))
            elements.append(Paragraph(f"CIF: {cif}", normal_style))

            # Tabla de donaciones para este canal
            donations_data = [["Fecha", "Concepto", "Importe"]]

            for payment in channel_data.get('payments', []):
                date_str = payment.get('date', '')
                if 'T' in date_str:
                    date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%d/%m/%Y")
                else:
                    formatted_date = date_str

                amount = payment.get('amount', 0)
                total_donated += amount

                donations_data.append([
                    formatted_date,
                    payment.get('description', 'Donación'),
                    f"€{amount:.2f}"
                ])

            # Añadir fila de total para este canal
            channel_total = channel_data.get('total_amount', 0)
            donations_data.append([
                "",
                f"<b>TOTAL {legal_name}</b>",
                f"<b>€{channel_total:.2f}</b>"
            ])

            donations_table = Table(donations_data, colWidths=[3*cm, 8*cm, 3*cm])
            donations_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -2), 'Helvetica'),
                ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
            ]))

            elements.append(donations_table)
            elements.append(Spacer(1, 15))

            # Información legal de la organización
            if channel_info:
                legal_text = f"Dirección: {channel_info.get('address', 'N/A')}<br/>"
                legal_text += f"Registro: {channel_info.get('registration', 'N/A')}"
                elements.append(Paragraph(legal_text, normal_style))
                elements.append(Spacer(1, 20))

    # Total general
    total_data = [["", "<b>TOTAL GENERAL DONADO</b>", f"<b>€{total_donated:.2f}</b>"]]
    total_table = Table(total_data, colWidths=[3*cm, 8*cm, 3*cm])
    total_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 2, colors.darkblue),
    ]))

    elements.append(total_table)
    elements.append(Spacer(1, 30))

    # Nota legal
    legal_note = """
    <b>CERTIFICADO DE DONACIONES</b><br/><br/>
    Este certificado se emite para efectos fiscales según la normativa vigente.
    Las donaciones realizadas a entidades sin ánimo de lucro pueden ser deducibles
    en la declaración del Impuesto sobre la Renta de las Personas Físicas (IRPF),
    conforme a la Ley 49/2002, de 23 de diciembre, de régimen fiscal de las entidades
    sin fines lucrativos y de los incentivos fiscales al mecenazgo.<br/><br/>
    Conserve este certificado para su declaración fiscal.
    """

    legal_paragraph = Paragraph(legal_note, normal_style)
    elements.append(legal_paragraph)

    # Pie de página
    elements.append(Spacer(1, 20))
    footer_text = f"Certificado generado electrónicamente el {datetime.now().strftime('%d de %B de %Y a las %H:%M')}"
    footer = Paragraph(footer_text, ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, alignment=TA_CENTER, textColor=colors.grey))
    elements.append(footer)

    # Construir el PDF
    doc.build(elements)
    buffer.seek(0)

    return buffer


@app.route('/donation-certificate', methods=['GET'])
@token_required
def get_donation_certificate(current_user):
    """
    Endpoint para generar y descargar el certificado de donaciones de un usuario

    Query parameters:
        year (opcional): Año del certificado (por defecto año actual)
        format (opcional): 'pdf' (por defecto) o 'json' para obtener solo los datos
    """
    try:
        year = request.args.get('year', datetime.now().year, type=int)
        output_format = request.args.get('format', 'pdf')

        # Verificar que el usuario tiene información de stripe
        if not hasattr(current_user, 'stripe') or not current_user.stripe:
            return jsonify({'error': 'Usuario sin información de donaciones'}), 404

        # Obtener datos de donaciones del usuario
        try:
            stripe_data = current_user.stripe
            if isinstance(stripe_data, str):
                stripe_data = json.loads(stripe_data)
            elif not isinstance(stripe_data, dict):
                stripe_data = {}

            payment_history = stripe_data.get('payment_history', {})
        except (json.JSONDecodeError, AttributeError) as e:
            app.logger.error(f"Error parsing stripe data for user {current_user.id}: {e}")
            return jsonify({'error': 'Datos de donaciones incorrectos'}), 500

        if not payment_history:
            return jsonify({'error': 'No se encontraron donaciones para este usuario'}), 404

        # Filtrar donaciones por año si se especifica
        filtered_donations = {}
        for channel_id, channel_data in payment_history.items():
            filtered_payments = []

            for payment in channel_data.get('payments', []):
                payment_date = payment.get('date', '')
                if payment_date:
                    try:
                        if 'T' in payment_date:
                            date_obj = datetime.fromisoformat(payment_date.replace('Z', '+00:00'))
                        else:
                            date_obj = datetime.strptime(payment_date, '%Y-%m-%d')

                        if date_obj.year == year:
                            filtered_payments.append(payment)
                    except (ValueError, TypeError):
                        # Si no se puede parsear la fecha, incluir el pago
                        filtered_payments.append(payment)

            if filtered_payments:
                filtered_donations[channel_id] = {
                    'channel_name': channel_data.get('channel_name', channel_id),
                    'payments': filtered_payments,
                    'count': len(filtered_payments),
                    'total_amount': sum(p.get('amount', 0) for p in filtered_payments)
                }

        if not filtered_donations:
            return jsonify({'error': f'No se encontraron donaciones para el año {year}'}), 404

        # Preparar datos del usuario
        user_data = {
            'username': current_user.username,
            'email': current_user.email,
            'user_id': current_user.id
        }

        # Si solo se solicitan los datos en JSON
        if output_format == 'json':
            return jsonify({
                'user': user_data,
                'donations': filtered_donations,
                'year': year,
                'total_donated': sum(d['total_amount'] for d in filtered_donations.values()),
                'total_transactions': sum(d['count'] for d in filtered_donations.values())
            })

        # Generar PDF
        pdf_buffer = generate_donation_certificate(user_data, filtered_donations, year)

        # Preparar respuesta
        filename = f"certificado_donaciones_{current_user.username}_{year}.pdf"

        return Response(
            pdf_buffer.read(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf'
            }
        )

    except Exception as e:
        app.logger.error(f"Error generando certificado de donaciones: {e}")
        return jsonify({'error': 'Error interno generando certificado'}), 500


@app.route('/demo-certificate')
def demo_certificate():
    """
    Endpoint de demostración para descargar el certificado de oriolfarras@gmail.com
    Sin autenticación - solo para mostrar funcionamiento
    """
    try:
        # Obtener el usuario de demostración
        user = User.query.filter_by(email='oriolfarras@gmail.com').first()
        if not user:
            return jsonify({'error': 'Usuario de demostración no encontrado'}), 404

        # Verificar que el usuario tiene información de stripe
        if not user.stripe:
            return jsonify({'error': 'Usuario sin información de donaciones'}), 404

        # Obtener datos de donaciones del usuario
        payment_history = user.stripe.get('payment_history', {})

        if not payment_history:
            return jsonify({'error': 'No se encontraron donaciones para este usuario'}), 404

        # Preparar datos del usuario
        user_data = {
            'username': user.username,
            'email': user.email,
            'user_id': user.id
        }

        # Generar PDF
        pdf_buffer = generate_donation_certificate(user_data, payment_history, 2025)

        # Preparar respuesta
        filename = f"certificado_donaciones_{user.username}_2025_DEMO.pdf"

        return Response(
            pdf_buffer.read(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf'
            }
        )

    except Exception as e:
        app.logger.error(f"Error generando certificado demo: {e}")
        return jsonify({'error': f'Error: {str(e)}'}), 500


@app.route('/demo-certificate-info')
def demo_certificate_info():
    """
    Página informativa sobre el certificado de demostración
    """
    try:
        # Obtener el usuario de demostración
        user = User.query.filter_by(email='oriolfarras@gmail.com').first()
        if not user:
            return "<h1>Usuario de demostración no encontrado</h1>", 404

        payment_history = user.stripe.get('payment_history', {}) if user.stripe else {}

        total_amount = sum(ch.get('total_amount', 0) for ch in payment_history.values())
        total_payments = sum(ch.get('count', 0) for ch in payment_history.values())

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Certificado de Donaciones - Demostración</title>
            <meta charset="utf-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    max-width: 800px;
                    margin: 50px auto;
                    padding: 20px;
                    line-height: 1.6;
                    background: #f5f5f5;
                }}
                .container {{
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    text-align: center;
                    color: #2c3e50;
                    border-bottom: 3px solid #3498db;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .info {{
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 5px;
                    margin: 20px 0;
                    border-left: 4px solid #3498db;
                }}
                .download-btn {{
                    display: inline-block;
                    background: #e74c3c;
                    color: white;
                    padding: 15px 30px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-size: 18px;
                    text-align: center;
                    margin: 20px 0;
                    transition: background 0.3s;
                    font-weight: bold;
                }}
                .download-btn:hover {{
                    background: #c0392b;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 15px;
                    margin: 20px 0;
                }}
                .stat {{
                    text-align: center;
                    background: #ecf0f1;
                    padding: 15px;
                    border-radius: 5px;
                }}
                .stat-number {{
                    font-size: 24px;
                    font-weight: bold;
                    color: #e74c3c;
                }}
                .stat-label {{
                    color: #7f8c8d;
                    font-size: 14px;
                }}
                .channel {{
                    background: white;
                    padding: 15px;
                    margin: 10px 0;
                    border-radius: 5px;
                    border: 1px solid #ddd;
                }}
                .legal {{
                    font-size: 12px;
                    color: #666;
                    background: #f9f9f9;
                    padding: 15px;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🏆 Certificado de Donaciones 2025</h1>
                    <h2>Demostración del Sistema</h2>
                    <p><strong>Usuario:</strong> {user.username} ({user.email})</p>
                </div>

                <div class="info">
                    <h3>📊 Resumen de Donaciones</h3>
                    <div class="stats">
                        <div class="stat">
                            <div class="stat-number">€{total_amount:.2f}</div>
                            <div class="stat-label">Total Donado</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">{total_payments}</div>
                            <div class="stat-label">Transacciones</div>
                        </div>
                        <div class="stat">
                            <div class="stat-number">{len(payment_history)}</div>
                            <div class="stat-label">Canales</div>
                        </div>
                    </div>
                </div>

                <div class="info">
                    <h4>🎯 Distribución por Canal:</h4>
        """

        for channel_id, channel_data in payment_history.items():
            channel_name = channel_data.get('channel_name', channel_id.replace('_', ' ').title())
            count = channel_data.get('count', 0)
            amount = channel_data.get('total_amount', 0)

            html_content += f"""
                    <div class="channel">
                        <strong>{channel_name}</strong>: {count} donaciones - €{amount:.2f}
                    </div>
            """

        html_content += f"""
                </div>

                <div style="text-align: center; margin: 30px 0;">
                    <a href="/demo-certificate" class="download-btn">
                        📄 Descargar Certificado PDF
                    </a>
                </div>

                <div class="info">
                    <h4>✨ Características del Certificado</h4>
                    <ul>
                        <li><strong>📋 Datos completos del usuario:</strong> Nombre, email, fecha de emisión</li>
                        <li><strong>💰 Desglose detallado:</strong> Por canal, con fechas y montos individuales</li>
                        <li><strong>🏛️ Información legal:</strong> CIF, direcciones y números de registro</li>
                        <li><strong>📑 Validez fiscal:</strong> Referencias a la Ley 49/2002 para IRPF</li>
                        <li><strong>🔐 Formato profesional:</strong> PDF A4 con diseño corporativo</li>
                    </ul>
                </div>

                <div class="info">
                    <h4>🏢 Organizaciones Beneficiarias</h4>
                    <div class="channel">
                        <strong>Fundación Escola de Pregaria</strong><br>
                        CIF: G12345678<br>
                        Registro de Fundaciones: 1234/2020
                    </div>
                    <div class="channel">
                        <strong>Asociación BeApostle</strong><br>
                        CIF: G87654321<br>
                        Registro Nacional de Asociaciones: 5678/2019
                    </div>
                </div>

                <div class="legal">
                    <strong>ℹ️ Información Legal:</strong> Este certificado es válido para la declaración del IRPF conforme a la Ley 49/2002,
                    de 23 de diciembre, de régimen fiscal de las entidades sin fines lucrativos y de los incentivos fiscales al mecenazgo.
                    <br><br>
                    <strong>🎯 Demostración:</strong> Este es un certificado de demostración generado automáticamente
                    desde los datos reales de donaciones sincronizados con Stripe.
                </div>
            </div>
        </body>
        </html>
        """

        return html_content

    except Exception as e:
        return f"<h1>Error: {str(e)}</h1>", 500

# --------------------------------------------------------------
#           CALENDAR EVENTS ENDPOINTS
# --------------------------------------------------------------

@app.route('/calendar-events', methods=['GET'])
@token_required
def get_calendar_events(current_user):
    """
    Obtiene eventos del calendario con soporte para filtros, búsqueda y paginación

    Query params:
    - search: Búsqueda por título o descripción
    - event_type: Filtrar por tipo de evento (free, paid, like, comment, follow, etc.)
    - channel_id: Filtrar por canal específico
    - channel_ids: Filtrar por múltiples canales (IDs separados por comas, ej: "1,2,3")
    - date_from / start_date: Filtrar eventos desde esta fecha (ISO format)
    - date_to / end_date: Filtrar eventos hasta esta fecha (ISO format)
    - payment_type: all, free, paid
    - price_min: Precio mínimo
    - price_max: Precio máximo
    - location: Filtrar por ubicación (texto)
    - latitude, longitude, distance: Filtrar por distancia desde ubicación (km)
    - friends_only: Solo eventos donde amigos están registrados (true/false)
    - page: Número de página (default: 1)
    - per_page: Elementos por página (default: 50)
    - view_mode: 'grouped' (default) o 'list' o 'calendar'
    """
    try:
        from datetime import datetime, timedelta
        import secrets
        import math

        # Obtener parámetros de query
        search_query = request.args.get('search', '').strip()
        event_type_filter = request.args.get('event_type', '').strip()
        channel_id_filter = request.args.get('channel_id', '').strip()
        channel_ids_filter = request.args.get('channel_ids', '').strip()  # Múltiples canales separados por comas
        date_from_str = request.args.get('date_from', request.args.get('start_date', '')).strip()
        date_to_str = request.args.get('date_to', request.args.get('end_date', '')).strip()
        payment_type = request.args.get('payment_type', 'all').strip()  # all, free, paid
        price_min = request.args.get('price_min', '').strip()
        price_max = request.args.get('price_max', '').strip()
        location_filter = request.args.get('location', '').strip()

        # Filtros de ubicación por distancia
        latitude_str = request.args.get('latitude', '').strip()
        longitude_str = request.args.get('longitude', '').strip()
        distance_str = request.args.get('distance', '').strip()

        # Filtro de amigos
        friends_only = request.args.get('friends_only', 'false').lower() == 'true'

        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 50))
        view_mode = request.args.get('view_mode', 'grouped')  # 'grouped', 'list', 'calendar'

        # Obtener eventos de la organización del usuario
        today = datetime.now()
        start_of_today = today.replace(hour=0, minute=0, second=0, microsecond=0)
        start_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start_of_year = today.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

        # Construir query base con filtros de visibilidad
        # El usuario puede ver eventos SOLO de canales a los que está suscrito

        # Obtener canales visibles según el rol del usuario
        # SUPERADMIN: ve todos los eventos
        # ORG_ADMIN: ve eventos de canales de sus organizaciones
        # Usuario normal: ve eventos de canales suscritos

        is_superadmin = current_user.role.upper() == "SUPERADMIN"

        if is_superadmin:
            # Superadmin ve todos los eventos activos
            app.logger.info(f"👑 SUPERADMIN {current_user.id} - showing all events")
            query = CalendarEvent.query.filter(CalendarEvent.is_active == True)
        else:
            # Obtener organizaciones administradas
            user_orgs = UserOrganization.query.filter_by(user_id=current_user.id, role='ORG_ADMIN').all()
            org_admin_ids = [uo.organization_id for uo in user_orgs]

            # Obtener canales de organizaciones administradas
            org_channels = []
            if org_admin_ids:
                org_channels = db.session.query(Channel.id).filter(
                    Channel.organization_id.in_(org_admin_ids)
                ).all()
                org_channel_ids = [ch[0] for ch in org_channels]
            else:
                org_channel_ids = []

            # Obtener canales suscritos
            subscribed_channels = db.session.query(UserChannel.channel_id).filter(
                UserChannel.user_id == current_user.id
            ).all()
            subscribed_channel_ids = [ch[0] for ch in subscribed_channels]

            # Combinar canales de org admin + canales suscritos
            visible_channel_ids = list(set(org_channel_ids + subscribed_channel_ids))

            app.logger.info(f"📅 User {current_user.id} - Org admin channels: {org_channel_ids}, Subscribed: {subscribed_channel_ids}, Total visible: {visible_channel_ids}")

            if visible_channel_ids:
                query = CalendarEvent.query.filter(
                    CalendarEvent.channel_id.in_(visible_channel_ids),
                    CalendarEvent.is_active == True
                )
            else:
                # Si no tiene canales visibles, mostrar vacío
                app.logger.warning(f"⚠️ User {current_user.id} has no visible channels")
                query = CalendarEvent.query.filter(CalendarEvent.id == -1)

        # Aplicar filtros
        if search_query:
            search_pattern = f"%{search_query}%"
            query = query.filter(
                db.or_(
                    CalendarEvent.title.like(search_pattern),
                    CalendarEvent.description.like(search_pattern),
                    CalendarEvent.location.like(search_pattern)
                )
            )

        if event_type_filter:
            query = query.filter(CalendarEvent.event_type == event_type_filter)

        # Filtro por canal (múltiples canales o uno solo)
        if channel_ids_filter:
            # Filtro por múltiples canales (separados por comas)
            try:
                channel_ids = [int(cid.strip()) for cid in channel_ids_filter.split(',') if cid.strip()]
                if channel_ids:
                    query = query.filter(CalendarEvent.channel_id.in_(channel_ids))
                    app.logger.info(f"🔍 Filtering by channel IDs: {channel_ids}")
            except ValueError as e:
                app.logger.warning(f"⚠️ Invalid channel_ids format: {e}")
                pass
        elif channel_id_filter:
            # Filtro por un solo canal (retrocompatibilidad)
            try:
                channel_id = int(channel_id_filter)
                query = query.filter(CalendarEvent.channel_id == channel_id)
                app.logger.info(f"🔍 Filtering by single channel ID: {channel_id}")
            except ValueError:
                pass

        # Filtro por tipo de pago
        if payment_type == 'free':
            query = query.filter(db.or_(
                CalendarEvent.event_price == 0,
                CalendarEvent.event_price.is_(None),
                CalendarEvent.event_type == 'free'
            ))
        elif payment_type == 'paid':
            query = query.filter(
                CalendarEvent.event_price > 0,
                CalendarEvent.event_type == 'paid'
            )

        if date_from_str:
            try:
                start_date = datetime.fromisoformat(date_from_str.replace('Z', '+00:00'))
                query = query.filter(CalendarEvent.event_date >= start_date)
            except ValueError:
                pass

        if date_to_str:
            try:
                end_date = datetime.fromisoformat(date_to_str.replace('Z', '+00:00'))
                query = query.filter(CalendarEvent.event_date <= end_date)
            except ValueError:
                pass

        if price_min:
            try:
                min_price = float(price_min)
                query = query.filter(CalendarEvent.event_price >= min_price)
            except ValueError:
                pass

        if price_max:
            try:
                max_price = float(price_max)
                query = query.filter(CalendarEvent.event_price <= max_price)
            except ValueError:
                pass

        if location_filter:
            location_pattern = f"%{location_filter}%"
            query = query.filter(CalendarEvent.location.like(location_pattern))

        # Filtro de amigos apuntados
        if friends_only:
            # Obtener IDs de amigos del usuario actual
            friends_ids = db.session.query(Friendship.friend_id).filter(
                Friendship.user_id == current_user.id,
                Friendship.status == 'accepted'
            ).union(
                db.session.query(Friendship.user_id).filter(
                    Friendship.friend_id == current_user.id,
                    Friendship.status == 'accepted'
                )
            ).all()

            friends_ids = [f[0] for f in friends_ids]

            if friends_ids:
                # Obtener IDs de eventos donde los amigos están registrados
                events_with_friends = db.session.query(CalendarEventRegistration.event_id).filter(
                    CalendarEventRegistration.user_id.in_(friends_ids)
                ).distinct().all()

                events_with_friends_ids = [e[0] for e in events_with_friends]

                if events_with_friends_ids:
                    query = query.filter(CalendarEvent.id.in_(events_with_friends_ids))
                else:
                    # No hay eventos con amigos, retornar vacío
                    query = query.filter(CalendarEvent.id == -1)  # Imposible, retorna vacío
            else:
                # No tiene amigos, retornar vacío
                query = query.filter(CalendarEvent.id == -1)

        # Filtro de ubicación por distancia (requiere coordenadas en eventos)
        # NOTA: Para implementar este filtro, se necesitan agregar campos latitude y longitude
        # a la tabla calendar_events. Por ahora, solo se puede filtrar por texto de ubicación.
        if latitude_str and longitude_str and distance_str:
            app.logger.warning("Filtro de ubicación por distancia no disponible - requiere campos de coordenadas en eventos")
            # TODO: Agregar campos latitude y longitude a CalendarEvent
            # TODO: Implementar cálculo de distancia con fórmula de Haversine

        # Ordenar por fecha (más recientes primero por defecto)
        query = query.order_by(CalendarEvent.event_date.desc())

        # Obtener total de eventos antes de paginación
        total_events = query.count()

        # Aplicar paginación solo si no es vista agrupada
        if view_mode != 'grouped':
            offset = (page - 1) * per_page
            events = query.limit(per_page).offset(offset).all()
        else:
            events = query.all()

        # Obtener todas las reacciones del usuario actual de una sola vez
        user_reactions = {}
        user_registrations = {}
        if events:
            event_ids = [event.id_code for event in events]
            reactions = CalendarReaction.query.filter(
                CalendarReaction.user_id == current_user.id,
                CalendarReaction.event_id.in_(event_ids)
            ).all()

            for reaction in reactions:
                user_reactions[reaction.event_id] = reaction.reaction_type

            # Obtener registros del usuario
            event_db_ids = [event.id for event in events]
            registrations = CalendarEventRegistration.query.filter(
                CalendarEventRegistration.user_id == current_user.id,
                CalendarEventRegistration.event_id.in_(event_db_ids)
            ).all()

            for reg in registrations:
                # Buscar el id_code correspondiente
                for event in events:
                    if event.id == reg.event_id:
                        user_registrations[event.id_code] = {
                            'registered': True,
                            'installments': reg.installments,
                            'total_price': reg.total_price,
                            'registration_date': reg.registration_date.isoformat()
                        }
                        break

        # Agrupar eventos por períodos
        today_events = []
        month_events = []
        year_events = []
        all_events_list = []

        for event in events:
            # Contar reacciones totales por tipo
            reaction_counts = {
                'heart': CalendarReaction.query.filter_by(event_id=event.id_code, reaction_type='heart').count(),
                'pray': CalendarReaction.query.filter_by(event_id=event.id_code, reaction_type='pray').count(),
                'comment': CalendarReaction.query.filter_by(event_id=event.id_code, reaction_type='comment').count()
            }

            # Contar asistentes registrados
            attendees_count = CalendarEventRegistration.query.filter_by(event_id=event.id).count()

            # Obtener imagen y nombre del canal si el evento no tiene profile_image
            channel_image = None
            channel_name = None
            if event.channel_id:
                channel = Channel.query.get(event.channel_id)
                if channel:
                    # Construir URL de imagen del canal basada en id_code
                    if hasattr(channel, 'id_code') and channel.id_code:
                        channel_image = f"https://delejove.s3.eu-west-3.amazonaws.com/app/channels/{channel.id_code}/profile.jpeg"
                    if hasattr(channel, 'name') and channel.name:
                        channel_name = channel.name

            event_data = {
                'id': event.id_code,
                'title': event.title,
                'description': event.description,
                'image': event.post_image or channel_image or 'IMAGES.storypic1',
                'time': _format_time_ago(event.event_date),
                'profile': event.profile_name or 'DeleJove',
                'descrption': event.description,  # Manteniendo el typo para compatibilidad
                'postimage': event.post_image or 'IMAGES.profilepic3',
                'channel_image': channel_image,
                'type': event.event_type,
                'event_date': event.event_date.isoformat(),
                'location': event.location,
                'channel_name': channel_name,
                'channel_id': event.channel_id,
                # Campos de pago necesarios para el modal
                'event_type': event.event_type,  # Campo duplicado por compatibilidad
                'event_price': event.event_price if event.event_price is not None else (
                    event.user_price if event.user_price else (
                        event.staff_price if event.staff_price else (
                            event.religious_price if event.religious_price else None
                        )
                    )
                ),
                'allow_installments': event.allow_installments,
                'reservation_amount': event.reservation_amount if event.reservation_amount is not None else (
                    # Auto-set default reservation amount if missing but installments enabled
                    50.0 if event.allow_installments and event.event_type == 'paid' else None
                ),
                'payment_deadline': event.payment_deadline,
                'max_attendees': event.max_attendees,
                'allow_help_requests': event.allow_help_requests,
                'custom_pricing_enabled': event.custom_pricing_enabled,
                'user_price': event.user_price,
                'staff_price': event.staff_price,
                'religious_price': event.religious_price,
                # Campos adicionales de fecha y configuración
                'event_end_date': event.event_end_date.isoformat() if event.event_end_date else None,
                'event_end_time': event.event_end_time,
                'is_all_day': event.is_all_day,
                'is_multi_day': event.is_multi_day,
                'has_end_time': event.has_end_time,
                'is_public': event.is_public,
                # Información de reacciones y registros
                'user_reaction': user_reactions.get(event.id_code),
                'reaction_counts': reaction_counts,
                'attendees_count': attendees_count,
                'user_registered': user_registrations.get(event.id_code, {}).get('registered', False),
                'user_registration': user_registrations.get(event.id_code)
            }

            all_events_list.append(event_data)

            if event.event_date >= start_of_today:
                today_events.append(event_data)
            elif event.event_date >= start_of_month:
                month_events.append(event_data)
            elif event.event_date >= start_of_year:
                year_events.append(event_data)

        # Preparar respuesta según el modo de vista
        if view_mode == 'list':
            # Vista de lista simple con paginación
            return jsonify({
                'success': True,
                'events': all_events_list,
                'pagination': {
                    'page': page,
                    'per_page': per_page,
                    'total': total_events,
                    'total_pages': (total_events + per_page - 1) // per_page
                }
            }), 200
        elif view_mode == 'calendar':
            # Vista de calendario - organizar por mes/año
            calendar_data = {}
            for event_data in all_events_list:
                event_date = datetime.fromisoformat(event_data['event_date'])
                month_key = event_date.strftime('%Y-%m')
                if month_key not in calendar_data:
                    calendar_data[month_key] = {
                        'month': event_date.strftime('%B %Y'),
                        'events': []
                    }
                calendar_data[month_key]['events'].append(event_data)

            return jsonify({
                'success': True,
                'calendar': list(calendar_data.values()),
                'total_events': total_events
            }), 200
        else:
            # Vista agrupada (default)
            response_data = []

            if today_events:
                response_data.append({
                    'title': 'Today',
                    'data': today_events
                })

            if month_events:
                response_data.append({
                    'title': 'This month',
                    'data': month_events
                })

            if year_events:
                response_data.append({
                    'title': 'This year',
                    'data': year_events
                })

            return jsonify({
                'success': True,
                'events': response_data,
                'total_events': total_events
            }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo eventos del calendario: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

def _format_time_ago(event_date):
    """Función auxiliar para formatear tiempo transcurrido"""
    try:
        now = datetime.now()
        diff = now - event_date

        if diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"
    except:
        return "Unknown"

@app.route('/calendar-events', methods=['POST'])
@token_required
def create_calendar_event(current_user):
    """
    Crea un nuevo evento en el calendario
    """
    try:
        data = request.get_json()

        # Validaciones
        required_fields = ['title', 'event_type', 'event_date']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo requerido: {field}'}), 400

        # Generar ID único
        import secrets
        import string
        id_code = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))

        # Preparar event_end_date si está presente
        event_end_date = None
        if data.get('event_end_date'):
            event_end_date = datetime.fromisoformat(data.get('event_end_date').replace('Z', '+00:00'))

        # Procesar location - puede venir como objeto o string
        location_str = None
        location_data = data.get('location')
        if location_data:
            if isinstance(location_data, dict):
                # Si es un objeto, convertir a string con la descripción/dirección
                location_str = location_data.get('description', location_data.get('address', ''))
            else:
                # Si ya es string, usarlo directamente
                location_str = str(location_data)

        # Validar que tenga channel_id (obligatorio)
        if not data.get('channel_id'):
            return jsonify({'error': 'Campo requerido: channel_id'}), 400

        # Obtener la organización del canal para mantener compatibilidad
        channel = Channel.query.get(data.get('channel_id'))
        if not channel:
            return jsonify({'error': 'Canal no encontrado'}), 404

        # Crear evento
        event = CalendarEvent(
            id_code=id_code,
            title=data.get('title'),
            description=data.get('description'),
            event_type=data.get('event_type'),
            event_date=datetime.fromisoformat(data.get('event_date').replace('Z', '+00:00')),
            event_end_date=event_end_date,
            event_end_time=data.get('event_end_time'),
            is_all_day=data.get('is_all_day', False),
            is_multi_day=data.get('is_multi_day', False),
            has_end_time=data.get('has_end_time', False),
            organization_id=channel.organization_id,  # Heredar del canal
            channel_id=data.get('channel_id'),
            user_id=current_user.id,
            profile_name=data.get('profile_name', current_user.username),
            profile_image=data.get('profile_image'),
            post_image=data.get('post_image'),
            location=location_str,
            is_public=data.get('is_public', True),
            # Campos de pago
            max_attendees=data.get('max_attendees'),
            event_price=data.get('event_price'),
            payment_deadline=data.get('payment_deadline'),
            allow_installments=data.get('allow_installments', False),
            reservation_amount=data.get('reservation_amount'),
            allow_help_requests=data.get('allow_help_requests', False),
            custom_pricing_enabled=data.get('custom_pricing_enabled', False),
            user_price=data.get('user_price'),
            staff_price=data.get('staff_price'),
            religious_price=data.get('religious_price')
        )

        db.session.add(event)
        db.session.commit()

        # Emitir evento WebSocket para actualizaciones en tiempo real
        try:
            event_data = {
                'id': event.id_code,
                'channel_id': event.channel_id,
                'channel_id_code': channel.id_code if channel else None,
                'channel_name': channel.title if channel else None,
                'channel_image': channel.image if channel else None,
                'title': event.title,
                'description': event.description,
                'event_date': event.event_date.isoformat() if event.event_date else None,
                'time': event.event_date.strftime('%H:%M') if event.event_date else None,
                'location': event.location,
                'event_price': event.event_price,
                'religious_price': event.religious_price,
                'event_type': event.event_type,
                'event_end_date': event.event_end_date.isoformat() if event.event_end_date else None,
                'event_end_time': event.event_end_time,
                'is_all_day': event.is_all_day,
                'is_multi_day': event.is_multi_day,
                'has_end_time': event.has_end_time,
                'is_public': event.is_public,
                'is_active': True,
                'created_at': event.created_at.isoformat() if event.created_at else None,
                'updated_at': datetime.utcnow().isoformat()
            }
            socketio.emit('calendar_event_created', event_data)
            app.logger.info(f"📅 WebSocket emitido: calendar_event_created para evento {event.id_code}")
        except Exception as ws_error:
            app.logger.error(f"⚠️ Error emitiendo WebSocket para evento creado: {ws_error}")
            # No fallar si WebSocket falla, el HTTP polling será el fallback

        return jsonify({
            'success': True,
            'message': 'Evento creado exitosamente',
            'event_id': event.id_code
        }), 201

    except Exception as e:
        app.logger.error(f"Error creando evento del calendario: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/<event_id>', methods=['PUT'])
@token_required
def update_calendar_event(current_user, event_id):
    """
    Actualiza un evento del calendario
    """
    try:
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos (solo el creador o admin puede editar)
        if event.user_id != current_user.id and current_user.role != 'SUPERADMIN':
            return jsonify({'error': 'No tienes permisos para editar este evento'}), 403

        data = request.get_json()

        # Log para debug: ver qué campos de pago se reciben
        payment_fields = {
            'allow_installments': data.get('allow_installments'),
            'allow_help_requests': data.get('allow_help_requests'),
            'custom_pricing_enabled': data.get('custom_pricing_enabled'),
            'event_price': data.get('event_price'),
            'event_type': data.get('event_type')
        }
        app.logger.info(f"📝 Actualizando evento {event_id} - Campos de pago recibidos: {payment_fields}")

        # Actualizar campos básicos
        if 'title' in data:
            event.title = data['title']
        if 'description' in data:
            event.description = data['description']
        if 'event_type' in data:
            event.event_type = data['event_type']
        if 'event_date' in data:
            event.event_date = datetime.fromisoformat(data['event_date'].replace('Z', '+00:00'))
        if 'location' in data:
            # Procesar location - puede venir como objeto o string
            location_data = data['location']
            if isinstance(location_data, dict):
                event.location = location_data.get('description', location_data.get('address', ''))
            else:
                event.location = str(location_data) if location_data else None
        if 'is_public' in data:
            event.is_public = data['is_public']
        if 'profile_image' in data:
            event.profile_image = data['profile_image']
        if 'post_image' in data:
            event.post_image = data['post_image']

        # Actualizar campos de fecha y hora
        if 'event_end_date' in data:
            if data['event_end_date']:
                event.event_end_date = datetime.fromisoformat(data['event_end_date'].replace('Z', '+00:00'))
            else:
                event.event_end_date = None
        if 'event_end_time' in data:
            event.event_end_time = data['event_end_time']
        if 'is_all_day' in data:
            event.is_all_day = data['is_all_day']
        if 'is_multi_day' in data:
            event.is_multi_day = data['is_multi_day']
        if 'has_end_time' in data:
            event.has_end_time = data['has_end_time']

        # Actualizar campos de pago
        if 'max_attendees' in data:
            event.max_attendees = data['max_attendees']
        if 'event_price' in data:
            event.event_price = data['event_price']
        if 'payment_deadline' in data:
            event.payment_deadline = data['payment_deadline']
        if 'allow_installments' in data:
            event.allow_installments = data['allow_installments']
        if 'reservation_amount' in data:
            event.reservation_amount = data['reservation_amount']
        if 'allow_help_requests' in data:
            event.allow_help_requests = data['allow_help_requests']
        if 'custom_pricing_enabled' in data:
            event.custom_pricing_enabled = data['custom_pricing_enabled']
        if 'user_price' in data:
            event.user_price = data['user_price']
        if 'child_price' in data:
            event.child_price = data['child_price']
        if 'max_child_age' in data:
            event.max_child_age = data['max_child_age']
        if 'staff_price' in data:
            event.staff_price = data['staff_price']
        if 'religious_price' in data:
            event.religious_price = data['religious_price']

        # Actualizar campos de marketing
        if 'event_destacado' in data:
            event.event_destacado = data['event_destacado']
        if 'notify_all_users' in data:
            event.notify_all_users = data['notify_all_users']
        if 'create_event_post' in data:
            event.create_event_post = data['create_event_post']

        event.updated_at = datetime.utcnow()
        db.session.commit()

        # Emitir evento WebSocket para actualizaciones en tiempo real
        try:
            # Obtener datos del canal si existe
            channel = None
            if event.channel_id:
                channel = Channel.query.filter_by(id=event.channel_id).first()

            event_data = {
                'id': event.id_code,
                'channel_id': event.channel_id,
                'channel_id_code': channel.id_code if channel else None,
                'channel_name': channel.title if channel else None,
                'channel_image': channel.image if channel else None,
                'title': event.title,
                'description': event.description,
                'event_date': event.event_date.isoformat() if event.event_date else None,
                'time': event.event_date.strftime('%H:%M') if event.event_date else None,
                'location': event.location,
                'event_price': event.event_price,
                'religious_price': event.religious_price,
                'event_type': event.event_type,
                'event_end_date': event.event_end_date.isoformat() if event.event_end_date else None,
                'event_end_time': event.event_end_time,
                'is_all_day': event.is_all_day,
                'is_multi_day': event.is_multi_day,
                'has_end_time': event.has_end_time,
                'is_public': event.is_public,
                'is_active': event.is_active,
                'created_at': event.created_at.isoformat() if event.created_at else None,
                'updated_at': event.updated_at.isoformat()
            }
            socketio.emit('calendar_event_updated', event_data)
            app.logger.info(f"📅 WebSocket emitido: calendar_event_updated para evento {event.id_code}")
        except Exception as ws_error:
            app.logger.error(f"⚠️ Error emitiendo WebSocket para evento actualizado: {ws_error}")
            # No fallar si WebSocket falla, el HTTP polling será el fallback

        return jsonify({
            'success': True,
            'message': 'Evento actualizado exitosamente'
        }), 200

    except Exception as e:
        app.logger.error(f"Error actualizando evento del calendario: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/<event_id>', methods=['DELETE'])
@token_required
def delete_calendar_event(current_user, event_id):
    """
    Elimina un evento del calendario
    """
    try:
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos (solo el creador o admin puede eliminar)
        if event.user_id != current_user.id and current_user.role != 'SUPERADMIN':
            return jsonify({'error': 'No tienes permisos para eliminar este evento'}), 403

        # Soft delete (marcar como inactivo en lugar de eliminar)
        event.is_active = False
        event.updated_at = datetime.utcnow()
        db.session.commit()

        # Emitir evento WebSocket para actualizaciones en tiempo real
        try:
            event_data = {
                'id': event.id_code,
                'channel_id': event.channel_id,
                'is_active': False
            }
            socketio.emit('calendar_event_deleted', event_data)
            app.logger.info(f"📅 WebSocket emitido: calendar_event_deleted para evento {event.id_code}")
        except Exception as ws_error:
            app.logger.error(f"⚠️ Error emitiendo WebSocket para evento eliminado: {ws_error}")
            # No fallar si WebSocket falla, el HTTP polling será el fallback

        return jsonify({
            'success': True,
            'message': 'Evento eliminado exitosamente'
        }), 200

    except Exception as e:
        app.logger.error(f"Error eliminando evento del calendario: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/dashboard', methods=['GET'])
@token_required
def get_event_dashboard(current_user, event_id):
    """
    Obtiene estadísticas y datos del dashboard para un evento
    Incluye: asistentes, recaudación, capacidad, ventas por día, etc.
    """
    try:
        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos (admin del evento, canal u organización)
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            return jsonify({'error': 'No tienes permisos para ver este dashboard'}), 403

        # Obtener todas las inscripciones del evento
        registrations = CalendarEventRegistration.query.filter_by(event_id=event.id).all()

        # Estadísticas generales
        total_attendees = len(registrations)
        confirmed_attendees = total_attendees  # Todos los registrados están confirmados
        checked_in_count = sum(1 for r in registrations if getattr(r, 'checked_in', False))

        # Calcular recaudación total
        total_revenue = sum(r.total_price or 0 for r in registrations)

        # Capacidad del evento (si no está definida, usar None)
        event_capacity = getattr(event, 'capacity', None) or 100  # Default 100 si no existe
        capacity_percentage = (total_attendees / event_capacity * 100) if event_capacity else 0

        # Ventas por día
        daily_sales = {}
        for reg in registrations:
            date_key = reg.registration_date.strftime('%Y-%m-%d')
            if date_key not in daily_sales:
                daily_sales[date_key] = {'count': 0, 'revenue': 0}
            daily_sales[date_key]['count'] += 1
            daily_sales[date_key]['revenue'] += reg.total_price or 0

        # Convertir a lista ordenada
        daily_sales_list = [
            {
                'date': date,
                'count': data['count'],
                'revenue': round(data['revenue'], 2)
            }
            for date, data in sorted(daily_sales.items())
        ]

        # Listado de asistentes con detalles
        attendees_list = []
        for reg in registrations:
            user = User.query.get(reg.user_id)
            if user:
                # Obtener transacciones de pago asociadas
                transactions = PaymentTransaction.query.filter_by(registration_id=reg.id).order_by(PaymentTransaction.payment_date).all()

                # Construir lista de transacciones
                transaction_list = []
                for tx in transactions:
                    transaction_list.append({
                        'id': tx.id,
                        'installment_number': tx.installment_number,
                        'amount': round(tx.amount, 2),
                        'status': tx.status,
                        'stripe_payment_intent_id': tx.stripe_payment_intent_id,
                        'stripe_charge_id': tx.stripe_charge_id,
                        'stripe_refund_id': tx.stripe_refund_id,
                        'payment_date': tx.payment_date.isoformat() if tx.payment_date else None,
                        'refund_date': tx.refund_date.isoformat() if tx.refund_date else None,
                        'refund_amount': round(tx.refund_amount, 2) if tx.refund_amount else None
                    })

                # Construir timeline de eventos
                timeline = []

                # Evento de compra
                if getattr(reg, 'purchase_date', None):
                    timeline.append({
                        'type': 'purchase',
                        'date': reg.purchase_date.isoformat(),
                        'description': 'Inscripción realizada'
                    })
                elif reg.registration_date:
                    timeline.append({
                        'type': 'purchase',
                        'date': reg.registration_date.isoformat(),
                        'description': 'Inscripción realizada'
                    })

                # Eventos de pago
                for tx in transactions:
                    if tx.payment_date and tx.status == 'completed':
                        timeline.append({
                            'type': 'payment',
                            'date': tx.payment_date.isoformat(),
                            'description': f'Pago de cuota {tx.installment_number} ({round(tx.amount, 2)}€)',
                            'amount': round(tx.amount, 2)
                        })

                    # Eventos de devolución
                    if tx.refund_date and tx.refund_amount:
                        timeline.append({
                            'type': 'refund',
                            'date': tx.refund_date.isoformat(),
                            'description': f'Devolución de {round(tx.refund_amount, 2)}€',
                            'amount': round(tx.refund_amount, 2)
                        })

                # Evento de check-in
                if getattr(reg, 'checked_in', False) and getattr(reg, 'check_in_time', None):
                    timeline.append({
                        'type': 'checkin',
                        'date': reg.check_in_time.isoformat(),
                        'description': 'Check-in realizado'
                    })

                # Ordenar timeline por fecha
                timeline.sort(key=lambda x: x['date'])

                attendees_list.append({
                    'id': str(reg.id),
                    'user_id': str(user.id),
                    'user_name': user.name or f"{user.first_name} {user.last_name}".strip() or user.email,
                    'user_email': user.email,
                    'amount_paid': round(getattr(reg, 'amount_paid', 0) or reg.total_price or 0, 2),
                    'amount_pending': round(getattr(reg, 'amount_pending', 0) or 0, 2),
                    'total_price': round(reg.total_price or 0, 2),
                    'payment_status': getattr(reg, 'payment_status', 'completed'),
                    'stripe_payment_intent_id': getattr(reg, 'stripe_payment_intent_id', None),
                    'stripe_customer_id': getattr(reg, 'stripe_customer_id', None),
                    'checked_in': getattr(reg, 'checked_in', False),
                    'check_in_time': getattr(reg, 'check_in_time', None).isoformat() if getattr(reg, 'check_in_time', None) else None,
                    'purchase_date': getattr(reg, 'purchase_date', None).isoformat() if getattr(reg, 'purchase_date', None) else reg.registration_date.isoformat(),
                    'registration_date': reg.registration_date.strftime('%Y-%m-%d'),
                    'installments': reg.installments or 1,
                    'transactions': transaction_list,
                    'timeline': timeline
                })

        return jsonify({
            'total_attendees': total_attendees,
            'confirmed_attendees': confirmed_attendees,
            'checked_in_count': checked_in_count,
            'total_revenue': round(total_revenue, 2),
            'event_capacity': event_capacity,
            'capacity_percentage': round(capacity_percentage, 1),
            'attendees': attendees_list,
            'daily_sales': daily_sales_list
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo dashboard del evento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/checkin', methods=['POST'])
@token_required
def toggle_event_checkin(current_user, event_id):
    """
    Toggle check-in/check-out de un asistente a un evento
    Body: { "attendee_id": "123" }
    """
    try:
        data = request.get_json()
        attendee_id = data.get('attendee_id')

        if not attendee_id:
            return jsonify({'error': 'attendee_id es requerido'}), 400

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            return jsonify({'error': 'No tienes permisos para hacer check-in'}), 403

        # Buscar la inscripción
        registration = CalendarEventRegistration.query.get(int(attendee_id))
        if not registration or registration.event_id != event.id:
            return jsonify({'error': 'Inscripción no encontrada'}), 404

        # Toggle check-in
        current_status = getattr(registration, 'checked_in', False)

        # Añadir campos si no existen (para evitar errores en DB antiguas)
        try:
            registration.checked_in = not current_status
            registration.check_in_time = datetime.utcnow() if not current_status else None
            registration.updated_at = datetime.utcnow()
            db.session.commit()
        except Exception as db_error:
            # Si falla, probablemente los campos no existen en la tabla
            # Necesitamos ejecutar la migración
            app.logger.error(f"Error al actualizar check-in: {db_error}")
            return jsonify({
                'error': 'La tabla necesita ser migrada. Por favor, ejecuta la migración de check-in.',
                'migration_needed': True
            }), 500

        return jsonify({
            'success': True,
            'checked_in': registration.checked_in,
            'message': 'Check-in actualizado correctamente'
        }), 200

    except Exception as e:
        app.logger.error(f"Error en check-in de evento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/refund', methods=['POST'])
@token_required
def refund_event_payment(current_user, event_id):
    """
    Procesa un reembolso (refund) de un pago de evento
    Body: {
        "registration_id": "123",
        "amount": 50.00,  # Opcional, si no se especifica se reembolsa todo
        "reason": "requested_by_customer"  # Opcional
    }
    """
    try:
        import stripe

        data = request.get_json()
        registration_id = data.get('registration_id')
        refund_amount = data.get('amount')  # Puede ser None para refund completo
        refund_reason = data.get('reason', 'requested_by_customer')

        if not registration_id:
            return jsonify({'error': 'registration_id es requerido'}), 400

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            return jsonify({'error': 'No tienes permisos para hacer refunds'}), 403

        # Buscar la inscripción
        registration = CalendarEventRegistration.query.get(int(registration_id))
        if not registration or registration.event_id != event.id:
            return jsonify({'error': 'Inscripción no encontrada'}), 404

        # Verificar que tenga un payment_intent_id de Stripe
        stripe_payment_intent_id = getattr(registration, 'stripe_payment_intent_id', None)
        if not stripe_payment_intent_id:
            return jsonify({'error': 'No se encontró información de pago de Stripe para esta inscripción'}), 400

        # Configurar Stripe (usar la clave del entorno)
        stripe.api_key = os.getenv('STRIPE_SECRET_KEY', 'sk_test_...')  # TODO: Configurar en producción

        # Obtener el PaymentIntent para obtener el charge_id
        try:
            payment_intent = stripe.PaymentIntent.retrieve(stripe_payment_intent_id)

            if not payment_intent.charges or len(payment_intent.charges.data) == 0:
                return jsonify({'error': 'No se encontró un cargo asociado a este pago'}), 400

            charge_id = payment_intent.charges.data[0].id

            # Crear el refund
            refund_params = {
                'charge': charge_id,
                'reason': refund_reason
            }

            if refund_amount:
                # Refund parcial (Stripe trabaja en centavos)
                refund_params['amount'] = int(refund_amount * 100)

            refund = stripe.Refund.create(**refund_params)

            # Actualizar el registro
            amount_refunded = refund.amount / 100  # Convertir de centavos a euros
            current_paid = getattr(registration, 'amount_paid', registration.total_price or 0)

            registration.amount_paid = max(0, current_paid - amount_refunded)
            registration.amount_pending = (registration.total_price or 0) - registration.amount_paid

            # Si el refund es total, cambiar el estado
            if registration.amount_paid == 0:
                registration.payment_status = 'refunded'
            else:
                registration.payment_status = 'partial'

            registration.updated_at = datetime.utcnow()
            db.session.commit()

            # Registrar la transacción de refund
            try:
                payment_transaction = PaymentTransaction(
                    registration_id=registration.id,
                    installment_number=0,  # 0 para refunds
                    amount=-amount_refunded,  # Negativo para indicar refund
                    status='refunded',
                    stripe_charge_id=charge_id,
                    stripe_refund_id=refund.id,
                    refund_date=datetime.utcnow(),
                    refund_amount=amount_refunded
                )
                db.session.add(payment_transaction)
                db.session.commit()
            except Exception as transaction_error:
                app.logger.error(f"Error al registrar transacción de refund: {transaction_error}")
                # No fallar si no se puede registrar, el refund ya se hizo

            return jsonify({
                'success': True,
                'refund_id': refund.id,
                'amount_refunded': amount_refunded,
                'message': 'Reembolso procesado correctamente'
            }), 200

        except stripe.error.StripeError as stripe_error:
            app.logger.error(f"Error de Stripe en refund: {stripe_error}")
            return jsonify({'error': f'Error de Stripe: {str(stripe_error)}'}), 400

    except Exception as e:
        app.logger.error(f"Error procesando refund: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/send-alert', methods=['POST'])
@token_required
def send_event_alert(current_user, event_id):
    """
    Envía una alerta/notificación a todos los suscriptores del canal del evento.
    Solo los administradores del evento pueden enviar alertas.
    La notificación incluye un deep link a la inscripción del evento.
    """
    try:
        app.logger.info(f"📣 Iniciando envío de alerta para evento {event_id}")

        # Obtener el mensaje del body
        data = request.get_json()
        message = data.get('message', '').strip()

        if not message:
            app.logger.warning("❌ Mensaje vacío")
            return jsonify({'error': 'El mensaje es requerido'}), 400

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            app.logger.warning(f"❌ Evento {event_id} no encontrado")
            return jsonify({'error': 'Evento no encontrado'}), 404

        app.logger.info(f"✅ Evento encontrado: {event.title}, channel_id={event.channel_id}")

        # Verificar permisos del administrador
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        app.logger.info(f"🔐 Permisos: event_admin={is_event_admin}, super_admin={is_super_admin}, channel_admin={is_channel_admin}, org_admin={is_org_admin}")

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            app.logger.warning(f"❌ Usuario {current_user.id} sin permisos")
            return jsonify({'error': 'No tienes permisos para enviar alertas para este evento'}), 403

        # Obtener el canal del evento para acceder a sus suscriptores
        if not event.channel_id:
            app.logger.warning(f"❌ Evento sin canal asociado")
            return jsonify({'error': 'Este evento no está asociado a ningún canal'}), 400

        channel = Channel.query.get(event.channel_id)
        if not channel:
            app.logger.warning(f"❌ Canal {event.channel_id} no encontrado")
            return jsonify({'error': 'Canal del evento no encontrado'}), 404

        app.logger.info(f"✅ Canal encontrado: {channel.name}")

        # Obtener todos los suscriptores del canal
        subscribers_list = channel.subscribers_json or []
        if isinstance(subscribers_list, str):
            try:
                subscribers_list = json.loads(subscribers_list)
            except Exception as parse_error:
                app.logger.error(f"❌ Error parsing subscribers_json: {parse_error}")
                subscribers_list = []

        app.logger.info(f"📋 Suscriptores encontrados: {len(subscribers_list)}")

        if not subscribers_list:
            app.logger.warning("❌ Canal sin suscriptores")
            return jsonify({'error': 'Este canal no tiene suscriptores'}), 400

        # Serializar datos del evento para la notificación
        event_data = {
            'event_id': event.id_code,
            'event_title': event.title,
            'event_date': event.date.isoformat() if event.date else None,
            'event_price': event.price,
            'channel_id': channel.id_code,
            'channel_name': channel.name,
            # Deep link para navegación directa a la inscripción
            'action': 'navigate_to_event_registration'
        }

        app.logger.info(f"📨 Iniciando envío a {len(subscribers_list)} suscriptores...")

        # Crear notificación para cada suscriptor
        notifications_sent = 0
        for user_id_code in subscribers_list:
            # Buscar el usuario por id_code
            subscriber = User.query.filter_by(id_code=user_id_code).first()
            if subscriber:
                try:
                    create_notification(
                        recipient_user_id=subscriber.id,
                        notification_type='event_alert',
                        title=f'📣 {event.title}',
                        message=message,
                        sender_user_id=current_user.id,
                        data=event_data
                    )
                    notifications_sent += 1
                except Exception as notif_error:
                    app.logger.error(f"❌ Error creating notification for user {subscriber.id}: {notif_error}")
                    import traceback
                    app.logger.error(traceback.format_exc())

        app.logger.info(f"✅ Alertas enviadas: {notifications_sent}/{len(subscribers_list)}")

        return jsonify({
            'message': f'Alerta enviada correctamente a {notifications_sent} suscriptor(es)',
            'notifications_sent': notifications_sent
        }), 200

    except Exception as e:
        app.logger.error(f"Error enviando alerta del evento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/discount-codes', methods=['POST'])
@token_required
def create_discount_code(current_user, event_id):
    """
    Crea un código de descuento para un evento.
    Body: {
        "code": "VERANO2025",
        "discount_type": "percentage" | "fixed",
        "discount_value": 20,  # 20% o 20€
        "start_date": "2025-01-01T00:00:00" | null,
        "end_date": "2025-12-31T23:59:59" | null
    }
    """
    try:
        data = request.get_json()
        code = data.get('code', '').strip().upper()
        discount_type = data.get('discount_type', '').strip().lower()
        discount_value = data.get('discount_value')
        start_date_str = data.get('start_date')
        end_date_str = data.get('end_date')

        # Validaciones
        if not code:
            return jsonify({'error': 'El código es requerido'}), 400
        if discount_type not in ['percentage', 'fixed']:
            return jsonify({'error': 'El tipo de descuento debe ser "percentage" o "fixed"'}), 400
        if not discount_value or discount_value <= 0:
            return jsonify({'error': 'El valor del descuento debe ser mayor a 0'}), 400
        if discount_type == 'percentage' and discount_value > 100:
            return jsonify({'error': 'El porcentaje no puede ser mayor a 100%'}), 400

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            return jsonify({'error': 'No tienes permisos para crear códigos de descuento'}), 403

        # Verificar que el código no exista para este evento
        existing_code = DiscountCode.query.filter_by(
            event_id=event.id,
            code=code
        ).first()
        if existing_code:
            return jsonify({'error': 'Este código ya existe para este evento'}), 400

        # Parsear fechas
        start_date = None
        end_date = None
        if start_date_str:
            try:
                start_date = datetime.fromisoformat(start_date_str.replace('Z', '+00:00'))
            except:
                return jsonify({'error': 'Formato de fecha de inicio inválido'}), 400

        if end_date_str:
            try:
                end_date = datetime.fromisoformat(end_date_str.replace('Z', '+00:00'))
            except:
                return jsonify({'error': 'Formato de fecha de fin inválido'}), 400

        # Crear el código de descuento
        discount_code = DiscountCode(
            event_id=event.id,
            code=code,
            discount_type=discount_type,
            discount_value=discount_value,
            start_date=start_date,
            end_date=end_date,
            created_by=current_user.id
        )

        db.session.add(discount_code)
        db.session.commit()

        return jsonify({
            'success': True,
            'discount_code': {
                'id': discount_code.id,
                'code': discount_code.code,
                'discount_type': discount_code.discount_type,
                'discount_value': discount_code.discount_value,
                'start_date': discount_code.start_date.isoformat() if discount_code.start_date else None,
                'end_date': discount_code.end_date.isoformat() if discount_code.end_date else None,
                'times_used': discount_code.times_used,
                'total_discount_amount': discount_code.total_discount_amount,
                'is_active': discount_code.is_active
            }
        }), 201

    except Exception as e:
        app.logger.error(f"Error creando código de descuento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/discount-codes', methods=['GET'])
@token_required
def get_discount_codes(current_user, event_id):
    """
    Obtiene todos los códigos de descuento de un evento.
    """
    try:
        app.logger.info(f"🏷️ Obteniendo códigos de descuento para evento {event_id}")

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            app.logger.warning(f"❌ Evento {event_id} no encontrado")
            return jsonify({'error': 'Evento no encontrado'}), 404

        app.logger.info(f"✅ Evento encontrado: {event.title}")

        # Verificar permisos
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        app.logger.info(f"🔐 Permisos: event_admin={is_event_admin}, super_admin={is_super_admin}, channel_admin={is_channel_admin}, org_admin={is_org_admin}")

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            app.logger.warning(f"❌ Usuario {current_user.id} sin permisos")
            return jsonify({'error': 'No tienes permisos para ver los códigos de descuento'}), 403

        # Obtener todos los códigos
        app.logger.info(f"📋 Consultando tabla discount_codes para event.id={event.id}...")

        try:
            codes = DiscountCode.query.filter_by(event_id=event.id).order_by(DiscountCode.created_at.desc()).all()
            app.logger.info(f"✅ Códigos encontrados: {len(codes)}")
        except Exception as db_error:
            # Si la tabla no existe aún, devolver lista vacía
            error_str = str(db_error)
            if "doesn't exist" in error_str or "no such table" in error_str:
                app.logger.warning(f"⚠️ Tabla discount_codes no existe aún. Devolviendo lista vacía.")
                return jsonify({
                    'discount_codes': []
                }), 200
            else:
                # Si es otro tipo de error, re-lanzarlo
                raise

        codes_list = []
        for code in codes:
            codes_list.append({
                'id': code.id,
                'code': code.code,
                'discount_type': code.discount_type,
                'discount_value': code.discount_value,
                'start_date': code.start_date.isoformat() if code.start_date else None,
                'end_date': code.end_date.isoformat() if code.end_date else None,
                'max_uses': code.max_uses,  # null = ilimitado
                'times_used': code.times_used,
                'total_discount_amount': round(code.total_discount_amount, 2),
                'is_active': code.is_active,
                'created_at': code.created_at.isoformat()
            })

        return jsonify({
            'discount_codes': codes_list
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error obteniendo códigos de descuento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/events/<event_id>/goal', methods=['PUT'])
@token_required
def update_event_goal(current_user, event_id):
    """
    Actualiza el objetivo de asistentes de un evento.
    Body: {
        "goal": 75
    }
    """
    try:
        data = request.get_json()
        goal = data.get('goal')

        if goal is None or goal < 0:
            return jsonify({'error': 'El objetivo debe ser un número positivo'}), 400

        # Buscar el evento
        event = CalendarEvent.query.filter_by(id_code=event_id).first()
        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar permisos
        is_event_admin = event.user_id == current_user.id
        is_super_admin = current_user.role == 'SUPERADMIN'
        is_channel_admin = False
        is_org_admin = False

        if event.channel_id:
            channel_admin = ChannelAdmin.query.filter_by(
                channel_id=event.channel_id,
                user_id=current_user.id
            ).first()
            is_channel_admin = channel_admin is not None

        if event.organization_id:
            org_admin = OrganizationAdmin.query.filter_by(
                organization_id=event.organization_id,
                user_id=current_user.id
            ).first()
            is_org_admin = org_admin is not None

        if not (is_event_admin or is_super_admin or is_channel_admin or is_org_admin):
            return jsonify({'error': 'No tienes permisos para modificar este evento'}), 403

        # Actualizar el objetivo
        event.goal_attendees = int(goal)
        event.updated_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'success': True,
            'goal': event.goal_attendees,
            'message': 'Objetivo actualizado correctamente'
        }), 200

    except Exception as e:
        app.logger.error(f"Error actualizando objetivo del evento: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/seed-calendar-events', methods=['POST'])
@token_required
def seed_calendar_events(current_user):
    """
    Endpoint temporal para crear eventos de muestra en el calendario
    """
    try:
        from datetime import datetime, timedelta
        import secrets
        import string

        # Solo permitir a admins y org admins
        if current_user.role not in ['SUPERADMIN', 'ORG_ADMIN']:
            return jsonify({'error': 'Solo administradores pueden usar este endpoint'}), 403

        # Eventos de muestra basados en los datos originales del CalendarList
        sample_events = [
            # Today events
            {
                'title': 'Post liked',
                'description': 'liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(hours=5),
                'profile_name': 'alex techie',
                'profile_image': 'IMAGES.storypic1',
                'post_image': 'IMAGES.profilepic3'
            },
            {
                'title': 'Multiple likes',
                'description': 'and 5 others liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(hours=8),
                'profile_name': 'lily learns',
                'profile_image': 'IMAGES.storypic3',
                'post_image': 'IMAGES.profilepic5'
            },
            {
                'title': 'Comment mention',
                'description': 'mentioned you in a comment: very nice',
                'event_type': 'comment',
                'event_date': datetime.now() - timedelta(hours=2),
                'profile_name': 'mia maven',
                'profile_image': 'IMAGES.storypic2',
                'post_image': 'IMAGES.profilepic4'
            },
            {
                'title': 'New follower',
                'description': 'started following you.',
                'event_type': 'follow',
                'event_date': datetime.now() - timedelta(hours=1),
                'profile_name': 'sophia james',
                'profile_image': 'IMAGES.storypic4',
                'post_image': 'IMAGES.profilepic4'
            },

            # This month events
            {
                'title': 'Post liked',
                'description': 'liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(days=3),
                'profile_name': 'deepesh gaur',
                'profile_image': 'IMAGES.profile2',
                'post_image': 'IMAGES.profilepic6'
            },
            {
                'title': 'Multiple likes',
                'description': 'and 5 others liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(days=5),
                'profile_name': 'herry moven',
                'profile_image': 'IMAGES.profilepic10',
                'post_image': 'IMAGES.profilepic5'
            },
            {
                'title': 'Comment mention',
                'description': 'mentioned you in a comment: very nice',
                'event_type': 'comment',
                'event_date': datetime.now() - timedelta(days=7),
                'profile_name': 'lily learns',
                'profile_image': 'IMAGES.storypic3',
                'post_image': 'IMAGES.profilepic11'
            },
            {
                'title': 'New follower',
                'description': 'started following you.',
                'event_type': 'follow',
                'event_date': datetime.now() - timedelta(days=10),
                'profile_name': 'alex techie',
                'profile_image': 'IMAGES.storypic1',
                'post_image': 'IMAGES.profilepic4'
            },

            # This year events
            {
                'title': 'Post liked',
                'description': 'liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(days=45),
                'profile_name': 'lily learns',
                'profile_image': 'IMAGES.profilepic8',
                'post_image': 'IMAGES.profilepic9'
            },
            {
                'title': 'Multiple likes',
                'description': 'and 5 others liked your post',
                'event_type': 'like',
                'event_date': datetime.now() - timedelta(days=60),
                'profile_name': 'herry moven',
                'profile_image': 'IMAGES.profilepic10',
                'post_image': 'IMAGES.profilepic11'
            },
            {
                'title': 'Comment mention',
                'description': 'mentioned you in a comment: very nice',
                'event_type': 'comment',
                'event_date': datetime.now() - timedelta(days=80),
                'profile_name': 'mia maven',
                'profile_image': 'IMAGES.storypic2',
                'post_image': 'IMAGES.profilepic9'
            },
            {
                'title': 'New follower',
                'description': 'started following you.',
                'event_type': 'follow',
                'event_date': datetime.now() - timedelta(days=100),
                'profile_name': 'herry techie',
                'profile_image': 'IMAGES.profile2',
                'post_image': 'IMAGES.profilepic4'
            }
        ]

        created_events = []

        for event_data in sample_events:
            # Generar ID único
            id_code = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))

            event = CalendarEvent(
                id_code=id_code,
                title=event_data['title'],
                description=event_data['description'],
                event_type=event_data['event_type'],
                event_date=event_data['event_date'],
                organization_id=1,
                user_id=current_user.id,
                profile_name=event_data['profile_name'],
                profile_image=event_data.get('profile_image'),
                post_image=event_data.get('post_image'),
                location=event_data.get('location'),
                is_public=True,
                is_active=True
            )

            db.session.add(event)
            created_events.append(event_data['title'])

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Se crearon {len(created_events)} eventos de muestra',
            'events': created_events
        }), 201

    except Exception as e:
        app.logger.error(f"Error creando eventos de muestra: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500


@app.route('/make-admin/<email>', methods=['GET'])
def make_admin(email):
    """Endpoint temporal para hacer admin a un usuario"""
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        # Cambiar role directo del usuario
        user.role = 'SUPERADMIN'

        # Verificar si ya existe la relación
        existing = UserOrganization.query.filter_by(user_id=user.id, organization_id=1).first()
        if existing:
            existing.role = 'ORG_ADMIN'
        else:
            # Crear nueva relación
            user_org = UserOrganization(user_id=user.id, organization_id=1, role='ORG_ADMIN')
            db.session.add(user_org)

        db.session.commit()
        return jsonify({'success': True, 'message': f'Usuario {email} es ahora SUPERADMIN y ORG_ADMIN'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/make-member/<email>', methods=['GET'])
def make_member(email):
    """Endpoint temporal para hacer miembro a un usuario"""
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        # Verificar si ya existe la relación
        existing = UserOrganization.query.filter_by(user_id=user.id, organization_id=1).first()
        if existing:
            return jsonify({'success': True, 'message': f'Usuario {email} ya es miembro con rol {existing.role}'})
        else:
            # Crear nueva relación como miembro normal
            user_org = UserOrganization(user_id=user.id, organization_id=1, role='MEMBER')
            db.session.add(user_org)

        db.session.commit()
        return jsonify({'success': True, 'message': f'Usuario {email} es ahora MEMBER de organización 1'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/demote-user/<email>', methods=['GET'])
def demote_user(email):
    """Endpoint temporal para cambiar usuario de ORG_ADMIN a MEMBER"""
    try:
        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        # Buscar la relación existente
        existing = UserOrganization.query.filter_by(user_id=user.id, organization_id=1).first()
        if existing:
            old_role = existing.role
            existing.role = 'MEMBER'
            db.session.commit()
            return jsonify({'success': True, 'message': f'Usuario {email} demoted from {old_role} to MEMBER'})
        else:
            return jsonify({'error': 'Usuario no pertenece a organización 1'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/debug-channels', methods=['GET'])
def debug_channels():
    """Endpoint para debuggear canales"""
    try:
        # Ver todos los canales
        all_channels = Channel.query.all()

        # Ver todas las organizaciones
        all_orgs = Organization.query.all()

        result = {
            'total_channels': len(all_channels),
            'channels': [
                {
                    'id': ch.id,
                    'name': ch.name,
                    'id_code': ch.id_code,
                    'organization_id': ch.organization_id
                } for ch in all_channels
            ],
            'organizations': [
                {
                    'id': org.id,
                    'name': org.name
                } for org in all_orgs
            ]
        }

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# --------------------------------------------------------------------
#                  ENDPOINTS TEMPORALES DE ADMINISTRACIÓN
# --------------------------------------------------------------------

@app.route('/admin-update-user-bio/<email>', methods=['POST'])
@token_required
def admin_update_user_bio(current_user, email):
    """
    ENDPOINT TEMPORAL: Actualiza la bio de un usuario específico (solo SUPERADMIN)
    """
    try:
        # Permitir temporalmente actualizar bio de oriolfarras@gmail.com
        if current_user.role != 'SUPERADMIN' and email != 'oriolfarras@gmail.com':
            return jsonify({'message': 'No tienes permisos para esta acción'}), 403

        data = request.get_json()
        bio = data.get('bio', '')

        target_user = User.query.filter_by(email=email).first()
        if not target_user:
            return jsonify({'message': f'Usuario no encontrado: {email}'}), 404

        # Obtener user_settings actual
        user_settings = target_user.user_settings or {}
        if isinstance(user_settings, str):
            try:
                user_settings = json.loads(user_settings)
            except:
                user_settings = {}

        # Actualizar bio
        user_settings['bio'] = bio
        target_user.user_settings = user_settings

        # Marcar como modificado y guardar
        flag_modified(target_user, "user_settings")
        db.session.commit()

        app.logger.info(f"📝 ADMIN_UPDATE_BIO - Bio actualizada para {email}: {bio}")

        return jsonify({
            'message': f'Bio actualizada para {email}',
            'user_id': target_user.id,
            'bio': bio
        }), 200

    except Exception as e:
        app.logger.error(f"Error in admin_update_user_bio: {e}")
        return jsonify({'message': 'Error al actualizar bio'}), 500

@app.route('/clear-saved-posts/<email>', methods=['POST'])
@token_required
def clear_saved_posts_for_user(current_user, email):
    """
    ENDPOINT TEMPORAL: Limpia todos los posts guardados de un usuario específico
    """
    try:
        # Solo permitir a SUPERADMIN o al propio usuario
        if current_user.role != 'SUPERADMIN' and current_user.email != email:
            return jsonify({'message': 'No tienes permisos para esta acción'}), 403

        target_user = User.query.filter_by(email=email).first()
        if not target_user:
            return jsonify({'message': f'Usuario no encontrado: {email}'}), 404

        app.logger.info(f"🗑️ CLEAR_SAVED_POSTS - Posts guardados antes: {target_user.post_fav}")

        # Limpiar posts guardados
        target_user.post_fav = []
        flag_modified(target_user, "post_fav")
        db.session.commit()

        app.logger.info(f"🗑️ CLEAR_SAVED_POSTS - Posts guardados después: {target_user.post_fav}")

        return jsonify({
            'message': f'Posts guardados eliminados para {email}',
            'user_id': target_user.id,
            'cleared_posts': True
        }), 200

    except Exception as e:
        app.logger.error(f"Error in clear_saved_posts_for_user: {e}")
        return jsonify({'message': 'Error al limpiar posts guardados'}), 500

# --------------------------------------------------------------------
#                     PARISH SEARCH ENDPOINTS
# --------------------------------------------------------------------

@app.route('/search-parishes', methods=['GET'])
@token_required
def search_parishes(current_user):
    """Busca parroquias por nombre, diócesis, municipio o provincia"""
    try:
        query = request.args.get('q', '').strip()
        limit = int(request.args.get('limit', 1000))  # Sin límite por defecto, máximo 1000 para prevenir sobrecarga

        if not query or len(query) < 2:
            return jsonify({'parishes': [], 'message': 'Query too short'}), 200

        # Búsqueda inteligente en múltiples campos incluyendo dirección
        search_pattern = f'%{query}%'

        # Si no se especifica límite o es muy alto, obtener todos los resultados
        query_builder = ParroquiaCee.query.filter(
            db.or_(
                ParroquiaCee.nombre_parroquia.like(search_pattern),
                ParroquiaCee.diocesis.like(search_pattern),
                ParroquiaCee.municipio.like(search_pattern),
                ParroquiaCee.provincia.like(search_pattern),
                ParroquiaCee.direccion.like(search_pattern)
            )
        ).order_by(ParroquiaCee.nombre_parroquia.asc())

        # Solo aplicar límite si es menor a 1000 (para casos específicos)
        if limit < 1000:
            parishes = query_builder.limit(limit).all()
        else:
            parishes = query_builder.all()  # Sin límite - todos los resultados

        parishes_data = []
        for parish in parishes:
            # Construir texto descriptivo completo
            description_parts = [parish.nombre_parroquia]
            if parish.municipio:
                description_parts.append(parish.municipio)
            if parish.diocesis:
                description_parts.append(f"({parish.diocesis})")

            parishes_data.append({
                'id': parish.id,
                'parroquia_id': parish.parroquia_id,
                'nombre_parroquia': parish.nombre_parroquia,
                'diocesis': parish.diocesis,
                'municipio': parish.municipio,
                'provincia': parish.provincia,
                'direccion': parish.direccion,
                'codigo_postal': parish.codigo_postal,
                'display_name': ' - '.join(description_parts),
                'full_info': {
                    'telefono': parish.telefono,
                    'email': parish.email,
                    'parroco': parish.parroco
                }
            })

        return jsonify({
            'parishes': parishes_data,
            'total': len(parishes_data),
            'query': query
        }), 200

    except Exception as e:
        app.logger.error(f"Error searching parishes: {e}")
        return jsonify({'error': 'Error al buscar parroquias'}), 500

@app.route('/search-dioceses', methods=['GET'])
@token_required
def search_dioceses(current_user):
    """Busca diócesis únicas por nombre con soporte para alias locales"""
    try:
        query = request.args.get('q', '').strip()
        limit = request.args.get('limit', 50, type=int)

        if len(query) < 2:
            return jsonify({'dioceses': [], 'message': 'Query too short'}), 200

        # Mapeo de nombres locales/variantes a nombres oficiales en la base de datos
        diocese_name_variants = {
            # Catalunya - nombres locales a nombres oficiales de la BD
            'terrassa': 'Tarrasa',  # catalán -> castellano en BD
            'girona': 'Gerona',     # catalán -> castellano en BD
            'lleida': 'Lérida',     # catalán -> castellano en BD
            'tarragona': 'Tarragona',  # igual en ambos
            'barcelona': 'Barcelona',  # igual en ambos
            'vic': 'Vic',              # igual en ambos
            'solsona': 'Solsona',      # igual en ambos
            'tortosa': 'Tortosa',      # igual en ambos
            'urgell': 'Urgel',         # catalán -> oficial en BD
            'seu d\'urgell': 'Urgel',  # catalán -> oficial en BD

            # País Vasco - euskera/castellano local a nombres oficiales
            'bilbo': 'Bilbao',         # euskera -> castellano en BD
            'donostia': 'San Sebastián',  # euskera -> castellano en BD
            'gasteiz': 'Vitoria',      # euskera -> castellano en BD
            'san sebastian': 'San Sebastián',  # variante

            # Galicia - gallego a castellano
            'ourense': 'Orense',       # gallego -> castellano en BD
            'vigo': 'Tui-Vigo',        # local -> oficial en BD
            'santiago': 'Santiago de Compostela',  # abreviado -> completo
            'compostela': 'Santiago de Compostela',  # abreviado -> completo
            'ferrol': 'Mondoñedo-Ferrol',  # local -> oficial compuesto
            'mondoñedo': 'Mondoñedo-Ferrol',  # local -> oficial compuesto

            # Valencia - variantes valencianas/catalanas
            'castello': 'Segorbe-Castellón',  # catalán -> oficial en BD
            'castellon': 'Segorbe-Castellón', # castellano -> oficial compuesto
            'segorbe': 'Segorbe-Castellón',   # local -> oficial compuesto
            'alicante': 'Orihuela-Alicante',  # local -> oficial compuesto
            'orihuela': 'Orihuela-Alicante',  # local -> oficial compuesto

            # Variantes comunes en castellano
            'cordoba': 'Córdoba',       # sin tilde -> con tilde
            'malaga': 'Málaga',         # sin tilde -> con tilde
            'almeria': 'Almería',       # sin tilde -> con tilde
            'cadiz': 'Cádiz y Ceuta',   # local -> oficial compuesto
            'ceuta': 'Cádiz y Ceuta',   # local -> oficial compuesto
            'jerez': 'Jerez de la Frontera',  # abreviado -> completo
            'merida': 'Mérida-Badajoz', # local -> oficial compuesto
            'badajoz': 'Mérida-Badajoz', # local -> oficial compuesto
            'pamplona': 'Pamplona y Tudela',  # local -> oficial compuesto
            'tudela': 'Pamplona y Tudela',    # local -> oficial compuesto
            'alcala': 'Alcalá de Henares',    # abreviado -> completo
            'teruel': 'Teruel y Albarracín',  # local -> oficial compuesto
            'albarracin': 'Teruel y Albarracín',  # local -> oficial compuesto
        }

        # Buscar alias local primero
        query_lower = query.lower()
        mapped_queries = []

        # Agregar la query original
        mapped_queries.append(query)

        # Buscar en variantes exactas
        if query_lower in diocese_name_variants:
            mapped_queries.append(diocese_name_variants[query_lower])

        # Buscar variantes parciales (por si escriben solo parte del nombre)
        for variant, official_name in diocese_name_variants.items():
            if query_lower in variant or variant in query_lower:
                mapped_queries.append(official_name)

        # Eliminar duplicados manteniendo orden
        mapped_queries = list(dict.fromkeys(mapped_queries))

        # Construir query SQL que busque en todas las variantes
        all_dioceses = set()

        for search_term in mapped_queries:
            search_pattern = f'%{search_term}%'
            dioceses_query = db.session.query(ParroquiaCee.diocesis).filter(
                ParroquiaCee.diocesis.like(search_pattern)
            ).distinct()

            dioceses_batch = [row[0] for row in dioceses_query.all() if row[0] and row[0].strip()]
            all_dioceses.update(dioceses_batch)

        # Convertir a lista y priorizar resultados
        dioceses_list = list(all_dioceses)

        # Priorizar resultados: exactos primero, luego parciales
        def sort_priority(diocese):
            diocese_lower = diocese.lower()
            query_lower = query.lower()

            # Prioridad 1: coincidencia exacta
            if diocese_lower == query_lower:
                return (1, diocese)

            # Prioridad 2: empieza con la query
            if diocese_lower.startswith(query_lower):
                return (2, diocese)

            # Prioridad 3: contiene la query
            if query_lower in diocese_lower:
                return (3, diocese)

            # Prioridad 4: otros (por alias)
            return (4, diocese)

        dioceses_list.sort(key=sort_priority)

        # Aplicar límite si se especifica
        if limit > 0:
            dioceses_list = dioceses_list[:limit]

        # Formatear los resultados para ser consistentes con el frontend
        dioceses_data = []
        for i, diocese_name in enumerate(dioceses_list):
            dioceses_data.append({
                'id': i + 1,  # ID temporal para el frontend
                'diocesis': diocese_name,
                'nombre_diocesis': diocese_name,  # Alias para compatibilidad
                'display_name': diocese_name
            })

        return jsonify({
            'dioceses': dioceses_data,
            'total': len(dioceses_data),
            'query': query,
            'mapped_queries': mapped_queries if app.debug else None  # Solo en debug
        }), 200

    except Exception as e:
        app.logger.error(f"Error searching dioceses: {e}")
        return jsonify({'error': 'Error al buscar diócesis'}), 500

# --------------------------------------------------------------------
#                     TUTORED ACCOUNTS ENDPOINTS (HIJOS)
# --------------------------------------------------------------------

@app.route('/tutored-accounts', methods=['GET'])
@token_required
def get_tutored_accounts(current_user):
    """Obtiene la lista de hijos del usuario autenticado y del cónyuge si está habilitado"""
    try:
        user = current_user

        # Obtener solo los hijos activos del usuario
        children = TutoredAccount.query.filter_by(tutor_user_id=user.id, is_active=True).all()

        # Si el usuario comparte información con su cónyuge, incluir también los hijos del cónyuge
        if user.shares_children_with_spouse and user.spouse_user_id:
            spouse = User.query.get(user.spouse_user_id)
            if spouse and spouse.shares_children_with_spouse:
                spouse_children = TutoredAccount.query.filter_by(tutor_user_id=spouse.id, is_active=True).all()
                children.extend(spouse_children)

        children_data = []
        for child in children:
            # Marcar si el hijo es del cónyuge
            is_spouse_child = child.tutor_user_id != user.id
            children_data.append({
                'id': child.id,
                'nombre': child.nombre,
                'apellidos': child.apellidos,
                'dni': child.dni or '',
                'correo_electronico': child.correo_electronico or '',
                'fecha_nacimiento': child.fecha_nacimiento.strftime('%Y-%m-%d'),
                'genero': child.genero,
                'parroquia_principal': child.parroquia_principal,
                'can_access': child.can_access,
                'created_at': child.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_spouse_child': is_spouse_child,
                'tutor_name': User.query.get(child.tutor_user_id).username if is_spouse_child else 'Yo'
            })

        return jsonify({'children': children_data}), 200

    except Exception as e:
        app.logger.error(f"Error getting tutored accounts: {e}")
        return jsonify({'error': 'Error al obtener los hijos'}), 500

@app.route('/tutored-accounts', methods=['POST'])
@token_required
def create_tutored_account(current_user):
    """Crea una nueva cuenta tutelada (hijo)"""
    try:
        user = current_user

        data = request.get_json()

        # Validaciones
        required_fields = ['nombre', 'apellidos', 'fecha_nacimiento', 'genero', 'parroquia_principal']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'El campo {field} es obligatorio'}), 400

        # Validaciones específicas de negocio
        nombre = data.get('nombre', '').strip().lower()
        if nombre == 'test':
            return jsonify({'error': 'El nombre "test" no está permitido'}), 400

        genero = data.get('genero', '').strip().lower()
        if genero == 'otro':
            return jsonify({'error': 'El género "otro" no está permitido. Use "masculino" o "femenino"'}), 400

        # Validar DNI/NIE si se proporciona
        dni_value = data.get('dni', '').strip()
        if dni_value:
            if not validate_dni_nie(dni_value):
                return jsonify({'error': 'El formato del DNI/NIE no es válido'}), 400

            # Verificar que no exista ya un hijo con el mismo DNI para este tutor
            existing_child = TutoredAccount.query.filter_by(
                dni=dni_value,
                tutor_user_id=user.id
            ).first()
            if existing_child:
                return jsonify({'error': 'Ya existe un hijo con este DNI/NIE'}), 400

        # Validar que la parroquia existe en la base de datos usando ID
        parroquia_principal_id = data.get('parroquia_principal_id')
        if not parroquia_principal_id:
            return jsonify({'error': 'Debes seleccionar una parroquia válida de la lista'}), 400

        selected_parish = ParroquiaCee.query.filter_by(id=parroquia_principal_id).first()
        if not selected_parish:
            return jsonify({'error': 'La parroquia seleccionada no existe en la base de datos'}), 400

        # Parsear fecha de nacimiento
        try:
            fecha_nacimiento = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
        except ValueError:
            return jsonify({'error': 'Formato de fecha inválido. Use YYYY-MM-DD'}), 400

        # Determinar si puede acceder (tiene email)
        correo_electronico = data.get('correo_electronico', '').strip()
        can_access = bool(correo_electronico)

        # Crear nueva cuenta tutelada
        new_child = TutoredAccount(
            nombre=data['nombre'].strip(),
            apellidos=data['apellidos'].strip(),
            dni=dni_value.upper() if dni_value else None,
            correo_electronico=correo_electronico if correo_electronico else None,
            fecha_nacimiento=fecha_nacimiento,
            genero=data['genero'],
            parroquia_principal=selected_parish.nombre_parroquia if selected_parish else data['parroquia_principal'].strip(),
            tutor_user_id=user.id,
            can_access=can_access
        )

        db.session.add(new_child)
        db.session.flush()  # Para obtener el ID

        # Si tiene email, crear cuenta de usuario real
        user_account_created = False
        if correo_electronico:
            # Verificar que el email no esté ya en uso
            existing_user = User.query.filter_by(email=correo_electronico).first()
            if not existing_user:
                # Crear cuenta de usuario para el hijo
                child_user = User(
                    username=f"{new_child.nombre}_{new_child.apellidos}_{new_child.id}",
                    email=correo_electronico,
                    password=generate_password_hash('temp_password_123'),  # Contraseña temporal
                    role='TUTORED_USER'
                )
                db.session.add(child_user)
                db.session.flush()
                user_account_created = True
            else:
                # El email ya existe, no crear cuenta duplicada
                new_child.correo_electronico = None
                new_child.can_access = False

        # Actualizar tutelados_json del usuario tutor
        if user.tutelados_json is None:
            user.tutelados_json = []

        if new_child.id not in user.tutelados_json:
            user.tutelados_json.append(new_child.id)
            flag_modified(user, 'tutelados_json')

        db.session.commit()

        return jsonify({
            'message': 'Hijo creado exitosamente',
            'child': {
                'id': new_child.id,
                'nombre': new_child.nombre,
                'apellidos': new_child.apellidos,
                'can_access': new_child.can_access
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating tutored account: {e}")
        return jsonify({'error': 'Error al crear el hijo'}), 500

@app.route('/tutored-accounts/<int:child_id>', methods=['PUT'])
@token_required
def update_tutored_account(current_user, child_id):
    """Actualiza una cuenta tutelada existente"""
    try:
        user = current_user

        # Verificar que el hijo pertenece al usuario
        child = TutoredAccount.query.filter_by(id=child_id, tutor_user_id=user.id).first()
        if not child:
            return jsonify({'error': 'Hijo no encontrado'}), 404

        data = request.get_json()

        # Verificar si se está actualizando el email
        email_changed = False
        old_email = child.correo_electronico
        new_email = None

        # Actualizar campos
        if 'nombre' in data:
            nombre = data['nombre'].strip()
            if nombre.lower() == 'test':
                return jsonify({'error': 'El nombre "test" no está permitido'}), 400
            child.nombre = nombre
        if 'apellidos' in data:
            child.apellidos = data['apellidos'].strip()
        if 'dni' in data:
            dni_value = data['dni'].strip()
            if dni_value:
                if not validate_dni_nie(dni_value):
                    return jsonify({'error': 'El formato del DNI/NIE no es válido'}), 400
                # Verificar que no exista otro hijo con el mismo DNI
                existing_child = TutoredAccount.query.filter(
                    TutoredAccount.dni == dni_value,
                    TutoredAccount.tutor_user_id == user.id,
                    TutoredAccount.id != child.id
                ).first()
                if existing_child:
                    return jsonify({'error': 'Ya existe otro hijo con este DNI/NIE'}), 400
                child.dni = dni_value.upper()
            else:
                child.dni = None
        if 'correo_electronico' in data:
            correo = data['correo_electronico'].strip()
            new_email = correo if correo else None
            if old_email != new_email:
                email_changed = True
                # Actualizar el email en el modelo
                child.correo_electronico = new_email
                # Actualizar can_access según si tiene email
                child.can_access = bool(new_email)
        if 'fecha_nacimiento' in data:
            try:
                child.fecha_nacimiento = datetime.strptime(data['fecha_nacimiento'], '%Y-%m-%d').date()
            except ValueError:
                return jsonify({'error': 'Formato de fecha inválido'}), 400
        if 'genero' in data:
            genero = data['genero'].strip().lower()
            if genero == 'otro':
                return jsonify({'error': 'El género "otro" no está permitido. Use "masculino" o "femenino"'}), 400
            child.genero = data['genero']
        if 'parroquia_principal_id' in data:
            parroquia_principal_id = data['parroquia_principal_id']
            if not parroquia_principal_id:
                return jsonify({'error': 'Debes seleccionar una parroquia válida de la lista'}), 400

            selected_parish = ParroquiaCee.query.filter_by(id=parroquia_principal_id).first()
            if not selected_parish:
                return jsonify({'error': 'La parroquia seleccionada no existe en la base de datos'}), 400

            child.parroquia_principal = selected_parish.nombre_parroquia

        # Si el email cambió, manejar las cuentas de usuario
        if email_changed:
            # Si tenía email antes, buscar y desactivar/eliminar la cuenta de usuario anterior
            if old_email:
                old_user = User.query.filter_by(email=old_email, role='TUTORED_USER').first()
                if old_user:
                    db.session.delete(old_user)

            # Si ahora tiene email, crear nueva cuenta de usuario
            if new_email:
                existing_user = User.query.filter_by(email=new_email).first()
                if not existing_user:
                    child_user = User(
                        username=f"{child.nombre}_{child.apellidos}_{child.id}",
                        email=new_email,
                        password=generate_password_hash('temp_password_123'),  # Contraseña temporal
                        role='TUTORED_USER'
                    )
                    db.session.add(child_user)
                else:
                    # El email ya está en uso, revertir el cambio
                    child.correo_electronico = old_email
                    child.can_access = bool(old_email)
                    return jsonify({'error': 'El email ya está en uso por otro usuario'}), 400

        db.session.commit()

        return jsonify({
            'message': 'Hijo actualizado exitosamente',
            'child': {
                'id': child.id,
                'nombre': child.nombre,
                'apellidos': child.apellidos,
                'can_access': child.can_access
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating tutored account: {e}")
        return jsonify({'error': 'Error al actualizar el hijo'}), 500

@app.route('/tutored-accounts/<int:child_id>', methods=['DELETE'])
@token_required
def delete_tutored_account(current_user, child_id):
    """Desactiva una cuenta tutelada en lugar de eliminarla"""
    try:
        user = current_user

        # Verificar que el hijo pertenece al usuario
        child = TutoredAccount.query.filter_by(id=child_id, tutor_user_id=user.id).first()
        if not child:
            return jsonify({'error': 'Hijo no encontrado'}), 404

        # Desactivar la cuenta tutelada en lugar de eliminarla
        child.is_active = False
        child.can_access = False  # También quitar acceso

        # Si tiene cuenta de usuario asociada, desactivarla también
        if child.correo_electronico:
            associated_user = User.query.filter_by(email=child.correo_electronico, role='TUTORED_USER').first()
            if associated_user:
                associated_user.is_active = False

        # Remover de tutelados_json del usuario (solo los activos)
        if user.tutelados_json and child_id in user.tutelados_json:
            user.tutelados_json.remove(child_id)
            flag_modified(user, 'tutelados_json')

        db.session.commit()

        return jsonify({'message': 'Hijo desactivado exitosamente'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deactivating tutored account: {e}")
        return jsonify({'error': 'Error al desactivar el hijo'}), 500

# --------------------------------------------------------------------
#                     ENDPOINTS PARA GESTIÓN DE CÓNYUGE
# --------------------------------------------------------------------

@app.route('/link-spouse', methods=['POST'])
@token_required
def link_spouse(current_user):
    """Vincular un cónyuge por email"""
    try:
        data = request.get_json()

        if not data or 'email' not in data:
            return jsonify({'error': 'Email es requerido'}), 400

        spouse_email = data['email'].strip().lower()

        if not spouse_email:
            return jsonify({'error': 'Email no puede estar vacío'}), 400

        # Validar que no sea el mismo usuario
        if spouse_email == current_user.email:
            return jsonify({'error': 'No puedes vincularte a ti mismo como cónyuge'}), 400

        # Buscar el usuario cónyuge por email
        spouse_user = User.query.filter_by(email=spouse_email, is_active=True).first()

        if not spouse_user:
            return jsonify({'error': 'No se encontró un usuario activo con ese email'}), 404

        # Verificar que el cónyuge no tenga ya un cónyuge vinculado
        if spouse_user.spouse_user_id:
            return jsonify({'error': 'El usuario ya tiene un cónyuge vinculado'}), 409

        # Verificar que el usuario actual no tenga ya un cónyuge vinculado
        if current_user.spouse_user_id:
            return jsonify({'error': 'Ya tienes un cónyuge vinculado'}), 409

        # Verificar si ya existe una notificación pendiente de este usuario a ese destinatario
        existing_notification = Notification.query.filter_by(
            sender_user_id=current_user.id,
            recipient_user_id=spouse_user.id,
            type='spouse_request',
            status='pending'
        ).first()

        if existing_notification:
            return jsonify({'error': 'Ya has enviado una solicitud a este usuario que está pendiente'}), 409

        # Crear notificación de solicitud de cónyuge
        spouse_notification = Notification(
            recipient_user_id=spouse_user.id,
            sender_user_id=current_user.id,
            type='spouse_request',
            title='Solicitud de vinculación como cónyuge',
            message=f'{current_user.username} ({current_user.email}) quiere vincularte como cónyuge',
            data={
                'sender_email': current_user.email,
                'sender_username': current_user.username,
                'sender_id': current_user.id
            }
        )

        # Crear notificación de compartir información de hijos
        children_notification = create_children_sharing_request(
            recipient_user_id=spouse_user.id,
            sender_user_id=current_user.id,
            sender_username=current_user.username
        )

        db.session.add(spouse_notification)
        db.session.commit()

        return jsonify({
            'message': 'Solicitudes enviadas exitosamente: vinculación como cónyuge y compartir información familiar',
            'notifications': {
                'spouse_request': {
                    'recipient_email': spouse_user.email,
                    'recipient_username': spouse_user.username,
                    'status': 'pending'
                },
                'children_sharing': {
                    'recipient_email': spouse_user.email,
                    'recipient_username': spouse_user.username,
                    'status': 'pending'
                }
            }
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error linking spouse: {e}")
        return jsonify({'error': 'Error al vincular cónyuge'}), 500

@app.route('/unlink-spouse', methods=['POST'])
@token_required
def unlink_spouse(current_user):
    """Desvincular cónyuge"""
    try:
        if not current_user.spouse_user_id:
            return jsonify({'error': 'No tienes un cónyuge vinculado'}), 404

        # Obtener el cónyuge actual
        spouse_user = User.query.get(current_user.spouse_user_id)

        # Remover la vinculación bidireccional
        current_user.spouse_user_id = None
        if spouse_user:
            spouse_user.spouse_user_id = None

        db.session.commit()

        return jsonify({'message': 'Cónyuge desvinculado exitosamente'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unlinking spouse: {e}")
        return jsonify({'error': 'Error al desvincular cónyuge'}), 500

@app.route('/spouse-info', methods=['GET'])
@token_required
def get_spouse_info(current_user):
    """Obtener información del cónyuge vinculado"""
    try:
        if not current_user.spouse_user_id:
            return jsonify({'spouse': None}), 200

        spouse_user = User.query.get(current_user.spouse_user_id)

        if not spouse_user or not spouse_user.is_active:
            # Si el cónyuge no existe o está inactivo, limpiar la vinculación
            current_user.spouse_user_id = None
            db.session.commit()
            return jsonify({'spouse': None}), 200

        return jsonify({
            'spouse': {
                'id': spouse_user.id,
                'email': spouse_user.email,
                'username': spouse_user.username,
                'profile_image_url': spouse_user.profile_image_url
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting spouse info: {e}")
        return jsonify({'error': 'Error al obtener información del cónyuge'}), 500

# --------------------------------------------------------------------
#                     ENDPOINTS PARA GESTIÓN DE NOTIFICACIONES
# --------------------------------------------------------------------

@app.route('/notifications', methods=['GET'])
@token_required
def get_notifications(current_user):
    """Obtener todas las notificaciones del usuario actual"""
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 20))
        unread_only = request.args.get('unread_only', 'false').lower() == 'true'

        query = Notification.query.filter_by(recipient_user_id=current_user.id)

        if unread_only:
            query = query.filter_by(is_read=False)

        # Ordenar por fecha de creación (más recientes primero)
        query = query.order_by(Notification.created_at.desc())

        notifications = query.paginate(page=page, per_page=per_page, error_out=False)

        notifications_data = []
        for notification in notifications.items:
            sender_info = None
            if notification.sender_user_id:
                sender = User.query.get(notification.sender_user_id)
                if sender:
                    sender_info = {
                        'id': sender.id,
                        'username': sender.username,
                        'email': sender.email,
                        'profile_image_url': sender.profile_image_url
                    }

            notifications_data.append({
                'id': notification.id,
                'type': notification.type,
                'title': notification.title,
                'message': notification.message,
                'data': notification.data,
                'status': notification.status,
                'is_read': notification.is_read,
                'created_at': notification.created_at.isoformat(),
                'updated_at': notification.updated_at.isoformat() if notification.updated_at else None,
                'expires_at': notification.expires_at.isoformat() if notification.expires_at else None,
                'sender': sender_info
            })

        return jsonify({
            'notifications': notifications_data,
            'pagination': {
                'page': notifications.page,
                'pages': notifications.pages,
                'per_page': notifications.per_page,
                'total': notifications.total,
                'has_next': notifications.has_next,
                'has_prev': notifications.has_prev
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting notifications: {e}")
        return jsonify({'error': 'Error al obtener notificaciones'}), 500

@app.route('/notifications/count', methods=['GET'])
@token_required
def get_notifications_count(current_user):
    """Obtener contador de notificaciones no leídas"""
    try:
        # Usar SQL directo para compatibilidad con la tabla real
        unread_result = db.session.execute(
            db.text('''
                SELECT COUNT(*) as count
                FROM notification
                WHERE recipient_user_id = :user_id AND is_read = 0
            '''),
            {'user_id': current_user.id}
        ).fetchone()

        pending_result = db.session.execute(
            db.text('''
                SELECT COUNT(*) as count
                FROM notification
                WHERE recipient_user_id = :user_id AND status = 'pending'
            '''),
            {'user_id': current_user.id}
        ).fetchone()

        return jsonify({
            'unread_count': unread_result.count if unread_result else 0,
            'pending_count': pending_result.count if pending_result else 0
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting notifications count: {e}")
        return jsonify({'error': 'Error al obtener contador de notificaciones'}), 500

@app.route('/notifications/<int:notification_id>/read', methods=['POST'])
@token_required
def mark_notification_read(current_user, notification_id):
    """Marcar una notificación como leída"""
    try:
        notification = Notification.query.filter_by(
            id=notification_id,
            recipient_user_id=current_user.id
        ).first()

        if not notification:
            return jsonify({'error': 'Notificación no encontrada'}), 404

        notification.is_read = True
        db.session.commit()

        # WebSocket deshabilitado temporalmente
        # try:
        #     unread_count = Notification.query.filter_by(
        #         recipient_user_id=current_user.id,
        #         is_read=False
        #     ).count()
        #     broadcast_notification_count_update(current_user.id, unread_count)
        # except Exception as ws_error:
        #     app.logger.error(f"Error actualizando contador via WebSocket: {ws_error}")

        return jsonify({'message': 'Notificación marcada como leída'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking notification as read: {e}")
        return jsonify({'error': 'Error al marcar notificación como leída'}), 500

@app.route('/notifications/<int:notification_id>/respond', methods=['POST'])
@token_required
def respond_to_notification(current_user, notification_id):
    """Responder a una notificación (aceptar/rechazar)"""
    try:
        data = request.get_json()
        action = data.get('action')  # 'accept' o 'reject'

        if action not in ['accept', 'reject']:
            return jsonify({'error': 'Acción inválida. Use "accept" o "reject"'}), 400

        notification = Notification.query.filter_by(
            id=notification_id,
            recipient_user_id=current_user.id
        ).first()

        if not notification:
            return jsonify({'error': 'Notificación no encontrada'}), 404

        if notification.status != 'pending':
            return jsonify({'error': 'Esta notificación ya fue procesada'}), 400

        # Procesar según el tipo de notificación
        if notification.type == 'spouse_request':
            return handle_spouse_request_response(notification, current_user, action)
        elif notification.type == 'channel_invite':
            return handle_channel_invitation_response(notification, current_user, action)
        elif notification.type == 'friend_request':
            return handle_friend_request_response(notification, current_user, action)
        elif notification.type == 'event_invite':
            return handle_event_invitation_response(notification, current_user, action)
        elif notification.type == 'children_sharing_request':
            return handle_children_sharing_response(notification, current_user, action)
        elif notification.type == 'follow_request':
            return handle_follow_request_response(notification, current_user, action)
        else:
            return jsonify({'error': 'Tipo de notificación no soportado'}), 400

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error responding to notification: {e}")
        return jsonify({'error': 'Error al responder notificación'}), 500

def handle_spouse_request_response(notification, current_user, action):
    """Manejar respuesta a solicitud de cónyuge"""
    try:
        sender_user_id = notification.sender_user_id
        sender_user = User.query.get(sender_user_id)

        if not sender_user:
            return jsonify({'error': 'Usuario solicitante no encontrado'}), 404

        if action == 'accept':
            # Verificar que ambos usuarios no tengan ya cónyuge
            if current_user.spouse_user_id:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'Ya tienes un cónyuge vinculado'}), 409

            if sender_user.spouse_user_id:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'El solicitante ya tiene un cónyuge vinculado'}), 409

            # Crear la vinculación bidireccional
            current_user.spouse_user_id = sender_user.id
            sender_user.spouse_user_id = current_user.id
            notification.status = 'accepted'

            message = f'Solicitud de cónyuge aceptada exitosamente'
        else:
            notification.status = 'rejected'
            message = f'Solicitud de cónyuge rechazada'

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'message': message,
            'status': notification.status
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

# --------------------------------------------------------------------
#                    NOTIFICATION HELPER FUNCTIONS
# --------------------------------------------------------------------

def create_notification(recipient_user_id, notification_type, title, message, sender_user_id=None, data=None):
    """
    Helper genérico para crear notificaciones
    """
    try:
        notification = Notification(
            recipient_user_id=recipient_user_id,
            sender_user_id=sender_user_id,
            type=notification_type,
            title=title,
            message=message,
            data=data,
            status='pending'
        )
        db.session.add(notification)
        db.session.commit()

        # 🔥 WEBSOCKET: Enviar notificación en tiempo real
        try:
            # Obtener información del sender para el WebSocket
            sender_info = None
            if sender_user_id:
                sender = User.query.get(sender_user_id)
                if sender:
                    sender_info = {
                        'id': sender.id,
                        'username': sender.username,
                        'email': sender.email
                    }

            notification_data = {
                'id': notification.id,
                'notification_type': notification.type,
                'type': notification.type,
                'title': notification.title,
                'message': notification.message,
                'data': notification.data,
                'status': notification.status,
                'is_read': notification.is_read,
                'created_at': notification.created_at.isoformat(),
                'sender': sender_info
            }

            # Enviar notificación via WebSocket
            emit_notification_to_user(recipient_user_id, notification_data)

            # Actualizar contador de notificaciones no leídas
            unread_count = Notification.query.filter_by(
                recipient_user_id=recipient_user_id,
                is_read=False
            ).count()
            broadcast_notification_count_update(recipient_user_id, unread_count)

        except Exception as ws_error:
            app.logger.error(f"Error enviando WebSocket notification: {ws_error}")
            # No fallar la creación de notificación si el WebSocket falla

        return notification
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating notification: {e}")
        raise e

def create_channel_invitation(recipient_user_id, sender_user_id, channel_id, channel_name):
    """
    Crear notificación de invitación a canal
    """
    title = f"Invitación a canal"
    message = f"Te han invitado a unirte al canal '{channel_name}'"
    data = {
        'channel_id': channel_id,
        'channel_name': channel_name,
        'action_type': 'channel_join'
    }
    return create_notification(
        recipient_user_id=recipient_user_id,
        notification_type='channel_invite',
        title=title,
        message=message,
        sender_user_id=sender_user_id,
        data=data
    )

def create_friend_request(recipient_user_id, sender_user_id, sender_username):
    """
    Crear notificación de solicitud de amistad
    """
    title = f"Solicitud de amistad"
    message = f"{sender_username} quiere ser tu amigo/a"
    data = {
        'sender_user_id': sender_user_id,
        'sender_username': sender_username,
        'action_type': 'friend_request'
    }
    return create_notification(
        recipient_user_id=recipient_user_id,
        notification_type='friend_request',
        title=title,
        message=message,
        sender_user_id=sender_user_id,
        data=data
    )

def create_system_notification(recipient_user_id, title, message, notification_subtype=None):
    """
    Crear notificación del sistema
    """
    data = {
        'subtype': notification_subtype,
        'action_type': 'system_info'
    }
    return create_notification(
        recipient_user_id=recipient_user_id,
        notification_type='system_notification',
        title=title,
        message=message,
        sender_user_id=None,
        data=data
    )

def create_event_invitation(recipient_user_id, sender_user_id, event_id, event_title, event_date):
    """
    Crear notificación de invitación a evento
    """
    title = f"Invitación a evento"
    message = f"Te han invitado al evento '{event_title}'"
    data = {
        'event_id': event_id,
        'event_title': event_title,
        'event_date': event_date,
        'action_type': 'event_join'
    }
    return create_notification(
        recipient_user_id=recipient_user_id,
        notification_type='event_invite',
        title=title,
        message=message,
        sender_user_id=sender_user_id,
        data=data
    )

def create_children_sharing_request(recipient_user_id, sender_user_id, sender_username):
    """
    Crear notificación para compartir información de hijos
    """
    title = f"Compartir información familiar"
    message = f"{sender_username} quiere compartir información de los hijos contigo. Si aceptas, podrás ver sus hijos y él/ella podrá ver los tuyos."
    data = {
        'sender_user_id': sender_user_id,
        'sender_username': sender_username,
        'action_type': 'children_sharing'
    }
    return create_notification(
        recipient_user_id=recipient_user_id,
        notification_type='children_sharing_request',
        title=title,
        message=message,
        sender_user_id=sender_user_id,
        data=data
    )

def handle_channel_invitation_response(notification, current_user, action):
    """Manejar respuesta a invitación de canal"""
    try:
        channel_id = notification.data.get('channel_id') if notification.data else None
        if not channel_id:
            return jsonify({'error': 'Datos de canal no encontrados'}), 400

        channel = Channel.query.filter_by(id_code=channel_id).first()
        if not channel:
            return jsonify({'error': 'Canal no encontrado'}), 404

        if action == 'accept':
            # Verificar si ya es miembro
            existing_member = ChannelMember.query.filter_by(
                channel_id=channel.id,
                user_id=current_user.id
            ).first()

            if existing_member:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'Ya eres miembro de este canal'}), 409

            # Crear membresía
            new_member = ChannelMember(
                channel_id=channel.id,
                user_id=current_user.id,
                role='member',
                joined_at=datetime.utcnow()
            )
            db.session.add(new_member)
            notification.status = 'accepted'
            message = f'Te has unido al canal "{channel.name}" exitosamente'
        else:
            notification.status = 'rejected'
            message = f'Invitación al canal rechazada'

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'message': message,
            'status': notification.status
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

def handle_friend_request_response(notification, current_user, action):
    """Manejar respuesta a solicitud de amistad"""
    try:
        sender_user_id = notification.sender_user_id
        sender_user = User.query.get(sender_user_id)

        if not sender_user:
            return jsonify({'error': 'Usuario solicitante no encontrado'}), 404

        if action == 'accept':
            # Verificar si ya son amigos
            existing_friendship = Friendship.query.filter(
                ((Friendship.user_id == current_user.id) & (Friendship.friend_id == sender_user.id)) |
                ((Friendship.user_id == sender_user.id) & (Friendship.friend_id == current_user.id))
            ).first()

            if existing_friendship:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'Ya son amigos'}), 409

            # Crear amistad bidireccional
            friendship1 = Friendship(
                user_id=current_user.id,
                friend_id=sender_user.id,
                created_at=datetime.utcnow()
            )
            friendship2 = Friendship(
                user_id=sender_user.id,
                friend_id=current_user.id,
                created_at=datetime.utcnow()
            )

            db.session.add(friendship1)
            db.session.add(friendship2)
            notification.status = 'accepted'
            message = f'Ahora eres amigo/a de {sender_user.username}'
        else:
            notification.status = 'rejected'
            message = f'Solicitud de amistad rechazada'

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'message': message,
            'status': notification.status
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

def handle_event_invitation_response(notification, current_user, action):
    """Manejar respuesta a invitación de evento"""
    try:
        event_id = notification.data.get('event_id') if notification.data else None
        if not event_id:
            return jsonify({'error': 'Datos de evento no encontrados'}), 400

        # Buscar evento en los posts (asumiendo que los eventos son posts)
        event_post = Post.query.get(event_id)
        if not event_post:
            return jsonify({'error': 'Evento no encontrado'}), 404

        if action == 'accept':
            # Verificar si ya está registrado
            existing_registration = CalendarEventRegistration.query.filter_by(
                event_id=event_id,
                user_id=current_user.id
            ).first()

            if existing_registration:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'Ya estás registrado en este evento'}), 409

            # Crear registro en el evento
            registration = CalendarEventRegistration(
                event_id=event_id,
                user_id=current_user.id
            )
            db.session.add(registration)
            notification.status = 'accepted'
            event_title = notification.data.get('event_title', 'el evento')
            message = f'Te has registrado en "{event_title}" exitosamente'
        else:
            notification.status = 'rejected'
            message = f'Invitación al evento rechazada'

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'message': message,
            'status': notification.status
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

def handle_children_sharing_response(notification, current_user, action):
    """Manejar respuesta a solicitud de compartir información de hijos"""
    try:
        sender_user_id = notification.sender_user_id
        sender_user = User.query.get(sender_user_id)

        if not sender_user:
            return jsonify({'error': 'Usuario solicitante no encontrado'}), 404

        if action == 'accept':
            # Verificar que ambos usuarios sean cónyuges
            if current_user.spouse_user_id != sender_user.id or sender_user.spouse_user_id != current_user.id:
                notification.status = 'rejected'
                notification.is_read = True
                db.session.commit()
                return jsonify({'error': 'Solo se puede compartir información de hijos con el cónyuge'}), 400

            # Establecer permisos de compartir hijos bidireccional
            current_user.shares_children_with_spouse = True
            sender_user.shares_children_with_spouse = True

            notification.status = 'accepted'
            message = f'Ahora compartes información familiar con {sender_user.username}. Podrán ver los hijos del otro.'
        else:
            notification.status = 'rejected'
            message = f'Solicitud de compartir información familiar rechazada'

        notification.is_read = True
        db.session.commit()

        return jsonify({
            'message': message,
            'status': notification.status
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

def handle_follow_request_response(notification, current_user, action):
    """Manejar respuesta a solicitud de seguimiento"""
    try:
        # Obtener datos de la notificación usando la estructura correcta
        data = safe_json_load(notification.data, {})
        follower_id = data.get('follower_id')

        if not follower_id:
            return jsonify({'error': 'Datos de notificación inválidos'}), 400

        # Buscar la solicitud de seguimiento
        follow_request = UserFollow.query.filter_by(
            follower_id=follower_id,
            following_id=current_user.id,
            status='pending'
        ).first()

        if not follow_request:
            # Actualizar usando SQL directo para compatibilidad
            db.session.execute(
                db.text('UPDATE notification SET status = :status, is_read = 1 WHERE id = :id'),
                {'status': 'processed', 'id': notification.id}
            )
            db.session.commit()
            return jsonify({'error': 'Solicitud de seguimiento no encontrada'}), 404

        follower_user = User.query.get(follower_id)
        if not follower_user:
            return jsonify({'error': 'Usuario solicitante no encontrado'}), 404

        if action == 'accept':
            # Aceptar la solicitud de seguimiento
            follow_request.status = 'accepted'
            follow_request.updated_at = datetime.utcnow()

            # Actualizar notificación usando SQL directo
            db.session.execute(
                db.text('UPDATE notification SET status = :status, is_read = 1 WHERE id = :id'),
                {'status': 'accepted', 'id': notification.id}
            )

            message = f'Has aceptado la solicitud de seguimiento de {follower_user.username}'

            # Crear notificación para el usuario que envió la solicitud usando SQL directo
            db.session.execute(
                db.text('''
                    INSERT INTO notification
                    (recipient_user_id, sender_user_id, type, title, message, data, status, is_read, created_at, updated_at)
                    VALUES (:recipient_id, :sender_id, :type, :title, :message, :data, :status, :is_read, NOW(), NOW())
                '''),
                {
                    'recipient_id': follower_id,
                    'sender_id': current_user.id,
                    'type': 'follow_accepted',
                    'title': 'Solicitud aceptada',
                    'message': f'{current_user.username} ha aceptado tu solicitud de seguimiento',
                    'data': json.dumps({
                        'following_id': current_user.id,
                        'following_username': current_user.username,
                        'following_image': current_user.profile_image_url
                    }),
                    'status': 'pending',
                    'is_read': 0
                }
            )
        else:
            # Rechazar la solicitud de seguimiento
            follow_request.status = 'rejected'
            follow_request.updated_at = datetime.utcnow()

            # Actualizar notificación usando SQL directo
            db.session.execute(
                db.text('UPDATE notification SET status = :status, is_read = 1 WHERE id = :id'),
                {'status': 'rejected', 'id': notification.id}
            )

            message = f'Has rechazado la solicitud de seguimiento de {follower_user.username}'

            # No enviamos notificación cuando se rechaza (según especificaciones)

        db.session.commit()

        return jsonify({
            'message': message,
            'status': action + 'ed'  # 'accepted' or 'rejected'
        }), 200

    except Exception as e:
        db.session.rollback()
        raise e

@app.route('/notifications/mark-all-read', methods=['POST'])
@token_required
def mark_all_notifications_read(current_user):
    """Marcar todas las notificaciones como leídas"""
    try:
        Notification.query.filter_by(
            recipient_user_id=current_user.id,
            is_read=False
        ).update({'is_read': True})

        db.session.commit()

        return jsonify({'message': 'Todas las notificaciones marcadas como leídas'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking all notifications as read: {e}")
        return jsonify({'error': 'Error al marcar todas las notificaciones como leídas'}), 500

# ============================================================================
#                    SERVICIO DE RECUPERACIÓN DE SOLICITUDES PENDIENTES
# ============================================================================

@app.route('/admin/recover-pending-requests', methods=['POST'])
@token_required
def recover_pending_requests(current_user):
    """
    Servicio para recuperar y procesar solicitudes pendientes que se quedaron colgadas
    - Encuentra follow requests sin notificación correspondiente
    - Reenvía notificaciones que no llegaron
    - Corrige estados inconsistentes
    """
    try:
        # Solo permitir a superadmins ejecutar este servicio
        if not superadmin_permission.can():
            return jsonify({'error': 'Solo los superadministradores pueden ejecutar este servicio'}), 403

        recovery_report = {
            'missing_notifications_created': 0,
            'inconsistent_states_fixed': 0,
            'old_notifications_cleaned': 0,
            'follow_requests_processed': 0,
            'errors': []
        }

        # 1. Encontrar follow requests pendientes sin notificación correspondiente
        orphaned_follows = db.session.execute(
            db.text('''
                SELECT uf.id, uf.follower_id, uf.following_id, uf.created_at, uf.updated_at,
                       follower.username as follower_username,
                       following.username as following_username
                FROM user_follows uf
                JOIN users follower ON uf.follower_id = follower.id
                JOIN users following ON uf.following_id = following.id
                LEFT JOIN notification n ON (
                    n.sender_user_id = uf.follower_id
                    AND n.recipient_user_id = uf.following_id
                    AND n.type = 'follow_request'
                    AND n.status = 'pending'
                )
                WHERE uf.status = 'pending'
                AND n.id IS NULL
                AND uf.created_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''')
        ).fetchall()

        # 2. Crear notificaciones faltantes para follow requests pendientes
        for follow in orphaned_follows:
            try:
                db.session.execute(
                    db.text('''
                        INSERT INTO notification
                        (recipient_user_id, sender_user_id, type, title, message, data, status, is_read, created_at, updated_at)
                        VALUES (:recipient_id, :sender_id, :type, :title, :message, :data, :status, :is_read, NOW(), NOW())
                    '''),
                    {
                        'recipient_id': follow.following_id,
                        'sender_id': follow.follower_id,
                        'type': 'follow_request',
                        'title': 'Nueva solicitud de seguimiento (Recuperada)',
                        'message': f'{follow.follower_username} quiere seguirte',
                        'data': json.dumps({
                            'follower_id': follow.follower_id,
                            'follower_username': follow.follower_username,
                            'recovery': True,
                            'original_date': follow.created_at.isoformat() if follow.created_at else None
                        }),
                        'status': 'pending',
                        'is_read': 0
                    }
                )
                recovery_report['missing_notifications_created'] += 1
                recovery_report['follow_requests_processed'] += 1
            except Exception as e:
                recovery_report['errors'].append(f'Error creating notification for follow {follow.id}: {str(e)}')

        # 3. Limpiar notificaciones muy antiguas que quedaron pendientes (más de 30 días)
        old_notifications = db.session.execute(
            db.text('''
                DELETE FROM notification
                WHERE type = 'follow_request'
                AND status = 'pending'
                AND created_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
            ''')
        )
        recovery_report['old_notifications_cleaned'] = old_notifications.rowcount

        # 4. Encontrar y corregir estados inconsistentes
        # Follow requests aceptados pero sin notificación de aceptación
        inconsistent_accepts = db.session.execute(
            db.text('''
                SELECT uf.id, uf.follower_id, uf.following_id,
                       follower.username as follower_username,
                       following.username as following_username
                FROM user_follows uf
                JOIN users follower ON uf.follower_id = follower.id
                JOIN users following ON uf.following_id = following.id
                LEFT JOIN notification n ON (
                    n.sender_user_id = uf.following_id
                    AND n.recipient_user_id = uf.follower_id
                    AND n.type = 'follow_accepted'
                )
                WHERE uf.status = 'accepted'
                AND n.id IS NULL
                AND uf.updated_at > DATE_SUB(NOW(), INTERVAL 7 DAY)
            ''')
        ).fetchall()

        # Crear notificaciones de aceptación faltantes
        for follow in inconsistent_accepts:
            try:
                db.session.execute(
                    db.text('''
                        INSERT INTO notification
                        (recipient_user_id, sender_user_id, type, title, message, data, status, is_read, created_at, updated_at)
                        VALUES (:recipient_id, :sender_id, :type, :title, :message, :data, :status, :is_read, NOW(), NOW())
                    '''),
                    {
                        'recipient_id': follow.follower_id,
                        'sender_id': follow.following_id,
                        'type': 'follow_accepted',
                        'title': 'Solicitud aceptada (Recuperada)',
                        'message': f'{follow.following_username} ha aceptado tu solicitud de seguimiento',
                        'data': json.dumps({
                            'following_id': follow.following_id,
                            'following_username': follow.following_username,
                            'recovery': True
                        }),
                        'status': 'pending',
                        'is_read': 0
                    }
                )
                recovery_report['inconsistent_states_fixed'] += 1
            except Exception as e:
                recovery_report['errors'].append(f'Error creating acceptance notification for follow {follow.id}: {str(e)}')

        # 5. Marcar notificaciones de follow_request como procesadas si el follow ya fue aceptado/rechazado
        processed_notifications = db.session.execute(
            db.text('''
                UPDATE notification n
                JOIN user_follows uf ON (
                    n.sender_user_id = uf.follower_id
                    AND n.recipient_user_id = uf.following_id
                )
                SET n.status = uf.status, n.is_read = 1
                WHERE n.type = 'follow_request'
                AND n.status = 'pending'
                AND uf.status IN ('accepted', 'rejected')
            ''')
        )
        recovery_report['inconsistent_states_fixed'] += processed_notifications.rowcount

        db.session.commit()

        return jsonify({
            'message': 'Servicio de recuperación ejecutado exitosamente',
            'report': recovery_report
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error in recovery service: {e}")
        return jsonify({'error': f'Error en servicio de recuperación: {str(e)}'}), 500

@app.route('/admin/pending-requests-status', methods=['GET'])
@token_required
def get_pending_requests_status(current_user):
    """
    Obtener estadísticas de solicitudes pendientes para monitoreo
    """
    try:
        # Solo permitir a superadmins ver estas estadísticas
        if not superadmin_permission.can():
            return jsonify({'error': 'Solo los superadministradores pueden ver estas estadísticas'}), 403

        # Estadísticas de follow requests
        follow_stats = db.session.execute(
            db.text('''
                SELECT
                    COUNT(*) as total_pending,
                    COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as pending_last_24h,
                    COUNT(CASE WHEN created_at < DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as pending_over_week
                FROM user_follows
                WHERE status = 'pending'
            ''')
        ).fetchone()

        # Estadísticas de notificaciones
        notification_stats = db.session.execute(
            db.text('''
                SELECT
                    COUNT(*) as total_pending,
                    COUNT(CASE WHEN created_at > DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as pending_last_24h,
                    COUNT(CASE WHEN created_at < DATE_SUB(NOW(), INTERVAL 7 DAY) THEN 1 END) as pending_over_week
                FROM notification
                WHERE type = 'follow_request' AND status = 'pending'
            ''')
        ).fetchone()

        # Follow requests sin notificación
        orphaned_count = db.session.execute(
            db.text('''
                SELECT COUNT(*) as count
                FROM user_follows uf
                LEFT JOIN notification n ON (
                    n.sender_user_id = uf.follower_id
                    AND n.recipient_user_id = uf.following_id
                    AND n.type = 'follow_request'
                )
                WHERE uf.status = 'pending' AND n.id IS NULL
            ''')
        ).fetchone()

        return jsonify({
            'follow_requests': {
                'total_pending': follow_stats.total_pending,
                'pending_last_24h': follow_stats.pending_last_24h,
                'pending_over_week': follow_stats.pending_over_week
            },
            'notifications': {
                'total_pending': notification_stats.total_pending,
                'pending_last_24h': notification_stats.pending_last_24h,
                'pending_over_week': notification_stats.pending_over_week
            },
            'orphaned_requests': orphaned_count.count,
            'needs_recovery': orphaned_count.count > 0 or follow_stats.pending_over_week > 0
        }), 200

    except Exception as e:
        app.logger.error(f"Error getting pending requests status: {e}")
        return jsonify({'error': f'Error obteniendo estadísticas: {str(e)}'}), 500

@app.route('/upload-profile-background', methods=['POST'])
@token_required
def upload_profile_background(current_user):
    """
    Endpoint para subir imagen personalizada de fondo de perfil
    """
    try:
        # Verificar que se envió un archivo
        if 'file' not in request.files:
            return jsonify({'error': 'No se encontró ningún archivo'}), 400

        file = request.files['file']

        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400

        # Verificar que es una imagen
        if not file.content_type.startswith('image/'):
            return jsonify({'error': 'El archivo debe ser una imagen'}), 400

        # Generar nombre único para el archivo
        file_extension = secure_filename(file.filename).split('.')[-1]
        unique_filename = f"profile_bg_{current_user.id}_{int(time.time())}.{file_extension}"

        try:
            # Subir a S3
            s3.upload_fileobj(
                file,
                S3_BUCKET,
                f"profile-backgrounds/{unique_filename}",
                ExtraArgs={
                    'ContentType': file.content_type,
                    'ACL': 'public-read'
                }
            )

            # Generar URL de S3
            image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/profile-backgrounds/{unique_filename}"

            app.logger.info(f"Profile background uploaded for user {current_user.id}: {image_url}")

            return jsonify({
                'message': 'Imagen de fondo subida exitosamente',
                'image_url': image_url
            }), 200

        except Exception as s3_error:
            app.logger.error(f"Error uploading to S3: {s3_error}")
            return jsonify({'error': 'Error al subir la imagen al servidor'}), 500

    except Exception as e:
        app.logger.error(f"Error in upload_profile_background: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
# Endpoint para subir imagen de perfil de usuario
# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————
# ——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————

@app.route('/upload-profile-image', methods=['POST'])
@token_required
def upload_profile_image(current_user):
    """
    Endpoint para subir imagen de perfil de usuario
    """
    try:
        # Verificar que se envió un archivo
        if 'file' not in request.files:
            return jsonify({'error': 'No se encontró ningún archivo'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400

        # Verificar que es una imagen
        if not file.content_type.startswith('image/'):
            return jsonify({'error': 'El archivo debe ser una imagen'}), 400

        # Generar nombre único para el archivo
        file_extension = secure_filename(file.filename).split('.')[-1]
        unique_filename = f"profile_{current_user.id}_{int(time.time())}.{file_extension}"

        try:
            # Subir a S3
            s3.upload_fileobj(
                file,
                S3_BUCKET,
                f"profile-images/{unique_filename}",
                ExtraArgs={
                    'ContentType': file.content_type,
                    'ACL': 'public-read'
                }
            )

            # Generar URL de S3
            image_url = f"https://{S3_BUCKET}.s3.{S3_REGION}.amazonaws.com/profile-images/{unique_filename}"

            # Actualizar el campo profile_image_url del usuario
            current_user.profile_image_url = image_url
            db.session.commit()

            app.logger.info(f"Profile image uploaded for user {current_user.id}: {image_url}")

            return jsonify({
                'message': 'Imagen de perfil subida exitosamente',
                'profile_image_url': image_url
            }), 200

        except Exception as s3_error:
            app.logger.error(f"Error uploading profile image to S3: {s3_error}")
            return jsonify({'error': 'Error al subir la imagen al servidor'}), 500

    except Exception as e:
        app.logger.error(f"Error in upload_profile_image: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# --------------------------------------------------------------------
#                     REACCIONES DEL CALENDARIO
# --------------------------------------------------------------------

@app.route('/calendar-events/react', methods=['POST'])
@token_required
def react_to_calendar_event(current_user):
    """Endpoint para que los usuarios reaccionen a eventos del calendario"""
    try:
        current_user_id = current_user.id
        data = request.get_json()

        event_id = data.get('eventId')
        reaction_type = data.get('reactionType')  # 'heart', 'pray', 'comment'

        if not event_id or not reaction_type:
            return jsonify({'success': False, 'error': 'eventId y reactionType son requeridos'}), 400

        if reaction_type not in ['heart', 'pray', 'comment']:
            return jsonify({'success': False, 'error': 'Tipo de reacción inválido'}), 400

        # Verificar si ya existe una reacción del usuario para este evento
        existing_reaction = db.session.query(CalendarReaction).filter_by(
            user_id=current_user_id,
            event_id=event_id
        ).first()

        if existing_reaction:
            if existing_reaction.reaction_type == reaction_type:
                # Si es la misma reacción, eliminarla (toggle)
                db.session.delete(existing_reaction)
                db.session.commit()

                return jsonify({
                    'success': True,
                    'message': f'Reacción {reaction_type} eliminada correctamente',
                    'action': 'removed',
                    'reaction': {
                        'event_id': event_id,
                        'reaction_type': None,
                        'user_id': current_user_id
                    }
                })
            else:
                # Si es una reacción diferente, actualizarla
                existing_reaction.reaction_type = reaction_type
                existing_reaction.created_at = datetime.utcnow()
                action = 'updated'
        else:
            # Crear nueva reacción
            new_reaction = CalendarReaction(
                user_id=current_user_id,
                event_id=event_id,
                reaction_type=reaction_type,
                created_at=datetime.utcnow()
            )
            db.session.add(new_reaction)
            action = 'added'

        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Reacción {reaction_type} registrada correctamente',
            'action': action,
            'reaction': {
                'event_id': event_id,
                'reaction_type': reaction_type,
                'user_id': current_user_id
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error en react_to_calendar_event: {str(e)}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/comment', methods=['POST'])
@token_required
def comment_calendar_event(current_user):
    """Endpoint para que los usuarios comenten eventos del calendario"""
    try:
        current_user_id = current_user.id
        data = request.get_json()

        event_id = data.get('eventId')
        comment_text = data.get('comment', '').strip()

        if not event_id or not comment_text:
            return jsonify({'success': False, 'error': 'eventId y comment son requeridos'}), 400

        if len(comment_text) > 500:  # Límite de caracteres
            return jsonify({'success': False, 'error': 'El comentario es demasiado largo (máximo 500 caracteres)'}), 400

        # Primero registrar la reacción de comentario
        existing_reaction = db.session.query(CalendarReaction).filter_by(
            user_id=current_user_id,
            event_id=event_id
        ).first()

        if existing_reaction:
            existing_reaction.reaction_type = 'comment'
            existing_reaction.created_at = datetime.utcnow()
        else:
            new_reaction = CalendarReaction(
                user_id=current_user_id,
                event_id=event_id,
                reaction_type='comment',
                created_at=datetime.utcnow()
            )
            db.session.add(new_reaction)

        # Luego agregar el comentario
        new_comment = CalendarComment(
            user_id=current_user_id,
            event_id=event_id,
            comment_text=comment_text,
            created_at=datetime.utcnow()
        )
        db.session.add(new_comment)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Comentario agregado correctamente',
            'comment': {
                'event_id': event_id,
                'comment_text': comment_text,
                'user_id': current_user_id
            }
        })

    except Exception as e:
        db.session.rollback()
        print(f"❌ Error en comment_calendar_event: {str(e)}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/reactions/<string:event_id>', methods=['GET'])
@token_required
def get_calendar_event_reactions(current_user, event_id):
    """Obtener todas las reacciones de un evento específico"""
    try:
        current_user_id = current_user.id

        # Obtener reacciones del evento
        reactions = db.session.query(CalendarReaction).filter_by(event_id=event_id).all()

        # Contar por tipo de reacción
        reaction_counts = {
            'heart': 0,
            'pray': 0,
            'comment': 0,
            'total': 0
        }

        user_reaction = None

        for reaction in reactions:
            reaction_counts[reaction.reaction_type] += 1
            reaction_counts['total'] += 1

            if reaction.user_id == current_user_id:
                user_reaction = reaction.reaction_type

        # Obtener comentarios si los hay
        comments = []
        if reaction_counts['comment'] > 0:
            comment_records = db.session.query(CalendarComment).filter_by(event_id=event_id).order_by(CalendarComment.created_at.desc()).limit(10).all()

            for comment in comment_records:
                user = db.session.query(User).filter_by(id=comment.user_id).first()
                comments.append({
                    'id': comment.id,
                    'user_name': user.username if user else 'Usuario desconocido',
                    'comment_text': comment.comment_text,
                    'created_at': comment.created_at.isoformat()
                })

        return jsonify({
            'success': True,
            'event_id': event_id,
            'reaction_counts': reaction_counts,
            'user_reaction': user_reaction,
            'comments': comments
        })

    except Exception as e:
        print(f"❌ Error en get_calendar_event_reactions: {str(e)}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/register', methods=['POST'])
@token_required
def register_for_calendar_event(current_user):
    """Endpoint para registrarse en un evento del calendario"""
    try:
        data = request.get_json()
        # Support both eventId and event_id
        event_id = data.get('event_id') or data.get('eventId')
        installments = data.get('installments', 1)
        total_price = data.get('total_price') or data.get('totalPrice') or '0.00'
        installment_amount = data.get('installment_amount') or data.get('installmentAmount') or '0.00'
        payment_option = data.get('payment_option', 'full')
        include_user = data.get('include_user', True)
        family_members = data.get('family_members', [])
        total_attendees = data.get('total_attendees', 1)

        if not event_id:
            return jsonify({'error': 'event_id es requerido'}), 400

        # Verificar que el evento existe (intentar primero con id, luego con id_code)
        event = CalendarEvent.query.filter_by(id=event_id).first()
        if not event:
            event = CalendarEvent.query.filter_by(id_code=event_id).first()
            if not event:
                return jsonify({'error': f'Evento no encontrado: {event_id}'}), 404

        # Verificar si el usuario ya está registrado
        existing_registration = CalendarEventRegistration.query.filter_by(
            event_id=event.id,
            user_id=current_user.id
        ).first()

        if existing_registration:
            return jsonify({
                'success': True,
                'message': 'Ya estás registrado en este evento',
                'registration': {
                    'id': existing_registration.id,
                    'event_id': event.id,
                    'user_id': current_user.id,
                    'total_price': existing_registration.total_price,
                    'installments': existing_registration.installments,
                    'created_at': existing_registration.registration_date.isoformat() if existing_registration.registration_date else None
                }
            }), 200

        # Verificar capacidad máxima si está definida
        if event.max_attendees:
            current_attendees = CalendarEventRegistration.query.filter_by(event_id=event.id).count()
            if current_attendees >= event.max_attendees:
                return jsonify({'error': 'El evento ha alcanzado su capacidad máxima'}), 400

        # Crear registro en la tabla de inscripciones
        new_registration = CalendarEventRegistration(
            event_id=event.id,
            user_id=current_user.id,
            installments=installments,
            total_price=total_price,
            installment_amount=installment_amount,
            registration_date=datetime.now()
        )
        db.session.add(new_registration)

        # Crear notificación de recordatorio 1 día antes del evento
        event_date = event.event_date
        reminder_date = event_date - timedelta(days=1)

        if reminder_date > datetime.now():
            reminder_notification = Notification(
                recipient_user_id=current_user.id,
                type='event_reminder',
                title=f'Recordatorio: {event.title}',
                message=f'Tu evento "{event.title}" es mañana a las {event_date.strftime("%H:%M")}',
                data={
                    'event_id': event.id_code,
                    'event_title': event.title,
                    'event_date': event_date.isoformat(),
                    'location': event.location
                },
                expires_at=event_date
            )
            db.session.add(reminder_notification)

        # Crear notificación de confirmación de registro
        confirmation_notification = Notification(
            recipient_user_id=current_user.id,
            type='event_registration',
            title='Inscripción confirmada',
            message=f'Te has inscrito exitosamente en "{event.title}"',
            data={
                'event_id': event.id_code,
                'event_title': event.title,
                'installments': installments,
                'total_price': total_price
            },
            status='read'
        )
        db.session.add(confirmation_notification)

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Registro exitoso en el evento',
            'event_title': event.title,
            'installments': installments,
            'registration': {
                'id': new_registration.id,
                'event_id': event.id,
                'user_id': current_user.id,
                'total_price': total_price,
                'installments': installments,
                'payment_option': payment_option,
                'total_attendees': total_attendees,
                'created_at': new_registration.registration_date.isoformat() if new_registration.registration_date else None
            }
        }), 201

    except Exception as e:
        app.logger.error(f"Error en register_for_calendar_event: {str(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/<event_id>/registration-status', methods=['GET'])
@token_required
def check_registration_status(current_user, event_id):
    """Verificar si el usuario está registrado en un evento"""
    try:
        # Intentar buscar por id numérico primero, luego por id_code
        event = None
        try:
            # Intentar como ID numérico
            event = CalendarEvent.query.filter_by(id=int(event_id)).first()
        except ValueError:
            # Si no es número, buscar por id_code
            pass

        if not event:
            # Buscar por id_code
            event = CalendarEvent.query.filter_by(id_code=event_id).first()

        if not event:
            return jsonify({'error': 'Evento no encontrado'}), 404

        # Verificar si el usuario está registrado
        registration = CalendarEventRegistration.query.filter_by(
            event_id=event.id,
            user_id=current_user.id
        ).first()

        if registration:
            return jsonify({
                'success': True,
                'isRegistered': True,
                'registration': {
                    'id': registration.id,
                    'event_id': event.id,
                    'user_id': current_user.id,
                    'total_price': registration.total_price,
                    'installments': registration.installments,
                    'installment_amount': registration.installment_amount,
                    'created_at': registration.registration_date.isoformat() if registration.registration_date else None
                }
            }), 200
        else:
            return jsonify({
                'success': True,
                'isRegistered': False
            }), 200

    except Exception as e:
        app.logger.error(f"Error en check_registration_status: {str(e)}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/statistics', methods=['GET'])
@token_required
def get_calendar_statistics(current_user):
    """Obtener estadísticas de eventos del calendario"""
    try:
        # Estadísticas generales
        total_events = CalendarEvent.query.filter_by(is_active=True, organization_id=1).count()

        # Eventos futuros vs pasados
        now = datetime.now()
        upcoming_events = CalendarEvent.query.filter(
            CalendarEvent.is_active == True,
            CalendarEvent.organization_id == 1,
            CalendarEvent.event_date >= now
        ).count()

        past_events = CalendarEvent.query.filter(
            CalendarEvent.is_active == True,
            CalendarEvent.organization_id == 1,
            CalendarEvent.event_date < now
        ).count()

        # Eventos por tipo
        event_types = db.session.query(
            CalendarEvent.event_type,
            db.func.count(CalendarEvent.id).label('count')
        ).filter_by(
            is_active=True,
            organization_id=1
        ).group_by(CalendarEvent.event_type).all()

        event_types_dict = {et[0]: et[1] for et in event_types}

        # Eventos del usuario actual
        user_registered_count = db.session.query(CalendarEventRegistration).join(
            CalendarEvent,
            CalendarEvent.id == CalendarEventRegistration.event_id
        ).filter(
            CalendarEventRegistration.user_id == current_user.id,
            CalendarEvent.is_active == True
        ).count()

        user_reactions_count = CalendarReaction.query.filter_by(user_id=current_user.id).count()

        # Próximo evento del usuario
        next_user_event = None
        next_registration = db.session.query(CalendarEventRegistration).join(
            CalendarEvent,
            CalendarEvent.id == CalendarEventRegistration.event_id
        ).filter(
            CalendarEventRegistration.user_id == current_user.id,
            CalendarEvent.is_active == True,
            CalendarEvent.event_date >= now
        ).order_by(CalendarEvent.event_date.asc()).first()

        if next_registration:
            event = CalendarEvent.query.get(next_registration.event_id)
            next_user_event = {
                'id': event.id_code,
                'title': event.title,
                'event_date': event.event_date.isoformat(),
                'location': event.location,
                'time_until': _format_time_until(event.event_date)
            }

        return jsonify({
            'success': True,
            'statistics': {
                'total_events': total_events,
                'upcoming_events': upcoming_events,
                'past_events': past_events,
                'event_types': event_types_dict,
                'user': {
                    'registered_events': user_registered_count,
                    'reactions': user_reactions_count,
                    'next_event': next_user_event
                }
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo estadísticas: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

def _format_time_until(event_date):
    """Función auxiliar para formatear tiempo hasta un evento"""
    try:
        now = datetime.now()
        diff = event_date - now

        if diff.days > 0:
            return f"En {diff.days} días"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"En {hours} horas"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"En {minutes} minutos"
        else:
            return "Muy pronto"
    except:
        return "Fecha desconocida"

@app.route('/calendar-events/price-limits', methods=['GET'])
@token_required
def get_calendar_price_limits(current_user):
    """
    Obtiene los límites de precios de eventos disponibles (mínimo y máximo)
    para configurar el slider de filtro de precios
    """
    try:
        # Obtener organizaciones del usuario
        user_orgs = UserOrganization.query.filter_by(user_id=current_user.id).all()

        if not user_orgs:
            organization_ids = [1]
        else:
            organization_ids = [uo.organization_id for uo in user_orgs]

        # Obtener el precio mínimo y máximo de eventos activos de pago
        min_price_result = db.session.query(
            db.func.min(CalendarEvent.event_price)
        ).filter(
            CalendarEvent.is_active == True,
            CalendarEvent.organization_id.in_(organization_ids),
            CalendarEvent.event_type == 'paid',
            CalendarEvent.event_price > 0
        ).scalar()

        max_price_result = db.session.query(
            db.func.max(CalendarEvent.event_price)
        ).filter(
            CalendarEvent.is_active == True,
            CalendarEvent.organization_id.in_(organization_ids),
            CalendarEvent.event_type == 'paid',
            CalendarEvent.event_price > 0
        ).scalar()

        # Si no hay eventos de pago, usar valores por defecto
        min_price = float(min_price_result) if min_price_result is not None else 0.0
        max_price = float(max_price_result) if max_price_result is not None else 1000.0

        # Asegurar que max >= min
        if max_price < min_price:
            max_price = min_price + 100

        return jsonify({
            'success': True,
            'min_price': min_price,
            'max_price': max_price
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo límites de precios: {e}")
        import traceback
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# --------------------------------------------------------------------
#                     EJECUCIÓN DE LA APP
# --------------------------------------------------------------------

# --------------------------------------------------------------------
#                    ENDPOINTS PARA CREAR NOTIFICACIONES DE PRUEBA
# --------------------------------------------------------------------

@app.route('/notifications/test/friend-request', methods=['POST'])
@token_required
def create_test_friend_request(current_user):
    """Crear una notificación de solicitud de amistad de prueba"""
    try:
        data = request.get_json()
        target_email = data.get('target_email')

        if not target_email:
            return jsonify({'error': 'target_email es requerido'}), 400

        target_user = User.query.filter_by(email=target_email, is_active=True).first()
        if not target_user:
            return jsonify({'error': 'Usuario no encontrado'}), 404

        notification = create_friend_request(
            recipient_user_id=target_user.id,
            sender_user_id=current_user.id,
            sender_username=current_user.username
        )

        return jsonify({
            'message': 'Solicitud de amistad enviada',
            'notification_id': notification.id
        }), 200

    except Exception as e:
        app.logger.error(f"Error creating test friend request: {e}")
        return jsonify({'error': 'Error al crear solicitud de amistad'}), 500

@app.route('/notifications/test/system', methods=['POST'])
@token_required
def create_test_system_notification(current_user):
    """Crear una notificación del sistema de prueba"""
    try:
        data = request.get_json()
        title = data.get('title', 'Notificación del sistema')
        message = data.get('message', 'Esta es una notificación de prueba del sistema')

        notification = create_system_notification(
            recipient_user_id=current_user.id,
            title=title,
            message=message,
            notification_subtype='test'
        )

        return jsonify({
            'message': 'Notificación del sistema creada',
            'notification_id': notification.id
        }), 200

    except Exception as e:
        app.logger.error(f"Error creating test system notification: {e}")
        return jsonify({'error': 'Error al crear notificación del sistema'}), 500

# --------------------------------------------------------------------
#                         WEBSOCKET EVENTS (DESHABILITADO)
# --------------------------------------------------------------------

# Diccionario para mantener track de usuarios conectados
connected_users = {}

@socketio.on('connect')
def handle_connect():
    """Cuando un usuario se conecta via WebSocket"""
    try:
        app.logger.info(f"🔌 Cliente conectado: {request.sid}")
        emit('connected', {'status': 'Connected to notification server'})
    except Exception as e:
        app.logger.error(f"Error in connect event: {e}")

@socketio.on('disconnect')
def handle_disconnect():
    """Cuando un usuario se desconecta"""
    try:
        app.logger.info(f"🔌 Cliente desconectado: {request.sid}")
        # Remover usuario de la lista de conectados
        user_to_remove = None
        for user_id, session_id in connected_users.items():
            if session_id == request.sid:
                user_to_remove = user_id
                break
        if user_to_remove:
            del connected_users[user_to_remove]
    except Exception as e:
        app.logger.error(f"Error in disconnect event: {e}")

@socketio.on('authenticate')
def handle_authenticate(data):
    """Autenticar usuario WebSocket con JWT token"""
    try:
        token = data.get('token')
        if not token:
            emit('auth_error', {'error': 'Token requerido'})
            return

        # Verificar JWT token
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = payload['user_id']

            # Verificar que el usuario existe
            user = User.query.get(user_id)
            if not user:
                emit('auth_error', {'error': 'Usuario no encontrado'})
                return

            # Registrar usuario como conectado
            connected_users[user_id] = request.sid

            app.logger.info(f"👤 Usuario autenticado: {user.username} (ID: {user_id})")
            emit('authenticated', {
                'status': 'Usuario autenticado',
                'user_id': user_id,
                'username': user.username
            })

        except jwt.ExpiredSignatureError:
            emit('auth_error', {'error': 'Token expirado'})
        except jwt.InvalidTokenError:
            emit('auth_error', {'error': 'Token inválido'})

    except Exception as e:
        app.logger.error(f"Error in authenticate event: {e}")
        emit('auth_error', {'error': 'Error de autenticación'})

# --------------------------------------------------------------------
#                      CHAT SYSTEM ENDPOINTS
# --------------------------------------------------------------------

@app.route('/conversations', methods=['GET'])
@token_required
def get_conversations(current_user):
    """Obtener todas las conversaciones del usuario"""
    try:
        # Obtener conversaciones donde el usuario es participante activo
        conversations = db.session.query(Conversation).join(
            ConversationParticipant,
            Conversation.id == ConversationParticipant.conversation_id
        ).filter(
            ConversationParticipant.user_id == current_user.id,
            ConversationParticipant.is_active == True
        ).order_by(Conversation.last_message_at.desc()).all()

        result = []
        for conv in conversations:
            # Obtener el último mensaje
            last_message = Message.query.filter_by(
                conversation_id=conv.id,
                is_deleted=False
            ).order_by(Message.created_at.desc()).first()

            # Obtener participantes (excluyendo al usuario actual para chats privados)
            participants = db.session.query(User).join(
                ConversationParticipant,
                User.id == ConversationParticipant.user_id
            ).filter(
                ConversationParticipant.conversation_id == conv.id,
                ConversationParticipant.is_active == True,
                User.id != current_user.id
            ).all()

            # Para chat privado, usar datos del otro usuario
            if conv.type == 'private' and participants:
                other_user = participants[0]
                display_name = other_user.username
                avatar_url = other_user.profile_image_url or None
            else:
                # Para grupos, usar título del grupo
                display_name = conv.title or "Grupo sin nombre"
                avatar_url = conv.avatar_url

            # Contar mensajes no leídos
            participant = ConversationParticipant.query.filter_by(
                conversation_id=conv.id,
                user_id=current_user.id
            ).first()

            unread_count = 0
            if participant and participant.last_read_message_id:
                unread_count = Message.query.filter(
                    Message.conversation_id == conv.id,
                    Message.id > participant.last_read_message_id,
                    Message.is_deleted == False
                ).count()
            elif not participant.last_read_message_id:
                unread_count = Message.query.filter_by(
                    conversation_id=conv.id,
                    is_deleted=False
                ).count()

            conv_data = {
                'id': conv.id,
                'type': conv.type,
                'title': display_name,
                'avatar_url': avatar_url,
                'last_message': {
                    'content': last_message.content if last_message else None,
                    'sender_name': last_message.sender.username if last_message else None,
                    'created_at': last_message.created_at.isoformat() if last_message else None,
                    'message_type': last_message.message_type if last_message else 'text'
                } if last_message else None,
                'unread_count': unread_count,
                'updated_at': conv.updated_at.isoformat()
            }
            result.append(conv_data)

        return jsonify({
            'conversations': result,
            'count': len(result)
        }), 200

    except Exception as e:
        app.logger.error(f"Error retrieving conversations: {e}")
        return jsonify({'message': 'Error al obtener conversaciones'}), 500

@app.route('/conversations', methods=['POST'])
@token_required
def create_conversation(current_user):
    """Crear nueva conversación"""
    try:
        data = request.get_json()
        participant_ids = data.get('participant_ids', [])
        conversation_type = data.get('type', 'private')
        title = data.get('title')
        channel_id = data.get('channel_id')

        # Conversación con canal
        if channel_id:
            # Verificar que el canal existe
            channel = Channel.query.get(channel_id)
            if not channel:
                return jsonify({'message': 'Canal no encontrado'}), 404

            # Verificar si ya existe una conversación entre este usuario y el canal
            existing_conv = Conversation.query.filter_by(
                type='channel',
                channel_id=channel_id,
                created_by=current_user.id
            ).first()

            if existing_conv:
                return jsonify({
                    'message': 'La conversación ya existe',
                    'conversation_id': existing_conv.id
                }), 200

            # Crear nueva conversación de canal
            conversation = Conversation(
                type='channel',
                title=title or channel.name,
                created_by=current_user.id,
                channel_id=channel_id
            )
            db.session.add(conversation)
            db.session.flush()

            # Solo agregar al usuario creador como participante
            participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=current_user.id,
                role='member'
            )
            db.session.add(participant)

            db.session.commit()

            return jsonify({
                'message': 'Conversación creada exitosamente',
                'conversation_id': conversation.id
            }), 201

        # Conversación entre usuarios (privada o grupo)
        if not participant_ids:
            return jsonify({'message': 'Se requiere al menos un participante'}), 400

        # Verificar que los usuarios existen
        participants = User.query.filter(User.id.in_(participant_ids)).all()
        if len(participants) != len(participant_ids):
            return jsonify({'message': 'Algunos usuarios no existen'}), 400

        # Para chat privado, verificar si ya existe conversación
        if conversation_type == 'private' and len(participant_ids) == 1:
            other_user_id = participant_ids[0]
            existing_conv = db.session.query(Conversation).join(
                ConversationParticipant, Conversation.id == ConversationParticipant.conversation_id
            ).filter(
                Conversation.type == 'private',
                ConversationParticipant.user_id.in_([current_user.id, other_user_id])
            ).group_by(Conversation.id).having(
                db.func.count(ConversationParticipant.user_id) == 2
            ).first()

            if existing_conv:
                return jsonify({
                    'message': 'La conversación ya existe',
                    'conversation_id': existing_conv.id
                }), 200

        # Crear nueva conversación
        conversation = Conversation(
            type=conversation_type,
            title=title,
            created_by=current_user.id
        )
        db.session.add(conversation)
        db.session.flush()

        # Agregar participantes
        all_participant_ids = participant_ids + [current_user.id]
        for user_id in set(all_participant_ids):
            participant = ConversationParticipant(
                conversation_id=conversation.id,
                user_id=user_id,
                role='admin' if user_id == current_user.id else 'member'
            )
            db.session.add(participant)

        db.session.commit()

        return jsonify({
            'message': 'Conversación creada exitosamente',
            'conversation_id': conversation.id
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating conversation: {e}")
        return jsonify({'message': 'Error al crear conversación'}), 500

@app.route('/conversations/<int:conversation_id>/messages', methods=['GET'])
@token_required
def get_messages(current_user, conversation_id):
    """Obtener mensajes de una conversación"""
    try:
        # Verificar que el usuario es participante
        participant = ConversationParticipant.query.filter_by(
            conversation_id=conversation_id,
            user_id=current_user.id,
            is_active=True
        ).first()

        if not participant:
            return jsonify({'message': 'No autorizado para esta conversación'}), 403

        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)

        # Obtener mensajes paginados
        messages_query = Message.query.filter_by(
            conversation_id=conversation_id,
            is_deleted=False
        ).order_by(Message.created_at.desc())

        messages_paginated = messages_query.paginate(
            page=page, per_page=per_page, error_out=False
        )

        result = []
        for msg in messages_paginated.items:
            # Obtener reacciones del mensaje
            reactions = MessageReaction.query.filter_by(message_id=msg.id).all()
            reactions_data = []
            for reaction in reactions:
                reactions_data.append({
                    'user_id': reaction.user_id,
                    'username': reaction.user.username,
                    'emoji': reaction.emoji,
                    'reaction_type': reaction.reaction_type
                })

            message_data = {
                'id': msg.id,
                'content': msg.content,
                'message_type': msg.message_type,
                'file_url': msg.file_url,
                'file_name': msg.file_name,
                'sender': {
                    'id': msg.sender_id,
                    'username': msg.sender.username,
                    'profile_image': msg.sender.profile_image_url
                },
                'reply_to': {
                    'id': msg.reply_to_message_id,
                    'content': msg.reply_to_message.content if msg.reply_to_message else None,
                    'sender_username': msg.reply_to_message.sender.username if msg.reply_to_message else None
                } if msg.reply_to_message_id else None,
                'reactions': reactions_data,
                'created_at': msg.created_at.isoformat(),
                'edited_at': msg.edited_at.isoformat() if msg.edited_at else None,
                'is_system_message': msg.is_system_message
            }
            result.append(message_data)

        # Marcar mensajes como leídos
        if result:
            latest_message_id = max(msg['id'] for msg in result)
            participant.last_read_message_id = latest_message_id
            participant.last_read_at = datetime.utcnow()
            db.session.commit()

        return jsonify({
            'messages': list(reversed(result)),  # Revertir para orden cronológico
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': messages_paginated.total,
                'pages': messages_paginated.pages,
                'has_next': messages_paginated.has_next,
                'has_prev': messages_paginated.has_prev
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error retrieving messages: {e}")
        return jsonify({'message': 'Error al obtener mensajes'}), 500

@app.route('/conversations/<int:conversation_id>/messages', methods=['POST'])
@token_required
def send_message(current_user, conversation_id):
    """Enviar mensaje a una conversación"""
    try:
        # Verificar que el usuario es participante
        participant = ConversationParticipant.query.filter_by(
            conversation_id=conversation_id,
            user_id=current_user.id,
            is_active=True
        ).first()

        if not participant:
            return jsonify({'message': 'No autorizado para esta conversación'}), 403

        data = request.get_json()
        content = data.get('content', '').strip()
        message_type = data.get('message_type', 'text')
        reply_to_message_id = data.get('reply_to_message_id')

        if not content and message_type == 'text':
            return jsonify({'message': 'El contenido del mensaje es requerido'}), 400

        # Crear mensaje
        message = Message(
            conversation_id=conversation_id,
            sender_id=current_user.id,
            content=content,
            message_type=message_type,
            reply_to_message_id=reply_to_message_id,
            file_url=data.get('file_url'),
            file_name=data.get('file_name'),
            file_size=data.get('file_size')
        )
        db.session.add(message)
        db.session.flush()

        # Actualizar conversación
        conversation = Conversation.query.get(conversation_id)
        conversation.last_message_id = message.id
        conversation.last_message_at = datetime.utcnow()
        conversation.updated_at = datetime.utcnow()

        db.session.commit()

        # TODO: Enviar notificación tiempo real a otros participantes

        return jsonify({
            'message': 'Mensaje enviado exitosamente',
            'message_id': message.id,
            'created_at': message.created_at.isoformat()
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error sending message: {e}")
        return jsonify({'message': 'Error al enviar mensaje'}), 500

@app.route('/messages/<int:message_id>', methods=['PUT'])
@token_required
def edit_message(current_user, message_id):
    """Editar mensaje (solo el autor puede editarlo)"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'message': 'Mensaje no encontrado'}), 404

        if message.sender_id != current_user.id:
            return jsonify({'message': 'Solo puedes editar tus propios mensajes'}), 403

        if message.is_deleted:
            return jsonify({'message': 'No se puede editar un mensaje eliminado'}), 400

        data = request.get_json()
        new_content = data.get('content', '').strip()

        if not new_content:
            return jsonify({'message': 'El contenido no puede estar vacío'}), 400

        message.content = new_content
        message.edited_at = datetime.utcnow()
        db.session.commit()

        return jsonify({
            'message': 'Mensaje editado exitosamente',
            'edited_at': message.edited_at.isoformat()
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error editing message: {e}")
        return jsonify({'message': 'Error al editar mensaje'}), 500

@app.route('/messages/<int:message_id>', methods=['DELETE'])
@token_required
def delete_message(current_user, message_id):
    """Eliminar mensaje (solo el autor puede eliminarlo)"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'message': 'Mensaje no encontrado'}), 404

        if message.sender_id != current_user.id:
            return jsonify({'message': 'Solo puedes eliminar tus propios mensajes'}), 403

        message.is_deleted = True
        message.deleted_at = datetime.utcnow()
        message.deleted_by = current_user.id
        message.content = "Este mensaje fue eliminado"
        db.session.commit()

        return jsonify({'message': 'Mensaje eliminado exitosamente'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting message: {e}")
        return jsonify({'message': 'Error al eliminar mensaje'}), 500

@app.route('/messages/<int:message_id>/reactions', methods=['POST'])
@token_required
def add_reaction(current_user, message_id):
    """Agregar reacción a un mensaje"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'message': 'Mensaje no encontrado'}), 404

        data = request.get_json()
        emoji = data.get('emoji')
        reaction_type = data.get('reaction_type', 'like')

        if not emoji:
            return jsonify({'message': 'Emoji es requerido'}), 400

        # Verificar si ya existe una reacción del usuario para este tipo
        existing_reaction = MessageReaction.query.filter_by(
            message_id=message_id,
            user_id=current_user.id,
            reaction_type=reaction_type
        ).first()

        if existing_reaction:
            # Actualizar emoji existente
            existing_reaction.emoji = emoji
        else:
            # Crear nueva reacción
            reaction = MessageReaction(
                message_id=message_id,
                user_id=current_user.id,
                reaction_type=reaction_type,
                emoji=emoji
            )
            db.session.add(reaction)

        db.session.commit()

        return jsonify({'message': 'Reacción agregada exitosamente'}), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error adding reaction: {e}")
        return jsonify({'message': 'Error al agregar reacción'}), 500

@app.route('/messages/<int:message_id>/reactions/<string:reaction_type>', methods=['DELETE'])
@token_required
def remove_reaction(current_user, message_id, reaction_type):
    """Eliminar reacción de un mensaje"""
    try:
        reaction = MessageReaction.query.filter_by(
            message_id=message_id,
            user_id=current_user.id,
            reaction_type=reaction_type
        ).first()

        if not reaction:
            return jsonify({'message': 'Reacción no encontrada'}), 404

        db.session.delete(reaction)
        db.session.commit()

        return jsonify({'message': 'Reacción eliminada exitosamente'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error removing reaction: {e}")
        return jsonify({'message': 'Error al eliminar reacción'}), 500

@app.route('/messages/<int:message_id>/report', methods=['POST'])
@token_required
def report_message(current_user, message_id):
    """Reportar mensaje inapropiado"""
    try:
        message = Message.query.get(message_id)
        if not message:
            return jsonify({'message': 'Mensaje no encontrado'}), 404

        data = request.get_json()
        reason = data.get('reason')
        description = data.get('description')

        valid_reasons = ['spam', 'harassment', 'inappropriate_content', 'violence', 'hate_speech', 'false_information', 'other']
        if reason not in valid_reasons:
            return jsonify({'message': 'Razón de reporte inválida'}), 400

        # Verificar si ya reportó este mensaje
        existing_report = MessageReport.query.filter_by(
            message_id=message_id,
            reported_by=current_user.id
        ).first()

        if existing_report:
            return jsonify({'message': 'Ya has reportado este mensaje'}), 400

        # Crear reporte
        report = MessageReport(
            message_id=message_id,
            reported_by=current_user.id,
            reason=reason,
            description=description
        )
        db.session.add(report)
        db.session.commit()

        return jsonify({'message': 'Mensaje reportado exitosamente'}), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error reporting message: {e}")
        return jsonify({'message': 'Error al reportar mensaje'}), 500

@app.route('/users/search', methods=['GET'])
@token_required
def search_users(current_user):
    """Buscar usuarios para iniciar conversación"""
    try:
        query = request.args.get('q', '').strip()
        if len(query) < 2:
            return jsonify({'message': 'La búsqueda debe tener al menos 2 caracteres'}), 400

        # Buscar usuarios por username o email (excluyendo al usuario actual)
        users = User.query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.email.ilike(f'%{query}%')
            ),
            User.id != current_user.id
        ).limit(20).all()

        result = []
        for user in users:
            result.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_image': user.profile_image_url
            })

        return jsonify({
            'users': result,
            'count': len(result)
        }), 200

    except Exception as e:
        app.logger.error(f"Error searching users: {e}")
        return jsonify({'message': 'Error al buscar usuarios'}), 500

@app.route('/chat/settings', methods=['GET'])
@token_required
def get_chat_settings(current_user):
    """Obtener configuración de chat del usuario"""
    try:
        settings = UserChatSettings.query.filter_by(user_id=current_user.id).first()

        if not settings:
            # Crear configuración por defecto
            settings = UserChatSettings(user_id=current_user.id)
            db.session.add(settings)
            db.session.commit()

        return jsonify({
            'notifications_enabled': settings.notifications_enabled,
            'sounds_enabled': settings.sounds_enabled,
            'read_receipts_enabled': settings.read_receipts_enabled,
            'last_seen_privacy': settings.last_seen_privacy,
            'profile_photo_privacy': settings.profile_photo_privacy
        }), 200

    except Exception as e:
        app.logger.error(f"Error retrieving chat settings: {e}")
        return jsonify({'message': 'Error al obtener configuración'}), 500

@app.route('/chat/settings', methods=['PUT'])
@token_required
def update_chat_settings(current_user):
    """Actualizar configuración de chat del usuario"""
    try:
        settings = UserChatSettings.query.filter_by(user_id=current_user.id).first()

        if not settings:
            settings = UserChatSettings(user_id=current_user.id)
            db.session.add(settings)

        data = request.get_json()

        if 'notifications_enabled' in data:
            settings.notifications_enabled = data['notifications_enabled']
        if 'sounds_enabled' in data:
            settings.sounds_enabled = data['sounds_enabled']
        if 'read_receipts_enabled' in data:
            settings.read_receipts_enabled = data['read_receipts_enabled']
        if 'last_seen_privacy' in data:
            if data['last_seen_privacy'] in ['everyone', 'contacts', 'nobody']:
                settings.last_seen_privacy = data['last_seen_privacy']
        if 'profile_photo_privacy' in data:
            if data['profile_photo_privacy'] in ['everyone', 'contacts', 'nobody']:
                settings.profile_photo_privacy = data['profile_photo_privacy']

        db.session.commit()

        return jsonify({'message': 'Configuración actualizada exitosamente'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating chat settings: {e}")
        return jsonify({'message': 'Error al actualizar configuración'}), 500

def emit_notification_to_user(user_id, notification_data):
    """Enviar notificación a un usuario específico via WebSocket"""
    try:
        if user_id in connected_users:
            session_id = connected_users[user_id]
            socketio.emit('new_notification', notification_data, room=session_id)
            app.logger.info(f"📨 Notificación enviada a usuario {user_id}")
            return True
        else:
            app.logger.info(f"⚠️ Usuario {user_id} no conectado via WebSocket")
            return False
    except Exception as e:
        app.logger.error(f"Error emitiendo notificación: {e}")
        return False

def broadcast_notification_count_update(user_id, count):
    """Actualizar contador de notificaciones via WebSocket"""
    try:
        if user_id in connected_users:
            session_id = connected_users[user_id]
            socketio.emit('notification_count_updated', {'unread_count': count}, room=session_id)
            app.logger.info(f"🔢 Contador actualizado para usuario {user_id}: {count}")
            return True
        else:
            return False
    except Exception as e:
        app.logger.error(f"Error actualizando contador: {e}")
        return False

# ============================================================
# ENDPOINTS PARA VIDA DE PIEDAD
# ============================================================

@app.route('/prayer-life/today', methods=['GET'])
@token_required
def get_prayer_life_today(current_user):
    """
    Obtiene todo el contenido litúrgico para hoy:
    - Laudes, Vísperas, Completas
    - Santo del día
    - Fiesta litúrgica
    - Evangelio del día
    """
    try:
        today = datetime.now().date()
        language = request.args.get('language', 'es')

        app.logger.info(f"📿 Obteniendo vida de piedad para {today} (idioma: {language})")

        # Laudes
        laudes = LiturgicalPrayer.query.filter_by(
            prayer_type='laudes',
            liturgical_date=today,
            language=language
        ).first()

        # Vísperas
        visperas = LiturgicalPrayer.query.filter_by(
            prayer_type='visperas',
            liturgical_date=today,
            language=language
        ).first()

        # Completas
        completas = LiturgicalPrayer.query.filter_by(
            prayer_type='completas',
            liturgical_date=today,
            language=language
        ).first()

        # Santo del día
        saint = DailySaint.query.filter_by(
            saint_date=today,
            language=language
        ).first()

        # Fiesta litúrgica
        feast = LiturgicalFeast.query.filter_by(
            feast_date=today,
            language=language
        ).first()

        # Evangelio del día
        gospel = DailyGospel.query.filter_by(
            gospel_date=today,
            language=language
        ).first()

        return jsonify({
            'date': today.isoformat(),
            'laudes': {
                'title': laudes.title if laudes else None,
                'content': laudes.content if laudes else None,
                'audio_url': laudes.audio_url if laudes else None
            } if laudes else None,
            'visperas': {
                'title': visperas.title if visperas else None,
                'content': visperas.content if visperas else None,
                'audio_url': visperas.audio_url if visperas else None
            } if visperas else None,
            'completas': {
                'title': completas.title if completas else None,
                'content': completas.content if completas else None,
                'audio_url': completas.audio_url if completas else None
            } if completas else None,
            'saint': {
                'name': saint.saint_name,
                'biography': saint.biography,
                'image_url': saint.image_url
            } if saint else None,
            'feast': {
                'name': feast.feast_name,
                'description': feast.description,
                'color': feast.liturgical_color,
                'importance': feast.importance
            } if feast else None,
            'gospel': {
                'reference': gospel.gospel_reference,
                'text': gospel.gospel_text,
                'reflection': gospel.reflection
            } if gospel else None
        }), 200

    except Exception as e:
        app.logger.error(f"❌ Error obteniendo vida de piedad: {e}")
        import traceback
        app.logger.error(traceback.format_exc())
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/prayer-life/general-prayers', methods=['GET'])
@token_required
def get_general_prayers(current_user):
    """
    Obtiene oraciones generales por categoría (rosario, vía crucis, ángelus, etc.)
    """
    try:
        category = request.args.get('category')
        language = request.args.get('language', 'es')

        if category:
            prayers = GeneralPrayer.query.filter_by(
                prayer_category=category,
                language=language
            ).order_by(GeneralPrayer.display_order).all()
        else:
            prayers = GeneralPrayer.query.filter_by(
                language=language
            ).order_by(GeneralPrayer.prayer_category, GeneralPrayer.display_order).all()

        return jsonify({
            'prayers': [{
                'id': p.id,
                'category': p.prayer_category,
                'name': p.prayer_name,
                'content': p.prayer_content,
                'order': p.display_order
            } for p in prayers]
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo oraciones generales: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/prayer-life/automatic-channels', methods=['GET'])
@token_required
def get_automatic_prayer_channels(current_user):
    """
    Obtiene TODOS los canales automáticos: liturgia, santos, evangelio, oraciones
    """
    try:
        today = datetime.now().date()
        language = request.args.get('language', 'es')

        # Obtener canales automáticos por id_code
        automatic_channel_codes = [
            'channel_laudes', 'channel_visperas', 'channel_completas',
            'channel_santo_dia', 'channel_evangelio_dia', 'channel_fiesta_liturgica',
            'channel_oraciones_basicas', 'channel_oraciones_marianas', 'channel_espiritu_santo',
            'channel_oraciones_proteccion', 'channel_oraciones_comunion',
            'channel_actos_fe', 'channel_otras_oraciones'
        ]

        try:
            automatic_channels = Channel.query.filter(Channel.id_code.in_(automatic_channel_codes)).all()
        except Exception as e:
            app.logger.error(f"Error obteniendo canales automáticos: {e}")
            automatic_channels = []

        result = []
        for channel in automatic_channels:
            try:
                # Verificar si el usuario está suscrito
                subscription = UserChannel.query.filter_by(
                    user_id=current_user.id,
                    channel_id=channel.id
                ).first()

                # Contar suscriptores
                subscribers_count = UserChannel.query.filter_by(channel_id=channel.id).count()

                # Obtener organización de manera segura
                org_id = None
                org_name = None
                try:
                    if hasattr(channel, 'organization_id') and channel.organization_id:
                        org = Organization.query.get(channel.organization_id)
                        if org:
                            org_id = org.id
                            org_name = org.name
                except:
                    pass

                channel_data = {
                    'id': channel.id,
                    'id_code': channel.id_code,
                    'name': channel.name,
                    'subscribers_count': subscribers_count,
                    'subscribed': subscription is not None,
                    'organization': {
                        'id': org_id,
                        'name': org_name
                    },
                    'type': 'prayers',  # Default type
                    'content': None,
                    'has_content': False
                }
            except Exception as channel_error:
                app.logger.error(f"Error procesando canal {channel.id if hasattr(channel, 'id') else 'unknown'}: {channel_error}")
                continue

            # Determinar tipo de canal y obtener contenido del día
            try:
                if channel.id_code == 'channel_laudes':
                    channel_data['type'] = 'liturgy'
                    try:
                        # Llamar al nuevo API de liturgia
                        fecha_str = today.strftime('%Y-%m-%d')
                        liturgia_url = f'http://localhost:2053/api/liturgia/laudes/{fecha_str}'
                        liturgia_response = requests.get(liturgia_url, timeout=5)

                        if liturgia_response.status_code == 200:
                            liturgia_data = liturgia_response.json()

                            # Formatear contenido de Laudes
                            content = ''
                            laudes = liturgia_data.get('laudes', {})

                            # Himno (usar español si está disponible, sino catalán)
                            content += '═══ HIMNO ═══\n\n'
                            himno = laudes.get('himno', {}).get('espanol') or laudes.get('himno', {}).get('catalan', '')
                            content += himno + '\n\n'

                            # Salmodia (usar español si está disponible)
                            for salmo in laudes.get('salmodia', []):
                                content += f"═══ SALMO {salmo.get('numero')} ═══\n\n"

                                antifona = salmo.get('antifonaEsp') or salmo.get('antifona')
                                if antifona and antifona != '-':
                                    content += f"Antífona: {antifona}\n\n"

                                titulo = salmo.get('tituloEsp') or salmo.get('titulo')
                                if titulo and titulo != '-':
                                    content += f"{titulo}\n\n"

                                comentario = salmo.get('comentarioEsp') or salmo.get('comentario')
                                if comentario and comentario != '-':
                                    content += f"{comentario}\n\n"

                                salmo_texto = salmo.get('salmoEsp') or salmo.get('salmo', '')
                                content += salmo_texto + '\n\n'

                                if salmo.get('gloria') == '1':
                                    content += 'Gloria al Padre y al Hijo\n'
                                    content += 'y al Espíritu Santo.\n'
                                    content += 'Como era en el principio, ahora y siempre\n'
                                    content += 'y por los siglos de los siglos. Amén.\n\n'

                            # Lectura Breve
                            content += '═══ LECTURA BREVE ═══\n\n'
                            lectura = laudes.get('lectura_breve', {})
                            verseto = lectura.get('versetoEsp') or lectura.get('verseto')
                            if verseto and verseto != '-':
                                content += f"{verseto}\n\n"
                            lectura_texto = lectura.get('lecturaEsp') or lectura.get('lectura', '')
                            content += lectura_texto + '\n\n'

                            # Responsorio
                            content += '═══ RESPONSORIO BREVE ═══\n\n'
                            resp = laudes.get('responsorio', {})
                            parte1 = resp.get('parte1Esp') or resp.get('parte1', '')
                            parte2 = resp.get('parte2Esp') or resp.get('parte2', '')
                            parte3 = resp.get('parte3Esp') or resp.get('parte3', '')
                            content += f"R. {parte1}\n\n"
                            content += f"{parte2}\n\n"
                            content += f"V. {parte3}\n\n"

                            # Cántico Evangélico
                            cantico = laudes.get('cantico_evangelico', {})
                            antifona_cantico = cantico.get('antifonaEsp') or cantico.get('antifona')
                            if antifona_cantico and antifona_cantico != '-':
                                content += '═══ CÁNTICO EVANGÉLICO ═══\n\n'
                                content += f"Ant: {antifona_cantico}\n\n"

                            # Preces
                            preces = laudes.get('precesEsp') or laudes.get('preces')
                            if preces and preces != '-':
                                content += '═══ PRECES ═══\n\n'
                                content += preces + '\n\n'

                            # Oración Final
                            oracion_final = laudes.get('oracionFinalEsp') or laudes.get('oracion_final')
                            if oracion_final and oracion_final != '-':
                                content += '═══ ORACIÓN FINAL ═══\n\n'
                                content += oracion_final + '\n'

                            channel_data['content'] = {
                                'title': 'Laudes',
                                'text': content,
                                'audio_url': None
                            }
                            channel_data['has_content'] = True
                        else:
                            # Fallback a la base de datos local si el API falla
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='laudes', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                    except Exception as e:
                        app.logger.error(f"Error obteniendo Laudes del API de liturgia: {e}")
                        # Fallback a la base de datos local
                        try:
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='laudes', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                        except: pass

                elif channel.id_code == 'channel_visperas':
                    channel_data['type'] = 'liturgy'
                    try:
                        # Llamar al nuevo API de liturgia
                        fecha_str = today.strftime('%Y-%m-%d')
                        liturgia_url = f'http://localhost:2053/api/liturgia/vespres/{fecha_str}'
                        liturgia_response = requests.get(liturgia_url, timeout=5)

                        if liturgia_response.status_code == 200:
                            liturgia_data = liturgia_response.json()

                            # Formatear contenido de Vísperas
                            content = ''
                            vespres = liturgia_data.get('vespres', {})

                            # Himno (usar español si está disponible, sino catalán)
                            content += '═══ HIMNO ═══\n\n'
                            himno = vespres.get('himno', {}).get('espanol') or vespres.get('himno', {}).get('catalan', '')
                            content += himno + '\n\n'

                            # Salmodia (usar español si está disponible)
                            for salmo in vespres.get('salmodia', []):
                                content += f"═══ SALMO {salmo.get('numero')} ═══\n\n"

                                antifona = salmo.get('antifonaEsp') or salmo.get('antifona')
                                if antifona and antifona != '-':
                                    content += f"Antífona: {antifona}\n\n"

                                titulo = salmo.get('tituloEsp') or salmo.get('titulo')
                                if titulo and titulo != '-':
                                    content += f"{titulo}\n\n"

                                comentario = salmo.get('comentarioEsp') or salmo.get('comentario')
                                if comentario and comentario != '-':
                                    content += f"{comentario}\n\n"

                                salmo_texto = salmo.get('salmoEsp') or salmo.get('salmo', '')
                                content += salmo_texto + '\n\n'

                                if salmo.get('gloria') == '1':
                                    content += 'Gloria al Padre y al Hijo\n'
                                    content += 'y al Espíritu Santo.\n'
                                    content += 'Como era en el principio, ahora y siempre\n'
                                    content += 'y por los siglos de los siglos. Amén.\n\n'

                            # Lectura Breve
                            content += '═══ LECTURA BREVE ═══\n\n'
                            lectura = vespres.get('lectura_breve', {})
                            verseto = lectura.get('versetoEsp') or lectura.get('verseto')
                            if verseto and verseto != '-':
                                content += f"{verseto}\n\n"
                            lectura_texto = lectura.get('lecturaEsp') or lectura.get('lectura', '')
                            content += lectura_texto + '\n\n'

                            # Responsorio
                            content += '═══ RESPONSORIO BREVE ═══\n\n'
                            resp = vespres.get('responsorio', {})
                            parte1 = resp.get('parte1Esp') or resp.get('parte1', '')
                            parte2 = resp.get('parte2Esp') or resp.get('parte2', '')
                            parte3 = resp.get('parte3Esp') or resp.get('parte3', '')
                            content += f"R. {parte1}\n\n"
                            content += f"{parte2}\n\n"
                            content += f"V. {parte3}\n\n"

                            # Cántico Evangélico
                            cantico = vespres.get('cantico_evangelico', {})
                            antifona_cantico = cantico.get('antifonaEsp') or cantico.get('antifona')
                            if antifona_cantico and antifona_cantico != '-':
                                content += '═══ CÁNTICO EVANGÉLICO ═══\n\n'
                                content += f"Ant: {antifona_cantico}\n\n"

                            # Preces
                            preces = vespres.get('precesEsp') or vespres.get('preces')
                            if preces and preces != '-':
                                content += '═══ PRECES ═══\n\n'
                                content += preces + '\n\n'

                            # Oración Final
                            oracion_final = vespres.get('oracionFinalEsp') or vespres.get('oracion_final')
                            if oracion_final and oracion_final != '-':
                                content += '═══ ORACIÓN FINAL ═══\n\n'
                                content += oracion_final + '\n'

                            channel_data['content'] = {
                                'title': 'Vísperas',
                                'text': content,
                                'audio_url': None
                            }
                            channel_data['has_content'] = True
                        else:
                            # Fallback a la base de datos local si el API falla
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='visperas', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                    except Exception as e:
                        app.logger.error(f"Error obteniendo Vísperas del API de liturgia: {e}")
                        # Fallback a la base de datos local
                        try:
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='visperas', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                        except: pass

                elif channel.id_code == 'channel_completas':
                    channel_data['type'] = 'liturgy'
                    try:
                        # Llamar al nuevo API de liturgia
                        fecha_str = today.strftime('%Y-%m-%d')
                        liturgia_url = f'http://localhost:2053/api/liturgia/completes/{fecha_str}'
                        liturgia_response = requests.get(liturgia_url, timeout=5)

                        if liturgia_response.status_code == 200:
                            liturgia_data = liturgia_response.json()

                            # Formatear contenido de Completas
                            content = ''
                            completes = liturgia_data.get('completes', {})

                            # Salmodia (usar español si está disponible)
                            for salmo in completes.get('salmodia', []):
                                content += f"═══ SALMO {salmo.get('numero')} ═══\n\n"

                                antifona = salmo.get('antifonaEsp') or salmo.get('antifona')
                                if antifona and antifona != '-':
                                    content += f"Antífona: {antifona}\n\n"

                                titulo = salmo.get('tituloEsp') or salmo.get('titulo')
                                if titulo and titulo != '-':
                                    content += f"{titulo}\n\n"

                                comentario = salmo.get('comentarioEsp') or salmo.get('comentario')
                                if comentario and comentario != '-':
                                    content += f"{comentario}\n\n"

                                salmo_texto = salmo.get('salmoEsp') or salmo.get('salmo', '')
                                content += salmo_texto + '\n\n'

                                if salmo.get('gloria') == '1':
                                    content += 'Gloria al Padre y al Hijo\n'
                                    content += 'y al Espíritu Santo.\n'
                                    content += 'Como era en el principio, ahora y siempre\n'
                                    content += 'y por los siglos de los siglos. Amén.\n\n'

                            # Lectura Breve
                            content += '═══ LECTURA BREVE ═══\n\n'
                            lectura = completes.get('lectura_breve', {})
                            verseto = lectura.get('versetoEsp') or lectura.get('verseto')
                            if verseto and verseto != '-':
                                content += f"{verseto}\n\n"
                            lectura_texto = lectura.get('lecturaEsp') or lectura.get('lectura', '')
                            content += lectura_texto + '\n\n'

                            # Oración Final
                            oracion_final = completes.get('oracionFinalEsp') or completes.get('oracion_final')
                            if oracion_final and oracion_final != '-':
                                content += '═══ ORACIÓN FINAL ═══\n\n'
                                content += oracion_final + '\n'

                            channel_data['content'] = {
                                'title': 'Completas',
                                'text': content,
                                'audio_url': None
                            }
                            channel_data['has_content'] = True
                        else:
                            # Fallback a la base de datos local si el API falla
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='completas', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                    except Exception as e:
                        app.logger.error(f"Error obteniendo Completas del API de liturgia: {e}")
                        # Fallback a la base de datos local
                        try:
                            prayer = LiturgicalPrayer.query.filter_by(prayer_type='completas', liturgical_date=today, language=language).first()
                            if prayer:
                                channel_data['content'] = {'title': prayer.title, 'text': prayer.content, 'audio_url': prayer.audio_url}
                                channel_data['has_content'] = True
                        except: pass

                elif channel.id_code == 'channel_santo_dia':
                    channel_data['type'] = 'saint'
                    try:
                        saint = DailySaint.query.filter_by(saint_date=today, language=language).first()
                        if saint:
                            channel_data['content'] = {'name': saint.saint_name, 'biography': saint.biography, 'image_url': saint.image_url}
                            channel_data['has_content'] = True
                    except: pass

                elif channel.id_code == 'channel_evangelio_dia':
                    channel_data['type'] = 'gospel'
                    try:
                        gospel = DailyGospel.query.filter_by(gospel_date=today, language=language).first()
                        if gospel:
                            channel_data['content'] = {'reference': gospel.reference, 'text': gospel.text, 'reflection': gospel.reflection}
                            channel_data['has_content'] = True
                    except: pass

                elif channel.id_code == 'channel_fiesta_liturgica':
                    channel_data['type'] = 'feast'
                    try:
                        feast = LiturgicalFeast.query.filter_by(feast_date=today, language=language).first()
                        if feast:
                            channel_data['content'] = {'name': feast.feast_name, 'description': feast.description, 'color': feast.liturgical_color, 'importance': feast.importance}
                            channel_data['has_content'] = True
                    except: pass

                else:
                    # Canal de oraciones tradicionales
                    try:
                        prayers = GeneralPrayer.query.filter_by(automatic_channel_id=channel.id).order_by(GeneralPrayer.display_order).all()
                        channel_data['prayers'] = [{'id': p.id, 'name': p.prayer_name, 'content': p.prayer_content, 'order': p.display_order} for p in prayers]
                        channel_data['prayers_count'] = len(prayers)
                        channel_data['has_content'] = len(prayers) > 0
                    except: pass

            except Exception as content_error:
                app.logger.warning(f"Error obteniendo contenido para canal {channel.id_code}: {content_error}")

            result.append(channel_data)

        return jsonify({'channels': result}), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo canales automáticos: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/prayer-life/setup-automatic-channels', methods=['POST'])
@token_required
def setup_automatic_channels(current_user):
    """
    Endpoint temporal para crear canales automáticos
    """
    try:
        # Solo admin puede ejecutar esto
        if current_user.id != 1:
            return jsonify({'error': 'No autorizado'}), 403

        # Obtener o crear organización
        org = Organization.query.filter_by(name='Vida de Piedad').first()
        if not org:
            org = Organization(name='Vida de Piedad', created_at=datetime.now())
            db.session.add(org)
            db.session.commit()

        # Crear canales automáticos
        channels_data = [
            {'id_code': 'channel_laudes', 'name': 'Laudes'},
            {'id_code': 'channel_visperas', 'name': 'Vísperas'},
            {'id_code': 'channel_completas', 'name': 'Completas'},
            {'id_code': 'channel_santo_dia', 'name': 'Santo del Día'},
            {'id_code': 'channel_evangelio_dia', 'name': 'Evangelio del Día'},
            {'id_code': 'channel_fiesta_liturgica', 'name': 'Fiesta Litúrgica'},
            {'id_code': 'channel_oraciones_basicas', 'name': 'Oraciones Básicas'},
            {'id_code': 'channel_oraciones_marianas', 'name': 'Oraciones Marianas'},
            {'id_code': 'channel_espiritu_santo', 'name': 'Espíritu Santo'},
            {'id_code': 'channel_oraciones_proteccion', 'name': 'Oraciones de Protección'},
            {'id_code': 'channel_oraciones_comunion', 'name': 'Oraciones Eucarísticas'},
            {'id_code': 'channel_actos_fe', 'name': 'Actos y Virtudes'},
            {'id_code': 'channel_otras_oraciones', 'name': 'Otras Oraciones'}
        ]

        created = 0
        existing = 0

        for ch_data in channels_data:
            channel = Channel.query.filter_by(id_code=ch_data['id_code']).first()
            if not channel:
                channel = Channel(
                    id_code=ch_data['id_code'],
                    name=ch_data['name'],
                    organization_id=org.id,
                    created_at=datetime.now()
                )
                db.session.add(channel)
                created += 1

                # Agregar is_automatic mediante SQL raw
                try:
                    db.session.flush()  # Para obtener el ID
                    db.session.execute(sa_text("UPDATE channels SET is_automatic = 1 WHERE id = :id"), {'id': channel.id})
                except:
                    pass
            else:
                existing += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'created': created,
            'existing': existing,
            'total': created + existing
        }), 200

    except Exception as e:
        app.logger.error(f"Error creando canales automáticos: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/prayer-life/scrape-vatican-news', methods=['POST'])
@token_required
def scrape_vatican_news(current_user):
    """
    Scrape contenido litúrgico de Vatican News
    """
    try:
        if current_user.id != 1:
            return jsonify({'error': 'No autorizado'}), 403

        import requests
        from bs4 import BeautifulSoup
        from datetime import datetime

        today = datetime.now().date()
        results = {'gospel': None, 'saint': None, 'errors': []}

        # Scrape evangelio y santo del día desde EWTN
        try:
            liturgy_url = "https://www.ewtn.com/es/catolicismo/lecturas"
            app.logger.info(f"Fetching liturgy: {liturgy_url}")

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(liturgy_url, timeout=10, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extraer todo el texto
            page_text = soup.get_text()

            # Extraer evangelio
            gospel_text = None
            gospel_ref = None

            if 'Evangelio' in page_text:
                # Dividir por "Evangelio"
                parts = page_text.split('Evangelio')
                if len(parts) > 1:
                    # Buscar hasta el próximo indicador de sección o límite de caracteres
                    gospel_section = parts[1][:3000]

                    # Limpiar y extraer líneas
                    lines = [l.strip() for l in gospel_section.split('\n') if l.strip()]

                    # La primera línea suele ser la referencia (ej: "Lucas 11, 1-4")
                    if lines:
                        gospel_ref = lines[0]
                        # Unir el resto como texto del evangelio
                        gospel_text = '\n'.join(lines[1:20])  # Primeras 20 líneas

            # Guardar evangelio en BD
            if gospel_text:
                db.session.execute(sa_text("""
                    INSERT INTO daily_gospel (gospel_date, reference, text, language, created_at)
                    VALUES (:date, :ref, :text, 'es', NOW())
                    ON DUPLICATE KEY UPDATE
                        reference = VALUES(reference),
                        text = VALUES(text)
                """), {
                    'date': today,
                    'ref': gospel_ref or 'Evangelio del día',
                    'text': gospel_text
                })
                db.session.commit()
                results['gospel'] = {'success': True, 'reference': gospel_ref}
            else:
                results['errors'].append('No se encontró texto del evangelio')

        except Exception as e:
            app.logger.error(f"Error scraping gospel: {e}")
            results['errors'].append(f'Gospel error: {str(e)}')

        # Scrape santo del día desde ACI Prensa
        try:
            saint_url = "https://www.aciprensa.com/santoral/santo-de-hoy"
            app.logger.info(f"Fetching saint: {saint_url}")

            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(saint_url, timeout=10, headers=headers)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')

            # Extraer nombre del santo (usualmente en h1)
            saint_name = None
            h1 = soup.find('h1')
            if h1:
                saint_name = h1.get_text(strip=True)

            # Extraer biografía (buscar en artículo principal)
            biography = None
            article = soup.find('article') or soup.find(class_='content')
            if article:
                for script in article(["script", "style", "nav", "header", "footer"]):
                    script.decompose()
                biography = article.get_text(separator='\n', strip=True)[:2000]  # Primeros 2000 caracteres

            # Guardar en BD
            if saint_name:
                db.session.execute(sa_text("""
                    INSERT INTO daily_saints (saint_date, saint_name, biography, language, created_at)
                    VALUES (:date, :name, :bio, 'es', NOW())
                    ON DUPLICATE KEY UPDATE
                        saint_name = VALUES(saint_name),
                        biography = VALUES(biography)
                """), {
                    'date': today,
                    'name': saint_name,
                    'bio': biography or 'Ver más en ACI Prensa'
                })
                db.session.commit()
                results['saint'] = {'success': True, 'name': saint_name}
            else:
                results['errors'].append('No se encontró información del santo')

        except Exception as e:
            app.logger.error(f"Error scraping saint: {e}")
            results['errors'].append(f'Saint error: {str(e)}')

        return jsonify({
            'success': True,
            'date': str(today),
            'results': results
        }), 200

    except Exception as e:
        app.logger.error(f"Error en scraping: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/prayer-life/automatic-channels/<channel_id_code>/subscribe', methods=['POST'])
@token_required
def subscribe_automatic_channel(current_user, channel_id_code):
    """
    Suscribirse o desuscribirse de un canal automático
    """
    try:
        # Buscar el canal
        channel = Channel.query.filter_by(id_code=channel_id_code, is_automatic=1).first()
        if not channel:
            return jsonify({'error': 'Canal no encontrado'}), 404

        # Verificar si ya está suscrito
        subscription = UserChannel.query.filter_by(
            user_id=current_user.id,
            channel_id=channel.id
        ).first()

        if subscription:
            # Desuscribirse
            db.session.delete(subscription)
            db.session.commit()
            return jsonify({
                'message': 'Desuscrito exitosamente',
                'subscribed': False
            }), 200
        else:
            # Suscribirse
            new_subscription = UserChannel(
                user_id=current_user.id,
                channel_id=channel.id,
                role='member'  # Rol básico para canales automáticos
            )
            db.session.add(new_subscription)
            db.session.commit()
            return jsonify({
                'message': 'Suscrito exitosamente',
                'subscribed': True
            }), 200

    except Exception as e:
        app.logger.error(f"Error en suscripción de canal automático: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/calendar-events/channel/<int:channel_id>', methods=['GET'])
@token_required
def get_channel_events(current_user, channel_id):
    """
    Obtiene los eventos de un canal específico
    """
    try:
        # Obtener solo eventos activos y futuros
        from datetime import datetime
        now = datetime.now()

        events = CalendarEvent.query.filter(
            CalendarEvent.channel_id == channel_id,
            CalendarEvent.is_active == True,
            CalendarEvent.event_date >= now
        ).order_by(CalendarEvent.event_date.asc()).limit(10).all()

        events_list = []
        for event in events:
            try:
                # Extraer solo la hora y fecha del event_date si existe
                event_time = None
                event_date_str = None

                if event.event_date:
                    # event_date es un datetime, extraer fecha y hora
                    event_time = event.event_date.strftime('%H:%M')
                    event_date_str = event.event_date.strftime('%Y-%m-%d')

                # Contar asistentes registrados
                current_attendees = 0
                try:
                    current_attendees = CalendarEventRegistration.query.filter_by(event_id=event.id).count()
                except:
                    pass

                events_list.append({
                    'id': event.id,
                    'title': event.title or '',
                    'event_date': event_date_str,
                    'event_time': event_time,
                    'location': event.location or '',
                    'image_url': event.post_image or '',
                    'max_attendees': event.max_attendees or 0,
                    'current_attendees': current_attendees,
                    'event_price': float(event.event_price) if event.event_price else 0,
                })
            except Exception as event_error:
                app.logger.error(f"Error procesando evento {event.id}: {event_error}")
                continue

        return jsonify({'events': events_list}), 200

    except Exception as e:
        import traceback
        app.logger.error(f"Error obteniendo eventos del canal: {e}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({'error': 'Error interno del servidor', 'details': str(e)}), 500

@app.route('/channels/<int:channel_id>/subscription-status', methods=['GET'])
@token_required
def get_channel_subscription_status(current_user, channel_id):
    """
    Obtiene el estado de suscripción y donación del usuario a un canal
    """
    try:
        # Verificar suscripción
        subscription = UserChannel.query.filter_by(
            user_id=current_user.id,
            channel_id=channel_id
        ).first()

        is_following = subscription is not None

        # Obtener donación mensual
        monthly_donation = 0
        if subscription and hasattr(subscription, 'monthly_donation'):
            monthly_donation = float(subscription.monthly_donation or 0)

        # Obtener información del canal y organización
        channel = Channel.query.filter_by(id=channel_id).first()
        organization_name = None
        is_main_channel = False

        if channel and channel.organization:
            organization_name = channel.organization.name
            # Verificar si este canal es el canal principal de la organización
            is_main_channel = (channel.organization.main_channel_id == channel_id)

        return jsonify({
            'is_following': is_following,
            'monthly_donation': monthly_donation,
            'organization_name': organization_name,
            'is_main_channel': is_main_channel
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo estado de suscripción: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/channels/<int:channel_id>/is-admin', methods=['GET'])
@token_required
def check_channel_admin(current_user, channel_id):
    """
    Verifica si el usuario es admin del canal, organización o superadmin
    """
    try:
        # Verificar si es superadmin
        if current_user.role.upper() == 'SUPERADMIN':
            return jsonify({'is_admin': True, 'admin_type': 'superadmin'}), 200

        # Buscar el canal
        channel = Channel.query.filter_by(id=channel_id).first()
        if not channel:
            return jsonify({'error': 'Canal no encontrado'}), 404

        # Verificar si es admin de la organización
        if channel.organization_id:
            org_admin = UserOrganization.query.filter_by(
                user_id=current_user.id,
                organization_id=channel.organization_id,
                role='ORG_ADMIN'
            ).first()
            if org_admin:
                return jsonify({'is_admin': True, 'admin_type': 'organization'}), 200

        # Verificar si es admin del canal
        channel_admin = UserChannel.query.filter_by(
            user_id=current_user.id,
            channel_id=channel_id,
            role='CHANNEL_ADMIN'
        ).first()

        if channel_admin:
            return jsonify({'is_admin': True, 'admin_type': 'channel'}), 200

        return jsonify({'is_admin': False}), 200

    except Exception as e:
        app.logger.error(f"Error verificando admin de canal: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/channels/<int:channel_id>/subscribe', methods=['POST'])
@token_required
def subscribe_to_channel(current_user, channel_id):
    """
    Suscribe al usuario a un canal
    """
    try:
        # Verificar si ya está suscrito
        existing = UserChannel.query.filter_by(
            user_id=current_user.id,
            channel_id=channel_id
        ).first()

        if existing:
            return jsonify({'message': 'Ya estás suscrito a este canal'}), 200

        # Crear suscripción
        subscription = UserChannel(
            user_id=current_user.id,
            channel_id=channel_id,
            role='member'
        )
        db.session.add(subscription)
        db.session.commit()

        return jsonify({'message': 'Suscripción exitosa'}), 200

    except Exception as e:
        app.logger.error(f"Error suscribiéndose al canal: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/channels/<int:channel_id>/unsubscribe', methods=['DELETE'])
@token_required
def unsubscribe_from_channel(current_user, channel_id):
    """
    Desuscribe al usuario de un canal
    """
    try:
        subscription = UserChannel.query.filter_by(
            user_id=current_user.id,
            channel_id=channel_id
        ).first()

        if not subscription:
            return jsonify({'message': 'No estás suscrito a este canal'}), 404

        db.session.delete(subscription)
        db.session.commit()

        return jsonify({'message': 'Desuscripción exitosa'}), 200

    except Exception as e:
        app.logger.error(f"Error desuscribiéndose del canal: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/prayer-life/prayer/<prayer_type>', methods=['GET'])
@token_required
def get_specific_prayer(current_user, prayer_type):
    """
    Obtiene una oración específica por tipo (laudes, visperas, completas)
    """
    try:
        date_str = request.args.get('date')
        language = request.args.get('language', 'es')

        if date_str:
            prayer_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            prayer_date = datetime.now().date()

        prayer = LiturgicalPrayer.query.filter_by(
            prayer_type=prayer_type,
            liturgical_date=prayer_date,
            language=language
        ).first()

        if not prayer:
            return jsonify({'error': f'No se encontró {prayer_type} para {prayer_date}'}), 404

        return jsonify({
            'type': prayer.prayer_type,
            'title': prayer.title,
            'content': prayer.content,
            'date': prayer.liturgical_date.isoformat()
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo oración específica: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

# ============================================================================
# ENDPOINTS: Organización Principal del Usuario
# ============================================================================

@app.route('/user/primary-organization', methods=['GET'])
@token_required
def get_user_primary_organization(current_user):
    """
    Obtiene la organización principal del usuario
    """
    try:
        if not current_user.primary_organization_id:
            return jsonify({
                'primary_organization': None,
                'message': 'Usuario no tiene organización principal configurada'
            }), 200

        organization = Organization.query.filter_by(id=current_user.primary_organization_id).first()

        if not organization:
            return jsonify({
                'primary_organization': None,
                'message': 'Organización principal no encontrada'
            }), 404

        return jsonify({
            'primary_organization': {
                'id': organization.id,
                'name': organization.name,
                'description': organization.description,
                'logo_url': organization.logo_url,
                'logo_color': organization.logo_color,
                'custom_logo_url': organization.custom_logo_url,
                'city': organization.city,
                'country': organization.country,
                'show_channel_navigation': organization.show_channel_navigation or False,
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error obteniendo organización principal del usuario: {e}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/user/primary-organization', methods=['PUT'])
@token_required
def update_user_primary_organization(current_user):
    """
    Actualiza la organización principal del usuario
    """
    try:
        data = request.get_json()
        organization_id = data.get('organization_id')

        if not organization_id:
            return jsonify({'error': 'organization_id es requerido'}), 400

        # Verificar que la organización existe
        organization = Organization.query.filter_by(id=organization_id, is_active=True).first()
        if not organization:
            return jsonify({'error': 'Organización no encontrada'}), 404

        # Actualizar la organización principal del usuario
        current_user.primary_organization_id = organization_id
        db.session.commit()

        return jsonify({
            'message': 'Organización principal actualizada correctamente',
            'primary_organization': {
                'id': organization.id,
                'name': organization.name,
                'description': organization.description,
                'logo_url': organization.logo_url,
                'logo_color': organization.logo_color,
                'custom_logo_url': organization.custom_logo_url,
                'city': organization.city,
                'country': organization.country,
            }
        }), 200

    except Exception as e:
        app.logger.error(f"Error actualizando organización principal del usuario: {e}")
        db.session.rollback()
        return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=8443, ssl_context=("cert.pem", "key.pem"))

