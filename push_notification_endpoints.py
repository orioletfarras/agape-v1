"""
Endpoints para manejar registro de push tokens y envío de notificaciones push

Añade estos endpoints al archivo login.py importando:
from push_notification_endpoints import register_push_endpoints
Y luego llamando: register_push_endpoints(app, db)
"""

from flask import request, jsonify, g
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# El modelo PushToken ahora está definido en login.py para evitar importación circular

# Importar el servicio de push notifications
from push_notification_service import push_service

def register_push_endpoints(app, db, token_required):
    # Obtener PushToken del módulo login
    from login import PushToken
    """
    Registra los endpoints de push notifications en la app Flask

    Args:
        app: Instancia de Flask
        db: Instancia de SQLAlchemy
        token_required: Decorador de autenticación
    """

    @app.route('/register-push-token', methods=['POST'])
    @token_required
    def register_push_token(current_user):
        """
        Registra un push token para un usuario

        Requiere autenticación (token JWT)
        Body: {
            "push_token": "ExponentPushToken[...]",
            "platform": "ios" | "android",
            "device_name": "iPhone de Juan" (opcional)
        }
        """
        try:
            # Obtener el usuario autenticado desde el decorador
            user_id = current_user.id

            data = request.get_json()
            push_token = data.get('push_token')
            platform = data.get('platform', 'unknown')
            device_name = data.get('device_name')

            if not push_token:
                return jsonify({'error': 'push_token es requerido'}), 400

            # Verificar si el token ya existe
            existing_token = PushToken.query.filter_by(push_token=push_token).first()

            if existing_token:
                # Actualizar el token existente
                existing_token.user_id = user_id
                existing_token.platform = platform
                existing_token.device_name = device_name
                existing_token.is_active = True
                existing_token.updated_at = datetime.utcnow()
                logger.info(f"✅ Push token actualizado para usuario {user_id}")
            else:
                # Crear nuevo token
                new_token = PushToken(
                    user_id=user_id,
                    push_token=push_token,
                    platform=platform,
                    device_name=device_name,
                    is_active=True
                )
                db.session.add(new_token)
                logger.info(f"✅ Nuevo push token registrado para usuario {user_id}")

            db.session.commit()

            return jsonify({
                'message': 'Push token registrado exitosamente',
                'push_token': push_token
            }), 200

        except Exception as e:
            logger.error(f"❌ Error registrando push token: {e}")
            db.session.rollback()
            return jsonify({'error': 'Error registrando push token'}), 500

    @app.route('/unregister-push-token', methods=['POST'])
    def unregister_push_token():
        """
        Desactiva un push token (cuando el usuario hace logout)

        Body: {
            "push_token": "ExponentPushToken[...]"
        }
        """
        try:
            data = request.get_json()
            push_token = data.get('push_token')

            if not push_token:
                return jsonify({'error': 'push_token es requerido'}), 400

            # Buscar y desactivar el token
            token = PushToken.query.filter_by(push_token=push_token).first()

            if token:
                token.is_active = False
                token.updated_at = datetime.utcnow()
                db.session.commit()
                logger.info(f"✅ Push token desactivado: {push_token[:20]}...")
                return jsonify({'message': 'Push token desactivado'}), 200
            else:
                return jsonify({'message': 'Token no encontrado'}), 404

        except Exception as e:
            logger.error(f"❌ Error desactivando push token: {e}")
            db.session.rollback()
            return jsonify({'error': 'Error desactivando push token'}), 500

    @app.route('/get-user-push-tokens/<int:user_id>', methods=['GET'])
    def get_user_push_tokens(user_id):
        """
        Obtiene todos los tokens activos de un usuario (endpoint interno/admin)
        """
        try:
            tokens = PushToken.query.filter_by(
                user_id=user_id,
                is_active=True
            ).all()

            return jsonify({
                'user_id': user_id,
                'tokens': [{
                    'push_token': t.push_token,
                    'platform': t.platform,
                    'device_name': t.device_name,
                    'created_at': t.created_at.isoformat() if t.created_at else None
                } for t in tokens]
            }), 200

        except Exception as e:
            logger.error(f"❌ Error obteniendo tokens: {e}")
            return jsonify({'error': 'Error obteniendo tokens'}), 500

def send_push_to_user(user_id, title, body, data=None):
    """
    Función helper para enviar push notification a todos los dispositivos de un usuario

    Args:
        user_id (int): ID del usuario
        title (str): Título de la notificación
        body (str): Cuerpo de la notificación
        data (dict): Datos adicionales

    Returns:
        dict: Estadísticas de envío
    """
    try:
        # Obtener todos los tokens activos del usuario
        tokens = PushToken.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()

        if not tokens:
            logger.info(f"⚠️ Usuario {user_id} no tiene tokens de push activos")
            return {'success': 0, 'failed': 0, 'no_tokens': True}

        # Extraer los push tokens
        push_tokens = [t.push_token for t in tokens]

        # Enviar notificaciones
        result = push_service.send_bulk_push_notifications(
            push_tokens=push_tokens,
            title=title,
            body=body,
            data=data
        )

        # Desactivar tokens inválidos
        if result.get('invalid_tokens'):
            for invalid_token in result['invalid_tokens']:
                token_record = PushToken.query.filter_by(push_token=invalid_token).first()
                if token_record:
                    token_record.is_active = False
            from login import db
            db.session.commit()
            logger.info(f"🗑️ {len(result['invalid_tokens'])} tokens inválidos desactivados")

        return result

    except Exception as e:
        logger.error(f"❌ Error enviando push a usuario {user_id}: {e}")
        return {'success': 0, 'failed': len(tokens) if tokens else 0, 'error': str(e)}
