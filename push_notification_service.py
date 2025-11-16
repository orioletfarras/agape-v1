"""
Servicio para enviar push notifications usando Expo Push Notification Service
"""

from exponent_server_sdk import (
    DeviceNotRegisteredError,
    PushClient,
    PushMessage,
    PushServerError,
    PushTicketError,
)
from requests.exceptions import ConnectionError, HTTPError
import logging

# Configurar logger
logger = logging.getLogger(__name__)

class PushNotificationService:
    def __init__(self):
        self.client = PushClient()

    def send_push_notification(self, push_token, title, body, data=None):
        """
        Envía una push notification a un dispositivo específico

        Args:
            push_token (str): Token de Expo Push del dispositivo
            title (str): Título de la notificación
            body (str): Cuerpo de la notificación
            data (dict): Datos adicionales para enviar con la notificación

        Returns:
            bool: True si se envió correctamente, False en caso contrario
        """
        try:
            # Validar que el token tenga el formato correcto
            if not push_token or not push_token.startswith('ExponentPushToken['):
                logger.error(f"❌ Token inválido: {push_token}")
                return False

            # Crear el mensaje de push
            message = PushMessage(
                to=push_token,
                title=title,
                body=body,
                data=data or {},
                sound='default',
                badge=None,  # El backend puede calcular el badge count
                priority='high',
            )

            # Enviar la notificación
            response = self.client.publish(message)

            # Verificar errores
            try:
                response.validate_response()
                logger.info(f"✅ Push notification enviada exitosamente a {push_token[:20]}...")
                return True
            except DeviceNotRegisteredError:
                # El token ya no es válido, debería eliminarse de la base de datos
                logger.warning(f"⚠️ Token no registrado (dispositivo desinstalado o expirado): {push_token}")
                return False
            except PushTicketError as exc:
                logger.error(f"❌ Error en ticket de push: {exc}")
                return False

        except PushServerError as exc:
            logger.error(f"❌ Error del servidor de push: {exc}")
            return False
        except (ConnectionError, HTTPError) as exc:
            logger.error(f"❌ Error de conexión con Expo Push Service: {exc}")
            return False
        except Exception as exc:
            logger.error(f"❌ Error inesperado enviando push notification: {exc}")
            return False

    def send_bulk_push_notifications(self, push_tokens, title, body, data=None):
        """
        Envía push notifications a múltiples dispositivos

        Args:
            push_tokens (list): Lista de tokens de Expo Push
            title (str): Título de la notificación
            body (str): Cuerpo de la notificación
            data (dict): Datos adicionales

        Returns:
            dict: Diccionario con estadísticas de envío
        """
        if not push_tokens:
            return {'success': 0, 'failed': 0}

        success_count = 0
        failed_count = 0
        invalid_tokens = []

        # Filtrar tokens válidos
        valid_tokens = [token for token in push_tokens if token and token.startswith('ExponentPushToken[')]

        if not valid_tokens:
            logger.warning("⚠️ No hay tokens válidos para enviar notificaciones")
            return {'success': 0, 'failed': len(push_tokens), 'invalid_tokens': push_tokens}

        try:
            # Crear mensajes
            messages = [
                PushMessage(
                    to=token,
                    title=title,
                    body=body,
                    data=data or {},
                    sound='default',
                    priority='high',
                ) for token in valid_tokens
            ]

            # Enviar en lotes (Expo recomienda máximo 100 por lote)
            batch_size = 100
            for i in range(0, len(messages), batch_size):
                batch = messages[i:i + batch_size]
                try:
                    responses = self.client.publish_multiple(batch)

                    # Procesar respuestas
                    for response in responses:
                        try:
                            response.validate_response()
                            success_count += 1
                        except DeviceNotRegisteredError:
                            failed_count += 1
                            # Marcar token como inválido
                            if hasattr(response, 'push_message') and response.push_message.to:
                                invalid_tokens.append(response.push_message.to)
                        except PushTicketError:
                            failed_count += 1

                except Exception as exc:
                    logger.error(f"❌ Error enviando lote de notificaciones: {exc}")
                    failed_count += len(batch)

            logger.info(f"📊 Envío masivo completado: {success_count} exitosas, {failed_count} fallidas")

        except Exception as exc:
            logger.error(f"❌ Error en envío masivo de notificaciones: {exc}")
            failed_count = len(valid_tokens)

        return {
            'success': success_count,
            'failed': failed_count,
            'invalid_tokens': invalid_tokens
        }

# Instancia global del servicio
push_service = PushNotificationService()
