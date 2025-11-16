"""
Script para crear la tabla de push tokens en la base de datos
"""

from login import db, app

# Modelo para guardar los push tokens de los usuarios
class PushToken(db.Model):
    __tablename__ = 'push_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    push_token = db.Column(db.String(255), nullable=False, unique=True)
    platform = db.Column(db.String(20), nullable=False)  # 'ios' o 'android'
    device_name = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    # Relación con el usuario
    user = db.relationship('User', backref='push_tokens')

    # Índice para búsquedas rápidas por usuario
    __table_args__ = (
        db.Index('idx_user_push_tokens', 'user_id', 'is_active'),
    )

if __name__ == '__main__':
    with app.app_context():
        # Crear la tabla
        db.create_all()
        print("✅ Tabla 'push_tokens' creada exitosamente")
