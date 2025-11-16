from db import db

class PushToken(db.Model):
    __tablename__ = 'push_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    device_type = db.Column(db.String(50))  # 'ios' or 'android'
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    def __repr__(self):
        return f'<PushToken {self.id}: user_id={self.user_id}, device_type={self.device_type}>'
