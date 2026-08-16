from . import db
from flask_login import UserMixin
from datetime import datetime, timezone


def _utcnow():
    return datetime.now(timezone.utc)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250))
    email = db.Column(db.String(100), unique=True, index=True)
    password = db.Column(db.String(500))  # null for SSO-only accounts
    phone = db.Column(db.String(30), nullable=True)
    auth_provider = db.Column(db.String(30), default="local", nullable=False)
    provider_sub = db.Column(db.String(255), nullable=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    picture = db.Column(db.String(500), nullable=True)
    role = db.Column(db.String(20), default="user", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)

    def to_json(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "auth_provider": self.auth_provider,
            "email_verified": self.email_verified,
            "role": self.role,
        }


class Scan(db.Model):
    id = db.Column(db.String(36), primary_key=True)  # uuid
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    target = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(20), default="Passive Scan")
    status = db.Column(db.String(20), default="queued", nullable=False, index=True)
    result_json = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=_utcnow)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)

    user = db.relationship("User", backref="scans")

    def to_dict(self):
        return {
            "scan_id": self.id,
            "target": self.target,
            "scan_type": self.scan_type,
            "status": self.status,
            "result": self.result_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }
