from datetime import datetime, timezone
from . import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="analyst")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(180), nullable=False, default="Untitled scan")
    source_type = db.Column(db.String(30), nullable=False, default="text")
    original_text = db.Column(db.Text, nullable=False)
    sanitized_text = db.Column(db.Text, nullable=True)
    risk_score = db.Column(db.Float, nullable=False, default=0.0)
    risk_level = db.Column(db.String(20), nullable=False, default="LOW")
    entity_count = db.Column(db.Integer, nullable=False, default=0)
    utility_score = db.Column(db.Float, nullable=True)
    reidentification_score = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    entities = db.relationship("Entity", backref="scan", cascade="all, delete-orphan")

class Entity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)
    entity_type = db.Column(db.String(80), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    start = db.Column(db.Integer, nullable=False)
    end = db.Column(db.Integer, nullable=False)
    confidence = db.Column(db.Float, nullable=False, default=0.0)
    source = db.Column(db.String(40), nullable=False, default="regex")
    risk_contribution = db.Column(db.Float, nullable=False, default=0.0)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    scan_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
