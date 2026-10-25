
import json
from datetime import datetime

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
)
from sqlalchemy import func

from . import db
from .models import User, Scan, Entity, AuditLog
from .security import hash_password, verify_password
from .detector import HybridDetector
from .risk import calculate_risk
from .sanitizer import Sanitizer
from .extractor import extract_text
from .audit import log_action
from .graph import build_graph
from .report import make_report


api = Blueprint("api", __name__)

detector = HybridDetector()
san = Sanitizer()


# ============================================================
# HELPERS
# ============================================================

def current_user():
    uid = int(get_jwt_identity())
    return db.session.get(User, uid)


def scan_payload(scan):
    return {
        "id": scan.id,
        "title": scan.title,
        "source_type": scan.source_type,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "entity_count": scan.entity_count,
        "utility_score": scan.utility_score,
        "reidentification_score": scan.reidentification_score,
        "created_at": (
            scan.created_at.isoformat()
            if scan.created_at else None
        ),
    }


def entity_to_detector_object(entity):
    """
    Convert a stored SQLAlchemy Entity into an object
    compatible with the detector, sanitizer, and risk engine.
    """
    return type(
        "DetectedEntityObject",
        (),
        {
            "entity_type": entity.entity_type,
            "text": entity.text,
            "start": entity.start,
            "end": entity.end,
            "confidence": entity.confidence,
            "source": entity.source,
        },
    )()


# ============================================================
# HEALTH CHECK
# ============================================================

@api.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "PrivacyGuard AI",
    })


# ============================================================
# AUTHENTICATION
# ============================================================

@api.post("/auth/register")
def register():
    data = request.get_json(silent=True) or {}

    name = str(data.get("name") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not isinstance(password, str):
        return jsonify({
            "message": "Invalid password format."
        }), 400

    if not name or not email or len(password) < 8:
        return jsonify({
            "message": (
                "Name, email and an 8+ character "
                "password are required."
            )
        }), 400

    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        return jsonify({
            "message": "An account with this email already exists."
        }), 409

    user = User(
        name=name,
        email=email,
        password_hash=hash_password(password),
    )

    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id))

    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        },
    }), 201


@api.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}

    email = str(data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    if not isinstance(password, str):
        return jsonify({
            "message": "Invalid email or password."
        }), 401

    user = User.query.filter_by(email=email).first()

    if not user or not verify_password(
        password, user.password_hash
    ):
        return jsonify({
            "message": "Invalid email or password."
        }), 401

    token = create_access_token(identity=str(user.id))

    return jsonify({
        "token": token,
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        },
    })


@api.get("/auth/me")
@jwt_required()
def me():
    user = current_user()

    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
    })


# ============================================================
# PII ANALYSIS
# ============================================================

@api.post("/analyze")
@jwt_required()
def analyze():
    user = current_user()

    source_type = "text"
    title = "Text scan"
    text = ""

    if (
        "file" in request.files
        and request.files["file"].filename
    ):
        file = request.files["file"]

        text = extract_text(file)

        source_type = (
            file.filename.rsplit(".", 1)[-1].lower()
            if "." in file.filename
            else "file"
        )

        title = file.filename

    else:
        data = request.get_json(silent=True) or {}

        text = data.get("text") or ""
        title = data.get("title") or "Text scan"

    if not isinstance(text, str) or not text.strip():
        return jsonify({
            "message": "No text was supplied."
        }), 400

    if not isinstance(title, str):
        title = "Text scan"

    # Detect personally identifiable information.
    entities = detector.detect(text)

    # Calculate original document risk.
    risk = calculate_risk(entities, text)

    scan = Scan(
        user_id=user.id,
        title=title,
        source_type=source_type,
        original_text=text,
        risk_score=risk["score"],
        risk_level=risk["level"],
        entity_count=len(entities),
    )

    db.session.add(scan)
    db.session.flush()

    # Store detected entities and their risk contributions.
    for index, entity in enumerate(entities):
        entity_risk = (
            risk["entity_risks"][index]
            if index < len(risk["entity_risks"])
            else {}
        )

        stored_entity = Entity(
            scan_id=scan.id,
            entity_type=entity.entity_type,
            text=entity.text,
            start=entity.start,
            end=entity.end,
            confidence=entity.confidence,
            source=entity.source,
            risk_contribution=entity_risk.get(
                "contribution", 0
            ),
        )

        db.session.add(stored_entity)

    db.session.commit()

    log_action(
        user.id,
        "ANALYZE",
        scan.id,
        {
            "entities": len(entities),
            "risk": risk["score"],
        },
    )

    return jsonify({
        **scan_payload(scan),
        "text": text,
        "entities": [
            entity.__dict__ for entity in entities
        ],
        "risk": risk,
        "graph": build_graph(entities),
    })


# ============================================================
# ANONYMIZATION
# ============================================================

@api.post("/scans/<int:scan_id>/sanitize")
@jwt_required()
def sanitize(scan_id):
    user = current_user()

    scan = Scan.query.filter_by(
        id=scan_id,
        user_id=user.id,
    ).first_or_404()

    data = request.get_json(silent=True) or {}
    mode = data.get("mode") or "adaptive"

    allowed_modes = {
        "adaptive",
        "mask",
        "pseudonymize",
        "hash",
        "remove",
    }

    if mode not in allowed_modes:
        return jsonify({
            "message": "Unsupported anonymization mode."
        }), 400

    entities = [
        entity_to_detector_object(entity)
        for entity in scan.entities
    ]

    sanitized_text = san.transform(
        scan.original_text,
        entities,
        mode,
    )

    # Re-scan the anonymized document.
    remaining_entities = detector.detect(sanitized_text)

    original_risk = scan.risk_score or 0

    post_risk = calculate_risk(
        remaining_entities,
        sanitized_text,
    )

    # Preserve original risk and store residual risk separately.
    scan.sanitized_text = sanitized_text
    scan.reidentification_score = post_risk["score"]

    original_length = max(
        1, len(scan.original_text)
    )

    # Length-based utility proxy, not semantic similarity.
    scan.utility_score = round(
        max(
            0.0,
            1 - (
                abs(
                    len(sanitized_text)
                    - len(scan.original_text)
                ) / original_length
            ),
        ),
        4,
    )

    db.session.commit()

    log_action(
        user.id,
        "SANITIZE",
        scan.id,
        {
            "mode": mode,
            "before": original_risk,
            "after": post_risk["score"],
        },
    )

    return jsonify({
        "scan": scan_payload(scan),
        "sanitized_text": sanitized_text,
        "remaining_entities": [
            entity.__dict__
            for entity in remaining_entities
        ],
        "post_risk": post_risk,
        "risk_reduction": round(
            original_risk - post_risk["score"],
            4,
        ),
    })


# ============================================================
# SCAN HISTORY
# ============================================================

@api.get("/scans")
@jwt_required()
def scans():
    user = current_user()

    rows = (
        Scan.query
        .filter_by(user_id=user.id)
        .order_by(
            Scan.created_at.desc(),
            Scan.id.desc(),
        )
        .limit(50)
        .all()
    )

    return jsonify([
        scan_payload(scan)
        for scan in rows
    ])


# ============================================================
# SINGLE SCAN DETAILS
# ============================================================

@api.get("/scans/<int:scan_id>")
@jwt_required()
def get_scan(scan_id):
    user = current_user()

    scan = Scan.query.filter_by(
        id=scan_id,
        user_id=user.id,
    ).first_or_404()

    entities = [
        entity_to_detector_object(entity)
        for entity in scan.entities
    ]

    risk = calculate_risk(
        entities,
        scan.original_text,
    )

    return jsonify({
        **scan_payload(scan),
        "original_text": scan.original_text,
        "sanitized_text": scan.sanitized_text,
        "entities": [
            {
                "type": entity.entity_type,
                "text": entity.text,
                "start": entity.start,
                "end": entity.end,
                "confidence": entity.confidence,
                "source": entity.source,
            }
            for entity in scan.entities
        ],
        "risk": risk,
    })


# ============================================================
# DASHBOARD - PHASE 4B
# ============================================================

@api.get("/dashboard")
@jwt_required()
def dashboard():
    user = current_user()

    # All user scans, not only the latest 50.
    rows = (
        Scan.query
        .filter_by(user_id=user.id)
        .all()
    )

    total_scans = len(rows)

    high_risk_scans = sum(
        scan.risk_level in {"HIGH", "CRITICAL"}
        for scan in rows
    )

    average_risk = (
        round(
            sum(
                (scan.risk_score or 0)
                for scan in rows
            ) / total_scans * 100,
            1,
        )
        if total_scans else 0
    )

    # Original scan risk distribution.
    risk_levels = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]

    risk_distribution = {
        level: sum(
            scan.risk_level == level
            for scan in rows
        )
        for level in risk_levels
    }

    # Count PII categories directly from the database.
    # This includes every scan belonging to the current user.
    category_rows = (
        db.session.query(
            Entity.entity_type,
            func.count(Entity.id),
        )
        .join(
            Scan,
            Entity.scan_id == Scan.id,
        )
        .filter(
            Scan.user_id == user.id
        )
        .group_by(
            Entity.entity_type
        )
        .all()
    )

    pii_categories = {}

    for entity_type, count in category_rows:
        normalized_type = str(
            entity_type or "OTHER"
        ).strip().upper()

        pii_categories[normalized_type] = (
            pii_categories.get(normalized_type, 0)
            + int(count)
        )

    # Sanitization statistics.
    sanitized_scans = [
        scan
        for scan in rows
        if scan.sanitized_text is not None
    ]

    sanitized_count = len(sanitized_scans)

    pending_sanitization = (
        total_scans - sanitized_count
    )

    average_residual_risk = (
        round(
            sum(
                (scan.reidentification_score or 0)
                for scan in sanitized_scans
            ) / sanitized_count * 100,
            1,
        )
        if sanitized_count else 0
    )

    # Recent scans for the dashboard.
    recent_scans = (
        Scan.query
        .filter_by(user_id=user.id)
        .order_by(
            Scan.created_at.desc(),
            Scan.id.desc(),
        )
        .limit(5)
        .all()
    )

    return jsonify({
        # Existing fields - retained for compatibility.
        "total_scans": total_scans,
        "high_risk_scans": high_risk_scans,
        "average_risk": average_risk,
        "entities_found": sum(
            (scan.entity_count or 0)
            for scan in rows
        ),
        "risk_distribution": risk_distribution,

        # New Phase 4B fields.
        "pii_categories": pii_categories,
        "sanitized_scans": sanitized_count,
        "pending_sanitization": pending_sanitization,
        "average_residual_risk": average_residual_risk,
        "recent_scans": [
            scan_payload(scan)
            for scan in recent_scans
        ],
    })


# ============================================================
# AUDIT TRAIL
# ============================================================

@api.get("/audit")
@jwt_required()
def audit():
    user = current_user()

    rows = (
        AuditLog.query
        .filter_by(user_id=user.id)
        .order_by(
            AuditLog.created_at.desc(),
            AuditLog.id.desc(),
        )
        .limit(100)
        .all()
    )

    return jsonify([
        {
            "id": row.id,
            "action": row.action,
            "scan_id": row.scan_id,
            "details": json.loads(
                row.details or "{}"
            ),
            "created_at": (
                row.created_at.isoformat()
                if row.created_at else None
            ),
        }
        for row in rows
    ])


# ============================================================
# PDF REPORT EXPORT
# ============================================================

@api.get("/scans/<int:scan_id>/report")
@jwt_required()
def report(scan_id):
    user = current_user()

    scan = Scan.query.filter_by(
        id=scan_id,
        user_id=user.id,
    ).first_or_404()

    entities = [
        entity_to_detector_object(entity)
        for entity in scan.entities
    ]

    risk = calculate_risk(
        entities,
        scan.original_text,
    )

    pdf = make_report(
        scan,
        entities,
        risk,
    )

    log_action(
        user.id,
        "EXPORT_REPORT",
        scan.id,
        {},
    )

    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=(
            f"privacyguard-scan-{scan.id}.pdf"
        ),
    )
