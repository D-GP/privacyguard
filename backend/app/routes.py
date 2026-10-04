import json
from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
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

def current_user():
    uid = int(get_jwt_identity())
    return User.query.get(uid)

def scan_payload(scan):
    return {
        "id": scan.id, "title": scan.title, "source_type": scan.source_type,
        "risk_score": scan.risk_score, "risk_level": scan.risk_level,
        "entity_count": scan.entity_count, "utility_score": scan.utility_score,
        "reidentification_score": scan.reidentification_score,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }

@api.get("/health")
def health():
    return jsonify({"status": "ok", "service": "PrivacyGuard AI"})

@api.post("/auth/register")
def register():
    data = request.get_json() or {}
    name, email, password = data.get("name", "").strip(), data.get("email", "").strip().lower(), data.get("password", "")
    if not name or not email or len(password) < 8:
        return jsonify({"message": "Name, email and an 8+ character password are required."}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"message": "An account with this email already exists."}), 409
    user = User(name=name, email=email, password_hash=hash_password(password))
    db.session.add(user); db.session.commit()
    token = create_access_token(identity=str(user.id))
    return jsonify({"token": token, "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}}), 201

@api.post("/auth/login")
def login():
    data = request.get_json() or {}
    user = User.query.filter_by(email=data.get("email", "").strip().lower()).first()
    if not user or not verify_password(data.get("password", ""), user.password_hash):
        return jsonify({"message": "Invalid email or password."}), 401
    return jsonify({"token": create_access_token(identity=str(user.id)), "user": {"id": user.id, "name": user.name, "email": user.email, "role": user.role}})

@api.get("/auth/me")
@jwt_required()
def me():
    u = current_user()
    return jsonify({"id": u.id, "name": u.name, "email": u.email, "role": u.role})

@api.post("/analyze")
@jwt_required()
def analyze():
    user = current_user()
    source_type = "text"
    title = "Text scan"
    text = ""
    if "file" in request.files and request.files["file"].filename:
        file = request.files["file"]
        text = extract_text(file)
        source_type = file.filename.rsplit(".", 1)[-1].lower()
        title = file.filename
    else:
        data = request.get_json() or {}
        text = data.get("text", "")
        title = data.get("title", "Text scan")
    if not text.strip():
        return jsonify({"message": "No text was supplied."}), 400

    entities = detector.detect(text)
    risk = calculate_risk(entities, text)
    scan = Scan(user_id=user.id, title=title, source_type=source_type, original_text=text,
                risk_score=risk["score"], risk_level=risk["level"], entity_count=len(entities))
    db.session.add(scan); db.session.flush()
    for e, er in zip(entities, risk["entity_risks"]):
        db.session.add(Entity(scan_id=scan.id, entity_type=e.entity_type, text=e.text,
                              start=e.start, end=e.end, confidence=e.confidence,
                              source=e.source, risk_contribution=er["contribution"]))
    db.session.commit()
    log_action(user.id, "ANALYZE", scan.id, {"entities": len(entities), "risk": risk["score"]})
    return jsonify({**scan_payload(scan), "text": text, "entities": [e.__dict__ for e in entities], "risk": risk, "graph": build_graph(entities)})

@api.post("/scans/<int:scan_id>/sanitize")
@jwt_required()
def sanitize(scan_id):
    user = current_user(); scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    mode = (request.get_json() or {}).get("mode", "adaptive")
    entities = [type("E", (), {"entity_type": e.entity_type, "text": e.text, "start": e.start, "end": e.end}) for e in scan.entities]
    sanitized = san.transform(scan.original_text, entities, mode)
    post_entities = detector.detect(sanitized)
    before = scan.risk_score
    post_risk = calculate_risk(post_entities, sanitized)
    scan.sanitized_text = sanitized
    scan.reidentification_score = post_risk["score"]
    scan.utility_score = round(max(0.0, 1 - abs(len(sanitized)-len(scan.original_text))/max(1, len(scan.original_text))), 4)
    db.session.commit()
    log_action(user.id, "SANITIZE", scan.id, {"mode": mode, "before": before, "after": post_risk["score"]})
    return jsonify({"scan": scan_payload(scan), "sanitized_text": sanitized,
                    "remaining_entities": [e.__dict__ for e in post_entities],
                    "post_risk": post_risk, "risk_reduction": round(before-post_risk["score"], 4)})

@api.get("/scans")
@jwt_required()
def scans():
    user = current_user()
    rows = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(50).all()
    return jsonify([scan_payload(s) for s in rows])

@api.get("/scans/<int:scan_id>")
@jwt_required()
def get_scan(scan_id):
    user = current_user(); scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    risk = calculate_risk([type("E", (), {"entity_type": e.entity_type, "text": e.text, "start": e.start, "end": e.end, "confidence": e.confidence}) for e in scan.entities], scan.original_text)
    return jsonify({**scan_payload(scan), "original_text": scan.original_text, "sanitized_text": scan.sanitized_text,
                    "entities": [{"type": e.entity_type, "text": e.text, "start": e.start, "end": e.end, "confidence": e.confidence, "source": e.source} for e in scan.entities], "risk": risk})

@api.get("/dashboard")
@jwt_required()
def dashboard():
    user = current_user(); rows = Scan.query.filter_by(user_id=user.id).all()
    total = len(rows); high = sum(s.risk_level in {"HIGH", "CRITICAL"} for s in rows)
    avg = round(sum(s.risk_score for s in rows)/total*100, 1) if total else 0
    return jsonify({"total_scans": total, "high_risk_scans": high, "average_risk": avg,
                    "entities_found": sum(s.entity_count for s in rows),
                    "risk_distribution": {k: sum(s.risk_level == k for s in rows) for k in ["LOW","MEDIUM","HIGH","CRITICAL"]}})

@api.get("/audit")
@jwt_required()
def audit():
    user = current_user()
    rows = AuditLog.query.filter_by(user_id=user.id).order_by(AuditLog.created_at.desc()).limit(100).all()
    return jsonify([{"id": r.id, "action": r.action, "scan_id": r.scan_id, "details": json.loads(r.details or "{}"), "created_at": r.created_at.isoformat()} for r in rows])

@api.get("/scans/<int:scan_id>/report")
@jwt_required()
def report(scan_id):
    user = current_user(); scan = Scan.query.filter_by(id=scan_id, user_id=user.id).first_or_404()
    entities = scan.entities
    lightweight = [type("E", (), {"entity_type": e.entity_type, "text": e.text, "start": e.start, "end": e.end, "confidence": e.confidence, "source": e.source}) for e in entities]
    risk = calculate_risk(lightweight, scan.original_text)
    pdf = make_report(scan, lightweight, risk)
    log_action(user.id, "EXPORT_REPORT", scan.id, {})
    return send_file(pdf, mimetype="application/pdf", as_attachment=True, download_name=f"privacyguard-scan-{scan.id}.pdf")
