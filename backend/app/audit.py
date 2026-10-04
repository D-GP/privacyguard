import json
from . import db
from .models import AuditLog

def log_action(user_id, action, scan_id=None, details=None):
    row = AuditLog(user_id=user_id, action=action, scan_id=scan_id, details=json.dumps(details or {}))
    db.session.add(row)
    db.session.commit()
    return row
