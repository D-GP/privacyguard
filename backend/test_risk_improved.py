"""Run from the backend directory: python test_risk_improved.py"""
from types import SimpleNamespace
from app.risk import calculate_risk


def ent(kind, value, start=0, confidence=0.99):
    return SimpleNamespace(entity_type=kind, text=value, start=start,
                           end=start + len(value), confidence=confidence)


def check(name, entities, text):
    result = calculate_risk(entities, text)
    assert 0 <= result["score"] <= 1
    assert result["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert len(result["entity_risks"]) == len(entities)
    assert all("contribution" in row for row in result["entity_risks"])
    print(f"{name:25} score={result['score']:.4f} level={result['level']}")
    return result


def run():
    email = ent("EMAIL_ADDRESS", "demo@example.com", 10)
    phone = ent("PHONE_NUMBER", "+91 9876543210", 40)
    a = check("No PII", [], "No identifiers here")
    b = check("Email", [email], "Contact demo@example.com")
    c = check("Email + phone", [email, phone], "Contact demo@example.com or +91 9876543210")
    d = check("Repeated email", [email, ent("EMAIL_ADDRESS", "demo@example.com", 60)], "demo@example.com demo@example.com")
    e = check("Aadhaar + bank", [ent("AADHAAR_IN", "123412341234"), ent("BANK_ACCOUNT_IN", "123456789012", 30)], "123412341234 123456789012")
    assert a["score"] == 0
    assert c["score"] >= b["score"]
    assert d["score"] <= b["score"] + 0.001
    assert d["entity_risks"][1]["contribution"] == 0
    assert e["score"] >= b["score"]
    print("All improved risk engine regression tests passed.")

if __name__ == "__main__":
    run()
