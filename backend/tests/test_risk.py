from app.risk import calculate_risk
from types import SimpleNamespace

def test_empty_risk():
    result = calculate_risk([], "hello")
    assert result["score"] == 0
    assert result["level"] == "LOW"

def test_multiple_identifiers_raise_risk():
    text = "John lives in Kochi. Email john@example.com and phone 9876543210."
    entities = [
        SimpleNamespace(entity_type="PERSON", text="John", start=0, end=4, confidence=.9),
        SimpleNamespace(entity_type="LOCATION", text="Kochi", start=14, end=19, confidence=.9),
        SimpleNamespace(entity_type="EMAIL_ADDRESS", text="john@example.com", start=27, end=43, confidence=.98),
        SimpleNamespace(entity_type="PHONE_NUMBER", text="9876543210", start=55, end=65, confidence=.98),
    ]
    result = calculate_risk(entities, text)
    assert result["score"] > 0.5
    assert result["pair_risks"]
