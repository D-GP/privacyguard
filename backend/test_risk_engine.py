
"""Run from backend: python test_risk_engine.py"""
from app.risk_engine import assess_risk


def entity(label, confidence=0.98, start=0, end=4, text="test"):
    return dict(
        entity_type=label,
        confidence=confidence,
        start=start,
        end=end,
        text=text,
    )


def run():
    examples = [
        ("No PII", []),
        ("Name", [entity("PERSON")]),
        ("Email + phone", [
            entity("EMAIL_ADDRESS"),
            entity("PHONE_NUMBER", start=5, end=9),
        ]),
        ("PAN + phone", [
            entity("PAN_IN"),
            entity("PHONE_NUMBER", start=5, end=9),
        ]),
        ("Aadhaar + bank + phone", [
            entity("AADHAAR_IN"),
            entity("BANK_ACCOUNT_IN", start=5, end=9),
            entity("PHONE_NUMBER", start=10, end=14),
        ]),
    ]

    for title, entities in examples:
        result = assess_risk(entities)
        assert 0 <= result.score <= 100
        print(
            f"{title:24} score={result.score:3} "
            f"level={result.level}"
        )

    assert assess_risk([]).score == 0

    assert assess_risk([entity("PERSON")]).score < assess_risk([
        entity("PERSON"),
        entity("PAN_IN", start=5, end=9),
    ]).score

    assert assess_risk([
        entity("PAN_IN"),
        entity("PAN_IN"),
    ]).entity_count == 1

    print("Risk engine smoke tests passed")


if __name__ == "__main__":
    run()
