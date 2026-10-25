"""PrivacyGuard AI: explainable, heuristic privacy risk scoring.

This score describes potential exposure of detected information, not a
probability of harm, a legal compliance verdict, or a calibrated ML metric.
"""
from dataclasses import dataclass, asdict
from typing import Any, Iterable

# Matches entity types emitted by the current HybridDetector.
SENSITIVITY = {
    "AADHAAR_IN": .95, "CREDIT_CARD": .95, "PAN_IN": .90,
    "PASSPORT_IN": .90, "BANK_ACCOUNT_IN": .90, "UPI_ID": .85,
    "PHONE_NUMBER": .85, "VEHICLE_REGISTRATION": .80,
    "EMAIL_ADDRESS": .75, "IP_ADDRESS": .65, "IFSC_IN": .60,
    "PERSON": .55, "LOCATION": .55, "ORGANIZATION": .45,
    "DATE_TIME": .25, "MISC": .30,
}

# Unrecognized labels do not automatically become high-risk PII.
UNKNOWN_SENSITIVITY = .30

@dataclass
class RiskResult:
    score: int
    level: str
    entity_count: int
    distinct_types: list[str]
    factors: list[str]
    disclaimer: str = "Heuristic exposure score; not a legal or clinical assessment."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def assess_risk(entities: Iterable[Any]) -> RiskResult:
    """Score detected entities without retaining their raw PII in the result.

    Supports HybridDetector DetectedEntity objects or dictionaries with
    entity_type and confidence. Ignores malformed entities.
    """
    clean = []
    seen = set()
    for item in entities:
        if isinstance(item, dict):
            label = item.get("entity_type", "")
            confidence = item.get("confidence", 0)
            start, end = item.get("start"), item.get("end")
            value = item.get("text", "")
        else:
            label = getattr(item, "entity_type", "")
            confidence = getattr(item, "confidence", 0)
            start, end = getattr(item, "start", None), getattr(item, "end", None)
            value = getattr(item, "text", "")
        if not isinstance(label, str) or not label.strip():
            continue
        try:
            conf = max(0.0, min(1.0, float(confidence)))
        except (TypeError, ValueError):
            continue
        if conf != conf:  # NaN
            continue
        label = label.upper().strip()
        key = (label, start, end, str(value))
        if key in seen:
            continue
        seen.add(key)
        clean.append((label, conf))

    if not clean:
        return RiskResult(0, "Low", 0, [], ["No detected entities"])

    # Strongest single finding: 0-57 points. Multiple findings: up to 25.
    weights = sorted((SENSITIVITY.get(t, UNKNOWN_SENSITIVITY) * c
                      for t, c in clean), reverse=True)
    strongest = 60 * weights[0]
    additional = min(25.0, 15 * sum(weights[1:]))
    types = sorted({t for t, _ in clean})
    diversity = min(10.0, max(0, len(types) - 1) * 3.0)

    # Higher exposure when financial/identity identifiers occur with contact info.
    sensitive = {"AADHAAR_IN", "PAN_IN", "PASSPORT_IN", "CREDIT_CARD",
                 "BANK_ACCOUNT_IN", "UPI_ID"}
    contact = {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON"}
    combo = 5.0 if set(types) & sensitive and set(types) & contact else 0.0
    score = round(min(100.0, strongest + additional + diversity + combo))
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 35:
        level = "Medium"
    else:
        level = "Low"

    factors = [f"Highest weighted finding: {weights[0]:.2f}"]
    if len(clean) > 1:
        factors.append(f"Multiple detected entities: {len(clean)}")
    if len(types) > 1:
        factors.append(f"Different entity types: {len(types)}")
    if combo:
        factors.append("Identity/financial and contact information appear together")
    return RiskResult(score, level, len(clean), types, factors)
