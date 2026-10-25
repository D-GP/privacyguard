"""Context-aware, bounded PII risk scoring (0.0 to 1.0).

Compatible with routes.py: calculate_risk(entities, text) -> dict.
Risk scores are heuristic indicators, not breach probabilities.
"""
import math
from .detector import SENSITIVITY

QI_TYPES = {
    "PERSON", "LOCATION", "DATE_TIME", "PHONE_NUMBER", "EMAIL_ADDRESS",
    "PAN_IN", "AADHAAR_IN", "BANK_ACCOUNT_IN", "PASSPORT_IN", "UPI_ID",
    "CREDIT_CARD", "VEHICLE_REGISTRATION", "IP_ADDRESS",
}


def uniqueness(entity, text):
    value = str(entity.text or "").strip().lower()
    if not value:
        return 0.0
    frequency = max(1, (text or "").lower().count(value))
    length_factor = min(1.0, len(value) / 24.0)
    return min(1.0, 0.35 + 0.25 / frequency + 0.40 * length_factor)


def _level(score):
    if score >= 0.75:
        return "CRITICAL"
    if score >= 0.55:
        return "HIGH"
    if score >= 0.30:
        return "MEDIUM"
    return "LOW"


def calculate_risk(entities, text):
    entities = list(entities or [])
    if not entities:
        return {"score": 0.0, "level": "LOW", "explanations": [],
                "entity_risks": [], "pair_risks": []}

    # Preserve one entity_risks entry per entity and its original order.
    # routes.py uses zip(entities, risk["entity_risks"]).
    seen = set()
    unique = []
    entity_risks = []
    for e in entities:
        kind = str(e.entity_type)
        value = str(e.text or "").strip()
        key = (kind, value.casefold())
        duplicate = key in seen
        if not duplicate:
            seen.add(key)
        u = uniqueness(e, text)
        confidence = max(0.0, min(1.0, float(getattr(e, "confidence", 0.5))))
        base = max(0.0, min(1.0, float(SENSITIVITY.get(kind, 0.40))))
        # An individual entity's contribution depends on its sensitivity,
        # detection confidence, and uniqueness in the source document.
        contribution = min(1.0, base * (0.55 + 0.45 * confidence) * (0.60 + 0.40 * u))
        if duplicate:
            contribution = 0.0
        else:
            unique.append((e, contribution))
        entity_risks.append({"type": kind, "text": value,
                             "uniqueness": round(u, 3),
                             "contribution": round(contribution, 3)})

    # Combination bonuses apply only to different PII types. The bounded
    # score avoids extreme inflation from large lists of repeated identifiers.
    strongest_by_type = {}
    for e, c in unique:
        strongest_by_type[e.entity_type] = max(
            strongest_by_type.get(e.entity_type, 0.0), c)
    ranked = sorted(strongest_by_type.values(), reverse=True)
    primary = ranked[0] if ranked else 0.0
    diversity_bonus = min(0.16, 0.10 * sum(ranked[1:]))

    pair_risks = []
    max_pair = 0.0
    for i, (a, _) in enumerate(unique):
        for b, _ in unique[i + 1:]:
            if a.entity_type == b.entity_type:
                continue
            if a.entity_type not in QI_TYPES or b.entity_type not in QI_TYPES:
                continue
            distance = max(1, abs(int(a.start) - int(b.start)))
            proximity = math.exp(-distance / 180.0)
            strength = (SENSITIVITY.get(a.entity_type, 0.4)
                        * SENSITIVITY.get(b.entity_type, 0.4))
            pair = min(0.08, 0.08 * strength * proximity)
            max_pair = max(max_pair, pair)
            pair_risks.append({"types": [a.entity_type, b.entity_type],
                               "proximity": round(proximity, 3),
                               "contribution": round(pair, 3)})

    score = round(min(1.0, max(0.0, primary + diversity_bonus + max_pair)), 4)
    explanations = []
    for e in sorted(entity_risks, key=lambda x: x["contribution"], reverse=True)[:3]:
        if e["contribution"] > 0:
            explanations.append(
                f"{e['type']} has an entity-level sensitivity contribution of "
                f"{round(e['contribution'] * 100)}% (not a breach probability).")
    if len(strongest_by_type) > 1:
        explanations.append("Different identifier types occur together, increasing linkage risk.")
    if max_pair > 0:
        explanations.append("Nearby identifiers add a bounded proximity risk bonus.")
    if len(unique) < len(entities):
        explanations.append("Repeated identical identifiers were counted only once for scoring.")

    return {"score": score, "level": _level(score),
            "explanations": explanations, "entity_risks": entity_risks,
            "pair_risks": pair_risks}
