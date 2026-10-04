import math
from collections import Counter
from .detector import SENSITIVITY

QI_TYPES = {"PERSON", "LOCATION", "ORGANIZATION", "DATE_TIME", "PHONE_NUMBER", "EMAIL_ADDRESS", "PAN_IN", "AADHAAR_LIKE", "IFSC_IN"}

def uniqueness(entity, text):
    value = entity.text.strip().lower()
    if not value:
        return 0.0
    frequency = text.lower().count(value)
    length_factor = min(1.0, len(value) / 24)
    return min(1.0, 0.35 + 0.25 * (1 / max(1, frequency)) + 0.40 * length_factor)

def calculate_risk(entities, text):
    if not entities:
        return {"score": 0.0, "level": "LOW", "explanations": [], "entity_risks": [], "pair_risks": []}

    entity_risks = []
    product = 1.0
    for e in entities:
        base = SENSITIVITY.get(e.entity_type, 0.40)
        u = uniqueness(e, text)
        contribution = min(1.0, base * (0.55 + 0.45 * e.confidence) * (0.60 + 0.40 * u))
        product *= (1 - contribution)
        entity_risks.append({"type": e.entity_type, "text": e.text, "uniqueness": round(u, 3), "contribution": round(contribution, 3)})

    pair_risks = []
    for i in range(len(entities)):
        for j in range(i + 1, len(entities)):
            a, b = entities[i], entities[j]
            if a.entity_type not in QI_TYPES and b.entity_type not in QI_TYPES:
                continue
            distance = max(1, abs(a.start - b.start))
            proximity = math.exp(-distance / 180.0)
            pair = min(0.35, 0.30 * SENSITIVITY.get(a.entity_type, .4) * SENSITIVITY.get(b.entity_type, .4) * proximity)
            product *= (1 - pair)
            pair_risks.append({"types": [a.entity_type, b.entity_type], "proximity": round(proximity, 3), "contribution": round(pair, 3)})

    score = min(1.0, max(0.0, 1 - product))
    if score >= 0.75:
        level = "CRITICAL"
    elif score >= 0.55:
        level = "HIGH"
    elif score >= 0.30:
        level = "MEDIUM"
    else:
        level = "LOW"

    explanations = []
    high = sorted(entity_risks, key=lambda x: x["contribution"], reverse=True)[:3]
    for e in high:
        explanations.append(f"{e['type']} contributes approximately {round(e['contribution']*100)}% to entity-level risk.")
    if pair_risks:
        explanations.append("Multiple identifiers occur close together, increasing potential re-identification risk.")
    if len(entities) >= 4:
        explanations.append("The document contains several identifiers that can be linked as a combined profile.")

    return {"score": round(score, 4), "level": level, "explanations": explanations, "entity_risks": entity_risks, "pair_risks": pair_risks}
