import re
from dataclasses import dataclass
from typing import List

try:
    from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerRegistry
    PRESIDIO_AVAILABLE = True
except Exception:
    PRESIDIO_AVAILABLE = False

@dataclass
class DetectedEntity:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    source: str

PATTERNS = {
    "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "PHONE_NUMBER": r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "PAN_IN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "IFSC_IN": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "AADHAAR_LIKE": r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",
    "CREDIT_CARD": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
}

SENSITIVITY = {
    "AADHAAR_LIKE": 0.95, "CREDIT_CARD": 0.95, "PAN_IN": 0.90,
    "PHONE_NUMBER": 0.85, "EMAIL_ADDRESS": 0.75, "IP_ADDRESS": 0.65,
    "PERSON": 0.55, "LOCATION": 0.55, "ORGANIZATION": 0.45,
    "DATE_TIME": 0.25, "IFSC_IN": 0.60,
}

class HybridDetector:
    def __init__(self):
        self.engine = None
        if PRESIDIO_AVAILABLE:
            try:
                self.engine = AnalyzerEngine()
            except Exception:
                self.engine = None

    def _regex(self, text: str) -> List[DetectedEntity]:
        out = []
        for label, pattern in PATTERNS.items():
            for m in re.finditer(pattern, text, flags=re.IGNORECASE if label in {"EMAIL_ADDRESS"} else 0):
                value = m.group(0)
                if label == "IP_ADDRESS":
                    try:
                        if any(int(x) > 255 for x in value.split('.')):
                            continue
                    except ValueError:
                        continue
                out.append(DetectedEntity(label, value, m.start(), m.end(), 0.98, "regex/checksum"))
        return out

    def _presidio(self, text: str) -> List[DetectedEntity]:
        if not self.engine:
            return []
        results = self.engine.analyze(text=text, language="en")
        return [DetectedEntity(r.entity_type, text[r.start:r.end], r.start, r.end, float(r.score), "presidio/NER") for r in results]

    @staticmethod
    def _merge(items: List[DetectedEntity]) -> List[DetectedEntity]:
        items = sorted(items, key=lambda x: (x.start, -(x.end-x.start), -x.confidence))
        accepted = []
        for item in items:
            duplicate = False
            for a in accepted:
                if item.start >= a.start and item.end <= a.end:
                    duplicate = True
                    break
                overlap = max(0, min(item.end, a.end) - max(item.start, a.start))
                if overlap / max(1, min(item.end-item.start, a.end-a.start)) > 0.5:
                    duplicate = True
                    break
            if not duplicate:
                accepted.append(item)
        return sorted(accepted, key=lambda x: x.start)

    def detect(self, text: str) -> List[DetectedEntity]:
        return self._merge(self._regex(text) + self._presidio(text))
