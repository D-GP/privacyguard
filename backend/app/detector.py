import re
from dataclasses import dataclass
from typing import List

from .transformer_detector import TransformerDetector

try:
    from presidio_analyzer import AnalyzerEngine
    PRESIDIO_AVAILABLE = True
except ImportError:
    AnalyzerEngine = None
    PRESIDIO_AVAILABLE = False


@dataclass
class DetectedEntity:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    source: str


# Keep the existing public constants for compatibility with other modules.
PATTERNS = {
    "EMAIL_ADDRESS": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "PHONE_NUMBER": r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)",
    "IP_ADDRESS": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "PAN_IN": r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "IFSC_IN": r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "AADHAAR_IN": r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",
    "CREDIT_CARD": r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
    "PASSPORT_IN": r"\b[A-Z][0-9]{7}\b",
    "UPI_ID": r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b",
    "VEHICLE_REGISTRATION": r"\b[A-Z]{2}[-\s]?\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?\d{4}\b",
}

BANK_ACCOUNT_CONTEXT = re.compile(
    r"""(?:bank\s+account|account\s+number|a/c\s+number|account\s+no\.?|a/c)
        [\s:#-]* (\d{9,18})\b""",
    re.IGNORECASE | re.VERBOSE,
)

SENSITIVITY = {
    "AADHAAR_IN": 0.95, "CREDIT_CARD": 0.95, "PAN_IN": 0.90,
    "PASSPORT_IN": 0.90, "BANK_ACCOUNT_IN": 0.90, "UPI_ID": 0.85,
    "PHONE_NUMBER": 0.85, "VEHICLE_REGISTRATION": 0.80,
    "EMAIL_ADDRESS": 0.75, "IP_ADDRESS": 0.65, "IFSC_IN": 0.60,
    "PERSON": 0.55, "LOCATION": 0.55, "ORGANIZATION": 0.45,
    "DATE_TIME": 0.25,
}

STRUCTURED_TYPES = set(PATTERNS) | {"BANK_ACCOUNT_IN"}
NER_TYPES = {"PERSON", "ORGANIZATION", "LOCATION", "MISC"}


class HybridDetector:
    def __init__(self):
        self.engine = None
        if PRESIDIO_AVAILABLE:
            try:
                self.engine = AnalyzerEngine()
            except Exception as exc:
                print("Presidio unavailable:", exc)

        self.transformer = None
        try:
            self.transformer = TransformerDetector()
            print("Transformer NER loaded successfully.")
        except Exception as exc:
            print("Transformer NER unavailable:", exc)

    @staticmethod
    def _luhn_valid(number: str) -> bool:
        digits = [int(ch) for ch in number if ch.isdigit()]
        if not 13 <= len(digits) <= 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit
        return checksum % 10 == 0

    def _regex(self, text: str) -> List[DetectedEntity]:
        entities = []
        for label, pattern in PATTERNS.items():
            flags = re.IGNORECASE if label in {"EMAIL_ADDRESS", "UPI_ID"} else 0
            for match in re.finditer(pattern, text, flags=flags):
                value = match.group(0)

                if label == "IP_ADDRESS":
                    if any(int(part) > 255 for part in value.split(".")):
                        continue

                if label == "AADHAAR_IN" and len(re.sub(r"\D", "", value)) != 12:
                    continue

                if label == "CREDIT_CARD" and not self._luhn_valid(value):
                    continue

                # A UPI ID and an email address share the '@' format.
                # Avoid labeling ordinary email domains as UPI handles.
                if label == "UPI_ID" and "." in value.split("@", 1)[1]:
                    continue

                entities.append(DetectedEntity(
                    label, value, match.start(), match.end(), 0.98, "regex/checksum"
                ))

        for match in BANK_ACCOUNT_CONTEXT.finditer(text):
            entities.append(DetectedEntity(
                "BANK_ACCOUNT_IN", match.group(1),
                match.start(1), match.end(1), 0.95, "regex/context"
            ))
        return entities

    def _presidio(self, text: str) -> List[DetectedEntity]:
        if self.engine is None:
            return []
        try:
            results = self.engine.analyze(text=text, language="en")
        except Exception as exc:
            print("Presidio detection error:", exc)
            return []

        entities = []
        for result in results:
            start, end = int(result.start), int(result.end)
            if 0 <= start < end <= len(text):
                entities.append(DetectedEntity(
                    str(result.entity_type), text[start:end], start, end,
                    float(result.score), "presidio/NER"
                ))
        return entities

    def _transformer(self, text: str) -> List[DetectedEntity]:
        if self.transformer is None:
            return []
        try:
            results = self.transformer.detect(text)
        except Exception as exc:
            print("Transformer detection error:", exc)
            return []

        entities = []
        for item in results:
            try:
                start, end = int(item["start"]), int(item["end"])
                if not 0 <= start < end <= len(text):
                    continue
                entities.append(DetectedEntity(
                    str(item["entity_type"]), text[start:end],
                    start, end, float(item["confidence"]),
                    str(item.get("source", "transformer-ner"))
                ))
            except (KeyError, TypeError, ValueError) as exc:
                print("Invalid transformer result:", exc)
        return entities

    @staticmethod
    def _is_likely_ordinary_word(entity: DetectedEntity, text: str) -> bool:
        if entity.entity_type.upper() not in {"PERSON", "ORGANIZATION", "LOCATION"}:
            return False
        if not 0 <= entity.start < entity.end <= len(text):
            return False

        word = text[entity.start:entity.end].strip().lower()
        rules = {
            "apple": [
                r"\b(?:ate|eat|eating|eats|fresh|green|red)\s+(?:an?\s+)?apple\b",
                r"\bapple\s+(?:fruit|juice|pie|tree|orchard)\b",
            ],
            "may": [
                r"\bmonth\s+of\s+may\b",
                r"\bmay\s+(?:comes|come|is)\s+after\s+april\b",
                r"\bin\s+may\b",
            ],
            "rose": [
                r"\b(?:red|pink|white|yellow)\s+rose\b",
                r"\brose\s+(?:flower|flowers|petals|bush|plant)\b",
                r"\ba\s+rose\s+flower\b",
            ],
        }
        if word not in rules:
            return False
        context = text[max(0, entity.start - 45):min(len(text), entity.end + 45)]
        return any(re.search(rule, context, re.IGNORECASE) for rule in rules[word])

    @staticmethod
    def _is_pii_field_label(entity: DetectedEntity, text: str) -> bool:
        """Suppress NER-only field-label mistakes, not actual PII values."""
        if entity.entity_type.upper() not in NER_TYPES:
            return False
        if not 0 <= entity.start < entity.end <= len(text):
            return False

        span = text[entity.start:entity.end]
        remaining = text[entity.start:]
        # 'IFSC:' is a label; an IFSC code is still retained separately.
        if span.upper() == "IFSC" and re.match(r"IFSC\s*:", remaining, re.I):
            return True

        # BERT sometimes tokenizes 'UPI' as the spurious entity 'UP'.
        if span.upper() == "UP" and re.match(r"UPI\s+ID\b", remaining, re.I):
            return True

        # A whole 'UPI ID' field label is not a named entity.
        if span.upper() == "UPI ID":
            return True
        return False

    def _context_validate(
        self, entities: List[DetectedEntity], text: str
    ) -> List[DetectedEntity]:
        validated = []
        for entity in entities:
            if not 0 <= entity.start < entity.end <= len(text):
                continue
            if self._is_pii_field_label(entity, text):
                continue
            if self._is_likely_ordinary_word(entity, text):
                continue
            validated.append(entity)
        return validated

    @staticmethod
    def _merge(items: List[DetectedEntity]) -> List[DetectedEntity]:
        """Resolve overlapping candidates, preferring structured PII.

        For nonstructured overlaps, prefer the longer span and then confidence.
        """
        def priority(item: DetectedEntity):
            is_structured = item.entity_type.upper() in STRUCTURED_TYPES
            is_regex = item.source.startswith("regex")
            return (
                int(is_structured),
                int(is_regex),
                item.end - item.start,
                item.confidence,
            )

        accepted = []
        for item in sorted(items, key=priority, reverse=True):
            if item.start < 0 or item.end <= item.start:
                continue
            overlaps = any(
                item.start < other.end and other.start < item.end
                for other in accepted
            )
            if not overlaps:
                accepted.append(item)
        return sorted(accepted, key=lambda item: item.start)

    def detect(self, text: str) -> List[DetectedEntity]:
        if not isinstance(text, str) or not text.strip():
            return []

        all_entities = (
            self._regex(text)
            + self._presidio(text)
            + self._transformer(text)
        )
        return self._merge(self._context_validate(all_entities, text))
