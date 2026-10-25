
from transformers import pipeline


class TransformerDetector:
    LABEL_MAP = {
        "PER": "PERSON",
        "LOC": "LOCATION",
        "ORG": "ORGANIZATION",
        "MISC": "MISC",
    }

    def __init__(self):
        self.pipeline = pipeline(
            "token-classification",
            model="dslim/bert-base-NER",
            aggregation_strategy="simple",
        )

    def detect(self, text):
        if not isinstance(text, str) or not text.strip():
            return []

        results = self.pipeline(text)
        entities = []

        for item in results:
            start = int(item["start"])
            end = int(item["end"])

            if not (0 <= start < end <= len(text)):
                continue

            entity_type = self.LABEL_MAP.get(
                item.get("entity_group", "MISC"),
                item.get("entity_group", "MISC"),
            )

            # Use exact source text, not the model's WordPiece string.
            value = text[start:end]

            # Generated anonymization placeholders are not source PII.
            if value.startswith("##"):
                continue

            # Avoid partial predictions wholly inside placeholders.
            import re

            if any(
                m.start() < end and start < m.end()
                for m in re.finditer(
                    r"<(?:[A-Z][A-Z0-9_]*_\d+|HASH_[0-9a-fA-F]{10})>",
                    text,
                )
            ):
                continue

            entities.append({
                "entity_type": entity_type,
                "text": value,
                "start": start,
                "end": end,
                "confidence": float(item["score"]),
                "source": "transformer-ner",
            })

        return entities
