from transformers import pipeline


class TransformerDetector:

    def __init__(self):

        self.pipeline = pipeline(
            "token-classification",
            model="dslim/bert-base-NER",
            aggregation_strategy="simple"
        )

    def detect(self, text):

        results = self.pipeline(text)

        entities = []

        label_map = {
            "PER": "PERSON",
            "LOC": "LOCATION",
            "ORG": "ORGANIZATION",
            "MISC": "MISC"
        }

        for item in results:

            entity_group = item.get(
                "entity_group",
                "MISC"
            )

            entity_type = label_map.get(
                entity_group,
                entity_group
            )

            entities.append({
                "entity_type": entity_type,
                "text": item["word"],
                "start": int(item["start"]),
                "end": int(item["end"]),
                "confidence": float(item["score"]),
                "source": "transformer-ner"
            })

        return entities