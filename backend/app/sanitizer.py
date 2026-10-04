import hashlib
import re
from typing import List
from .detector import DetectedEntity

class Sanitizer:
    def transform(self, text: str, entities: List[DetectedEntity], mode: str = "adaptive"):
        replacements = []
        counters = {}
        for e in entities:
            counters[e.entity_type] = counters.get(e.entity_type, 0) + 1
            n = counters[e.entity_type]
            if mode == "mask":
                replacement = "[REDACTED]"
            elif mode == "pseudonymize":
                replacement = f"<{e.entity_type}_{n}>"
            elif mode == "hash":
                replacement = "<HASH_" + hashlib.sha256(e.text.encode()).hexdigest()[:10] + ">"
            elif mode == "remove":
                replacement = ""
            else:
                replacement = self._adaptive(e, n)
            replacements.append((e.start, e.end, replacement))

        output = text
        for start, end, replacement in sorted(replacements, reverse=True):
            output = output[:start] + replacement + output[end:]
        return output

    @staticmethod
    def _adaptive(e, n):
        high = {"AADHAAR_LIKE", "CREDIT_CARD", "PAN_IN", "PHONE_NUMBER"}
        medium = {"EMAIL_ADDRESS", "IP_ADDRESS", "IFSC_IN"}
        if e.entity_type in high:
            return f"<{e.entity_type}_{n}>"
        if e.entity_type in medium:
            return f"<{e.entity_type}_{n}>"
        if e.entity_type in {"PERSON", "LOCATION", "ORGANIZATION"}:
            return f"<{e.entity_type}_{n}>"
        return "[REDACTED]"
