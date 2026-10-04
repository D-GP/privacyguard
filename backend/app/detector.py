import re

from dataclasses import dataclass
from typing import List

from .transformer_detector import TransformerDetector


# ============================================================
# PRESIDIO IMPORT
# ============================================================

try:
    from presidio_analyzer import (
        AnalyzerEngine,
        PatternRecognizer,
        Pattern,
        RecognizerRegistry,
    )

    PRESIDIO_AVAILABLE = True

except Exception:
    PRESIDIO_AVAILABLE = False


# ============================================================
# DETECTED ENTITY
# ============================================================

@dataclass
class DetectedEntity:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float
    source: str


# ============================================================
# REGEX PATTERNS
# ============================================================

PATTERNS = {

    # Email
    "EMAIL_ADDRESS":
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",

    # Indian phone number
    "PHONE_NUMBER":
        r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)",

    # IPv4 address
    "IP_ADDRESS":
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",

    # Indian PAN
    "PAN_IN":
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",

    # Indian IFSC
    "IFSC_IN":
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",

    # Aadhaar-like number
    "AADHAAR_LIKE":
        r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",

    # Credit/debit card-like number
    "CREDIT_CARD":
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",
}


# ============================================================
# SENSITIVITY VALUES
# ============================================================

SENSITIVITY = {

    "AADHAAR_LIKE": 0.95,

    "CREDIT_CARD": 0.95,

    "PAN_IN": 0.90,

    "PHONE_NUMBER": 0.85,

    "EMAIL_ADDRESS": 0.75,

    "IP_ADDRESS": 0.65,

    "PERSON": 0.55,

    "LOCATION": 0.55,

    "ORGANIZATION": 0.45,

    "DATE_TIME": 0.25,

    "IFSC_IN": 0.60,
}


# ============================================================
# HYBRID DETECTOR
# ============================================================

class HybridDetector:

    def __init__(self):

        # ----------------------------------------------------
        # PRESIDIO
        # ----------------------------------------------------

        self.engine = None

        if PRESIDIO_AVAILABLE:

            try:

                self.engine = AnalyzerEngine()

            except Exception as exc:

                print(
                    "Presidio unavailable:",
                    exc
                )

                self.engine = None

        # ----------------------------------------------------
        # TRANSFORMER NER
        # ----------------------------------------------------

        self.transformer = None

        try:

            self.transformer = TransformerDetector()

            print(
                "Transformer NER loaded successfully."
            )

        except Exception as exc:

            print(
                "Transformer NER unavailable:",
                exc
            )


    # ========================================================
    # REGEX DETECTION
    # ========================================================

    def _regex(
        self,
        text: str
    ) -> List[DetectedEntity]:

        out = []

        for label, pattern in PATTERNS.items():

            for match in re.finditer(
                pattern,
                text,
                flags=(
                    re.IGNORECASE
                    if label == "EMAIL_ADDRESS"
                    else 0
                ),
            ):

                value = match.group(0)

                # --------------------------------------------
                # Validate IP address
                # --------------------------------------------

                if label == "IP_ADDRESS":

                    try:

                        if any(
                            int(x) > 255
                            for x in value.split(".")
                        ):

                            continue

                    except ValueError:

                        continue

                # --------------------------------------------
                # Add detected entity
                # --------------------------------------------

                out.append(
                    DetectedEntity(

                        entity_type=label,

                        text=value,

                        start=match.start(),

                        end=match.end(),

                        confidence=0.98,

                        source="regex/checksum",
                    )
                )

        return out


    # ========================================================
    # PRESIDIO DETECTION
    # ========================================================

    def _presidio(
        self,
        text: str
    ) -> List[DetectedEntity]:

        if not self.engine:

            return []

        try:

            results = self.engine.analyze(
                text=text,
                language="en"
            )

        except Exception as exc:

            print(
                "Presidio detection error:",
                exc
            )

            return []

        return [

            DetectedEntity(

                entity_type=result.entity_type,

                text=text[
                    result.start:
                    result.end
                ],

                start=result.start,

                end=result.end,

                confidence=float(
                    result.score
                ),

                source="presidio/NER",
            )

            for result in results
        ]


    # ========================================================
    # TRANSFORMER NER DETECTION
    # ========================================================

    def _transformer(
        self,
        text: str
    ) -> List[DetectedEntity]:

        if not self.transformer:

            return []

        try:

            results = self.transformer.detect(
                text
            )

        except Exception as exc:

            print(
                "Transformer detection error:",
                exc
            )

            return []

        return [

            DetectedEntity(

                entity_type=item["entity_type"],

                text=item["text"],

                start=item["start"],

                end=item["end"],

                confidence=item["confidence"],

                source=item["source"],
            )

            for item in results
        ]


    # ========================================================
    # MERGE RESULTS
    # ========================================================

    @staticmethod
    def _merge(
        items: List[DetectedEntity]
    ) -> List[DetectedEntity]:

        # Sort entities by:
        # 1. Start position
        # 2. Longer entity first
        # 3. Higher confidence first

        items = sorted(
            items,
            key=lambda x: (
                x.start,
                -(x.end - x.start),
                -x.confidence,
            ),
        )

        accepted = []

        for item in items:

            duplicate = False

            for existing in accepted:

                # ------------------------------------------------
                # Entity completely inside another entity
                # ------------------------------------------------

                if (
                    item.start >= existing.start
                    and
                    item.end <= existing.end
                ):

                    duplicate = True

                    break

                # ------------------------------------------------
                # Calculate overlap
                # ------------------------------------------------

                overlap = max(
                    0,

                    min(
                        item.end,
                        existing.end
                    )
                    -
                    max(
                        item.start,
                        existing.start
                    ),
                )

                smaller_length = max(
                    1,

                    min(
                        item.end - item.start,
                        existing.end - existing.start,
                    ),
                )

                overlap_ratio = (
                    overlap /
                    smaller_length
                )

                # ------------------------------------------------
                # Ignore strongly overlapping entity
                # ------------------------------------------------

                if overlap_ratio > 0.5:

                    duplicate = True

                    break

            if not duplicate:

                accepted.append(item)

        return sorted(
            accepted,
            key=lambda x: x.start
        )


    # ========================================================
    # MAIN DETECTION FUNCTION
    # ========================================================

    def detect(
        self,
        text: str
    ) -> List[DetectedEntity]:

        # ----------------------------------------------------
        # 1. Regex
        # ----------------------------------------------------

        regex_entities = self._regex(
            text
        )

        # ----------------------------------------------------
        # 2. Presidio
        # ----------------------------------------------------

        presidio_entities = self._presidio(
            text
        )

        # ----------------------------------------------------
        # 3. Transformer
        # ----------------------------------------------------

        transformer_entities = self._transformer(
            text
        )

        # ----------------------------------------------------
        # Combine everything
        # ----------------------------------------------------

        all_entities = (
            regex_entities
            +
            presidio_entities
            +
            transformer_entities
        )

        # ----------------------------------------------------
        # Remove duplicates/overlaps
        # ----------------------------------------------------

        return self._merge(
            all_entities
        )