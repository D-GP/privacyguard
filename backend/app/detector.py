import re

from dataclasses import dataclass
from typing import List

from .transformer_detector import TransformerDetector


# ============================================================
# PRESIDIO
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
# INDIAN PII REGEX PATTERNS
# ============================================================

PATTERNS = {

    # --------------------------------------------------------
    # EMAIL
    # --------------------------------------------------------

    "EMAIL_ADDRESS":
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",


    # --------------------------------------------------------
    # INDIAN PHONE NUMBER
    # --------------------------------------------------------

    "PHONE_NUMBER":
        r"(?<!\d)(?:\+91[-\s]?)?[6-9]\d{9}(?!\d)",


    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    "IP_ADDRESS":
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",


    # --------------------------------------------------------
    # INDIAN PAN
    #
    # Example:
    # ABCDE1234F
    # --------------------------------------------------------

    "PAN_IN":
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",


    # --------------------------------------------------------
    # INDIAN IFSC
    #
    # Example:
    # SBIN0001234
    # --------------------------------------------------------

    "IFSC_IN":
        r"\b[A-Z]{4}0[A-Z0-9]{6}\b",


    # --------------------------------------------------------
    # AADHAAR
    #
    # Accept:
    # 1234 5678 9012
    # 1234-5678-9012
    # 123456789012
    # --------------------------------------------------------

    "AADHAAR_IN":
        r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)",


    # --------------------------------------------------------
    # CREDIT / DEBIT CARD
    # --------------------------------------------------------

    "CREDIT_CARD":
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)",


    # --------------------------------------------------------
    # INDIAN PASSPORT
    #
    # Example:
    # A1234567
    # --------------------------------------------------------

    "PASSPORT_IN":
        r"\b[A-Z][0-9]{7}\b",


    # --------------------------------------------------------
    # UPI ID
    #
    # Examples:
    # rahul@oksbi
    # name@upi
    # user123@paytm
    # --------------------------------------------------------

    "UPI_ID":
        r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b",


    # --------------------------------------------------------
    # VEHICLE REGISTRATION
    #
    # Examples:
    # KL07AB1234
    # KA01MN5678
    # TN38C1234
    # --------------------------------------------------------

    "VEHICLE_REGISTRATION":
        r"\b[A-Z]{2}[-\s]?\d{1,2}[-\s]?[A-Z]{1,3}[-\s]?\d{4}\b",


    # --------------------------------------------------------
    # BANK ACCOUNT
    #
    # This is intentionally context-dependent.
    # The actual detection is handled separately below.
    # --------------------------------------------------------

}


# ============================================================
# BANK ACCOUNT CONTEXT
# ============================================================

BANK_ACCOUNT_CONTEXT = re.compile(
    r"""
    (?:
        bank\s+account
        |
        account\s+number
        |
        a\/c\s+number
        |
        account\s+no
        |
        a\/c
    )
    [\s:#-]*
    (\d{9,18})
    """,
    re.IGNORECASE | re.VERBOSE,
)


# ============================================================
# SENSITIVITY
# ============================================================

SENSITIVITY = {

    "AADHAAR_IN": 0.95,

    "CREDIT_CARD": 0.95,

    "PAN_IN": 0.90,

    "PASSPORT_IN": 0.90,

    "BANK_ACCOUNT_IN": 0.90,

    "UPI_ID": 0.85,

    "PHONE_NUMBER": 0.85,

    "VEHICLE_REGISTRATION": 0.80,

    "EMAIL_ADDRESS": 0.75,

    "IP_ADDRESS": 0.65,

    "IFSC_IN": 0.60,

    "PERSON": 0.55,

    "LOCATION": 0.55,

    "ORGANIZATION": 0.45,

    "DATE_TIME": 0.25,
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
    # LUHN VALIDATION
    # ========================================================

    @staticmethod
    def _luhn_valid(number: str) -> bool:

        digits = [
            int(char)
            for char in number
            if char.isdigit()
        ]

        if len(digits) < 13:
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


    # ========================================================
    # REGEX DETECTION
    # ========================================================

    def _regex(
        self,
        text: str
    ) -> List[DetectedEntity]:

        out = []


        # ----------------------------------------------------
        # Normal regex patterns
        # ----------------------------------------------------

        for label, pattern in PATTERNS.items():

            for match in re.finditer(
                pattern,
                text,
                flags=(
                    re.IGNORECASE
                    if label in {
                        "EMAIL_ADDRESS",
                        "UPI_ID"
                    }
                    else 0
                ),
            ):

                value = match.group(0)


                # ------------------------------------------------
                # IP VALIDATION
                # ------------------------------------------------

                if label == "IP_ADDRESS":

                    try:

                        if any(
                            int(x) > 255
                            for x in value.split(".")
                        ):

                            continue

                    except ValueError:

                        continue


                # ------------------------------------------------
                # Aadhaar validation
                # ------------------------------------------------

                if label == "AADHAAR_IN":

                    digits = re.sub(
                        r"\D",
                        "",
                        value
                    )

                    if len(digits) != 12:

                        continue


                # ------------------------------------------------
                # Credit card Luhn validation
                # ------------------------------------------------

                if label == "CREDIT_CARD":

                    if not self._luhn_valid(value):

                        continue


                # ------------------------------------------------
                # Add entity
                # ------------------------------------------------

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


        # ----------------------------------------------------
        # Bank account detection
        # ----------------------------------------------------

        for match in BANK_ACCOUNT_CONTEXT.finditer(text):

            account_number = match.group(1)

            start = match.start(1)

            end = match.end(1)

            out.append(
                DetectedEntity(

                    entity_type="BANK_ACCOUNT_IN",

                    text=account_number,

                    start=start,

                    end=end,

                    confidence=0.95,

                    source="regex/context",
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
    # TRANSFORMER NER
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
    # MERGE / REMOVE DUPLICATES
    # ========================================================

    @staticmethod
    def _merge(
        items: List[DetectedEntity]
    ) -> List[DetectedEntity]:

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
                # Entity inside another entity
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
                        existing.end - existing.start
                    ),
                )


                overlap_ratio = (
                    overlap /
                    smaller_length
                )


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
        # 1. Regex / Indian PII
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
        # 3. Transformer NER
        # ----------------------------------------------------

        transformer_entities = self._transformer(
            text
        )


        # ----------------------------------------------------
        # Combine
        # ----------------------------------------------------

        all_entities = (
            regex_entities
            +
            presidio_entities
            +
            transformer_entities
        )


        # ----------------------------------------------------
        # Remove duplicates
        # ----------------------------------------------------

        return self._merge(
            all_entities
        )