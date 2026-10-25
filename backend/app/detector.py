import re

from dataclasses import dataclass

from typing import List



from .transformer_detector import TransformerDetector





# ============================================================

# OPTIONAL PRESIDIO IMPORT

# ============================================================



try:

    from presidio_analyzer import AnalyzerEngine

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





# Bank account numbers are detected only when accompanied by context.

BANK_ACCOUNT_CONTEXT = re.compile(

    r"""

    (?:

        bank\s+account

        | account\s+number

        | a/c\s+number

        | account\s+no\.?

        | a/c

    )

    [\s:#-]*

    (\d{9,18})

    """,

    re.IGNORECASE | re.VERBOSE,

)





# ============================================================

# SENSITIVITY VALUES

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

        # Initialize Presidio if installed.

        self.engine = None



        if PRESIDIO_AVAILABLE:

            try:

                self.engine = AnalyzerEngine()

            except Exception as exc:

                print("Presidio unavailable:", exc)



        # Initialize transformer NER.

        self.transformer = None



        try:

            self.transformer = TransformerDetector()

            print("Transformer NER loaded successfully.")

        except Exception as exc:

            print("Transformer NER unavailable:", exc)



    # ========================================================

    # LUHN CHECKSUM VALIDATION

    # ========================================================



    @staticmethod

    def _luhn_valid(number: str) -> bool:

        digits = [int(char) for char in number if char.isdigit()]



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



    def _regex(self, text: str) -> List[DetectedEntity]:

        entities = []



        for label, pattern in PATTERNS.items():

            flags = (

                re.IGNORECASE

                if label in {"EMAIL_ADDRESS", "UPI_ID"}

                else 0

            )



            for match in re.finditer(pattern, text, flags=flags):

                value = match.group(0)



                # Validate IP address octets.

                if label == "IP_ADDRESS":

                    try:

                        if any(

                            int(part) > 255

                            for part in value.split(".")

                        ):

                            continue

                    except ValueError:

                        continue



                # Check Aadhaar digit count.

                if label == "AADHAAR_IN":

                    digits = re.sub(r"\D", "", value)



                    if len(digits) != 12:

                        continue



                # Validate credit card number.

                if label == "CREDIT_CARD":

                    if not self._luhn_valid(value):

                        continue



                entities.append(

                    DetectedEntity(

                        entity_type=label,

                        text=value,

                        start=match.start(),

                        end=match.end(),

                        confidence=0.98,

                        source="regex/checksum",

                    )

                )



        # Context-based bank account detection.

        for match in BANK_ACCOUNT_CONTEXT.finditer(text):

            account_number = match.group(1)



            entities.append(

                DetectedEntity(

                    entity_type="BANK_ACCOUNT_IN",

                    text=account_number,

                    start=match.start(1),

                    end=match.end(1),

                    confidence=0.95,

                    source="regex/context",

                )

            )



        return entities



    # ========================================================

    # PRESIDIO DETECTION

    # ========================================================



    def _presidio(self, text: str) -> List[DetectedEntity]:

        if self.engine is None:

            return []



        try:

            results = self.engine.analyze(

                text=text,

                language="en",

            )

        except Exception as exc:

            print("Presidio detection error:", exc)

            return []



        entities = []



        for result in results:

            start = int(result.start)

            end = int(result.end)



            entities.append(

                DetectedEntity(

                    entity_type=str(result.entity_type),

                    text=text[start:end],

                    start=start,

                    end=end,

                    confidence=float(result.score),

                    source="presidio/NER",

                )

            )



        return entities



    # ========================================================

    # TRANSFORMER NER DETECTION

    # ========================================================



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

                entities.append(

                    DetectedEntity(

                        entity_type=str(item["entity_type"]),

                        text=str(item["text"]),

                        start=int(item["start"]),

                        end=int(item["end"]),

                        confidence=float(item["confidence"]),

                        source=str(

                            item.get("source", "transformer-ner")

                        ),

                    )

                )

            except (KeyError, TypeError, ValueError) as exc:

                print("Invalid transformer result:", exc)



        return entities



    # ========================================================

    # CONTEXT-AWARE VALIDATION

    # ========================================================



    @staticmethod

    def _is_likely_ordinary_word(

        entity: DetectedEntity,

        text: str,

    ) -> bool:

        """

        Detect a few known cases where an English word is likely

        being used in its ordinary meaning rather than as an entity.



        This is a conservative prototype, not a general language model.

        """



        # Only validate unstructured NER entity types.

        if entity.entity_type.upper() not in {

            "PERSON",

            "ORGANIZATION",

            "LOCATION",

        }:

            return False



        # Ensure offsets are valid.

        if (

            entity.start < 0

            or entity.end > len(text)

            or entity.start >= entity.end

        ):

            return False



        # Use the actual source-text span.

        word = text[entity.start:entity.end].strip().lower()



        if word not in {"apple", "may", "rose"}:

            return False



        # Inspect nearby words.

        left = max(0, entity.start - 45)

        right = min(len(text), entity.end + 45)

        context = text[left:right].lower()



        ordinary_word_rules = {

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



        return any(

            re.search(pattern, context, flags=re.IGNORECASE)

            for pattern in ordinary_word_rules[word]

        )



    def _context_validate(

        self,

        entities: List[DetectedEntity],

        text: str,

    ) -> List[DetectedEntity]:

        """

        Remove only candidates covered by the specific ordinary-word

        rules above. Keep all other detections.

        """



        validated = []



        for entity in entities:

            # Only work with valid source-text spans.
            if not (0 <= entity.start < entity.end <= len(text)):
                continue

            detected = text[entity.start:entity.end]
            label = entity.entity_type.upper()

            # Suppress NER mistakes on PII field labels, but retain the
            # actual IFSC_IN / UPI_ID values from structured detectors.
            if label in {"ORGANIZATION", "MISC", "PERSON", "LOCATION"}:
                tail = text[entity.start:]
                if (
                    detected.upper() == "IFSC"
                    and re.match(r"IFSC\s*:", tail, flags=re.IGNORECASE)
                ):
                    continue
                if (
                    detected.upper() == "UP"
                    and re.match(r"UPI\s+ID\b", tail, flags=re.IGNORECASE)
                ):
                    continue
                if detected.upper() == "UPI ID":
                    continue

            # 'May submitted...' is likely a person's name, not a month.
            # Restrict this to explicit action verbs; do not rewrite
            # 'in May' or the modal verb 'May I ...'.
            if (
                label == "DATE_TIME"
                and detected == "May"
                and re.match(
                    r"May\s+(?:submitted|visited|completed|prepared|"
                    r"attended|finished|reported|presented|delivered)\b",
                    text[entity.start:],
                    flags=re.IGNORECASE,
                )
            ):
                entity = DetectedEntity(
                    entity_type="PERSON",
                    text=detected,
                    start=entity.start,
                    end=entity.end,
                    confidence=0.80,
                    source="context/disambiguation",
                )

            if self._is_likely_ordinary_word(entity, text):

                print(

                    "Context validation: ordinary-word candidate:",

                    repr(entity.text),

                    entity.entity_type,

                )

                continue



            validated.append(entity)



        return validated



    # ========================================================

    # MERGE / REMOVE DUPLICATES

    # ========================================================



    @staticmethod

    def _merge(

        items: List[DetectedEntity],

    ) -> List[DetectedEntity]:



        items = sorted(

            items,

            key=lambda item: (

                item.start,

                -(item.end - item.start),

                -item.confidence,

            ),

        )



        accepted = []



        for item in items:

            if item.start < 0 or item.end <= item.start:

                continue



            duplicate = False



            for existing in accepted:

                # Candidate is contained within an existing entity.

                if (

                    item.start >= existing.start

                    and item.end <= existing.end

                ):

                    duplicate = True

                    break



                overlap = max(

                    0,

                    min(item.end, existing.end)

                    - max(item.start, existing.start),

                )



                smaller_length = max(

                    1,

                    min(

                        item.end - item.start,

                        existing.end - existing.start,

                    ),

                )



                overlap_ratio = overlap / smaller_length



                if overlap_ratio > 0.5:

                    duplicate = True

                    break



            if not duplicate:

                accepted.append(item)



        return sorted(accepted, key=lambda item: item.start)



    # ========================================================

    # MAIN DETECTION FUNCTION

    # ========================================================



    def detect(self, text: str) -> List[DetectedEntity]:



        if not isinstance(text, str) or not text.strip():

            return []



        # 1. Structured PII detection.

        regex_entities = self._regex(text)



        # 2. Presidio detection.

        presidio_entities = self._presidio(text)



        # 3. Transformer NER detection.

        transformer_entities = self._transformer(text)



        # 4. Combine detector results.

        all_entities = (

            regex_entities

            + presidio_entities

            + transformer_entities

        )



        # 5. Context-aware validation.

        validated_entities = self._context_validate(

            all_entities,

            text,

        )



        # 6. Merge duplicate/overlapping detections.

        return self._merge(validated_entities)