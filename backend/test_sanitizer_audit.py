
import re
from collections import Counter

from app.detector import HybridDetector
from app.sanitizer import Sanitizer
from app.risk import calculate_risk


# ============================================================
# PRIVACYGUARD AI - SANITIZER AUDIT TEST
# ============================================================

TEST_TEXT = """
Name: Rahul Sharma
Email: rahul.sharma@example.com
Phone: +91 9876543210
PAN: ABCDE1234F
City: Kochi, Kerala

May submitted the report.
Rose completed her homework.
"""

# Generated placeholders used by PrivacyGuard AI.
PLACEHOLDER_PATTERN = re.compile(
    r"<(?:[A-Z][A-Z0-9_]*_[0-9]+|HASH_[0-9a-fA-F]{10})>"
)

# Sensitive identifiers we expect to protect in this test.
EXPECTED_IDENTIFIERS = {
    "EMAIL_ADDRESS": "rahul.sharma@example.com",
    "PHONE_NUMBER": "+91 9876543210",
    "PAN_IN": "ABCDE1234F",
}

# Names included in the test.
EXPECTED_NAMES = ["Rahul Sharma", "May", "Rose"]


def section(title):
    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)


def entity_span_valid(entity, text):
    """Check whether an entity's offsets match the original text."""
    start = entity.start
    end = entity.end

    if not (
        isinstance(start, int)
        and isinstance(end, int)
        and 0 <= start < end <= len(text)
    ):
        return False

    return text[start:end] == entity.text


def print_entities(entities, text):
    if not entities:
        print("No entities detected.")
        return

    for index, entity in enumerate(entities, start=1):
        valid = entity_span_valid(entity, text)

        print(f"\n[{index}]")
        print("Type       :", entity.entity_type)
        print("Text       :", repr(entity.text))
        print("Confidence :", round(entity.confidence, 3))
        print("Source     :", getattr(entity, "source", "unknown"))
        print("Start      :", entity.start)
        print("End        :", entity.end)
        print("Span valid :", valid)

        if not valid:
            print("WARNING: Entity text does not match its offsets.")


def detect_overlaps(entities):
    """Find overlapping entity spans."""
    overlaps = []

    ordered = sorted(
        entities,
        key=lambda e: (e.start, e.end)
    )

    for i, first in enumerate(ordered):
        for second in ordered[i + 1:]:
            if second.start >= first.end:
                break

            if (
                first.start < second.end
                and second.start < first.end
            ):
                overlaps.append((first, second))

    return overlaps


def find_cross_line_entities(entities):
    """Find detections that include line breaks."""
    return [
        entity
        for entity in entities
        if "\n" in entity.text or "\r" in entity.text
    ]


def inside_generated_placeholder(text, start, end):
    """Check if a detection span lies inside a generated placeholder."""
    if not (
        isinstance(start, int)
        and isinstance(end, int)
        and 0 <= start < end <= len(text)
    ):
        return False

    for match in PLACEHOLDER_PATTERN.finditer(text):
        if match.start() <= start and end <= match.end():
            return True

    return False


def is_wordpiece_artifact(entity, text):
    """Identify suspicious WordPiece predictions for diagnostics."""
    value = entity.text.strip()

    if not value.startswith("##"):
        return False

    # WordPiece tokens should normally be reconstructed
    # before being exposed as detected entities.
    actual = (
        text[entity.start:entity.end]
        if 0 <= entity.start < entity.end <= len(text)
        else ""
    )

    return actual != value


def classify_residual(entity, text):
    """Classify residual detections without hiding them."""
    if not entity_span_valid(entity, text):
        return "INVALID_SPAN"

    if inside_generated_placeholder(text, entity.start, entity.end):
        return "PLACEHOLDER_ARTIFACT"

    if is_wordpiece_artifact(entity, text):
        return "WORDPIECE_ARTIFACT"

    return "REVIEW_REQUIRED"


def print_risk(title, entities, text):
    """Calculate and display risk using the active risk engine."""
    try:
        risk = calculate_risk(entities, text)

        print(f"\n{title}")
        print("Risk score :", f"{risk['score'] * 100:.2f}%")
        print("Risk level :", risk["level"])

        return risk

    except Exception as exc:
        print("Risk calculation failed:", exc)
        return None


def run_audit():
    section("PRIVACYGUARD AI - SANITIZER AUDIT")

    print("Initializing HybridDetector...")
    detector = HybridDetector()
    sanitizer = Sanitizer()

    # --------------------------------------------------------
    # 1. ORIGINAL TEXT
    # --------------------------------------------------------
    section("1. ORIGINAL TEXT")
    print(TEST_TEXT)

    # --------------------------------------------------------
    # 2. ORIGINAL PII DETECTION
    # --------------------------------------------------------
    section("2. ORIGINAL PII DETECTION")

    entities = detector.detect(TEST_TEXT)
    print_entities(entities, TEST_TEXT)

    print("\nTotal detected entities:", len(entities))

    counts = Counter(e.entity_type for e in entities)

    print("\nEntity distribution:")
    for entity_type, count in sorted(counts.items()):
        print(f"  {entity_type:22} {count}")

    # --------------------------------------------------------
    # 3. DETECTION QUALITY CHECKS
    # --------------------------------------------------------
    section("3. DETECTION QUALITY CHECKS")

    overlaps = detect_overlaps(entities)

    if overlaps:
        print("WARNING: Overlapping entities detected.")

        for first, second in overlaps:
            print(
                f"  {first.entity_type}: {first.text!r}"
                f" overlaps {second.entity_type}: {second.text!r}"
            )
    else:
        print("PASS: No overlapping entity spans.")

    cross_line = find_cross_line_entities(entities)

    if cross_line:
        print("\nWARNING: Entities crossing line boundaries:")

        for entity in cross_line:
            print(
                f"  {entity.entity_type}: {entity.text!r}"
            )
    else:
        print("\nPASS: No entities cross line boundaries.")

    print("\nExpected identifier checks:")

    for entity_type, value in EXPECTED_IDENTIFIERS.items():
        found = any(
            e.entity_type == entity_type
            and e.text == value
            for e in entities
        )

        status = "PASS" if found else "FAIL"

        print(f"  {status}: {entity_type} - {value}")

    print("\nExpected person-name checks:")

    for name in EXPECTED_NAMES:
        found = any(
            e.entity_type == "PERSON"
            and e.text == name
            for e in entities
        )

        status = "PASS" if found else "REVIEW"

        print(f"  {status}: {name}")

    # --------------------------------------------------------
    # 4. ORIGINAL RISK
    # --------------------------------------------------------
    section("4. ORIGINAL RISK ASSESSMENT")

    before_risk = print_risk(
        "Before anonymization:",
        entities,
        TEST_TEXT
    )

    # --------------------------------------------------------
    # 5. ANONYMIZATION
    # --------------------------------------------------------
    section("5. ADAPTIVE ANONYMIZATION")

    sanitized = sanitizer.transform(
        TEST_TEXT,
        entities,
        "adaptive"
    )

    print(sanitized)

    # --------------------------------------------------------
    # 6. DIRECT IDENTIFIER LEAK CHECK
    # --------------------------------------------------------
    section("6. DIRECT IDENTIFIER LEAK CHECK")

    leaked_identifiers = []

    for entity_type, value in EXPECTED_IDENTIFIERS.items():
        if value in sanitized:
            leaked_identifiers.append((entity_type, value))
            print(f"FAIL: {entity_type} remains visible.")
        else:
            print(f"PASS: {entity_type} not visible.")

    # --------------------------------------------------------
    # 7. POST-SANITIZATION DETECTION
    # --------------------------------------------------------
    section("7. POST-SANITIZATION DETECTION")

    remaining = detector.detect(sanitized)

    print("Raw residual detections:", len(remaining))

    for entity in remaining:
        print("\nEntity:", repr(entity.text))
        print("Type:", entity.entity_type)
        print("Confidence:", entity.confidence)
        print("Start:", entity.start)
        print("End:", entity.end)

        if 0 <= entity.start < entity.end <= len(sanitized):
            print(
                "Actual substring:",
                repr(sanitized[entity.start:entity.end])
            )

            print(
                "Context:",
                repr(
                    sanitized[
                        max(0, entity.start - 35):
                        min(len(sanitized), entity.end + 35)
                    ]
                )
            )

        print(
            "Classification:",
            classify_residual(entity, sanitized)
        )

    # --------------------------------------------------------
    # 8. RESIDUAL VALIDATION
    # --------------------------------------------------------
    section("8. VALIDATED RESIDUAL AUDIT")

    placeholder_artifacts = []
    wordpiece_artifacts = []
    invalid_spans = []
    review_required = []

    for entity in remaining:
        classification = classify_residual(
            entity,
            sanitized
        )

        if classification == "PLACEHOLDER_ARTIFACT":
            placeholder_artifacts.append(entity)

        elif classification == "WORDPIECE_ARTIFACT":
            wordpiece_artifacts.append(entity)

        elif classification == "INVALID_SPAN":
            invalid_spans.append(entity)

        else:
            review_required.append(entity)

    print("Raw detections          :", len(remaining))
    print("Placeholder artifacts   :", len(placeholder_artifacts))
    print("WordPiece artifacts     :", len(wordpiece_artifacts))
    print("Invalid spans           :", len(invalid_spans))
    print("Other residual entities :", len(review_required))

    # --------------------------------------------------------
    # 9. POST-SANITIZATION RISK
    # --------------------------------------------------------
    section("9. POST-SANITIZATION RISK")

    after_risk = print_risk(
        "After anonymization (raw detector output):",
        remaining,
        sanitized
    )

    if before_risk and after_risk:
        reduction = (
            before_risk["score"] - after_risk["score"]
        ) * 100

        print(
            "\nRisk score reduction:",
            f"{reduction:.2f} percentage points"
        )

    # --------------------------------------------------------
    # 10. FINAL SUMMARY
    # --------------------------------------------------------
    section("10. FINAL AUDIT SUMMARY")

    print("Original entities       :", len(entities))
    print("Remaining raw entities  :", len(remaining))
    print("Cross-line detections   :", len(cross_line))
    print("Overlapping detections  :", len(overlaps))
    print("Direct identifier leaks :", len(leaked_identifiers))
    print("Residuals for review    :", len(review_required))
    print("Invalid residual spans  :", len(invalid_spans))

    if leaked_identifiers:
        print("\nFAIL: Known sensitive values remain visible.")

    if cross_line:
        print("\nWARNING: Incorrect entity boundaries need fixing.")

    if invalid_spans or wordpiece_artifacts:
        print("\nWARNING: Transformer token/span mapping needs review.")

    if review_required:
        print("\nWARNING: Some residual entities require manual review.")

    if (
        not leaked_identifiers
        and not cross_line
        and not overlaps
        and not invalid_spans
        and not review_required
    ):
        print("\nPASS: No issues found by these audit checks.")
    else:
        print("\nREVIEW REQUIRED: One or more audit checks found issues.")

    print(
        "\nNote: This diagnostic cannot guarantee that "
        "all personal information has been removed."
    )


if __name__ == "__main__":
    run_audit()
