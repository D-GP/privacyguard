"""PrivacyGuard AI: inspect context-sensitive NER false positives.

Place in backend/test_false_positives.py and run:
    python test_false_positives.py

This diagnostic script does not change the detector. CHECK means a model
prediction deserves review, not that the application necessarily failed.
"""
from app.detector import HybridDetector

CASES = [
    ("Apple as fruit", "I ate a fresh apple after lunch.", {"apple": {"PERSON", "ORGANIZATION", "LOCATION"}}),
    ("Apple as company", "Apple announced a new product today.", {}),
    ("May as month", "The meeting is scheduled in May.", {"may": {"PERSON", "ORGANIZATION", "LOCATION"}}),
    ("May as person's name", "May visited the library yesterday.", {}),
    ("Rose as flower", "She planted a red rose in the garden.", {"rose": {"PERSON", "ORGANIZATION", "LOCATION"}}),
    ("Rose as person's name", "Rose submitted her assignment.", {}),
    ("IFSC label", "IFSC: SBIN0001234.", {"ifsc": {"ORGANIZATION", "PERSON", "LOCATION", "MISC"}}),
    ("UPI label", "Pay using the UPI ID gowtham@okaxis.", {"up": {"MISC", "PERSON", "ORGANIZATION"}, "upi": {"MISC", "PERSON", "ORGANIZATION"}}),
    ("Person name", "Please send the report to Rahul Sharma.", {}),
    ("Ordinary text", "The student read a book under a tree.", {}),
]


def main():
    detector = HybridDetector()
    review_count = 0
    print("\n" + "=" * 70)
    print("PrivacyGuard AI - Context / False Positive Diagnostics")
    print("=" * 70)

    for index, (label, sentence, suspicious) in enumerate(CASES, 1):
        print(f"\n[{index}/{len(CASES)}] {label}\nInput: {sentence}")
        try:
            entities = detector.detect(sentence)
        except Exception as exc:
            print(f"ERROR: {type(exc).__name__}: {exc}")
            review_count += 1
            continue

        if not entities:
            print("  No entities detected")
        flagged = []
        for entity in entities:
            kind = str(entity.entity_type).upper()
            value = str(entity.text)
            print(f"  {kind}: {value!r} | confidence={entity.confidence:.2f} | source={entity.source}")
            if kind in suspicious.get(value.strip().lower(), set()):
                flagged.append(f"{kind}: {value!r}")

        if flagged:
            review_count += 1
            print("RESULT: CHECK - possible false positive(s): " + ", ".join(flagged))
        else:
            print("RESULT: OK - no specifically flagged prediction")

    print("\n" + "=" * 70)
    print(f"Completed {len(CASES)} cases; {review_count} case(s) flagged for review.")
    print("Review the full output: OK does not guarantee perfect detection.")


if __name__ == "__main__":
    main()
