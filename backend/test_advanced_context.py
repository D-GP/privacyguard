"""
PrivacyGuard AI - Advanced Context-Aware Detection Diagnostics

Place in: privacyguard-ai/backend/test_advanced_context.py
Run: python test_advanced_context.py

Uses synthetic example data only. CHECK means a potential issue to investigate,
not proof that the model is incorrect.
"""
from app.detector import HybridDetector

CASES = [
    ("Apple fruit", "I ate a green apple yesterday.",
     [], [("ORGANIZATION", "apple")]),
    ("Apple company", "Apple released a new laptop.",
     [("ORGANIZATION", "Apple")], []),
    ("May as month", "The conference takes place in May.",
     [("DATE_TIME", "May")], [("PERSON", "May")]),
    ("May as name", "May submitted the project report.",
     [("PERSON", "May")], []),
    ("Rose as flower", "A pink rose bloomed in the garden.",
     [], [("PERSON", "rose")]),
    ("Rose as name", "Rose completed her homework.",
     [("PERSON", "Rose")], []),
    ("Jordan as person", "Jordan prepared the presentation.",
     [("PERSON", "Jordan")], []),
    ("Jordan as country", "They traveled to Jordan last summer.",
     [], []),
    ("Amazon company", "Amazon announced a new service.",
     [("ORGANIZATION", "Amazon")], []),
    ("Amazon river", "The Amazon River flows through South America.",
     [], []),
    ("IFSC field label", "IFSC: SBIN0001234.",
     [("IFSC_IN", "SBIN0001234")], [("ORGANIZATION", "IFSC")]),
    ("UPI field label", "Pay via UPI ID gowtham@okaxis.",
     [("UPI_ID", "gowtham@okaxis")], [("MISC", "UP")]),
    ("Email in a sentence", "Write to demo.student@example.com for details.",
     [("EMAIL_ADDRESS", "demo.student@example.com")], []),
    ("Indian phone", "Contact us at +91 9876543210 tomorrow.",
     [("PHONE_NUMBER", "+91 9876543210")], []),
    ("PAN", "The sample PAN is ABCDE1234F.",
     [("PAN_IN", "ABCDE1234F")], []),
    ("Invalid IPv4", "The invalid address is 999.999.999.999.",
     [], [("IP_ADDRESS", "999.999.999.999")]),
    ("Multiple structured PII",
     "Contact demo.student@example.com or call +91 9876543210.",
     [("EMAIL_ADDRESS", "demo.student@example.com"),
      ("PHONE_NUMBER", "+91 9876543210")], []),
    ("Ordinary English", "The student opened a book near the window.",
     [], [("PERSON", "student"), ("ORGANIZATION", "book")]),
]

def main():
    print("=" * 75)
    print("PrivacyGuard AI - Advanced Context Diagnostics")
    print("=" * 75)
    detector = HybridDetector()
    clean = 0
    review = 0

    for index, (name, text, expected, forbidden) in enumerate(CASES, 1):
        print(f"\n[{index}/{len(CASES)}] {name}")
        print("Input:", text)
        try:
            entities = detector.detect(text)
        except Exception as exc:
            print("RESULT: ERROR:", repr(exc))
            review += 1
            continue

        found = set()
        bad_spans = []
        for entity in entities:
            kind = str(entity.entity_type).upper()
            value = str(entity.text)
            found.add((kind, value.casefold()))
            start, end = entity.start, entity.end
            if not (0 <= start < end <= len(text)) or text[start:end] != value:
                bad_spans.append((kind, value, start, end))
            print(
                f"  {kind}: {value!r} | confidence={entity.confidence:.2f}"
                f" | source={entity.source} | span={start}:{end}"
            )
        if not entities:
            print("  No entities detected")

        missing = [(kind, value) for kind, value in expected
                   if (kind.upper(), value.casefold()) not in found]
        unwanted = [(kind, value) for kind, value in forbidden
                    if (kind.upper(), value.casefold()) in found]

        if missing or unwanted or bad_spans:
            review += 1
            print("RESULT: CHECK")
            if missing:
                print("  Expected but missing:", missing)
            if unwanted:
                print("  Potential false positives:", unwanted)
            if bad_spans:
                print("  Invalid text spans:", bad_spans)
        else:
            clean += 1
            print("RESULT: OK")

    print("\n" + "=" * 75)
    print(f"Finished: {clean} OK, {review} CHECK/ERROR, {len(CASES)} cases")
    print("These are diagnostic expectations, not a complete accuracy benchmark.")
    print("Review CHECK cases in context before modifying detector.py.")
    print("=" * 75)

if __name__ == "__main__":
    main()
