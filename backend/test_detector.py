"""
PrivacyGuard AI - detector test file
------------------------------------
Save this as: backend/test_detector.py

Run from the backend folder:
    python test_detector.py

This tests the HybridDetector with ordinary words and common PII examples.
It prints detected entities and reports basic checks. Detection results can vary
depending on the installed Presidio/Transformer models, so review failures rather
than assuming every model prediction is a bug.
"""

import sys
from pathlib import Path

# Allow imports when this file is run from the backend folder.
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    from app.detector import HybridDetector
except Exception as exc:
    print("Could not import HybridDetector.")
    print("Make sure this file is in the backend folder and dependencies are installed.")
    print(f"Import error: {exc}")
    raise SystemExit(1)


TEST_CASES = [
    {
        "name": "Ordinary word: apple as fruit",
        "text": "I ate an apple after lunch.",
        "expect_no_named_entity": True,
    },
    {
        "name": "Ordinary word: May as month",
        "text": "The meeting is scheduled in May.",
        "expect_no_named_entity": True,
    },
    {
        "name": "Ordinary word: rose as flower",
        "text": "She planted a red rose in the garden.",
        "expect_no_named_entity": True,
    },
    {
        "name": "Real person name",
        "text": "Please send the report to Rahul Sharma.",
        "expect_person": True,
    },
    {
        "name": "Email address",
        "text": "Contact the user at gowtham.test@example.com.",
        "expect_type": "EMAIL_ADDRESS",
    },
    {
        "name": "Indian phone number",
        "text": "Call me at +91 9876543210.",
        "expect_type": "PHONE_NUMBER",
    },
    {
        "name": "PAN format",
        "text": "PAN: ABCDE1234F.",
        "expect_type": "PAN_IN",
    },
    {
        "name": "IFSC format",
        "text": "IFSC: SBIN0001234.",
        "expect_type": "IFSC_IN",
    },
    {
        "name": "UPI ID",
        "text": "Pay using the UPI ID gowtham@okaxis.",
        "expect_type": "UPI_ID",
    },
    {
        "name": "Invalid IPv4 octet should not be detected",
        "text": "Server IP: 999.999.999.999.",
        "expect_no_type": "IP_ADDRESS",
    },
]


def normalize_type(value):
    return str(value).upper()


def run_tests():
    print("=" * 72)
    print("PrivacyGuard AI - HybridDetector tests")
    print("=" * 72)

    detector = HybridDetector()
    passed = 0
    failed = 0

    for index, case in enumerate(TEST_CASES, start=1):
        print(f"\n[{index}/{len(TEST_CASES)}] {case['name']}")
        print(f"Input: {case['text']}")

        try:
            entities = detector.detect(case["text"])
        except Exception as exc:
            failed += 1
            print(f"FAIL: detector raised an exception: {exc}")
            continue

        for entity in entities:
            print(
                f"  - {entity.entity_type}: {entity.text!r} "
                f"(confidence={entity.confidence:.2f}, source={entity.source}, "
                f"span={entity.start}:{entity.end})"
            )

        types = {normalize_type(entity.entity_type) for entity in entities}
        success = True
        reasons = []

        if case.get("expect_no_named_entity"):
            named_types = {"PERSON", "ORGANIZATION", "LOCATION"}
            unwanted = [
                entity for entity in entities
                if normalize_type(entity.entity_type) in named_types
            ]
            if unwanted:
                success = False
                reasons.append(
                    "ordinary-word sentence still contains a PERSON/ORGANIZATION/LOCATION entity"
                )

        if case.get("expect_person") and "PERSON" not in types:
            success = False
            reasons.append("expected a PERSON entity; NER models may vary")

        expected_type = case.get("expect_type")
        if expected_type and normalize_type(expected_type) not in types:
            success = False
            reasons.append(f"expected entity type {expected_type} was not detected")

        unwanted_type = case.get("expect_no_type")
        if unwanted_type and normalize_type(unwanted_type) in types:
            success = False
            reasons.append(f"unexpected entity type {unwanted_type} was detected")

        if success:
            passed += 1
            print("RESULT: PASS")
        else:
            failed += 1
            print("RESULT: CHECK")
            for reason in reasons:
                print(f"  Reason: {reason}")

    print("\n" + "=" * 72)
    print(f"Finished: {passed} passed, {failed} need review, {len(TEST_CASES)} total")
    print("Note: the real-person NER test may vary by model/version.")
    print("=" * 72)


if __name__ == "__main__":
    run_tests()
