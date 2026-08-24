import unittest

from brama_assurance.sanitizer import BoundaryRejected, validate_sanitized_event


DIGEST = "d" * 64


class BoundaryV02Tests(unittest.TestCase):
    def base(self):
        return {
            "submission_id": "opaque-1",
            "platform": "platform-class",
            "observed_at": "2026-08-24T04:00:00Z",
            "evidence_sha256": DIGEST,
            "review_state": "RECEIVED",
        }

    def test_raw_locator_is_denied(self):
        event = self.base()
        event["url"] = "denied"
        with self.assertRaises(BoundaryRejected):
            validate_sanitized_event(event)

    def test_directive_field_is_denied(self):
        event = self.base()
        event["directive"] = "denied"
        with self.assertRaises(BoundaryRejected):
            validate_sanitized_event(event)

    def test_extended_metadata_is_allowed(self):
        event = self.base()
        event.update({
            "source_type": "account",
            "finding_confidence": 0.8,
            "attribution_confidence": 0.3,
            "policy_sha256": "e" * 64,
            "provenance_status": "UNVERIFIED",
        })
        validate_sanitized_event(event)


if __name__ == "__main__":
    unittest.main()
