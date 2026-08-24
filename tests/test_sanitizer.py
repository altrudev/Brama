import unittest

from brama_assurance.sanitizer import BoundaryRejected, validate_sanitized_event


class SanitizerTests(unittest.TestCase):
    def base(self):
        return {
            "submission_id": "opaque-1",
            "platform": "platform-class",
            "observed_at": "2026-08-23T00:00:00Z",
            "evidence_sha256": "b" * 64,
            "review_state": "HUMAN_REVIEW_PENDING",
        }

    def test_sanitized_event_passes(self):
        validate_sanitized_event(self.base())

    def test_raw_content_field_denied(self):
        event = self.base()
        key = "raw_" + "content"
        event[key] = "denied"
        with self.assertRaises(BoundaryRejected):
            validate_sanitized_event(event)

    def test_unknown_field_denied(self):
        event = self.base()
        event["extra"] = "denied"
        with self.assertRaises(BoundaryRejected):
            validate_sanitized_event(event)
