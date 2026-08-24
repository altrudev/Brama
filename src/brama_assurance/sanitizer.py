from __future__ import annotations

from datetime import datetime
import re

ALLOWED_KEYS = {
    "submission_id",
    "platform",
    "observed_at",
    "evidence_sha256",
    "review_state",
    "authority_id",
    "decision",
    "outcome",
}
PROHIBITED_CONTENT_KEYS = {
    "content",
    "raw_content",
    "text",
    "body",
    "payload",
    "message",
    "transcript",
    "media",
    "attachment",
}
SHA256 = re.compile(r"^[a-f0-9]{64}$")


class BoundaryRejected(ValueError):
    pass


def validate_sanitized_event(event: dict) -> None:
    keys = set(event)
    prohibited = keys & PROHIBITED_CONTENT_KEYS
    if prohibited:
        raise BoundaryRejected(f"raw content-like field denied: {sorted(prohibited)[0]}")
    unknown = keys - ALLOWED_KEYS
    if unknown:
        raise BoundaryRejected(f"unknown field denied: {sorted(unknown)[0]}")
    required = {"submission_id", "platform", "observed_at", "evidence_sha256", "review_state"}
    missing = required - keys
    if missing:
        raise BoundaryRejected(f"missing required field: {sorted(missing)[0]}")
    if not isinstance(event["submission_id"], str) or not event["submission_id"]:
        raise BoundaryRejected("submission_id must be non-empty text")
    if not isinstance(event["platform"], str) or not event["platform"]:
        raise BoundaryRejected("platform must be non-empty text")
    if not isinstance(event["evidence_sha256"], str) or not SHA256.fullmatch(event["evidence_sha256"]):
        raise BoundaryRejected("valid evidence_sha256 required")
    try:
        datetime.fromisoformat(str(event["observed_at"]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise BoundaryRejected("observed_at must be ISO-8601") from exc
