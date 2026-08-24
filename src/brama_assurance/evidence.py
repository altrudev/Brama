from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import re

from .canonical import sha256_json

SHA256 = re.compile(r"^[a-f0-9]{64}$")
ALLOWED_REVIEW_STATES = {
    "RECEIVED",
    "QUARANTINED",
    "HUMAN_REVIEW_PENDING",
    "VERIFIED",
    "REJECTED",
    "INSUFFICIENT_EVIDENCE",
    "AUTHORIZED_FOR_ACTION",
    "ACTION_ACTIVE",
    "OUTCOME_OBSERVED",
    "CLOSED",
}


class EvidenceCapsuleRejected(ValueError):
    pass


@dataclass(frozen=True)
class EvidenceCapsule:
    case_id: str
    evidence_sha256: str
    observed_at: str
    platform: str
    source_type: str
    review_state: str
    finding_confidence: float | None = None
    attribution_confidence: float | None = None
    authority_id: str | None = None
    policy_version: str | None = None
    policy_sha256: str | None = None
    evidence_set_root: str | None = None
    provenance_status: str = "UNAVAILABLE"

    def validate(self) -> None:
        for field_name in ("case_id", "platform", "source_type"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise EvidenceCapsuleRejected(f"{field_name} must be non-empty text")
        if not SHA256.fullmatch(self.evidence_sha256):
            raise EvidenceCapsuleRejected("valid evidence_sha256 required")
        try:
            datetime.fromisoformat(self.observed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceCapsuleRejected("observed_at must be ISO-8601") from exc
        if self.review_state not in ALLOWED_REVIEW_STATES:
            raise EvidenceCapsuleRejected("unsupported review_state")
        if self.policy_sha256 is not None and not SHA256.fullmatch(self.policy_sha256):
            raise EvidenceCapsuleRejected("valid policy_sha256 required when provided")
        if self.evidence_set_root is not None and not SHA256.fullmatch(self.evidence_set_root):
            raise EvidenceCapsuleRejected("valid evidence_set_root required when provided")
        if self.provenance_status not in {"UNAVAILABLE", "UNVERIFIED", "VALID", "INVALID"}:
            raise EvidenceCapsuleRejected("unsupported provenance_status")
        for field_name in ("finding_confidence", "attribution_confidence"):
            value = getattr(self, field_name)
            if value is not None and not (0.0 <= value <= 1.0):
                raise EvidenceCapsuleRejected(f"{field_name} must be between 0 and 1")

    def payload(self) -> dict:
        self.validate()
        return asdict(self)

    def capsule_hash(self) -> str:
        return sha256_json(self.payload())
