from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from .canonical import sha256_json


@dataclass(frozen=True)
class ReconsiderationRecord:
    case_id: str
    requested_at: str
    requester_role: str
    reason_code: str
    independent_review_required: bool = True

    def validate(self) -> None:
        if not self.case_id or not self.requester_role or not self.reason_code:
            raise ValueError("case_id, requester_role and reason_code are required")
        try:
            datetime.fromisoformat(self.requested_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("requested_at must be ISO-8601") from exc

    def record_hash(self) -> str:
        self.validate()
        return sha256_json(
            {
                "case_id": self.case_id,
                "requested_at": self.requested_at,
                "requester_role": self.requester_role,
                "reason_code": self.reason_code,
                "independent_review_required": self.independent_review_required,
            }
        )
