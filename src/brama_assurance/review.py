from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum

from .canonical import sha256_json


class ReviewDecision(str, Enum):
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class ReviewAttestation:
    case_id: str
    reviewer_id: str
    reviewer_group: str
    evidence_sha256: str
    decision: ReviewDecision
    confidence: float
    occurred_at: str

    def validate(self) -> None:
        if not self.case_id or not self.reviewer_id or not self.reviewer_group:
            raise ValueError("case_id, reviewer_id and reviewer_group are required")
        if len(self.evidence_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.evidence_sha256):
            raise ValueError("valid evidence_sha256 required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        try:
            datetime.fromisoformat(self.occurred_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("occurred_at must be ISO-8601") from exc

    def attestation_hash(self) -> str:
        self.validate()
        value = asdict(self)
        value["decision"] = self.decision.value
        return sha256_json(value)


@dataclass(frozen=True)
class ConsensusResult:
    reached: bool
    decision: str | None
    independent_reviewers: int
    reviewer_groups: int


def evaluate_consensus(
    attestations: list[ReviewAttestation],
    *,
    min_reviewers: int = 2,
    min_groups: int = 1,
) -> ConsensusResult:
    if min_reviewers < 1 or min_groups < 1:
        raise ValueError("minimums must be positive")
    if not attestations:
        return ConsensusResult(False, None, 0, 0)
    for item in attestations:
        item.validate()
    case_ids = {item.case_id for item in attestations}
    evidence = {item.evidence_sha256 for item in attestations}
    if len(case_ids) != 1 or len(evidence) != 1:
        raise ValueError("consensus inputs must address one case and evidence digest")
    reviewers = {item.reviewer_id for item in attestations}
    groups = {item.reviewer_group for item in attestations}
    counts: dict[ReviewDecision, set[str]] = {}
    for item in attestations:
        counts.setdefault(item.decision, set()).add(item.reviewer_id)
    winner = max(counts, key=lambda decision: len(counts[decision]))
    reached = len(counts[winner]) >= min_reviewers and len(groups) >= min_groups
    return ConsensusResult(
        reached=reached,
        decision=winner.value if reached else None,
        independent_reviewers=len(reviewers),
        reviewer_groups=len(groups),
    )
