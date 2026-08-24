from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class State(str, Enum):
    RECEIVED = "RECEIVED"
    QUARANTINED = "QUARANTINED"
    HUMAN_REVIEW_PENDING = "HUMAN_REVIEW_PENDING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    AUTHORIZED_FOR_ACTION = "AUTHORIZED_FOR_ACTION"
    ACTION_ACTIVE = "ACTION_ACTIVE"
    OUTCOME_OBSERVED = "OUTCOME_OBSERVED"
    CLOSED = "CLOSED"


ALLOWED = {
    State.RECEIVED: {State.QUARANTINED},
    State.QUARANTINED: {State.HUMAN_REVIEW_PENDING},
    State.HUMAN_REVIEW_PENDING: {
        State.VERIFIED,
        State.REJECTED,
        State.INSUFFICIENT_EVIDENCE,
    },
    State.VERIFIED: {State.AUTHORIZED_FOR_ACTION},
    State.REJECTED: {State.CLOSED},
    State.INSUFFICIENT_EVIDENCE: {State.CLOSED, State.HUMAN_REVIEW_PENDING},
    State.AUTHORIZED_FOR_ACTION: {State.ACTION_ACTIVE},
    State.ACTION_ACTIVE: {State.OUTCOME_OBSERVED},
    State.OUTCOME_OBSERVED: {State.CLOSED},
    State.CLOSED: set(),
}


@dataclass(frozen=True)
class TransitionRequest:
    from_state: State
    to_state: State
    actor_type: str
    evidence_sha256: str
    human_approval: bool = False


class TransitionDenied(ValueError):
    pass


def validate_transition(request: TransitionRequest) -> None:
    if request.to_state not in ALLOWED[request.from_state]:
        raise TransitionDenied(
            f"transition denied: {request.from_state.value} -> {request.to_state.value}"
        )
    if len(request.evidence_sha256) != 64 or any(c not in "0123456789abcdef" for c in request.evidence_sha256):
        raise TransitionDenied("valid SHA-256 evidence digest required")
    if request.to_state is State.AUTHORIZED_FOR_ACTION:
        if request.actor_type != "human" or not request.human_approval:
            raise TransitionDenied("human approval is required to create action authority")
