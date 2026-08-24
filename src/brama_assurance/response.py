from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ResponseType(str, Enum):
    OBSERVE = "OBSERVE"
    ARCHIVE_EVIDENCE = "ARCHIVE_EVIDENCE"
    INCREASE_MONITORING = "INCREASE_MONITORING"
    REQUEST_PLATFORM_REVIEW = "REQUEST_PLATFORM_REVIEW"
    PUBLIC_CORRECTION = "PUBLIC_CORRECTION"
    PUBLIC_WARNING = "PUBLIC_WARNING"
    MEDIA_LITERACY_RESPONSE = "MEDIA_LITERACY_RESPONSE"
    ESCALATE_TO_AUTHORITY = "ESCALATE_TO_AUTHORITY"
    TAKE_NO_ACTION = "TAKE_NO_ACTION"


@dataclass(frozen=True)
class SimulationInput:
    response: ResponseType
    evidence_confidence: float
    attribution_confidence: float
    amplification_risk: float
    rights_risk: float
    current_reach: float

    def validate(self) -> None:
        for name in (
            "evidence_confidence",
            "attribution_confidence",
            "amplification_risk",
            "rights_risk",
            "current_reach",
        ):
            value = getattr(self, name)
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True)
class SimulationResult:
    advisory_only: bool
    response: str
    risk_score: float
    recommendation: str
    reasons: tuple[str, ...]


def simulate(value: SimulationInput) -> SimulationResult:
    value.validate()
    reasons: list[str] = []
    risk = (
        value.amplification_risk * 0.35
        + value.rights_risk * 0.35
        + (1.0 - value.evidence_confidence) * 0.20
        + (1.0 - value.attribution_confidence) * 0.10
    )
    if value.response in {ResponseType.PUBLIC_CORRECTION, ResponseType.PUBLIC_WARNING}:
        risk += value.amplification_risk * (1.0 - value.current_reach) * 0.20
        if value.current_reach < 0.25 and value.amplification_risk > 0.5:
            reasons.append("public response may amplify a currently low-reach resource")
    if value.rights_risk >= 0.5:
        reasons.append("rights-risk review required")
    if value.evidence_confidence < 0.6:
        reasons.append("evidence confidence is below action-oriented threshold")
    if value.attribution_confidence < 0.5:
        reasons.append("attribution confidence is limited")
    risk = min(1.0, risk)
    recommendation = "HUMAN_REVIEW_REQUIRED"
    if value.response in {ResponseType.OBSERVE, ResponseType.ARCHIVE_EVIDENCE, ResponseType.TAKE_NO_ACTION}:
        recommendation = "LOW_AUTHORITY_OPTION"
    elif risk >= 0.6:
        recommendation = "PREFER_LOWER_IMPACT_RESPONSE"
    return SimulationResult(
        advisory_only=True,
        response=value.response.value,
        risk_score=round(risk, 4),
        recommendation=recommendation,
        reasons=tuple(reasons),
    )
