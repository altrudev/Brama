from __future__ import annotations

from dataclasses import asdict, dataclass

from .canonical import sha256_json


@dataclass(frozen=True)
class OutcomeMetrics:
    reach_index: float
    spread_velocity: float
    recurrence_index: float
    collateral_amplification: float

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if not 0.0 <= value <= 1.0:
                raise ValueError(f"{name} must be between 0 and 1")


@dataclass(frozen=True)
class OutcomeAssessment:
    observed_effect: float
    classification: str
    counterfactual_gap: float | None
    confidence: str
    assessment_hash: str


def assess_outcome(
    before: OutcomeMetrics,
    after: OutcomeMetrics,
    *,
    counterfactual_reach_index: float | None = None,
    confidence: str = "limited",
) -> OutcomeAssessment:
    before.validate()
    after.validate()
    if confidence not in {"limited", "moderate", "strong"}:
        raise ValueError("unsupported confidence")
    if counterfactual_reach_index is not None and not 0.0 <= counterfactual_reach_index <= 1.0:
        raise ValueError("counterfactual_reach_index must be between 0 and 1")
    before_harm = (
        before.reach_index * 0.35
        + before.spread_velocity * 0.30
        + before.recurrence_index * 0.20
        + before.collateral_amplification * 0.15
    )
    after_harm = (
        after.reach_index * 0.35
        + after.spread_velocity * 0.30
        + after.recurrence_index * 0.20
        + after.collateral_amplification * 0.15
    )
    effect = round(before_harm - after_harm, 4)
    if effect >= 0.2:
        classification = "IMPROVEMENT_OBSERVED"
    elif effect <= -0.1:
        classification = "ADVERSE_EFFECT_OBSERVED"
    else:
        classification = "INCONCLUSIVE"
    gap = None if counterfactual_reach_index is None else round(counterfactual_reach_index - after.reach_index, 4)
    payload = {
        "before": asdict(before),
        "after": asdict(after),
        "observed_effect": effect,
        "classification": classification,
        "counterfactual_gap": gap,
        "confidence": confidence,
    }
    return OutcomeAssessment(
        observed_effect=effect,
        classification=classification,
        counterfactual_gap=gap,
        confidence=confidence,
        assessment_hash=sha256_json(payload),
    )
