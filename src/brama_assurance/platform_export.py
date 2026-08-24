from __future__ import annotations

from enum import Enum
from typing import Iterable

from .evidence import EvidenceCapsule
from .ledger import LedgerEntry


class ExportDenied(ValueError):
    pass


class ReviewRequestType(str, Enum):
    POLICY_COMPLIANCE_REVIEW = "POLICY_COMPLIANCE_REVIEW"
    FRAUD_REVIEW = "FRAUD_REVIEW"
    COORDINATED_BEHAVIOR_REVIEW = "COORDINATED_BEHAVIOR_REVIEW"
    SAFETY_REVIEW = "SAFETY_REVIEW"


AUTHORIZED_STATES = {"AUTHORIZED_FOR_ACTION", "ACTION_ACTIVE", "OUTCOME_OBSERVED", "CLOSED"}


def build_platform_review_package(
    capsule: EvidenceCapsule,
    entries: Iterable[LedgerEntry],
    *,
    requested_review: ReviewRequestType,
) -> dict:
    capsule.validate()
    case_entries = [entry for entry in entries if entry.case_id == capsule.case_id]
    if not case_entries:
        raise ExportDenied("case ledger is required")
    latest = case_entries[-1]
    if latest.to_state not in AUTHORIZED_STATES:
        raise ExportDenied("human-authorized action state required before export")
    authority = next(
        (entry for entry in reversed(case_entries) if entry.to_state == "AUTHORIZED_FOR_ACTION"),
        None,
    )
    if authority is None or authority.actor_type != "human" or not authority.human_approval:
        raise ExportDenied("verified human authority record required")
    return {
        "profile": "brama-proofline-platform-review-v1",
        "case_id": capsule.case_id,
        "platform": capsule.platform,
        "resource_type": capsule.source_type,
        "observed_at": capsule.observed_at,
        "evidence_sha256": capsule.evidence_sha256,
        "evidence_set_root": capsule.evidence_set_root,
        "capsule_sha256": capsule.capsule_hash(),
        "provenance_status": capsule.provenance_status,
        "review_state": latest.to_state,
        "authority_id": authority.authority_id,
        "policy_version": authority.policy_version,
        "policy_sha256": authority.policy_sha256,
        "requested_review": requested_review.value,
        "ledger_head_sha256": latest.entry_hash,
    }
