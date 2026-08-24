from __future__ import annotations

from dataclasses import asdict, replace
from typing import Any, Iterable

from .evidence import EvidenceCapsule
from .ledger import LedgerEntry
from .review import ReviewAttestation, ReviewDecision
from .verifier import VerificationReport, verify_proof


PROFILE = "brama-proofline-proof-bundle-v1"


def _serialize_attestation(item: ReviewAttestation | dict[str, Any]) -> dict[str, Any]:
    if isinstance(item, ReviewAttestation):
        value = asdict(item)
        value["decision"] = item.decision.value
        value["attestation_sha256"] = item.attestation_hash()
        return value
    return dict(item)


def build_proof_bundle(
    capsule: EvidenceCapsule,
    entries: Iterable[LedgerEntry],
    *,
    outcome: dict[str, Any] | None = None,
    reviewer_attestations: list[ReviewAttestation | dict[str, Any]] | None = None,
) -> dict[str, Any]:
    capsule.validate()
    case_entries = [entry for entry in entries if entry.case_id == capsule.case_id]
    if not case_entries:
        raise ValueError("proof bundle requires at least one case ledger entry")
    return {
        "profile": PROFILE,
        "capsule": capsule.payload(),
        "capsule_sha256": capsule.capsule_hash(),
        "ledger": [asdict(entry) for entry in case_entries],
        "ledger_head_sha256": case_entries[-1].entry_hash,
        "reviewer_attestations": [_serialize_attestation(item) for item in (reviewer_attestations or [])],
        "outcome": outcome,
        "raw_content_included": False,
    }


def verify_bundle(bundle: dict[str, Any]) -> VerificationReport:
    if bundle.get("profile") != PROFILE:
        raise ValueError("unsupported proof bundle profile")
    if bundle.get("raw_content_included") is not False:
        raise ValueError("proof bundle must declare raw_content_included=false")
    capsule = EvidenceCapsule(**bundle["capsule"])
    entries = [LedgerEntry(**item) for item in bundle["ledger"]]
    if not entries or bundle.get("ledger_head_sha256") != entries[-1].entry_hash:
        raise ValueError("ledger head mismatch")
    report = verify_proof(capsule, bundle["capsule_sha256"], entries, require_authority=True)
    failures = list(report.failures)
    for index, item in enumerate(bundle.get("reviewer_attestations", [])):
        try:
            attestation = ReviewAttestation(
                case_id=item["case_id"],
                reviewer_id=item["reviewer_id"],
                reviewer_group=item["reviewer_group"],
                evidence_sha256=item["evidence_sha256"],
                decision=ReviewDecision(item["decision"]),
                confidence=float(item["confidence"]),
                occurred_at=item["occurred_at"],
            )
            if attestation.case_id != capsule.case_id or attestation.evidence_sha256 != capsule.evidence_sha256:
                failures.append(f"reviewer attestation scope mismatch at {index}")
            if item.get("attestation_sha256") != attestation.attestation_hash():
                failures.append(f"reviewer attestation hash mismatch at {index}")
        except (KeyError, TypeError, ValueError) as exc:
            failures.append(f"reviewer attestation invalid at {index}: {exc}")
    if failures != list(report.failures):
        return replace(report, integrity_verified=False, failures=tuple(failures))
    return report
