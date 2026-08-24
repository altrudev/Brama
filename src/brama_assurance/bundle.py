from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable

from .evidence import EvidenceCapsule
from .ledger import LedgerEntry
from .verifier import VerificationReport, verify_proof


PROFILE = "brama-proofline-proof-bundle-v1"


def build_proof_bundle(
    capsule: EvidenceCapsule,
    entries: Iterable[LedgerEntry],
    *,
    outcome: dict[str, Any] | None = None,
    reviewer_attestations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    capsule.validate()
    items = list(entries)
    case_entries = [entry for entry in items if entry.case_id == capsule.case_id]
    if not case_entries:
        raise ValueError("proof bundle requires at least one case ledger entry")
    return {
        "profile": PROFILE,
        "capsule": capsule.payload(),
        "capsule_sha256": capsule.capsule_hash(),
        "ledger": [asdict(entry) for entry in items],
        "ledger_head_sha256": items[-1].entry_hash,
        "reviewer_attestations": reviewer_attestations or [],
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
    return verify_proof(capsule, bundle["capsule_sha256"], entries, require_authority=True)
