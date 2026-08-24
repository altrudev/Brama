from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .evidence import EvidenceCapsule
from .ledger import LedgerEntry, verify_chain


@dataclass(frozen=True)
class VerificationReport:
    integrity_verified: bool
    capsule_verified: bool
    authority_chain_verified: bool
    contents_disclosed: bool
    decision_correctness_asserted: bool
    failures: tuple[str, ...]


def verify_proof(
    capsule: EvidenceCapsule,
    expected_capsule_hash: str,
    entries: Iterable[LedgerEntry],
    *,
    require_authority: bool = True,
) -> VerificationReport:
    failures: list[str] = []
    try:
        actual_capsule_hash = capsule.capsule_hash()
    except ValueError as exc:
        failures.append(f"capsule invalid: {exc}")
        actual_capsule_hash = ""
    capsule_verified = actual_capsule_hash == expected_capsule_hash
    if not capsule_verified:
        failures.append("capsule hash mismatch")

    items = list(entries)
    chain_failures = verify_chain(items)
    failures.extend(chain_failures)

    authority_entries = [
        entry for entry in items
        if entry.case_id == capsule.case_id and entry.to_state == "AUTHORIZED_FOR_ACTION"
    ]
    authority_chain_verified = bool(authority_entries) and all(
        entry.actor_type == "human"
        and entry.human_approval
        and bool(entry.authority_id)
        and bool(entry.policy_version)
        and bool(entry.policy_sha256)
        for entry in authority_entries
    )
    if require_authority and not authority_chain_verified:
        failures.append("required human authority record missing or invalid")

    return VerificationReport(
        integrity_verified=not failures,
        capsule_verified=capsule_verified,
        authority_chain_verified=authority_chain_verified,
        contents_disclosed=False,
        decision_correctness_asserted=False,
        failures=tuple(failures),
    )
