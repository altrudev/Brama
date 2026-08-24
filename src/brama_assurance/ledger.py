from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .canonical import sha256_json
from .governance import State, TransitionRequest, validate_transition


class LedgerRejected(ValueError):
    pass


@dataclass(frozen=True)
class LedgerEntry:
    sequence: int
    case_id: str
    from_state: str
    to_state: str
    actor_id: str
    actor_type: str
    occurred_at: str
    evidence_sha256: str
    authority_id: str | None
    policy_version: str | None
    policy_sha256: str | None
    human_approval: bool
    previous_hash: str | None
    entry_hash: str

    def unsigned_payload(self) -> dict:
        value = asdict(self)
        value.pop("entry_hash")
        return value


def _timestamp(value: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LedgerRejected("occurred_at must be ISO-8601") from exc


def build_entry(
    *,
    sequence: int,
    case_id: str,
    from_state: State,
    to_state: State,
    actor_id: str,
    actor_type: str,
    occurred_at: str,
    evidence_sha256: str,
    authority_id: str | None = None,
    policy_version: str | None = None,
    policy_sha256: str | None = None,
    human_approval: bool = False,
    previous_hash: str | None = None,
) -> LedgerEntry:
    if sequence < 0:
        raise LedgerRejected("sequence must be non-negative")
    if not case_id or not actor_id:
        raise LedgerRejected("case_id and actor_id are required")
    _timestamp(occurred_at)
    validate_transition(
        TransitionRequest(
            from_state=from_state,
            to_state=to_state,
            actor_type=actor_type,
            evidence_sha256=evidence_sha256,
            human_approval=human_approval,
        )
    )
    if to_state is State.AUTHORIZED_FOR_ACTION:
        if not authority_id:
            raise LedgerRejected("authority_id required when action authority is created")
        if not policy_version:
            raise LedgerRejected("policy_version required when action authority is created")
        if not policy_sha256 or len(policy_sha256) != 64 or any(c not in "0123456789abcdef" for c in policy_sha256):
            raise LedgerRejected("valid policy_sha256 required when action authority is created")
    unsigned = {
        "sequence": sequence,
        "case_id": case_id,
        "from_state": from_state.value,
        "to_state": to_state.value,
        "actor_id": actor_id,
        "actor_type": actor_type,
        "occurred_at": occurred_at,
        "evidence_sha256": evidence_sha256,
        "authority_id": authority_id,
        "policy_version": policy_version,
        "policy_sha256": policy_sha256,
        "human_approval": human_approval,
        "previous_hash": previous_hash,
    }
    return LedgerEntry(entry_hash=sha256_json(unsigned), **unsigned)


def append_transition(
    entries: list[LedgerEntry],
    *,
    case_id: str,
    from_state: State,
    to_state: State,
    actor_id: str,
    actor_type: str,
    occurred_at: str,
    evidence_sha256: str,
    authority_id: str | None = None,
    policy_version: str | None = None,
    policy_sha256: str | None = None,
    human_approval: bool = False,
) -> LedgerEntry:
    case_entries = [entry for entry in entries if entry.case_id == case_id]
    if case_entries and case_entries[-1].to_state != from_state.value:
        raise LedgerRejected("from_state does not match current case state")
    if not case_entries and from_state is not State.RECEIVED:
        raise LedgerRejected("first transition must start at RECEIVED")
    previous_hash = entries[-1].entry_hash if entries else None
    entry = build_entry(
        sequence=len(entries),
        case_id=case_id,
        from_state=from_state,
        to_state=to_state,
        actor_id=actor_id,
        actor_type=actor_type,
        occurred_at=occurred_at,
        evidence_sha256=evidence_sha256,
        authority_id=authority_id,
        policy_version=policy_version,
        policy_sha256=policy_sha256,
        human_approval=human_approval,
        previous_hash=previous_hash,
    )
    entries.append(entry)
    return entry


def verify_chain(entries: Iterable[LedgerEntry]) -> list[str]:
    failures: list[str] = []
    previous_hash: str | None = None
    current_by_case: dict[str, str] = {}
    for expected_sequence, entry in enumerate(entries):
        if entry.sequence != expected_sequence:
            failures.append(f"sequence mismatch at {expected_sequence}")
        if entry.previous_hash != previous_hash:
            failures.append(f"previous_hash mismatch at {expected_sequence}")
        if sha256_json(entry.unsigned_payload()) != entry.entry_hash:
            failures.append(f"entry hash mismatch at {expected_sequence}")
        expected_from = current_by_case.get(entry.case_id, State.RECEIVED.value)
        if entry.from_state != expected_from:
            failures.append(f"case state continuity mismatch at {expected_sequence}")
        try:
            validate_transition(
                TransitionRequest(
                    from_state=State(entry.from_state),
                    to_state=State(entry.to_state),
                    actor_type=entry.actor_type,
                    evidence_sha256=entry.evidence_sha256,
                    human_approval=entry.human_approval,
                )
            )
        except (ValueError, KeyError) as exc:
            failures.append(f"governance violation at {expected_sequence}: {exc}")
        if entry.to_state == State.AUTHORIZED_FOR_ACTION.value:
            if not entry.authority_id:
                failures.append(f"authority_id missing at {expected_sequence}")
            if not entry.policy_version:
                failures.append(f"policy_version missing at {expected_sequence}")
            if not entry.policy_sha256 or len(entry.policy_sha256) != 64 or any(c not in "0123456789abcdef" for c in entry.policy_sha256):
                failures.append(f"policy_sha256 missing or invalid at {expected_sequence}")
        current_by_case[entry.case_id] = entry.to_state
        previous_hash = entry.entry_hash
    return failures
