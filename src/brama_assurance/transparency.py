from __future__ import annotations

from collections import Counter
from typing import Iterable

from .ledger import LedgerEntry


def summarize(entries: Iterable[LedgerEntry]) -> dict:
    items = list(entries)
    cases = {entry.case_id for entry in items}
    states = Counter(entry.to_state for entry in items)
    return {
        "cases_seen": len(cases),
        "transitions": len(items),
        "verified": states["VERIFIED"],
        "rejected": states["REJECTED"],
        "insufficient_evidence": states["INSUFFICIENT_EVIDENCE"],
        "actions_authorized": states["AUTHORIZED_FOR_ACTION"],
        "outcomes_observed": states["OUTCOME_OBSERVED"],
        "closed": states["CLOSED"],
    }
