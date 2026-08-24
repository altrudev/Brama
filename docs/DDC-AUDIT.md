# DDC audit profile — BRAMA Proofline v0.2

## Directive

Provide a clean-side, read-only and human-governed assurance layer for BRAMA that can preserve evidence integrity, review history, authority, policy version, outcome and auditability without importing hostile content or creating automated action authority.

## Authority

### Allowed

- public HTTPS GET requests to the explicit BRAMA portal allowlist;
- content-free Evidence Capsules;
- SHA-256 and Merkle commitments;
- reviewer attestations;
- deterministic risk simulation;
- human-governed state transitions;
- policy fingerprints;
- content-free platform review packages after human authorization;
- outcome summaries;
- transparency summaries;
- offline integrity verification.

### Denied

- raw hostile-content persistence;
- raw URL or resource-locator promotion into the clean bridge;
- directive/prompt promotion;
- autonomous classification-to-action transition;
- automated reporting, takedown or blocking;
- implicit privilege expansion;
- non-public access;
- telemetry;
- remote code execution.

## Transition invariants

`AUTHORIZED_FOR_ACTION` requires:

1. valid prior state;
2. human actor;
3. explicit human approval;
4. valid evidence SHA-256;
5. authority identifier;
6. policy version;
7. policy SHA-256.

The ledger verifier also checks per-case state continuity, global sequence continuity, previous-hash continuity and entry integrity.

## Evidence invariants

- raw evidence remains outside the clean domain;
- Evidence Capsules contain metadata only;
- evidence-set membership may be represented through Merkle proofs;
- a digest proves byte commitment, not truth;
- provenance status is separate from substantive correctness;
- finding confidence and attribution confidence remain separate.

## Human safeguards

- response simulation is advisory only;
- reviewer consensus primitives support independent review;
- reconsideration requires independent review;
- platform export is denied before valid human authority;
- offline verification does not assert that the underlying decision was correct.

## Current release gate

Required before a release is treated as DDC-passing:

- full unit-test suite passes;
- Python modules compile;
- clean-corpus scan passes;
- no prohibited locale surface is introduced;
- no raw-content field is introduced into the clean bridge schema;
- no secret-like material is committed;
- no unexpected runtime dependency is introduced;
- network scope remains explicit and bounded;
- committed files match the audited source;
- release manifest is regenerated after all file changes.
