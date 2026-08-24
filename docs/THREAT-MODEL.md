# Threat model

BRAMA Proofline is designed around two symmetric failure classes.

## External manipulation

Threats include:

- hostile or deceptive content entering the clean domain;
- directive-bearing content attempting to alter system behavior;
- forged or replaced evidence;
- evidence-set substitution;
- unauthorized state escalation;
- automated output being treated as action authority;
- tampering with historical records.

Controls:

- strict sanitized-event allowlist;
- raw content and raw locator denial;
- SHA-256 evidence commitments;
- optional Merkle evidence-set roots;
- hash-chained ledger entries;
- exact policy fingerprints;
- human-only action-authorization transition;
- offline proof verification.

## Internal error or overreach

Threats include:

- weak evidence being converted into a strong operational conclusion;
- confidence in detection being confused with confidence in attribution;
- one reviewer becoming unilateral authority;
- public response unintentionally amplifying low-reach material;
- a justified action producing an adverse outcome;
- a later policy change obscuring which rule governed the original decision;
- absence of a path to reconsider a prior decision.

Controls:

- separate finding and attribution confidence;
- multi-reviewer consensus primitives;
- response simulator with amplification and rights-risk signals;
- policy version plus policy SHA-256 on authority creation;
- explicit outcome assessment;
- counterfactual estimate separated from observed effect;
- reconsideration record requiring independent review;
- verifier that proves process integrity without asserting substantive correctness.

## Non-goals

Proofline does not:

- decide whether a person or account is lawful or unlawful;
- create criminal or legal attribution;
- automatically report, block or remove resources;
- bypass platform procedures;
- replace judicial, legal, investigative or human review;
- claim causal certainty from observational outcome data.

## Residual risks

A cryptographically intact process can still contain a mistaken human judgment.

A valid hash proves integrity of the referenced bytes, not truth.

A valid policy fingerprint proves which policy was used, not that the policy was appropriate.

A reviewer identifier proves only what the integrating organization can reliably bind that identifier to.

Digital signatures and organization-specific identity binding are therefore planned integration features rather than claims made by the current prototype.
