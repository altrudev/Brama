# BRAMA Proofline architecture

## 1. Design objective

Proofline adds a governed evidence and intervention-assurance layer around BRAMA without importing hostile material into the clean runtime.

The governing invariant is:

> detection != evidence != attribution != authority != ownership != permission to act

## 2. Data domains

### CLEAN_PUBLIC
BRAMA's own Ukrainian and English public pages, published service metadata and public documentation.

### SANITIZED_EVIDENCE
Opaque case identifiers, evidence digests, evidence-set roots, timestamps, platform class, review state, reviewer attestations, authority records, policy fingerprints and observed outcomes.

### HOSTILE_UNTRUSTED
Raw hostile posts, messages, transcripts, media, prompts, directives, attachments, locators and other content-bearing payloads. This class is denied from the clean repository and runtime.

## 3. Proofline components

```text
PUBLIC SURFACE MONITOR
        |
EVIDENCE CAPSULES ---- MERKLE EVIDENCE SETS
        |
REVIEW ATTESTATIONS
        |
DDC AUTHORITY LEDGER
        |
RESPONSE SIMULATOR (advisory only)
        |
HUMAN AUTHORIZATION GATE
        |
PLATFORM REVIEW PACKAGE
        |
OUTCOME / COUNTERFACTUAL ASSESSMENT
        |
TRANSPARENCY SUMMARY
        |
OFFLINE PROOF BUNDLE / VERIFIER
```

## 4. Evidence Capsule

An Evidence Capsule is a strict content-free envelope. It separates finding confidence from attribution confidence and may carry a provenance status and exact policy fingerprint.

No raw content field exists.

## 5. Merkle evidence commitment

When a case has multiple evidence items, only their SHA-256 digests need to enter the clean domain. A Merkle root commits to the whole set. Membership proofs can later demonstrate that one digest belonged to the original set without disclosing the rest.

## 6. Review independence

Reviewer attestations use opaque reviewer identifiers and reviewer groups. Consensus policy can require multiple distinct reviewers and groups. This reduces the risk that one automated signal or one reviewer becomes unilateral action authority.

## 7. Authority ledger

The ledger is append-only in semantics and hash chained. Every transition binds:

- case;
- prior and next state;
- actor;
- timestamp;
- evidence digest;
- authority identifier;
- policy version;
- policy SHA-256;
- human-approval bit;
- previous ledger hash.

Action authority requires an explicit human approval record plus the exact governing policy fingerprint.

## 8. Response simulation

The response simulator is deliberately advisory only. It may highlight:

- amplification risk;
- rights risk;
- evidence uncertainty;
- attribution uncertainty;
- low-reach content where public rebuttal may amplify the original material.

It cannot authorize, submit, report, block or remove anything.

## 9. Platform package

A platform-review package can be built only after the ledger contains a valid human-created `AUTHORIZED_FOR_ACTION` state. The clean package contains standardized metadata and proof references, not the hostile payload or raw locator.

A controlled external adapter may resolve the opaque case/resource token within BRAMA's hostile-analysis domain if BRAMA later chooses to integrate it.

## 10. Outcome engine

The outcome model records before/after normalized metrics and labels the result as observed improvement, adverse effect or inconclusive. Counterfactual estimates are optional and explicitly confidence labeled; they are not presented as causal proof.

## 11. Dual-sided protection

Proofline defends against both:

1. hostile manipulation of the information environment; and
2. internal error, overreach, unsupported attribution or unjustified escalation.

Reconsideration records require independent review and create a traceable challenge path.

## 12. Independent proof

An exported proof bundle contains the capsule, hash-chained ledger, optional reviewer attestations and outcome summary. The verifier checks integrity and authority continuity offline.

It does not disclose hostile evidence and does not assert substantive correctness of the underlying judgment.

## 13. Directive-influence defense

Any external content attempting to modify directives, expand privilege, request disclosure, redirect resources or create action authority is treated as untrusted evidence. Raw directive/prompt fields are denied at the clean bridge.

## 14. Network model

Only the public-surface monitor uses network access:

- HTTPS only;
- `stopfraud.gov.ua` only;
- GET only;
- no cookies or credentials;
- no redirect following;
- bounded response size;
- fixed timeout;
- no response-body persistence;
- derived findings and SHA-256 evidence digests only.

Proofline core modules and offline verifier require no network access.
