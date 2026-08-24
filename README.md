# BRAMA Proofline

**Governed evidence, authority and outcome assurance for Ukraine's BRAMA / Cyber Brama ecosystem.**

BRAMA Proofline grows the original Assurance Boundary into a clean-side operational assurance layer:

> evidence -> human judgment -> authority -> action -> observed outcome -> verifiable proof

It is deliberately **not** a propaganda corpus, autonomous classifier, scraping pipeline, mass-reporting bot, or automated takedown system. Hostile material remains outside the clean domain. Proofline works with sanitized metadata, cryptographic digests, policy fingerprints, review attestations and governed state transitions.

## Why Proofline

Counter-disinformation systems need more than detection. A defensible operation should be able to answer:

- what evidence existed at the time;
- which reviewers assessed it;
- what exact policy version governed the decision;
- who created authority to act;
- whether a lower-impact response was considered;
- what happened after the intervention;
- whether the process can be independently verified later.

Proofline is designed to make those answers part of the system rather than retrospective paperwork.

## v0.2 capabilities

### Evidence Capsules
Strict, content-free case envelopes carrying opaque identifiers, timestamps, evidence hashes, confidence separation, provenance status and policy fingerprints.

### Merkle evidence sets
Multiple evidence digests can be committed into one Merkle root and later proven to belong to the original set without disclosing other evidence.

### Independent review consensus
Reviewer attestations are hashed independently and consensus rules can require multiple reviewers and reviewer groups.

### DDC authority ledger
Every state transition is hash chained. Action authority requires a human actor, explicit approval, an authority identifier, a policy version and the SHA-256 fingerprint of that policy.

### Response simulator
A deterministic **advisory-only** model highlights amplification risk, rights risk, weak evidence and weak attribution. Its output cannot create authority.

### Outcome and counterfactual assessment
Before/after metrics record observed effect and may include a clearly confidence-labeled counterfactual estimate. The system distinguishes observed change from causal certainty.

### Human-gated platform review package
A structured review package can be generated only after a valid human authority transition. Free-form hostile content and raw resource locators are not part of the clean package.

### Dual-sided safeguards
A reconsideration record provides a path for independent review when new evidence, policy conflict or possible error is identified.

### Automatic transparency summary
Structured ledgers can produce counts of reviewed, rejected, insufficient-evidence, authorized, outcome-observed and closed cases.

### Offline proof verifier
`brama-proof` verifies a proof bundle locally. It can verify capsule integrity, ledger integrity, policy/authority continuity and tampering without receiving the hostile content.

The verifier explicitly does **not** claim that a decision was substantively correct. It proves that the represented process and hashes are internally consistent.

## Trust boundary

```text
CLEAN ASSURANCE DOMAIN
        |
        | opaque IDs / hashes / review state / policy fingerprints
        v
+----------------------+
|   BRAMA PROOFLINE    |
+----------------------+
        |
======== TRUST BOUNDARY ========
        |
        v
HOSTILE / UNTRUSTED EVIDENCE DOMAIN
```

Raw hostile material has:

```text
trust: untrusted_external_evidence
executability: none
directive_authority: none
training_eligibility: denied
memory_promotion: denied
clean_corpus_export: denied
```

Raw URLs, prompts, directives, messages, transcripts, attachments and equivalent payload fields are denied at the clean bridge.

## Governed lifecycle

```text
RECEIVED
  -> QUARANTINED
  -> HUMAN_REVIEW_PENDING
  -> VERIFIED | REJECTED | INSUFFICIENT_EVIDENCE
  -> AUTHORIZED_FOR_ACTION
  -> ACTION_ACTIVE
  -> OUTCOME_OBSERVED
  -> CLOSED
```

`AUTHORIZED_FOR_ACTION` cannot be created by an automated actor.

## Run

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m brama_assurance.audit
```

Public-surface monitor:

```bash
python -m brama_assurance.cli --live
```

Offline proof verification:

```bash
brama-proof proof-bundle.json
```

No command performs implicit network access. The monitor is the only networked component and remains HTTPS GET-only to the explicit `stopfraud.gov.ua` allowlist.

## Public observations that motivated the original boundary

Verified against the live public portal on 2026-08-23:

1. the portal states that it is in testing/filling mode;
2. UA and EN surfaces showed material freshness/translation drift;
3. the privacy policy text referenced the earlier `.com.ua` domain while being served from `.gov.ua`;
4. the privacy policy declared automatic MAC-address collection, which merits implementation/policy verification.

These are public-surface assurance observations, not allegations of wrongdoing.

## Ukrainian proposal

See [`docs/PROPOSAL-UA.md`](docs/PROPOSAL-UA.md) and [`docs/OUTREACH-UA.md`](docs/OUTREACH-UA.md).

## Author / contact

**Valentyn Rukhaylo**  
Altru.dev  
Email: altrudevelop@gmail.com  
Contact: https://altru.dev/contact  
GitHub: https://github.com/altrudev  
LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6

## Status

Research prototype / contribution package. Not affiliated with or endorsed by the Department of Cyber Police of the National Police of Ukraine, EUAM Ukraine, or BRAMA unless explicitly adopted.
