# BRAMA Assurance Boundary

External integrity and transition-assurance tooling for Ukraine's **Кібер Брама / Cyber Brama** public infrastructure.

This project is deliberately **not** a propaganda corpus, classifier, scraping pipeline, or mass-reporting tool. It is a clean-side assurance layer that evaluates the public Ukrainian/English service surface and models governed transitions without ingesting or retaining hostile content.

## Why this exists

BRAMA's mission necessarily brings it into contact with hostile information. That makes direct corpus integration inappropriate for systems that require a clean Ukrainian-only operating corpus. The safer contribution pattern is an explicit trust boundary:

```text
CLEAN ASSURANCE DOMAIN
        |
        | metadata / hashes / state only
        v
+--------------------------+
| BRAMA Assurance Boundary |
+--------------------------+
        |
======== TRUST BOUNDARY ========
        |
        v
HOSTILE / UNTRUSTED EVIDENCE DOMAIN
```

The clean side may receive identifiers, timestamps, hashes, platform classes, review states, approval records and outcome states. It does **not** receive raw hostile payloads.

## Prototype capabilities

`brama-monitor` performs read-only checks against an explicit host allowlist and emits findings without retaining response bodies.

Current checks:

- canonical HTTPS host enforcement;
- UA/EN public-locale surface check;
- unexpected Russian-locale exposure detection;
- public testing-mode banner detection;
- UA/EN freshness drift detection;
- mixed-language signal detection on the English route;
- privacy-policy canonical-domain drift detection;
- privacy-policy MAC-address collection declaration detection;
- page SHA-256 evidence digests for reproducibility.

## DDC transition model

The project treats detection, evidence, attribution, authority and action as separate states.

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

No detector output can directly authorize coordinated action.

## Containment invariants

Raw hostile material is classified as:

```text
trust: untrusted_external_evidence
executability: none
directive_authority: none
training_eligibility: denied
memory_promotion: denied
clean_corpus_export: denied
```

The implementation is intentionally small and auditable. Network access is GET-only, allowlisted, bounded by response-size and timeout limits, and emits no telemetry.

## Run

```bash
python -m brama_assurance.cli --live
```

For local development:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src python -m brama_assurance.audit
```

The audit checks repository invariants, including absence of Russian-language locale surfaces and Russian-specific Cyrillic characters in project text.

## Public observations motivating the prototype

Verified against the live public portal on 2026-08-23:

1. `https://stopfraud.gov.ua/` states that the portal is in testing/filling mode.
2. The Ukrainian homepage exposes August 2026 news while `/en` exposes February 2024 news and Ukrainian-language headlines, indicating translation/freshness drift.
3. The live privacy policy is hosted on `.gov.ua` while its text still identifies `https://stopfraud.com.ua`.
4. The privacy policy declares automatic collection of a MAC address. Ordinary web browsers do not normally expose a client's network-interface MAC address to a remote website, so this declaration merits implementation/policy verification.

These are public-surface assurance findings, not allegations of wrongdoing.

## Non-goals

- no hostile-content collection;
- no Russian-language corpus;
- no automated propaganda classification;
- no automated reporting of accounts or resources;
- no bypassing moderation or platform controls;
- no attribution or corruption allegations;
- no privileged or non-public BRAMA access.

## Author / contact

**Valentyn Rukhaylo**  
Altru.dev  
Email: altrudevelop@gmail.com  
Contact: https://altru.dev/contact  
GitHub: https://github.com/altrudev  
LinkedIn: https://www.linkedin.com/in/val-rukhaylo-437a1b3b6

## Status

Research prototype / contribution package. Not affiliated with or endorsed by the Department of Cyber Police of the National Police of Ukraine, EUAM Ukraine, or BRAMA unless they explicitly adopt it.
